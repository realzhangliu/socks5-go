package socks5

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

//AssembleHeader assemble data with header
/*
	+----+------+------+----------+----------+----------+
	 |RSV | FRAG | ATYP | DST.ADDR | DST.PORT | DATA |
	 +----+------+------+----------+----------+----------+
	 | 2 | 1 | 1 | Variable | 2 | Variable |
	 +----+------+------+----------+----------+----------+*/
func AssembleHeader(data []byte, addr *net.UDPAddr) *bytes.Buffer {
	proxyData := bytes.NewBuffer(nil)
	if addr == nil {
		return nil
	}
	addrATYP := byte(0)
	var addrBody []byte
	switch {
	case addr.IP == nil:
		addrATYP = atypIPV4
		addrBody = []byte{0, 0, 0, 0}
	case addr.IP.To4() != nil:
		addrATYP = atypIPV4
		addrBody = []byte(addr.IP.To4())
	case addr.IP.To16() != nil:
		addrATYP = atypIPV6
		addrBody = []byte(addr.IP.To16())
	default:
		fmt.Errorf("failed to format address")
		return nil
	}
	proxyData.Write([]byte{0, 0, 0, addrATYP})
	proxyData.Write(addrBody)
	proxyData.Write([]byte{byte(addr.Port >> 8)})
	proxyData.Write([]byte{byte(addr.Port & 0xff)})
	proxyData.Write(data)
	return proxyData
}

//TrimHeader trim socks5 header to send exact data to remote
/*
	+----+------+------+----------+----------+----------+
	 |RSV | FRAG | ATYP | DST.ADDR | DST.PORT | DATA |
	 +----+------+------+----------+----------+----------+
	 | 2 | 1 | 1 | Variable | 2 | Variable |
	 +----+------+------+----------+----------+----------+*/
func TrimHeader(dataBuf *bytes.Buffer) (frag byte, dstIP *net.IP, dstPort int) {
	// Each UDP datagram carries a UDP request   header with it:

	//RSV
	dataBuf.ReadByte()
	dataBuf.ReadByte()
	//FRAG
	frag, err := dataBuf.ReadByte()
	if err != nil {
		return
	}
	//ATYP
	atyp, err := dataBuf.ReadByte()
	switch int(atyp) {
	case int(atypIPV4):
		//ipv4
		b := make([]byte, 4)
		_, err = dataBuf.Read(b)
		if err != nil {
			return
		}
		d := net.IP(b)
		dstIP = &d
	case int(atypFQDN):
		//domain name
		b := make([]byte, 1)
		_, err = dataBuf.Read(b)
		if err != nil {
			return
		}
		domainNameBytes := make([]byte, int(b[0]))
		_, err = dataBuf.Read(domainNameBytes)
		if err != nil {
			return
		}
		addrs, err := net.LookupHost(string(domainNameBytes))
		if err != nil {
			return
		}
		ipAddr, err := net.ResolveIPAddr("tcp", addrs[0])
		if err != nil {
			return
		}
		dstIP = &ipAddr.IP
	case int(atypIPV6):
		//ipv6
		b := make([]byte, 16)
		_, err = dataBuf.Read(b)
		if err != nil {
			return
		}
		d := net.IP(b)
		dstIP = &d
	default:
		return
	}
	b := make([]byte, 2)
	_, err = dataBuf.Read(b)
	if err != nil {
		return
	}
	dstPort = int(b[0])<<8 + int(b[1])
	//log.Printf("dstIP:%v dstPort:%v\n", dstIP, dstPort)
	return
}

//UDPTransport handle UDP traffic
func (s *Server) UDPTransport(relayConn *net.UDPConn, clientAddr *net.UDPAddr, b []byte) {
	dataBuf := bytes.NewBuffer(b)
	frag, dstIP, dstPort := TrimHeader(dataBuf)
	remoteAddr := &net.UDPAddr{
		IP:   *dstIP,
		Port: dstPort,
		Zone: "",
	}
	//udp dial
	remoteConn, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		return
	}
	//rAddrChan <- TargetConn.LocalAddr().(*net.UDPAddr)
	//if request is existed
	if s.UDPRequestMap[clientAddr.String()] == nil {
		s.UDPRequestMap[clientAddr.String()] = &UDPRequest{
			clientAddr:      clientAddr,
			remoteConn:      remoteConn,
			remoteAddr:      remoteAddr,
			reassemblyQueue: []byte{},
			position:        0,
		}
	}
	request := s.UDPRequestMap[clientAddr.String()]
	//UDPRequestChan <- request
	LaunchReplyChan := make(chan struct{})
	go func(v *UDPRequest) {
		request.remoteConn.SetReadDeadline(time.Now().Add(time.Second * 3))
		//assemble proxy header
		b := make([]byte, MAXUDPDATA)
		LaunchReplyChan <- struct{}{}
		for {
			n, _, err := request.remoteConn.ReadFromUDP(b)
			if n == 0 {
				if err != nil {
					if err == io.EOF || strings.Contains(err.Error(), "timeout") {
						break
					}
				}
				time.Sleep(time.Second * 3)
			}
			dataBuf := AssembleHeader(b[:n], v.clientAddr)
			relayConn.WriteMsgUDP(dataBuf.Bytes(), nil, v.clientAddr)
			log.Printf("[UDP]remote:%v send %v bytes -> client:%v\n", v.remoteAddr, n, v.clientAddr)
		}
		delete(s.UDPRequestMap, v.clientAddr.String())
	}(request)
	<-LaunchReplyChan

	if int(frag) > request.position {
		request.position = int(frag)
		//save data
		request.reassemblyQueue = append(request.reassemblyQueue, dataBuf.Bytes()...)
		return
	}
	//standalone
	if frag == 0 {
		if len(request.reassemblyQueue) > 0 {
			remoteConn.Write(request.reassemblyQueue)
			//reinitialize
			request.reassemblyQueue = []byte{}
			request.position = 0
		}
		remoteConn.Write(dataBuf.Bytes())
		log.Printf("[UDP]client:%v send %v bytes -> remote:%v\n", clientAddr, len(b), remoteAddr)
		return
	}

	//begin to handle  a new datagrams
	if int(frag) < request.position {
		//send previous datagrams
		remoteConn.Write(request.reassemblyQueue)
		log.Printf("[UDP]client:%v send %v bytes -> remote:%v\n", relayConn.LocalAddr(), len(b), remoteConn.RemoteAddr())
		//reinitialize
		request.reassemblyQueue = []byte{}
		request.position = 0

		//save data
		request.position = int(frag)
		//save data
		request.reassemblyQueue = append(request.reassemblyQueue, dataBuf.Bytes()...)
	}
}
