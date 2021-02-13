package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"time"
)

//AssembleHeader assemble data with header
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
func TrimHeader(dataBuf *bytes.Buffer) (frag byte, dstIP *net.IP, dstPort int) {
	// Each UDP datagram carries a UDP request   header with it:
	/*
		+----+------+------+----------+----------+----------+
		 |RSV | FRAG | ATYP | DST.ADDR | DST.PORT | DATA |
		 +----+------+------+----------+----------+----------+
		 | 2 | 1 | 1 | Variable | 2 | Variable |
		 +----+------+------+----------+----------+----------+*/
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
func UDPTransport(relayConn *net.UDPConn, ctx context.Context) {
	reassemblyQueue := make([]byte, 0)
	position := 0 //1-127
	expires := time.Second * 5
	//create remote relayed UDP conn
	rAddrChan := make(chan *net.UDPAddr)
	cAddrChan := make(chan *net.UDPAddr, 1)
	closeChan := make(chan struct{}, 2)

	// remote -> relay -> client
	go func() {
		for {
			select {
			case <-closeChan:
				return
			default:
				remoteAddr := <-rAddrChan
				remoteRelayConn, err := net.ListenUDP("udp", remoteAddr)
				if err != nil {
					return
				}
				//assemble proxy header
				b := make([]byte, MAXUDPDATA)
				n, _, err := remoteRelayConn.ReadFromUDP(b)
				if err != nil {
					//closeChan <- err
					return
				}
				clientAddr := <-cAddrChan
				dataBuf := AssembleHeader(b[:n], clientAddr)
				relayConn.WriteMsgUDP(dataBuf.Bytes(), nil, clientAddr)
				log.Printf("[UDP]remote:%v send %v bytes -> client:%v\n", remoteAddr, n, clientAddr)
			}
		}
	}()

	// client -> relay -> remote
	go func() {
		for {
			select {
			case <-closeChan:
				return
			default:
				b := make([]byte, MAXUDPDATA)
				n, clientAddr, err := relayConn.ReadFromUDP(b)
				if err != nil {
					continue
				}
				cAddrChan <- clientAddr

				dataBuf := bytes.NewBuffer(b[:n])
				frag, dstIP, dstPort := TrimHeader(dataBuf)
				//drop any datagrams arriving from any source IP other than one recorded for the particular association.
				//todo

				if int(frag) > position {
					position = int(frag)
					//save data
					reassemblyQueue = append(reassemblyQueue, dataBuf.Bytes()...)
					continue
				}

				//udp dial
				remoteConn, err := net.DialUDP("udp", nil, &net.UDPAddr{
					IP:   *dstIP,
					Port: dstPort,
					Zone: "",
				})
				if err != nil {
					continue
				}
				rAddrChan <- remoteConn.LocalAddr().(*net.UDPAddr)

				//standalone
				if frag == 0 {
					if len(reassemblyQueue) > 0 {
						remoteConn.Write(reassemblyQueue)
						//reinitialize
						reassemblyQueue = make([]byte, 0)
						position = 0
						relayConn.SetReadDeadline(time.Time{})
					}
					remoteConn.Write(dataBuf.Bytes())
					log.Printf("[UDP]client:%v send %v bytes -> remote:%v\n", relayConn.LocalAddr(), n, remoteConn.RemoteAddr())
					continue
				}

				//begin to handle  a new datagrams
				if int(frag) < position {
					//send previous datagrams
					remoteConn.Write(reassemblyQueue)
					log.Printf("[UDP]client:%v send %v bytes -> remote:%v\n", relayConn.LocalAddr(), n, remoteConn.RemoteAddr())
					//reinitialize
					reassemblyQueue = make([]byte, 0)
					position = 0
					relayConn.SetReadDeadline(time.Time{})

					//set timeout
					err := relayConn.SetReadDeadline(time.Now().Add(expires))
					if err != nil {
						//closeChan <- err
						continue
					}
					//save data
					position = int(frag)
					//save data
					reassemblyQueue = append(reassemblyQueue, dataBuf.Bytes()...)
				}
			}
		}
	}()

	go func() {
		<-ctx.Done()
		closeChan <- struct{}{}
		closeChan <- struct{}{}
	}()
}
