package main

import (
	"bytes"
	"fmt"
	"net"
	"time"
)

func AssemblyProxyHeader(dataBuf *bytes.Buffer, dstAddr net.Addr) {
	proxyData := bytes.NewBuffer(nil)
	var atyp byte
	addr, err := net.ResolveUDPAddr("udp", dstAddr.String())
	if err != nil {
		return
	}
	switch len(addr.IP) {
	case 4:
		atyp = 1
	case 16:
		atyp = 4
	default:
		atyp = 3
	}
	proxyData.Write([]byte{0, 0, 0, atyp})
	proxyData.Write(addr.IP)
	proxyData.Write(int2bytes(addr.Port, 2))
	proxyData.Write(dataBuf.Bytes())
	dataBuf = proxyData
}

//trim head
func TrimProxyHeader(dataBuf *bytes.Buffer) (frag byte) {
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
	var dstIP *net.IP
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
	var dstPort int
	b := make([]byte, 2)
	_, err = dataBuf.Read(b)
	if err != nil {
		return
	}
	dstPort = int(bytes2int(b))
	fmt.Printf("dstIP:%v dstPort:%v\n", dstIP, dstPort)
	//todo filter
	return frag
}
func TransferUDPTraffic(src, dst *net.UDPConn, conn net.Conn, closeChan chan error) {
	// remote -> relay -> client
	go func() {
		for {
			//assemble proxy header
			b := make([]byte, MAXUDPDATA)
			n, _, err := dst.ReadFromUDP(b)
			if err != nil {
				closeChan <- err
				return
			}
			dataBuf := bytes.NewBuffer(b[:n])
			AssemblyProxyHeader(dataBuf, dst.RemoteAddr())
			dst.Write(dataBuf.Bytes())
		}
	}()
	reassemblyQueue := make([]byte, 0)
	position := 0
	expires := time.Second * 5
	// client -> relay -> remote
	go func() {
		for {
			b := make([]byte, MAXUDPDATA)
			n, _, err := src.ReadFromUDP(b)
			if err != nil {
				continue
			}
			dataBuf := bytes.NewBuffer(b[:n])
			frag := TrimProxyHeader(dataBuf)
			//standalone
			if frag == 0 {
				if len(reassemblyQueue) > 0 {
					dst.Write(reassemblyQueue)
					//reinitialize
					reassemblyQueue = make([]byte, 0)
					position = 0
					src.SetReadDeadline(time.Time{})
				}
				dst.Write(dataBuf.Bytes())
				continue
			}
			if int(frag) > position {
				//set timeout
				err := src.SetReadDeadline(time.Now().Add(expires))
				if err != nil {
					closeChan <- err
				}
				position = int(frag)
				//save data
				reassemblyQueue = append(reassemblyQueue, dataBuf.Bytes()...)
			}
			//begin to handle  a new datagrams
			if int(frag) < position {
				dst.Write(reassemblyQueue)
				//reinitialize
				reassemblyQueue = make([]byte, 0)
				position = 0
				src.SetReadDeadline(time.Time{})

				//set timeout
				err := src.SetReadDeadline(time.Now().Add(expires))
				if err != nil {
					closeChan <- err
				}
				//save data
				position = int(frag)
				//save data
				reassemblyQueue = append(reassemblyQueue, dataBuf.Bytes()...)
			}
		}
	}()
}
