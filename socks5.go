package socks5

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

/*
SOCKS5 SERVER
2021.02.01
zhangliu
https://www.rfc-editor.org/rfc/pdfrfc/rfc1928.txt.pdf
https://www.rfc-editor.org/info/rfc1929
https://cloud.tencent.com/developer/article/1682604
*/

const (
	VERSION    = 5
	MAXUDPDATA = 1472 //MTU-IPHEADER-UDPHEADER
	atypIPV4   = byte(1)
	atypIPV6   = byte(4)
	atypFQDN   = byte(3)
)

var ErrMethod = byte(255)

func (s *Socks5Conn) sendReply(conn net.Conn, addrIP net.IP, addrPort int, resp int) {
	addrATYP := byte(0)
	var addrBody []byte
	switch {
	case addrIP == nil:
		addrATYP = atypIPV4
		addrBody = []byte{0, 0, 0, 0}
	case addrIP.To4() != nil:
		addrATYP = atypIPV4
		addrBody = []byte(addrIP.To4())
	case addrIP.To16() != nil:
		addrATYP = atypIPV6
		addrBody = []byte(addrIP.To16())
	default:
		log.Printf("[ID:%v]failed to format address.", s.ID())
	}
	msg := make([]byte, 0)
	msg = append(msg, byte(VERSION))
	msg = append(msg, byte(resp))
	msg = append(msg, byte(0))
	msg = append(msg, addrATYP)
	msg = append(msg, addrBody...)
	msg = append(msg, byte(addrPort>>8))
	msg = append(msg, byte(addrPort&0xff))
	_, err := conn.Write(msg)
	if err != nil {
		log.Printf("[ID:%v]%v", err)
	}
}
func (s *Socks5Conn) VerifyPassword(conn net.Conn) bool {
	verByte := make([]byte, 1)
	n, err := conn.Read(verByte)
	if err != nil || n == 0 {
		panic(err)
	}
	if uint(verByte[0]) != 1 {
		panic(verByte)
	}
	ulenByte := make([]byte, 1)
	n, err = conn.Read(ulenByte)
	if err != nil || n == 0 {
		panic(err)
	}
	if uint(ulenByte[0]) < 1 {
		panic(ulenByte)
	}
	unameByte := make([]byte, uint(ulenByte[0]))
	n, err = conn.Read(unameByte)
	if err != nil || n == 0 {
		panic(err)
	}
	uname := string(unameByte)
	plen := make([]byte, 1)
	n, err = conn.Read(plen)
	if err != nil || n == 0 {
		panic(err)
	}
	if uint(plen[0]) < 1 {
		panic(plen)
	}
	passwdByte := make([]byte, uint(plen[0]))
	n, err = conn.Read(passwdByte)
	if err != nil || n == 0 {
		panic(err)
	}
	passwd := string(passwdByte)
	log.Printf("user:%v\rpassed:%v\n", uname, passwd)

	return true
}
func (s *Socks5Conn) TCPTransport(clientConn, remoteConn net.Conn, closeChan chan error) {
	//client -> relay ->remote
	go func() {
		for {
			b := make([]byte, 1024)
			n, err := clientConn.Read(b)
			if err != nil {
				log.Printf("[ID:%v]%v", s.ID(), err)
				closeChan <- err
				clientConn.Close()
				return
			}
			remoteConn.Write(b[:n])
			log.Printf("[ID:%v][TCP]client:%v send %v bytes -> remote:%v\n", s.ID(), clientConn.RemoteAddr(), n, remoteConn.RemoteAddr())
		}

	}()
	//remote -> relay -> client
	go func() {
		for {
			b := make([]byte, 1024)
			n, err := remoteConn.Read(b)
			if err != nil {
				if strings.Contains(err.Error(), "EOF") {
					time.Sleep(time.Second)
					continue
				}
				log.Printf("[ID:%v]%v", s.ID(), err)
				closeChan <- err
				remoteConn.Close()
				return
			}
			clientConn.Write(b[:n])
			log.Printf("[ID:%v][TCP]remote:%v send %v bytes -> client:%v\n", s.ID(), remoteConn.RemoteAddr(), n, clientConn.RemoteAddr())
		}
	}()
}
func (s *Socks5Conn) GetIPWithATYP(conn net.Conn, atyp int) *net.IP {
	//address types
	switch atyp {
	case int(atypIPV4):
		log.Printf("[ID:%v]ADDRESS TYPE: IP V4 address <- %v\n", s.ID(), conn.RemoteAddr())
		dstAddrBytes := make([]byte, 4)
		n, err := conn.Read(dstAddrBytes)
		if err != nil || n == 0 {
			panic(err)
		}
		d := net.IP(dstAddrBytes)
		return &d
	case int(atypFQDN):
		log.Printf("[ID:%v]ADDRESS TYPE: DOMAINNAME <- %v\n", s.ID(), conn.RemoteAddr())
		hostLenByte := make([]byte, 1)
		n, err := conn.Read(hostLenByte)
		if err != nil || n == 0 {
			panic(err)
		}
		hostBytes := make([]byte, int(hostLenByte[0]))
		n, err = conn.Read(hostBytes)
		if err != nil || n == 0 {
			panic(err)
		}
		domain := string(hostBytes)
		addrs, err := net.LookupHost(domain)
		if err != nil {
			panic(err)
		}
		ipAddr, err := net.ResolveIPAddr("ip", addrs[0])
		if err != nil {
			panic(err)
		}
		return &ipAddr.IP
	case int(atypIPV6):
		log.Printf("[ID:%v]ADDRESS TYPE: IP V6 address <- %v\n", s.ID(), conn.RemoteAddr())
		dstAddrBytes := make([]byte, 16)
		n, err := conn.Read(dstAddrBytes)
		if err != nil || n == 0 {
			panic(err)
		}
		d := net.IP(dstAddrBytes)
		return &d
	default:
		panic(atyp)
	}
}
func (s *Socks5Conn) ServConn(conn net.Conn) {
	verByte := []byte{0}
	nmethods := make([]byte, 1)
	/*+----+----------+----------+
	|VER | NMETHODS | METHODS |
	+----+----------+----------+
	| 1 | 1 | 1 to 255 |
	+----+----------+----------+
	*/
	n, err := conn.Read(verByte)
	if err != nil {
		return
	}
	//VER
	if uint(verByte[0]) != VERSION {
		return
	}
	//NMETHODS
	n, err = conn.Read(nmethods)
	if err != nil {
		return
	}
	//METHODS
	methods := []int{}
	for i := 0; i < int(nmethods[0]); i++ {
		method := make([]byte, 1)
		n, err = conn.Read(method)
		if err != nil {
			return
		}
		methods = append(methods, int(method[0]))
	}
	//reply
	/*
		+----+--------+
		 |VER | METHOD |
		 +----+--------+
		 | 1 | 1 |
		 +----+--------+
	*/
	b := []byte{}
	//VER
	b = append(b, byte(5))
	//authentication
	//METHOD
	for _, v := range methods {
		if v == 0 {
			log.Printf("[ID:%v]AUTHENTICATION:NO AUTHEN <- %v\n", s.ID(), conn.RemoteAddr())
			b = append(b, byte(0))
			conn.Write(b)
			log.Printf("[ID:%v]REPLY NO AUTHEN METHOD OK -> %v\n", s.ID(), conn.RemoteAddr())
			break
		}
		//USERNAME/PASSWORD
		if v == 2 {
			log.Printf("[ID:%v]AUTHENTICATION:USERNAME/PASSWORD  <- %v\n", s.ID(), conn.RemoteAddr())
			b = append(b, byte(2))
			//reply
			conn.Write(b)
			closeBytes := make([]byte, 0)
			closeBytes = append(closeBytes, byte(1))
			//verify
			if !s.VerifyPassword(conn) {
				closeBytes = append(closeBytes, byte(1))
				conn.Write(closeBytes)
				os.Exit(1)
			}
			//success
			closeBytes = append(closeBytes, byte(0))
			n, err = conn.Write(closeBytes)
			if err != nil || n == 0 {
				return
			}
			log.Printf("[ID:%v]REPLY USERNAME/PASSWORD METHOD OK -> %v\n", s.ID(), conn.RemoteAddr())
			break
		}
		b = append(b, ErrMethod)
		conn.Write(b)
		return
	}
	//request
	/*
		+----+-----+-------+------+----------+----------+
		 |VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT |
		 +----+-----+-------+------+----------+----------+
		 | 1 | 1 | X’00’ | 1 | Variable | 2 |
		 +----+-----+-------+------+----------+----------+
	*/
	headBytes := make([]byte, 4)
	n, err = conn.Read(headBytes)
	if err != nil || n == 0 {
		return
	}
	ver, cmd, atyp := int(headBytes[0]), int(headBytes[1]), int(headBytes[3])
	if ver != VERSION {
		return
	}
	dstIP := s.GetIPWithATYP(conn, atyp)
	dstPortBytes := make([]byte, 2)
	n, err = conn.Read(dstPortBytes)
	if err != nil || n == 0 {
		panic(err)
	}
	//dstPort := bytes2int(dstPortBytes)
	dstPort := int(dstPortBytes[0])<<8 + int(dstPortBytes[1])
	//reply
	/*
		+----+-----+-------+------+----------+----------+
		 |VER | REP | RSV | ATYP | BND.ADDR | BND.PORT |
		 +----+-----+-------+------+----------+----------+
		 | 1 | 1 | X’00’ | 1 | Variable | 2 |
		 +----+-----+-------+------+----------+----------+
	*/
	//command
	switch cmd {
	case 1:
		log.Printf("[ID:%v]COMMAND: CONNECT <- %v\n", s.ID(), conn.RemoteAddr())
		targetConn, err := net.DialTCP("tcp", nil, &net.TCPAddr{
			IP:   *dstIP,
			Port: dstPort,
			Zone: "",
		})
		if err != nil {
			b = append(b, byte(1))
			conn.Write(b)
			return
		}
		s.sendReply(conn, targetConn.LocalAddr().(*net.TCPAddr).IP, targetConn.LocalAddr().(*net.TCPAddr).Port, 0)
		closeChan := make(chan error, 2)
		s.TCPTransport(conn, targetConn, closeChan)
		for i := 0; i < 2; i++ {
			e := <-closeChan
			if e != nil {
				return
			}
		}
		return
	case 2:
		log.Printf("[ID:%v]COMMAND: BIND <- %v\n", s.ID(), conn.RemoteAddr())
		//BIND之前需要有CONNECT连接验证
		//建立监听 给目标服务用 例如 FTP 的数据传输
		listener, err := net.Listen("tcp", ":0")
		if err != nil {
			return
		}
		//first reply
		s.sendReply(conn, listener.Addr().(*net.TCPAddr).IP, listener.Addr().(*net.TCPAddr).Port, 0)
		//server -> client
		targetConn, err := listener.Accept()
		if err != nil {
			return
		}
		//sec reply
		s.sendReply(conn, targetConn.RemoteAddr().(*net.TCPAddr).IP, targetConn.RemoteAddr().(*net.TCPAddr).Port, 0)
		closeChan := make(chan error, 2)
		s.TCPTransport(conn, targetConn, closeChan)
		for i := 0; i < 2; i++ {
			e := <-closeChan
			if e != nil {
				return
			}
		}
		return
	case 3:
		log.Printf("[ID:%v]COMMAND: UDP ASSOCIATE <- %v\n", s.ID(), conn.RemoteAddr())
		//dstPort is client expected port send UDP data to.
		if s.server.Socks5UDPserver != nil {
			s.sendReply(conn, conn.LocalAddr().(*net.TCPAddr).IP, s.server.udpServer.LocalAddr().(*net.UDPAddr).Port, 0)
			log.Printf("[ID:%v][UDP] REPLY ALREADY BIND PORT: %v \n", s.ID(), s.server.udpServer.LocalAddr().(*net.UDPAddr).Port)
		} else {
			expectedAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%v:%v", dstIP.String(), dstPort))
			if err != nil {
				return
			}
			//it's for receiving data from client
			relayConn, err := net.ListenUDP("udp", expectedAddr)
			if err != nil {
				return
			}
			s.server.Socks5UDPserver = &Socks5UDPserver{
				udpServer:     relayConn,
				UDPRequestMap: make(map[string]*UDPRequest),
			}

			//indicate server UDP addr and port
			s.sendReply(conn, conn.LocalAddr().(*net.TCPAddr).IP, relayConn.LocalAddr().(*net.UDPAddr).Port, 0)
			log.Printf("[ID:%v][UDP] REPLY BIND PORT: %v \n", s.ID(), relayConn.LocalAddr().(*net.UDPAddr).Port)

			//some authenticity
			ctx, cancelFunc := context.WithCancel(context.Background())
			s.UDPTransport(relayConn, ctx)
			/*A UDP association terminates when the TCP connection that the UDP
			ASSOCIATE request arrived on terminates.*/
			for {
				conn.SetReadDeadline(time.Now())
				if _, err := conn.Read([]byte{}); err == io.EOF {
					cancelFunc()
					break
				} else {
					conn.SetReadDeadline(time.Time{})
				}
				time.Sleep(time.Second * 10)
			}
		}
	}
}

//多次相同请求的处理
func Launch() {
	log.SetFlags(log.LstdFlags)
	listener, err := net.Listen("tcp", ":1090")
	if err != nil {
		os.Exit(1)
	}
	ser := &Server{}
	for {
		conn, err := listener.Accept()
		if err != nil {
			os.Exit(1)
		}
		s := &Socks5Conn{
			server:  ser,
			tcpConn: conn.(*net.TCPConn),
			lock:    sync.RWMutex{},
		}
		ser.conn = append(ser.conn, s)
		go s.ServConn(conn)
	}
}
