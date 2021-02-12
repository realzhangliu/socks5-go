package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
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

func sendReply(conn net.Conn, addrIP net.IP, addrPort int, resp int) error {
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
		return fmt.Errorf("failed to format address")
	}
	msg := make([]byte, 0)
	msg = append(msg, byte(VERSION))
	msg = append(msg, byte(resp))
	msg = append(msg, byte(0))
	msg = append(msg, addrATYP)
	msg = append(msg, addrBody...)
	msg = append(msg, byte(addrPort>>8))
	msg = append(msg, byte(addrPort&0xff))
	conn.Write(msg)
	return nil
}
func VerifyPassword(conn net.Conn) bool {
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
func TransferTraffic(clientConn, remoteConn net.Conn, closeChan chan error) {
	go func() {
		n, err := io.Copy(remoteConn, clientConn)
		log.Printf("client:%v send %v bytes -> remote:%v\n", clientConn.RemoteAddr(), n, remoteConn.RemoteAddr())
		remoteConn.Close()
		closeChan <- err
	}()
	go func() {
		n, err := io.Copy(clientConn, remoteConn)
		log.Printf("remote:%v send %v bytes -> client:%v\n", remoteConn.RemoteAddr(), n, clientConn.RemoteAddr())
		clientConn.Close()
		closeChan <- err
	}()
}
func GetIPWithATYP(conn net.Conn, atyp int) *net.IP {
	//address types
	switch atyp {
	case int(atypIPV4):
		log.Println("IP V4 address")
		dstAddrBytes := make([]byte, 4)
		n, err := conn.Read(dstAddrBytes)
		if err != nil || n == 0 {
			panic(err)
		}
		d := net.IP(dstAddrBytes)
		return &d
	case int(atypFQDN):
		log.Println("DOMAINNAME")
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
		log.Println("IP V6 address")
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
func HandleConn(conn net.Conn) {
	defer conn.Close()
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
		panic(err)
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
			log.Println("NO AUTHEN")
			b = append(b, byte(0))
			conn.Write(b)
			break
		}
		//GSSAPI
		//TODO
		if v == 1 {
			log.Println("GSSAPI")
			b = append(b, byte(255))
			conn.Write(b)
			return
		}
		//USERNAME/PASSWORD
		if v == 2 {
			log.Println("USERNAME/PASSWORD")
			b = append(b, byte(2))
			//reply
			conn.Write(b)
			closeBytes := make([]byte, 0)
			closeBytes = append(closeBytes, byte(1))
			//verify
			if !VerifyPassword(conn) {
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
	ver, cmd, _, atyp := int(headBytes[0]), int(headBytes[1]), int(headBytes[2]), int(headBytes[3])
	if ver != VERSION {
		return
	}
	dstIP := GetIPWithATYP(conn, atyp)
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
		log.Println("CONNECT")
		addr := fmt.Sprintf("%v:%v", dstIP.String(), dstPort)
		targetConn, err := net.Dial("tcp", addr)
		if err != nil {
			b = append(b, byte(1))
			conn.Write(b)
			os.Exit(1)
		}
		serverAddr, _ := net.ResolveTCPAddr("tcp", targetConn.LocalAddr().String())

		sendReply(conn, serverAddr.IP, serverAddr.Port, 0)

		closeChan := make(chan error, 2)
		TransferTraffic(conn, targetConn, closeChan)
		for i := 0; i < 2; i++ {
			e := <-closeChan
			if e != nil {
				return
			}
		}
		return
	case 2:
		log.Println("BIND")
		//BIND之前需要有CONNECT连接验证
		//建立监听 给目标服务用 例如 FTP 的数据传输
		listener, err := net.Listen("tcp", ":0")
		if err != nil {
			return
		}
		serverAddr, err := net.ResolveTCPAddr("tcp", listener.Addr().String())
		if err != nil {
			return
		}
		//first reply
		sendReply(conn, serverAddr.IP, serverAddr.Port, 0)
		//server -> client
		targetConn, err := listener.Accept()
		if err != nil {
			return
		}
		remoteAddr, _ := net.ResolveTCPAddr("tcp", targetConn.RemoteAddr().String())
		//sec reply
		sendReply(conn, remoteAddr.IP, remoteAddr.Port, 0)
		closeChan := make(chan error, 2)
		TransferTraffic(conn, targetConn, closeChan)
		for i := 0; i < 2; i++ {
			e := <-closeChan
			if e != nil {
				return
			}
		}
		return
	case 3:
		log.Println("UDP ASSOCIATE")
		//dstPort is client expected port send UDP data to.
		relayed, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%v:%v", dstIP.String(), dstPort))
		if err != nil {
			return
		}
		relayedCoon, err := net.ListenUDP("udp", relayed)
		if err != nil {
			return
		}
		//indicate server UDP addr and port
		laddr, err := net.ResolveUDPAddr("udp", conn.LocalAddr().String())
		sendReply(conn, laddr.IP, relayed.Port, 0)
		//some authenticity
		ctx, cancel := context.WithCancel(context.Background())
		TransferUDPTraffic(relayedCoon, ctx)
		/*A UDP association terminates when the TCP connection that the UDP
		ASSOCIATE request arrived on terminates.*/
		_, err = conn.Read([]byte{})
		cancel()
	}
}

//records for udp clients as authenticate condition
//todo

func Server() {
	log.SetFlags(log.LstdFlags)
	listener, err := net.Listen("tcp", ":1090")
	if err != nil {
		os.Exit(1)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			os.Exit(1)
		}
		go HandleConn(conn)
	}
}
