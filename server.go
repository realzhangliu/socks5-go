package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
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
)

func bytes2int(b []byte) (sum int64) {
	length := len(b)
	for i := length - 1; i >= 0; i-- {
		sum += int64(b[i]) << uint(8*i)
	}
	return
}

func int2bytes(n int, length int) (b []byte) {
	b = make([]byte, length)
	for i := length - 1; i >= 0; i-- {
		b[i] = byte(n & 0xff)
		n = n >> 8
	}
	return
}

var ErrMethod = byte(255)

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
	fmt.Printf("user:%v\rpassed:%v\n", uname, passwd)

	return true
}
func TransferTraffic(src, dst net.Conn, close chan error) {
	go func() {
		for {
			n, err := io.Copy(dst, src)
			if err != nil || n == 0 {
				close <- err
			}
		}
	}()
	go func() {
		for {
			n, err := io.Copy(src, dst)
			if err != nil || n == 0 {
				close <- err
			}
		}
	}()
}
func GetIPWithATYP(conn net.Conn, atyp int) *net.IP {
	//address types
	switch atyp {
	case 1:
		fmt.Println("IP V4 address")
		dstAddrBytes := make([]byte, 4)
		n, err := conn.Read(dstAddrBytes)
		if err != nil || n == 0 {
			panic(err)
		}
		d := net.IP(dstAddrBytes)
		return &d
	case 3:
		fmt.Println("DOMAINNAME")
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
		ipAddr, _ := net.ResolveIPAddr("tcp", addrs[0])
		return &ipAddr.IP
	case 4:
		fmt.Println("IP V6 address")
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
	verByte := make([]byte, 1)
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
	b := make([]byte, 0)
	//VER
	b = append(b, byte(5))
	//authentication
	//METHOD
	for _, v := range methods {
		if v == 0 {
			fmt.Println("NO AUTHEN")
			b = append(b, byte(0))
			conn.Write(b)
			break
		}
		//GSSAPI
		//TODO
		if v == 1 {
			fmt.Println("GSSAPI")
			b = append(b, byte(255))
			conn.Write(b)
			return
		}
		//USERNAME/PASSWORD
		if v == 2 {
			fmt.Println("USERNAME/PASSWORD")
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
	dstPort := bytes2int(dstPortBytes)
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
		fmt.Println("CONNECT")
		addr := fmt.Sprintf("%v:%v", dstIP.String(), dstPort)
		targetConn, err := net.Dial("tcp", addr)
		b := make([]byte, 0)
		b = append(b, byte(5)) //VER
		if err != nil {
			b = append(b, byte(1))
			conn.Write(b)
			os.Exit(1)
		}
		b = append(b, byte(0))    //REP
		b = append(b, byte(0))    //RSV
		b = append(b, byte(atyp)) //ATYP

		remoteAddr, _ := net.ResolveTCPAddr("tcp", targetConn.RemoteAddr().String())
		b = append(b, []byte(remoteAddr.IP)...)         //BND.ADDR
		b = append(b, int2bytes(remoteAddr.Port, 2)...) //BND.PORT

		conn.Write(b)
		closeConn := make(chan error)
		TransferTraffic(conn, targetConn, closeConn)
		//todo 超时 time_wait
		fmt.Println(<-closeConn)
		conn.Close()
	case 2:
		fmt.Println("BIND")
		//BIND之前需要有CONNECT连接验证
		//建立监听 给目标服务用 例如 FTP 的数据传输
		listener, err := net.Listen("tcp", ":0")
		serverAddr, err := net.ResolveTCPAddr("tcp", listener.Addr().String())
		if err != nil {
			panic(err)
		}
		//first reply
		b := make([]byte, 0)
		b = append(b, byte(5)) //VER
		if err != nil {
			b = append(b, byte(1))
			conn.Write(b)
			os.Exit(1)
		}
		b = append(b, byte(0))                               //REP
		b = append(b, byte(0))                               //RSV
		b = append(b, byte(atyp))                            //ATYP
		b = append(b, []byte(serverAddr.IP)...)              //BND.ADDR
		b = append(b, int2bytes(int(serverAddr.Port), 2)...) //BND.PORT
		conn.Write(b)
		//server -> client
		targetConn, err := listener.Accept()
		//sec reply
		b = make([]byte, 0)
		b = append(b, byte(5)) //VER
		if err != nil {
			b = append(b, byte(1))
			conn.Write(b)
			os.Exit(1)
		}
		b = append(b, byte(0))    //REP
		b = append(b, byte(0))    //RSV
		b = append(b, byte(atyp)) //ATYP
		remoteAddr, _ := net.ResolveTCPAddr("tcp", targetConn.RemoteAddr().String())
		b = append(b, []byte(remoteAddr.IP)...)         //BND.ADDR
		b = append(b, int2bytes(remoteAddr.Port, 2)...) //BND.PORT
		conn.Write(b)
		closeChn := make(chan error)
		TransferTraffic(conn, targetConn, closeChn)
		fmt.Println(<-closeChn)
		targetConn.Close()
	case 3:
		fmt.Println("UDP ASSOCIATE")
		go func() {
			//create process to listen incoming data from client through UDP
			uAddr, err := net.ResolveUDPAddr("udp", ":0")
			if err != nil {
				return
			}
			listenConn, err := net.ListenUDP("udp", uAddr)
			//dstIP and dstPort is target server
			targetAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%v:%v", dstIP.String(), dstPort))
			if err != nil {
				return
			}
			targetConn, err := net.DialUDP("udp", nil, targetAddr)
			b = make([]byte, 0)
			b = append(b, byte(5)) //VER
			if err != nil {
				b = append(b, byte(1))
				conn.Write(b)
				return
			}
			b = append(b, byte(0))    //REP
			b = append(b, byte(0))    //RSV
			b = append(b, byte(atyp)) //ATYP
			//indicate server UDP addr and port
			laddr, err := net.ResolveUDPAddr("udp", listenConn.LocalAddr().String())
			b = append(b, []byte(laddr.IP)...)
			b = append(b, int2bytes(laddr.Port, 2)...)
			conn.Write(b)
			closeChan := make(chan error)
			TransferUDPTraffic(listenConn, targetConn, conn, closeChan)
			fmt.Println(<-closeChan)
			listenConn.Close()
			targetConn.Close()
			conn.Close()
		}()
	default:
		panic(cmd)
	}
}

//records for udp clients as authenticate condition
//todo
var recordUDPClients = make(map[struct{}]struct{})

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
	case 1:
		//ipv4
		b := make([]byte, 4)
		_, err = dataBuf.Read(b)
		if err != nil {
			return
		}
		d := net.IP(b)
		dstIP = &d
	case 3:
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
	case 4:
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
func Server() {
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
