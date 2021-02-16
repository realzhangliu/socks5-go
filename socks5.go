package socks5

import (
	"io"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
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
	MAXUDPDATA = 1024 //MTU-IPHEADER-UDPHEADER
	atypIPV4   = byte(1)
	atypIPV6   = byte(4)
	atypFQDN   = byte(3)
	TCPRETRY   = 3
)

var ErrMethod = byte(255)

func (s *TcpConn) ServConn(conn net.Conn) {
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
	targetAddr, err := s.getDstTCPAddr(conn, atyp)
	if err != nil {
		log.Printf("[ID:%v]%v", s.ID(), err)
		return
	}
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
		s.HandleCONNECT(conn, targetAddr)
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
			<-closeChan
		}
		conn.Close()
		targetConn.Close()
	case 3:
		log.Printf("[ID:%v]COMMAND: UDP ASSOCIATE <- %v\n", s.ID(), conn.RemoteAddr())
		log.Printf("[ID:%v]CLIENT EXPECT IP:%v  PORT:%v\n", s.ID(), targetAddr.IP.String(), targetAddr.Port)
		//dstPort is client expected port send UDP data to.
		s.sendReply(conn, conn.LocalAddr().(*net.TCPAddr).IP, s.server.udpConn.LocalAddr().(*net.UDPAddr).Port, 0)
		log.Printf("[ID:%v][UDP] REPLY ALREADY BIND PORT: %v \n", s.ID(), s.server.udpConn.LocalAddr().(*net.UDPAddr).Port)
		for {
			conn.SetReadDeadline(time.Now())
			if _, err := conn.Read([]byte{}); err == io.EOF {
				break
			} else {
				conn.SetReadDeadline(time.Time{})
				time.Sleep(time.Second * 10)
			}
		}
	}
}

func Launch() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
	socks5Srv := NewSocks5Server()
	listener, err := net.Listen("tcp", ":1090")
	if err != nil {
		os.Exit(1)
	}
	go func() {
		for {
			log.Printf("TOTAL TCP CONN:%v  UDP CONN:%v\n", len(socks5Srv.TCPRequestMap), len(socks5Srv.UDPRequestMap))
			time.Sleep(time.Second * 1)
		}
	}()
	go func() {
		log.Println(http.ListenAndServe("localhost:8866", nil))
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			os.Exit(1)
		}
		s := &TcpConn{
			server:  socks5Srv,
			tcpConn: conn.(*net.TCPConn),
		}
		socks5Srv.conn = append(socks5Srv.conn, s)
		go s.ServConn(conn)
	}
}
