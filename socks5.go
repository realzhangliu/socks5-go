package socks5

import (
	"errors"
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
	SOCKS5VERSION = 5
	MAXUDPDATA    = 1024 //MTU-IPHEADER-UDPHEADER
	atypIPV4      = byte(1)
	atypIPV6      = byte(4)
	atypFQDN      = byte(3)
	TCPRETRY      = 3
)

var (
	ERR_READ_USR_PWD = errors.New("ERR_READ_USR_PWD")
	ERR_METHOD       = errors.New("ERR_METHOD")
	ERR_VERSION      = errors.New("ERR_VERSION")
	ERR_READ_FAILED  = errors.New("ERR_READ_FAILED")
	ERR_ADDRESS_TYPE = errors.New("ERR_ADDRESS_TYPE")
	ERR_AUTH_FAILED  = errors.New("ERR_AUTH_FAILED")
)
var ErrMethod = byte(255)

/*
+----+----------+----------+
|VER | NMETHODS | METHODS |
+----+----------+----------+
| 1 | 1 | 1 to 255 |
+----+----------+----------+
*/
/*
	+----+--------+
	 |VER | METHOD |
	 +----+--------+
	 | 1 | 1 |
	 +----+--------+
*/
func (s *TCPConn) authHandle(conn net.Conn) error {
	//NMETHODS
	nmethods := []byte{0}
	n, err := conn.Read(nmethods)
	if n == 0 {
		return err
	}
	var methods []int
	for i := 0; i < int(nmethods[0]); i++ {
		method := make([]byte, 1)
		n, err = conn.Read(method)
		if n == 0 {
			return err
		}
		methods = append(methods, int(method[0]))
	}

	//loop and specify auth method
	for _, v := range methods {
		//USERNAME/PASSWORD
		if v == 2 {
			log.Printf("[ID:%v]AUTHENTICATION:USERNAME/PASSWORD  <- %v\n", s.ID(), conn.RemoteAddr())
			b := []byte{5}
			b = append(b, byte(2))
			conn.Write(b)

			user, pwd, err := s.resolveUserPwd(conn)
			if user == "" || pwd == "" {
				return err
			}

			if !s.server.Auth.Authenticate(user, pwd) {
				return ERR_AUTH_FAILED
			}

			//success
			closeBytes := make([]byte, 0)
			closeBytes = append(closeBytes, byte(1))
			closeBytes = append(closeBytes, byte(0))
			conn.Write(closeBytes)
			log.Printf("[ID:%v]REPLY USERNAME/PASSWORD METHOD OK -> %v\n", s.ID(), conn.RemoteAddr())
			break
		}
		//NO AUTH
		if v == 0 {
			log.Printf("[ID:%v]AUTHENTICATION:NO AUTHEN <- %v\n", s.ID(), conn.RemoteAddr())
			b := []byte{5}
			b = append(b, byte(0))
			conn.Write(b)
			log.Printf("[ID:%v]REPLY NO AUTHEN METHOD OK -> %v\n", s.ID(), conn.RemoteAddr())
			break
		}
		b := []byte{5}
		b = append(b, ErrMethod)
		conn.Write(b)
		return ERR_METHOD
	}
	return nil
}

func (s *TCPConn) ServConn(conn net.Conn) {
	defer conn.Close()

	//version
	verByte := []byte{0}
	n, err := conn.Read(verByte)
	if err != nil {
		log.Println(ERR_READ_FAILED)
		return
	}
	if uint(verByte[0]) != SOCKS5VERSION {
		log.Println(ERR_VERSION)
		return
	}

	//auth
	if err := s.authHandle(conn); err != nil {
		log.Println(err)
		return
	}

	//request
	headBytes := make([]byte, 4)
	n, err = conn.Read(headBytes)
	if err != nil || n == 0 {
		return
	}
	/*
		+----+-----+-------+------+----------+----------+
		 |VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT |
		 +----+-----+-------+------+----------+----------+
		 | 1 | 1 | X’00’ | 1 | Variable | 2 |
		 +----+-----+-------+------+----------+----------+
	*/
	_, cmd, atyp := int(headBytes[0]), int(headBytes[1]), int(headBytes[3])

	request := &TCPRequest{
		clientAddr: conn.RemoteAddr().(*net.TCPAddr),
		atyp:       atyp,
		cmd:        cmd,
	}

	//dst address
	err = s.resolveAddress(conn, request)
	if err != nil {
		log.Printf("[ID:%v]%v", s.ID(), err)
		return
	}

	log.Printf("TOTAL TCP CONN:%v  UDP CONN:%v\n", len(s.server.TCPRequestMap), len(s.server.UDPRequestMap))

	//command
	switch cmd {
	case 1:
		log.Printf("[ID:%v]COMMAND: CONNECT <- %v\n", s.ID(), conn.RemoteAddr())
		s.HandleCONNECT(conn, request)
	case 2:
		log.Printf("[ID:%v]COMMAND: BIND <- %v\n", s.ID(), conn.RemoteAddr())
		s.HandleBIND(conn, request)
	case 3:
		log.Printf("[ID:%v]COMMAND: UDP ASSOCIATE <- %v\n", s.ID(), conn.RemoteAddr())
		log.Printf("[ID:%v]CLIENT EXPECT IP:%v  PORT:%v\n", s.ID(), request.TargetAddr.IP.String(), request.TargetAddr.Port)
		s.sendReply(conn, conn.LocalAddr().(*net.TCPAddr).IP, s.server.udpConn.LocalAddr().(*net.UDPAddr).Port, 0)
		log.Printf("[ID:%v][UDP] REPLY BIND PORT: %v \n", s.ID(), s.server.udpConn.LocalAddr().(*net.UDPAddr).Port)
		for {
			conn.SetReadDeadline(time.Time{})
			if _, err := conn.Read([]byte{}); err == io.EOF {
				return
			} else {
				time.Sleep(time.Second * 10)
			}
		}
	}
}

func Launch() {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("Recovering from panic in parsing error is %v: \n", err)
		}
	}()
	log.SetFlags(log.Lshortfile | log.LstdFlags)
	socks5Server := NewSocks5Server()
	var listener net.Listener
	var err error
	//TCP SERVER
	listener, err = net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}

	log.Printf("listening on :%v", listener.Addr())
	go func() {
		log.Println(http.ListenAndServe("localhost:8866", nil))
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			os.Exit(1)
		}
		s := &TCPConn{
			server:  socks5Server,
			tcpConn: conn.(*net.TCPConn),
		}
		socks5Server.conn = append(socks5Server.conn, s)
		go s.ServConn(conn)
	}
}
