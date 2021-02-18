package socks5

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

type Server struct {
	*Socks5UDPserver
	conn          []*TCPConn
	lock          sync.RWMutex
	TCPRequestMap map[string]*TCPRequest
	hostResolver  *net.Resolver
	Auth          Socks5Auth
}

var DNSAddrs = []string{
	"114.114.114.114:53",
	"8.8.8.8:53",
	"223.5.5.5:53",
	"101.226.4.6:53",
	"123.125.81.6:53"}

func NewSocks5Server() *Server {
	s := &Server{}
	s.TCPRequestMap = make(map[string]*TCPRequest)
	s.lock = sync.RWMutex{}
	s.hostResolver = &net.Resolver{
		PreferGo: false,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Second * 1,
			}
			for _, addr := range DNSAddrs {
				conn, err := d.DialContext(ctx, "udp", addr)
				if err != nil {
					continue
				}
				return conn, err
			}
			return nil, nil
		},
	}
	//auth
	//todo

	//UDP SERVER
	go s.UDPServer()
	return s
}
func (s *Server) UDPServer() {
	expectedAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%v:%v", "0.0.0.0", 0))
	if err != nil {
		panic(err)
	}
	//it's for receiving data from client
	relayConn, err := net.ListenUDP("udp", expectedAddr)
	if err != nil {
		panic(err)
	}
	s.Socks5UDPserver = &Socks5UDPserver{
		udpConn:       relayConn,
		UDPRequestMap: make(map[string]*UDPRequest),
	}
	for {
		b := make([]byte, MAXUDPDATA)
		n, clientAddr, err := relayConn.ReadFromUDP(b)
		if err != nil {
			if err == io.EOF {
				log.Println(err)
				return
			} else {
				time.Sleep(time.Second * 1)
				continue
			}
		}
		go s.UDPTransport(relayConn, clientAddr, b[:n])
	}
}

type TCPConn struct {
	server  *Server
	id      string
	tcpConn *net.TCPConn
	Dialer  *net.Dialer
}

//NewTCPRequest Add new connect request
func (s *TCPConn) NewTCPRequest(conn net.Conn, req *TCPRequest) *TCPRequest {
	s.server.lock.Lock()
	defer s.server.lock.Unlock()
	targetAddrStr := req.TargetConn.RemoteAddr().(*net.TCPAddr).String()
	if s.server.TCPRequestMap[targetAddrStr] == nil {
		s.server.TCPRequestMap[targetAddrStr] = req
	}
	return s.server.TCPRequestMap[targetAddrStr]
}

//DelTCPRequest del request & close connection
func (s *TCPConn) DelTCPRequest(targetAddr string) {
	s.server.lock.Lock()
	defer s.server.lock.Unlock()
	request := s.server.TCPRequestMap[targetAddr]
	if request != nil {
		if request.TargetConn != nil {
			request.TargetConn.Close()
		}
	}
	delete(s.server.TCPRequestMap, targetAddr)

}
func (s *TCPConn) DialTCP(addr *net.TCPAddr) (net.Conn, error) {
	if s.Dialer == nil {
		s.Dialer = DEFAULT_TCP_DIALER
	}
	return s.Dialer.Dial("tcp", addr.String())
}

var DEFAULT_TCP_DIALER = &net.Dialer{
	Timeout: time.Second * 3,
}

func (s *TCPConn) ID() string {
	if s.id == "" {
		m := md5.New()
		m.Write([]byte(s.tcpConn.RemoteAddr().String()))
		s.id = hex.EncodeToString(m.Sum(nil))[:5]
	}
	return s.id
}

type Socks5UDPserver struct {
	server        *Server
	udpConn       *net.UDPConn
	UDPRequestMap map[string]*UDPRequest
}

//UDPRequest save each of udp conn by client.support for fragments
type UDPRequest struct {
	clientAddr      *net.UDPAddr
	remoteConn      *net.UDPConn
	remoteAddr      *net.UDPAddr
	reassemblyQueue []byte
	position        int
	requestConn     net.Conn
}
type TCPRequest struct {
	TargetAddr *net.TCPAddr
	clientAddr *net.TCPAddr
	//clientConn net.Conn
	TargetConn net.Conn
	atyp       int
	cmd        int
}
