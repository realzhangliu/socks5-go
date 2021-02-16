package socks5

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"
)

type Server struct {
	*Socks5UDPserver
	conn          []*TcpConn
	lock          sync.RWMutex
	TCPRequestMap map[string]*TCPRequest
	hostResolver  *net.Resolver
}

func GenerateTCPRequestKey(clientAddr, targetAddr *net.TCPAddr) string {
	//key=client ip + remote addr
	s := fmt.Sprintf("%v|%v", clientAddr.IP.String(), targetAddr.String())
	return s
}

var DNSAddrs = []string{
	"114.114.114.114:53",
	"8.8.8.8:53",
	"223.5.5.5:53",
	"101.226.4.6:53",
	"123.125.81.6:53"}

func NewSocks5Server() *Server {
	s := Server{}
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
	s.UDPServer()
	return &s
}
func (s *Server) UDPServer() {
	expectedAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%v:%v", "0.0.0.0", 0))
	if err != nil {
		return
	}
	//it's for receiving data from client
	relayConn, err := net.ListenUDP("udp", expectedAddr)
	if err != nil {
		return
	}
	s.Socks5UDPserver = &Socks5UDPserver{
		udpConn:       relayConn,
		UDPRequestMap: make(map[string]*UDPRequest),
	}
	go s.UDPTransport(relayConn)
}

type TcpConn struct {
	server  *Server
	id      string
	tcpConn *net.TCPConn
	Dialer  *net.Dialer
}

func (s *TcpConn) DialTCP(addr *net.TCPAddr) (net.Conn, error) {
	if s.Dialer == nil {
		s.Dialer = DEFAULT_TCP_DIALER
	}
	return s.Dialer.Dial("tcp", addr.String())
}

var DEFAULT_TCP_DIALER = &net.Dialer{
	Timeout: time.Second * 3,
}

func (s *TcpConn) ID() string {
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
	clientSrcAddr    *net.UDPAddr
	remoteListenAddr *net.UDPAddr
	remoteAddr       *net.UDPAddr
	reassemblyQueue  []byte
	position         int
	requestConn      net.Conn
}
type TCPRequest struct {
	remoteAddr *net.TCPAddr
	clientAddr *net.TCPAddr
	clientConn net.Conn
	remoteConn net.Conn
}
