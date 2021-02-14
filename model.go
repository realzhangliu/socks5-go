package socks5

import (
	"crypto/md5"
	"encoding/hex"
	"net"
	"sync"
)

type Server struct {
	*Socks5UDPserver
	conn []*Socks5Conn
}

type Socks5Conn struct {
	server  *Server
	id      string
	tcpConn *net.TCPConn
	lock    sync.RWMutex
}
type Socks5UDPserver struct {
	udpServer     *net.UDPConn
	UDPRequestMap map[string]*UDPRequest
}

func (s Socks5Conn) ID() string {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.id == "" {
		m := md5.New()
		m.Write([]byte(s.tcpConn.RemoteAddr().String()))
		s.id = hex.EncodeToString(m.Sum(nil))[:5]
	}
	return s.id
}

//UDPRequest save each of udp conn by client.support for fragments
type UDPRequest struct {
	clientSrcAddr    *net.UDPAddr
	remoteListenAddr *net.UDPAddr
	reassemblyQueue  []byte
	position         int
}
