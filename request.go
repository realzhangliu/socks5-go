package socks5

import (
	"crypto/md5"
	"encoding/hex"
	"net"
	"sync"
)

type Socks5Conn struct {
	id      string
	tcpConn *net.TCPConn
	lock    sync.RWMutex
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
