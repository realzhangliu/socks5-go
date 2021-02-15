package socks5

import (
	"context"
	"io"
	"log"
	"net"
	"time"
)

func (s *TcpConn) TCPTransportb(clientConn, remoteConn net.Conn, closeChan chan error) {
	//client -> relay ->remote
	go func() {
		limit := 3
		clientConn.SetReadDeadline(time.Now().Add(time.Second * 3))
		for {
			b := make([]byte, 1024)
			n, err := clientConn.Read(b)
			if err != nil {
				if err == io.EOF {
					closeChan <- err
					clientConn.Close()
					return
				}
				if limit <= 0 {
					closeChan <- err
					clientConn.Close()
					return
				}
				time.Sleep(time.Second * 5)
				limit--
				continue
			}
			remoteConn.Write(b[:n])
			log.Printf("[ID:%v][TCP]client:%v send %v bytes -> remote:%v\n", s.ID(), clientConn.RemoteAddr(), n, remoteConn.RemoteAddr())
		}
	}()

	//remote -> relay -> client
	go func() {
		limit := 3
		remoteConn.SetReadDeadline(time.Now().Add(time.Second * 3))
		for {
			b := make([]byte, 1024)
			n, err := remoteConn.Read(b)
			if err != nil {
				if err == io.EOF {
					closeChan <- err
					remoteConn.Close()
					return
				}
				if limit <= 0 {
					closeChan <- err
					remoteConn.Close()
					return
				}
				time.Sleep(time.Second * 5)
				limit--
				continue
			}
			clientConn.Write(b[:n])
			log.Printf("[ID:%v][TCP]remote:%v send %v bytes -> client:%v\n", s.ID(), remoteConn.RemoteAddr(), n, clientConn.RemoteAddr())
		}
	}()
}
func (s *TcpConn) TCPTransport(clientConn, remoteConn net.Conn, closeChan chan error) {
	go func() {
		limit := 3
		for {
			_, err := io.Copy(clientConn, remoteConn)
			if err == io.EOF {
				closeChan <- err
				return
			} else if limit <= 0 {
				closeChan <- err
				return
			} else {
				time.Sleep(time.Second * 5)
				limit--
			}
		}
	}()
	go func() {
		limit := 3
		for {
			_, err := io.Copy(remoteConn, clientConn)
			if err == io.EOF {
				closeChan <- err
				return
			} else if limit <= 0 {
				closeChan <- err
				return
			} else {
				time.Sleep(time.Second * 5)
				limit--
			}
		}
	}()
}
func (s *TcpConn) sendReply(conn net.Conn, addrIP net.IP, addrPort int, resp int) {
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
func (s *TcpConn) VerifyPassword(conn net.Conn) bool {
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
func (s *TcpConn) GetIPWithATYP(conn net.Conn, atyp int) *net.IP {
	//address types
	switch atyp {
	case int(atypIPV4):
		log.Printf("[ID:%v]ADDRESS TYPE: IP V4 address <- %v\n", s.ID(), conn.RemoteAddr())
		dstAddrBytes := make([]byte, 4)
		_, err := conn.Read(dstAddrBytes)
		if err != nil {
			log.Printf("[ID:%v]%v", s.ID(), err)
			return nil
		}
		d := net.IP(dstAddrBytes)
		return &d
	case int(atypFQDN):
		log.Printf("[ID:%v]ADDRESS TYPE: DOMAINNAME <- %v\n", s.ID(), conn.RemoteAddr())
		hostLenByte := make([]byte, 1)
		_, err := conn.Read(hostLenByte)
		if err != nil {
			log.Printf("[ID:%v]%v", s.ID(), err)
			return nil
		}
		hostBytes := make([]byte, int(hostLenByte[0]))
		_, err = conn.Read(hostBytes)
		if err != nil {
			log.Printf("[ID:%v]%v", s.ID(), err)
			return nil
		}
		domain := string(hostBytes)
		IPAddrs, err := s.server.hostResolver.LookupIPAddr(context.Background(), domain)
		if err != nil {
			log.Printf("[ID:%v]%v", s.ID(), err)
			return nil
		}
		return &IPAddrs[0].IP
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
