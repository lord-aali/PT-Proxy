package standalone

import (
	"fmt"
	"log"
	"net"

	"github.com/lord-aali/PT-Proxy/snowflake/common/socks5"
	"github.com/xtaci/smux"
)

// ServeLocalSOCKS listens on addr and routes each CONNECT via the server (StreamClientDial).
func ServeLocalSOCKS(addr string, sess *smux.Session) (net.Addr, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Temporary() {
					continue
				}
				log.Printf("SOCKS accept: %v", err)
				return
			}
			go handleLocalSocks(conn, sess)
		}
	}()
	return ln.Addr(), nil
}

// ServeLocalTCP listens on addr and pipes each accepted TCP connection through
// StreamClientDial (server dials external-service).
func ServeLocalTCP(addr string, sess *smux.Session) (net.Addr, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Temporary() {
					continue
				}
				log.Printf("TCP accept: %v", err)
				return
			}
			go handleLocalTCP(conn, sess)
		}
	}()
	return ln.Addr(), nil
}

func handleLocalTCP(conn net.Conn, sess *smux.Session) {
	defer conn.Close()
	stream, err := OpenClientDial(sess, socks5.Target{Network: "tcp", Host: "127.0.0.1", Port: 0})
	if err != nil {
		log.Printf("OpenClientDial: %v", err)
		return
	}
	defer stream.Close()
	CopyLoop(conn, stream)
}

func handleLocalSocks(conn net.Conn, sess *smux.Session) {
	target, err := socks5.HandshakeServer(conn)
	if err != nil {
		conn.Close()
		return
	}
	stream, err := OpenClientDial(sess, target)
	if err != nil {
		_ = socks5.ReplyConnectFailed(conn)
		conn.Close()
		log.Printf("OpenClientDial: %v", err)
		return
	}
	if err := socks5.ReplyConnectSuccess(conn); err != nil {
		stream.Close()
		conn.Close()
		return
	}
	CopyLoop(conn, stream)
}

// ServeTunnelForward listens on addr and bridges each TCP connection to the
// server's SOCKS port through StreamForward.
func ServeTunnelForward(addr string, sess *smux.Session) (net.Addr, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Temporary() {
					continue
				}
				log.Printf("forward accept: %v", err)
				return
			}
			go handleForward(conn, sess)
		}
	}()
	return ln.Addr(), nil
}

func handleForward(conn net.Conn, sess *smux.Session) {
	defer conn.Close()
	stream, err := OpenForward(sess)
	if err != nil {
		log.Printf("OpenForward: %v", err)
		return
	}
	defer stream.Close()
	CopyLoop(conn, stream)
}

// PickListenAddr returns host:0 for binding on a random port.
func PickListenAddr(host string) string {
	if host == "" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("%s:0", host)
}
