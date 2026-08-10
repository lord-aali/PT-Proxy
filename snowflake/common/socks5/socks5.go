// Package socks5 implements a minimal SOCKS5 server (RFC 1928).
package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

const (
	version5   = 0x05
	cmdConnect = 0x01
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)

var (
	ErrUnsupportedVersion = errors.New("unsupported SOCKS version")
	ErrUnsupportedCommand = errors.New("unsupported SOCKS command")
	ErrUnsupportedAddr    = errors.New("unsupported address type")
)

// Target is a host:port destination from a SOCKS5 CONNECT request.
type Target struct {
	Network string
	Host    string
	Port    int
}

func (t Target) Addr() string {
	return net.JoinHostPort(t.Host, fmt.Sprintf("%d", t.Port))
}

// HandshakeServer performs the SOCKS5 method negotiation and CONNECT handling
// on conn. It returns the dial target after the client sends CONNECT.
func HandshakeServer(conn net.Conn) (Target, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return Target{}, err
	}
	if hdr[0] != version5 {
		return Target{}, ErrUnsupportedVersion
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return Target{}, err
	}
	// No auth.
	if _, err := conn.Write([]byte{version5, 0x00}); err != nil {
		return Target{}, err
	}

	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return Target{}, err
	}
	if hdr[0] != version5 {
		return Target{}, ErrUnsupportedVersion
	}
	if hdr[1] != cmdConnect {
		return Target{}, ErrUnsupportedCommand
	}
	// RSV
	var rsv [1]byte
	if _, err := io.ReadFull(conn, rsv[:]); err != nil {
		return Target{}, err
	}

	var atyp [1]byte
	if _, err := io.ReadFull(conn, atyp[:]); err != nil {
		return Target{}, err
	}

	var host string
	switch atyp[0] {
	case atypIPv4:
		var ip [4]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			return Target{}, err
		}
		host = net.IP(ip[:]).String()
	case atypDomain:
		var lenByte [1]byte
		if _, err := io.ReadFull(conn, lenByte[:]); err != nil {
			return Target{}, err
		}
		name := make([]byte, lenByte[0])
		if _, err := io.ReadFull(conn, name); err != nil {
			return Target{}, err
		}
		host = string(name)
	case atypIPv6:
		var ip [16]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			return Target{}, err
		}
		host = net.IP(ip[:]).String()
	default:
		return Target{}, ErrUnsupportedAddr
	}

	var portBytes [2]byte
	if _, err := io.ReadFull(conn, portBytes[:]); err != nil {
		return Target{}, err
	}
	port := int(binary.BigEndian.Uint16(portBytes[:]))

	return Target{Network: "tcp", Host: host, Port: port}, nil
}

// ReplyConnectSuccess sends a SOCKS5 success reply bound to 0.0.0.0:0.
func ReplyConnectSuccess(conn net.Conn) error {
	reply := []byte{
		version5, 0x00, 0x00, atypIPv4,
		0, 0, 0, 0,
		0, 0,
	}
	_, err := conn.Write(reply)
	return err
}

// ReplyConnectFailed sends a SOCKS5 failure reply.
func ReplyConnectFailed(conn net.Conn) error {
	reply := []byte{
		version5, 0x01, 0x00, atypIPv4,
		0, 0, 0, 0,
		0, 0,
	}
	_, err := conn.Write(reply)
	return err
}

// ListenAndServe accepts SOCKS5 connections and calls handle for each CONNECT.
func ListenAndServe(addr string, handle func(net.Conn, Target) error) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			return err
		}
		go func(c net.Conn) {
			target, err := HandshakeServer(c)
			if err != nil {
				c.Close()
				return
			}
			if err := handle(c, target); err != nil {
				_ = ReplyConnectFailed(c)
				c.Close()
			}
		}(conn)
	}
}
