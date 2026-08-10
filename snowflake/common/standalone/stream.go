package standalone

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/lord-aali/PT-Proxy/snowflake/common/socks5"
)

// Stream types multiplexed over smux.
const (
	StreamClientDial = 1 // client wants remote (server) to dial target
	StreamServerDial = 2 // server wants remote (client) to dial target
	StreamForward    = 3 // bridge to server local SOCKS port
)

// SessionConfig configures inbound stream handling on the server.
type SessionConfig struct {
	// ServerForwardSocks is the loopback address of the server SOCKS listener.
	ServerForwardSocks string
}

// WriteTarget writes a stream type and SOCKS-style address to the stream.
// For StreamForward, target is ignored.
func WriteTarget(w io.Writer, streamType byte, target socks5.Target) error {
	if _, err := w.Write([]byte{streamType}); err != nil {
		return err
	}
	if streamType == StreamForward {
		return nil
	}
	host := target.Host
	ip := net.ParseIP(host)
	var atyp byte
	var addr []byte
	switch {
	case ip != nil && ip.To4() != nil:
		atyp = 0x01
		addr = ip.To4()
	case ip != nil && ip.To16() != nil:
		atyp = 0x04
		addr = ip.To16()
	default:
		atyp = 0x03
		addr = []byte(host)
	}
	hdr := []byte{atyp}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	switch atyp {
	case 0x01, 0x04:
		if _, err := w.Write(addr); err != nil {
			return err
		}
	case 0x03:
		if len(addr) > 255 {
			return fmt.Errorf("hostname too long")
		}
		if _, err := w.Write([]byte{byte(len(addr))}); err != nil {
			return err
		}
		if _, err := w.Write(addr); err != nil {
			return err
		}
	}
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(target.Port))
	_, err := w.Write(port)
	return err
}

// ReadTarget reads stream type and target from the stream.
func ReadTarget(r io.Reader) (byte, socks5.Target, error) {
	var streamType [1]byte
	if _, err := io.ReadFull(r, streamType[:]); err != nil {
		return 0, socks5.Target{}, err
	}
	if streamType[0] == StreamForward {
		return streamType[0], socks5.Target{}, nil
	}
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return 0, socks5.Target{}, err
	}
	var host string
	switch atyp[0] {
	case 0x01:
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return 0, socks5.Target{}, err
		}
		host = net.IP(ip[:]).String()
	case 0x03:
		var lenByte [1]byte
		if _, err := io.ReadFull(r, lenByte[:]); err != nil {
			return 0, socks5.Target{}, err
		}
		name := make([]byte, lenByte[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return 0, socks5.Target{}, err
		}
		host = string(name)
	case 0x04:
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return 0, socks5.Target{}, err
		}
		host = net.IP(ip[:]).String()
	default:
		return 0, socks5.Target{}, socks5.ErrUnsupportedAddr
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(r, portBytes[:]); err != nil {
		return 0, socks5.Target{}, err
	}
	port := int(binary.BigEndian.Uint16(portBytes[:]))
	return streamType[0], socks5.Target{Network: "tcp", Host: host, Port: port}, nil
}

// CopyLoop bidirectionally copies between two connections.
func CopyLoop(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(a, b)
		a.Close()
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(b, a)
		b.Close()
		done <- struct{}{}
	}()
	<-done
}
