package socks5

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"strconv"

	"github.com/lord-aali/PT-Proxy/common/ptlog"
	gosocks "github.com/things-go/go-socks5"
)

// Serve binds TCP (and UDP on the same port) and runs SOCKS5. user/pass empty = no auth.
func Serve(addr, user, pass, tag string) (bound string, err error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	bound = ln.Addr().String()
	lg := ptlog.PTLog{LogTag: tag}

	ua, _ := net.ResolveUDPAddr("udp", bound)
	var udp *net.UDPConn
	if ua != nil {
		udp, _ = net.ListenUDP("udp", ua)
	}

	opts := []gosocks.Option{
		gosocks.WithLogger(gosocks.NewLogger(log.New(io.Discard, "", 0))),
	}
	if user != "" || pass != "" {
		opts = append(opts, gosocks.WithCredential(gosocks.StaticCredentials{user: pass}))
	}
	if host, _, err := net.SplitHostPort(bound); err == nil {
		ip := net.ParseIP(host)
		if ip == nil {
			ip = net.IPv4(127, 0, 0, 1)
		}
		opts = append(opts, gosocks.WithBindIP(ip))
	}
	srv := gosocks.NewServer(opts...)
	if udp != nil {
		go serveUDP(udp)
	}
	go func() {
		if err := srv.Serve(ln); err != nil {
			lg.Error("socks listen:", err)
		}
	}()
	lg.Info("socks on", bound)
	return bound, nil
}

func serveUDP(pc *net.UDPConn) {
	buf := make([]byte, 65535)
	conns := map[string]*net.UDPConn{}
	for {
		n, from, err := pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 10 {
			continue
		}
		host, port, payload, err := parseSocksUDP(buf[:n])
		if err != nil {
			continue
		}
		dst, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			continue
		}
		key := from.String()
		uc := conns[key]
		if uc == nil {
			uc, err = net.ListenUDP("udp", nil)
			if err != nil {
				continue
			}
			conns[key] = uc
			go func(uc *net.UDPConn, client *net.UDPAddr) {
				rbuf := make([]byte, 65535)
				for {
					rn, raddr, err := uc.ReadFromUDP(rbuf)
					if err != nil {
						return
					}
					out := packSocksUDP(raddr, rbuf[:rn])
					_, _ = pc.WriteToUDP(out, client)
				}
			}(uc, from)
		}
		_, _ = uc.WriteToUDP(payload, dst)
	}
}

func parseSocksUDP(p []byte) (host string, port int, payload []byte, err error) {
	if len(p) < 4 || p[2] != 0 {
		return "", 0, nil, io.ErrUnexpectedEOF
	}
	atyp := p[3]
	off := 4
	switch atyp {
	case 1:
		if len(p) < off+6 {
			return "", 0, nil, io.ErrUnexpectedEOF
		}
		host = net.IP(p[off : off+4]).String()
		off += 4
	case 3:
		if len(p) < off+1 {
			return "", 0, nil, io.ErrUnexpectedEOF
		}
		l := int(p[off])
		off++
		if len(p) < off+l+2 {
			return "", 0, nil, io.ErrUnexpectedEOF
		}
		host = string(p[off : off+l])
		off += l
	case 4:
		if len(p) < off+18 {
			return "", 0, nil, io.ErrUnexpectedEOF
		}
		host = net.IP(p[off : off+16]).String()
		off += 16
	default:
		return "", 0, nil, io.ErrUnexpectedEOF
	}
	port = int(binary.BigEndian.Uint16(p[off : off+2]))
	off += 2
	return host, port, p[off:], nil
}

func packSocksUDP(raddr *net.UDPAddr, payload []byte) []byte {
	ip4 := raddr.IP.To4()
	var hdr []byte
	if ip4 != nil {
		hdr = make([]byte, 10)
		hdr[3] = 1
		copy(hdr[4:8], ip4)
		binary.BigEndian.PutUint16(hdr[8:10], uint16(raddr.Port))
	} else {
		ip := raddr.IP.To16()
		hdr = make([]byte, 22)
		hdr[3] = 4
		copy(hdr[4:20], ip)
		binary.BigEndian.PutUint16(hdr[20:22], uint16(raddr.Port))
	}
	return append(hdr, payload...)
}
