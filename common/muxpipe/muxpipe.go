package muxpipe

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/xtaci/smux"
)

const Magic = "PTPXMUX1"

const (
	KindTCP     byte = 1
	KindUDP     byte = 2
	KindRevBind byte = 3
	KindRevTCP  byte = 4
)

type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// Detect peeks for Magic. Non-mux (Tor) connections get leftover bytes pushed back.
func Detect(conn net.Conn) (isMux bool, rest net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, len(Magic))
	n, err := io.ReadFull(conn, buf)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		if n > 0 {
			return false, &prefixConn{Conn: conn, prefix: buf[:n]}
		}
		return false, conn
	}
	if string(buf) != Magic {
		return false, &prefixConn{Conn: conn, prefix: buf}
	}
	return true, conn
}

func writeMagic(conn net.Conn) error {
	_, err := conn.Write([]byte(Magic))
	return err
}

func OpenClient(conn net.Conn) (*smux.Session, error) {
	if err := writeMagic(conn); err != nil {
		return nil, err
	}
	cfg := smux.DefaultConfig()
	cfg.Version = 2
	cfg.KeepAliveTimeout = 10 * time.Minute
	return smux.Client(conn, cfg)
}

func OpenServer(conn net.Conn) (*smux.Session, error) {
	cfg := smux.DefaultConfig()
	cfg.Version = 2
	cfg.KeepAliveTimeout = 10 * time.Minute
	return smux.Server(conn, cfg)
}

func OpenTCP(sess *smux.Session) (*smux.Stream, error) {
	st, err := sess.OpenStream()
	if err != nil {
		return nil, err
	}
	if _, err := st.Write([]byte{KindTCP}); err != nil {
		st.Close()
		return nil, err
	}
	return st, nil
}

func Copy(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(a, b)
		a.Close()
		b.Close()
	}()
	go func() {
		defer wg.Done()
		io.Copy(b, a)
		a.Close()
		b.Close()
	}()
	wg.Wait()
}

func WriteUDP(w io.Writer, addr string, payload []byte) error {
	ab := []byte(addr)
	if len(ab) > 255 {
		ab = ab[:255]
	}
	hdr := []byte{byte(len(ab))}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if _, err := w.Write(ab); err != nil {
		return err
	}
	var ln [2]byte
	binary.BigEndian.PutUint16(ln[:], uint16(len(payload)))
	if _, err := w.Write(ln[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func ReadUDP(r io.Reader) (string, []byte, error) {
	var al [1]byte
	if _, err := io.ReadFull(r, al[:]); err != nil {
		return "", nil, err
	}
	ab := make([]byte, al[0])
	if _, err := io.ReadFull(r, ab); err != nil {
		return "", nil, err
	}
	var ln [2]byte
	if _, err := io.ReadFull(r, ln[:]); err != nil {
		return "", nil, err
	}
	n := int(binary.BigEndian.Uint16(ln[:]))
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return "", nil, err
	}
	return string(ab), payload, nil
}

func writeString(w io.Writer, s string) error {
	b := []byte(s)
	var ln [2]byte
	binary.BigEndian.PutUint16(ln[:], uint16(len(b)))
	if _, err := w.Write(ln[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

func readString(r io.Reader) (string, error) {
	var ln [2]byte
	if _, err := io.ReadFull(r, ln[:]); err != nil {
		return "", err
	}
	b := make([]byte, binary.BigEndian.Uint16(ln[:]))
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return string(b), nil
}

// RequestReverseBind asks the server to bind listen (TCP+UDP) and returns the bound address.
func RequestReverseBind(sess *smux.Session, listen string) (string, error) {
	st, err := sess.OpenStream()
	if err != nil {
		return "", err
	}
	defer st.Close()
	if _, err := st.Write([]byte{KindRevBind}); err != nil {
		return "", err
	}
	if err := writeString(st, listen); err != nil {
		return "", err
	}
	return readString(st)
}

// Serve runs the server side of a mux session.
// target set => dial that address for forward KindTCP/KindUDP; reverse binds are always accepted.
// target empty => reverse-only hub (forward streams are dropped). skipUDP true => do not dial UDP (http).
func Serve(sess *smux.Session, target string, skipUDP bool) {
	for {
		st, err := sess.AcceptStream()
		if err != nil {
			return
		}
		go handleServerStream(sess, st, target, skipUDP, nil)
	}
}

func handleServerStream(sess *smux.Session, st *smux.Stream, target string, skipUDP bool, udpConn *net.UDPConn) {
	defer st.Close()
	var kind [1]byte
	if _, err := io.ReadFull(st, kind[:]); err != nil {
		return
	}
	switch kind[0] {
	case KindTCP:
		if target == "" {
			return
		}
		remote, err := net.Dial("tcp", target)
		if err != nil {
			return
		}
		defer remote.Close()
		Copy(st, remote)
	case KindUDP:
		if target == "" || skipUDP {
			return
		}
		relayUDP(st, target, udpConn)
	case KindRevBind:
		listen, err := readString(st)
		if err != nil {
			return
		}
		runReverse(sess, st, listen)
	}
}

func relayUDP(st *smux.Stream, target string, pc *net.UDPConn) {
	dst, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return
	}
	if pc == nil {
		pc, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			return
		}
		defer pc.Close()
	}
	var lastSrc *net.UDPAddr
	var mu sync.Mutex
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.Lock()
			lastSrc = from
			mu.Unlock()
			_ = WriteUDP(st, from.String(), buf[:n])
		}
	}()
	for {
		_, payload, err := ReadUDP(st)
		if err != nil {
			return
		}
		if _, err := pc.WriteToUDP(payload, dst); err != nil {
			return
		}
		_ = lastSrc
	}
}

func runReverse(sess *smux.Session, ctl *smux.Stream, listen string) {
	ln, udp, bound, err := listenDual(listen)
	if err != nil {
		_ = writeString(ctl, "")
		return
	}
	defer ln.Close()
	if udp != nil {
		defer udp.Close()
	}
	if err := writeString(ctl, bound); err != nil {
		return
	}

	go func() {
		if udp == nil {
			return
		}
		// UDP stream to the client
		ust, err := sess.OpenStream()
		if err != nil {
			return
		}
		defer ust.Close()
		if _, err := ust.Write([]byte{KindUDP}); err != nil {
			return
		}
		var last *net.UDPAddr
		var mu sync.Mutex
		go func() {
			for {
				_, payload, err := ReadUDP(ust)
				if err != nil {
					return
				}
				mu.Lock()
				dst := last
				mu.Unlock()
				if dst != nil {
					_, _ = udp.WriteToUDP(payload, dst)
				}
			}
		}()
		buf := make([]byte, 65535)
		for {
			n, from, err := udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.Lock()
			last = from
			mu.Unlock()
			if err := WriteUDP(ust, from.String(), buf[:n]); err != nil {
				return
			}
		}
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			st, err := sess.OpenStream()
			if err != nil {
				c.Close()
				return
			}
			if _, err := st.Write([]byte{KindRevTCP}); err != nil {
				st.Close()
				c.Close()
				return
			}
			Copy(st, c)
			st.Close()
			c.Close()
		}(c)
	}
}

func listenDual(addr string) (net.Listener, *net.UDPConn, string, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, "", err
	}
	bound := ln.Addr().String()
	ua, err := net.ResolveUDPAddr("udp", bound)
	if err != nil {
		log.Printf("muxpipe: UDP resolve %s: %v (TCP-only)", bound, err)
		return ln, nil, bound, nil
	}
	pc, err := net.ListenUDP("udp", ua)
	if err != nil {
		log.Printf("muxpipe: UDP listen %s: %v (TCP-only)", bound, err)
		return ln, nil, bound, nil
	}
	return ln, pc, bound, nil
}

// RunForwardClient binds listen TCP+UDP and pipes through sess to a server with target.
func RunForwardClient(sess *smux.Session, tcpLn net.Listener, udp *net.UDPConn) {
	if udp != nil {
		go func() {
			st, err := sess.OpenStream()
			if err != nil {
				return
			}
			defer st.Close()
			if _, err := st.Write([]byte{KindUDP}); err != nil {
				return
			}
			var last *net.UDPAddr
			var mu sync.Mutex
			go func() {
				for {
					_, payload, err := ReadUDP(st)
					if err != nil {
						return
					}
					mu.Lock()
					dst := last
					mu.Unlock()
					if dst != nil && udp != nil {
						_, _ = udp.WriteToUDP(payload, dst)
					}
				}
			}()
			buf := make([]byte, 65535)
			for {
				n, from, err := udp.ReadFromUDP(buf)
				if err != nil {
					return
				}
				mu.Lock()
				last = from
				mu.Unlock()
				if err := WriteUDP(st, from.String(), buf[:n]); err != nil {
					return
				}
			}
		}()
	}
	for {
		c, err := tcpLn.Accept()
		if err != nil {
			return
		}
		st, err := OpenTCP(sess)
		if err != nil {
			c.Close()
			return
		}
		go func(c net.Conn, st *smux.Stream) {
			defer c.Close()
			defer st.Close()
			Copy(st, c)
		}(c, st)
	}
}

// RunReverseClient handles KindRevTCP / KindUDP from the hub and dials localAddr.
func RunReverseClient(sess *smux.Session, localAddr string, skipUDP bool) {
	for {
		st, err := sess.AcceptStream()
		if err != nil {
			return
		}
		go func(st *smux.Stream) {
			defer st.Close()
			var kind [1]byte
			if _, err := io.ReadFull(st, kind[:]); err != nil {
				return
			}
			switch kind[0] {
			case KindRevTCP:
				remote, err := net.Dial("tcp", localAddr)
				if err != nil {
					return
				}
				defer remote.Close()
				Copy(st, remote)
			case KindUDP:
				if skipUDP {
					return
				}
				relayUDP(st, localAddr, nil)
			}
		}(st)
	}
}
