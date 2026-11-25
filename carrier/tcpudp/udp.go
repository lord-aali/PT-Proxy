package tcpudp

import (
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/lord-aali/PT-Proxy/carrier/core"
	"github.com/lord-aali/PT-Proxy/common/ptlog"
)

const maxUDPPayload = 60 * 1024

// UDPLink: each datagram is one encrypted frame (no length prefix).
type UDPLink struct {
	conn      *net.UDPConn
	remote    *net.UDPAddr
	enc       *core.Encryptor
	padMax    int
	jitter    time.Duration
	wmu       sync.Mutex
	inbox     chan []byte // optional pre-fed ciphertext; nil = read from conn
	owned     bool        // close conn on Close
	connected bool        // DialUDP: use Read/Write (WriteToUDP fails on connected sockets)
}

func NewUDPLink(conn *net.UDPConn, remote *net.UDPAddr, enc *core.Encryptor, padMax int, jitter time.Duration, owned bool) *UDPLink {
	return &UDPLink{conn: conn, remote: remote, enc: enc, padMax: padMax, jitter: jitter, owned: owned}
}

func NewConnectedUDPLink(conn *net.UDPConn, remote *net.UDPAddr, enc *core.Encryptor, padMax int, jitter time.Duration) *UDPLink {
	return &UDPLink{conn: conn, remote: remote, enc: enc, padMax: padMax, jitter: jitter, owned: true, connected: true}
}

func (l *UDPLink) Close() error {
	if l.owned && l.conn != nil {
		return l.conn.Close()
	}
	return nil
}

func (l *UDPLink) WriteFrame(f core.Frame) error {
	pad := 0
	if l.padMax > 0 {
		pad = rand.Intn(l.padMax + 1)
	}
	plain, err := core.EncodeFramePadded(f, pad)
	if err != nil {
		return err
	}
	ct, err := l.enc.Encrypt(plain)
	if err != nil {
		return err
	}
	if len(ct) > maxUDPPayload {
		return fmt.Errorf("udp frame too large")
	}
	if l.jitter > 0 {
		time.Sleep(time.Duration(rand.Int63n(int64(l.jitter) + 1)))
	}
	l.wmu.Lock()
	defer l.wmu.Unlock()
	if l.connected {
		_, err = l.conn.Write(ct)
		return err
	}
	if l.remote == nil {
		return io.ErrClosedPipe
	}
	_, err = l.conn.WriteToUDP(ct, l.remote)
	return err
}

func (l *UDPLink) ReadFrame() (core.Frame, error) {
	if l.inbox != nil {
		ct, ok := <-l.inbox
		if !ok {
			return core.Frame{}, io.EOF
		}
		plain, err := l.enc.Decrypt(ct)
		if err != nil {
			return core.Frame{}, err
		}
		return core.DecodeFrame(plain)
	}
	buf := make([]byte, 65535)
	for {
		_ = l.conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		var n int
		var err error
		if l.connected {
			n, err = l.conn.Read(buf)
			if err != nil {
				return core.Frame{}, err
			}
		} else {
			var addr *net.UDPAddr
			n, addr, err = l.conn.ReadFromUDP(buf)
			if err != nil {
				return core.Frame{}, err
			}
			if l.remote == nil {
				l.remote = addr
			} else if !addr.IP.Equal(l.remote.IP) || addr.Port != l.remote.Port {
				continue
			}
		}
		plain, err := l.enc.Decrypt(buf[:n])
		if err != nil {
			continue
		}
		return core.DecodeFrame(plain)
	}
}

func RunUDPServer(cfg Config) error {
	lg := ptlog.PTLog{LogTag: cfg.LogTag}
	enc, err := core.NewEncryptor([]byte(cfg.EncKey))
	if err != nil {
		return err
	}
	addr, err := net.ResolveUDPAddr("udp", cfg.Listen)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	lg.Info("carrier udp server listen", cfg.Listen)

	type sess struct {
		inbox chan []byte
	}
	sessions := make(map[string]*sess)
	var mu sync.Mutex

	buf := make([]byte, 65535)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		ct := make([]byte, n)
		copy(ct, buf[:n])
		if _, err := enc.Decrypt(ct); err != nil {
			continue
		}
		key := from.String()
		mu.Lock()
		s, ok := sessions[key]
		if !ok {
			inbox := make(chan []byte, 128)
			s = &sess{inbox: inbox}
			sessions[key] = s
			link := NewUDPLink(conn, from, enc, cfg.PadMax, cfg.JitterMax, false)
			link.inbox = inbox
			go func(k string, lk *UDPLink) {
				core.Serve(lk, core.ServerConfig{
					Target:      cfg.Target,
					SkipUDP:     cfg.SkipUDP,
					DNSNetwork:  cfg.DNSNetwork,
					DNSUpstream: cfg.DNSUpstream,
				})
				mu.Lock()
				delete(sessions, k)
				mu.Unlock()
				close(inbox)
			}(key, link)
		}
		select {
		case s.inbox <- ct:
		default:
		}
		mu.Unlock()
	}
}

func RunUDPClient(cfg Config) error {
	lg := ptlog.PTLog{LogTag: cfg.LogTag}
	enc, err := core.NewEncryptor([]byte(cfg.EncKey))
	if err != nil {
		return err
	}
	for {
		raddr, err := net.ResolveUDPAddr("udp", cfg.Address)
		if err != nil {
			return err
		}
		conn, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			lg.Error("dial udp:", err)
			time.Sleep(time.Second)
			continue
		}
		link := NewConnectedUDPLink(conn, raddr, enc, cfg.PadMax, cfg.JitterMax)
		if err := core.HandshakeClient(link); err != nil {
			lg.Error("handshake:", err)
			_ = link.Close()
			time.Sleep(time.Second)
			continue
		}
		sess := core.NewClientSession(link, cfg.ReverseAddr)
		if cfg.ReverseAddr != "" {
			err = core.RunClientSocks(sess, core.SocksConfig{
				Listen:      cfg.Listen,
				ReverseAddr: cfg.ReverseAddr,
				SkipUDP:     cfg.SkipUDP,
				LogTag:      cfg.LogTag,
			})
		} else {
			err = core.RunClientForward(sess, cfg.Listen, "", cfg.SkipUDP, cfg.LogTag, "udp", cfg.Address)
		}
		_ = sess.Close()
		if err != nil {
			lg.Error("client:", err)
		}
		time.Sleep(time.Second)
	}
}
