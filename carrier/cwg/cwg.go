package cwg

import (
	"crypto/cipher"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/lord-aali/PT-Proxy/carrier/core"
	"github.com/lord-aali/PT-Proxy/common/ptlog"
)

const (
	defaultListen = "0.0.0.0:4446"
	maxPlain      = 60 * 1024
)

// Config is one custom tunnel endpoint. The outer datagrams are UDP.
// They are not WireGuard and will not talk to a WireGuard peer.
type Config struct {
	Listen      string
	Address     string
	Target      string
	EncKey      string
	ReverseAddr string
	SkipUDP     bool
	PadMax      int
	JitterMax   time.Duration
	LogTag      string
	DNSNetwork  string
	DNSUpstream string
}

type Link struct {
	conn      *net.UDPConn
	remote    *net.UDPAddr
	aead      cipher.AEAD
	role      byte
	peerRole  byte
	padMax    int
	jitter    time.Duration
	connected bool
	owned     bool

	wmu     sync.Mutex
	counter uint64

	inbox chan []byte
}

func RunServer(cfg Config) error {
	listen := cfg.Listen
	if listen == "" {
		listen = defaultListen
	}
	addr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	lg := ptlog.PTLog{LogTag: cfg.LogTag}
	lg.Info("carrier cwg listen", conn.LocalAddr().String())
	return serve(conn, cfg)
}

func serve(conn *net.UDPConn, cfg Config) error {
	aead, err := newAEAD(cfg.EncKey)
	if err != nil {
		return err
	}
	type sess struct {
		inbox chan []byte
		win   replay
		dead  bool
	}
	sessions := make(map[string]*sess)
	var mu sync.Mutex
	buf := make([]byte, 65535)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		plain, counter, err := open(aead, roleClient, buf[:n])
		if err != nil {
			continue
		}
		key := from.String()
		mu.Lock()
		s, ok := sessions[key]
		if !ok {
			s = &sess{inbox: make(chan []byte, 128)}
			sessions[key] = s
			link := &Link{
				conn:     conn,
				remote:   from,
				aead:     aead,
				role:     roleServer,
				peerRole: roleClient,
				padMax:   cfg.PadMax,
				jitter:   cfg.JitterMax,
				inbox:    s.inbox,
			}
			go func(k string, lk *Link, st *sess) {
				core.Serve(lk, core.ServerConfig{
					Target:      cfg.Target,
					SkipUDP:     cfg.SkipUDP,
					DNSNetwork:  cfg.DNSNetwork,
					DNSUpstream: cfg.DNSUpstream,
				})
				mu.Lock()
				st.dead = true
				delete(sessions, k)
				close(st.inbox)
				mu.Unlock()
			}(key, link, s)
		}
		if s.dead || !s.win.accept(counter) {
			mu.Unlock()
			continue
		}
		select {
		case s.inbox <- append([]byte(nil), plain...):
		default:
		}
		mu.Unlock()
	}
}

func RunClient(cfg Config) error {
	lg := ptlog.PTLog{LogTag: cfg.LogTag}
	if cfg.Address == "" {
		return fmt.Errorf("cwg address required")
	}
	aead, err := newAEAD(cfg.EncKey)
	if err != nil {
		return err
	}
	for {
		err := runClientOnce(aead, cfg, lg)
		if err != nil {
			lg.Error("cwg:", err)
		}
		time.Sleep(time.Second)
	}
}

func runClientOnce(aead cipher.AEAD, cfg Config, lg ptlog.PTLog) error {
	raddr, err := net.ResolveUDPAddr("udp", cfg.Address)
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return err
	}
	link := &Link{
		conn:      conn,
		remote:    raddr,
		aead:      aead,
		role:      roleClient,
		peerRole:  roleServer,
		padMax:    cfg.PadMax,
		jitter:    cfg.JitterMax,
		connected: true,
		owned:     true,
	}
	defer link.Close()
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	if err := core.HandshakeClient(link); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	lg.Info("cwg session open", cfg.Address)
	sess := core.NewClientSession(link, cfg.ReverseAddr)
	defer sess.Close()
	if cfg.ReverseAddr != "" {
		return core.RunClientSocks(sess, core.SocksConfig{
			Listen:      cfg.Listen,
			ReverseAddr: cfg.ReverseAddr,
			SkipUDP:     cfg.SkipUDP,
			LogTag:      cfg.LogTag,
		})
	}
	return core.RunClientForward(sess, cfg.Listen, "", cfg.SkipUDP, cfg.LogTag)
}

func (l *Link) Close() error {
	if l.owned && l.conn != nil {
		return l.conn.Close()
	}
	return nil
}

func (l *Link) WriteFrame(f core.Frame) error {
	pad := choosePad(len(f.Data), l.padMax)
	plain, err := core.EncodeFramePadded(f, pad)
	if err != nil {
		return err
	}
	if len(plain) > maxPlain {
		return fmt.Errorf("cwg frame too large")
	}
	if l.jitter > 0 {
		time.Sleep(time.Duration(rand.Int63n(int64(l.jitter) + 1)))
	}
	l.wmu.Lock()
	defer l.wmu.Unlock()
	l.counter++
	pkt, err := seal(l.aead, l.role, l.counter, plain)
	if err != nil {
		return err
	}
	if l.connected {
		_, err = l.conn.Write(pkt)
		return err
	}
	if l.remote == nil {
		return io.ErrClosedPipe
	}
	_, err = l.conn.WriteToUDP(pkt, l.remote)
	return err
}

func (l *Link) ReadFrame() (core.Frame, error) {
	if l.inbox != nil {
		plain, ok := <-l.inbox
		if !ok {
			return core.Frame{}, io.EOF
		}
		return core.DecodeFrame(plain)
	}
	buf := make([]byte, 65535)
	var win replay
	for {
		if err := l.conn.SetReadDeadline(time.Now().Add(5 * time.Minute)); err != nil {
			return core.Frame{}, err
		}
		n, err := l.conn.Read(buf)
		if err != nil {
			return core.Frame{}, err
		}
		plain, counter, err := open(l.aead, l.peerRole, buf[:n])
		if err != nil || !win.accept(counter) {
			continue
		}
		return core.DecodeFrame(plain)
	}
}
