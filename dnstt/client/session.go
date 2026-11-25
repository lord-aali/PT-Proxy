package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/lord-aali/PT-Proxy/dnstt/dns"
	"github.com/lord-aali/PT-Proxy/dnstt/keys"
	"github.com/lord-aali/PT-Proxy/dnstt/noise"
	"github.com/lord-aali/PT-Proxy/dnstt/turbotunnel"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

// smux streams will be closed after this much time without receiving data.
const idleTimeout = 2 * time.Minute

// Config is a local TCP forwarder over encrypted DNS.
type Config struct {
	Listen string
	Domain dns.Name
	EncKey string
	Remote string // resolver host:port, or the VPS in direct mode
	QType  uint16 // 0 is TXT. AAAA and A are the other accepted query types.
	// PacketSize is the KCP payload per query. 0 uses the largest size that fits.
	PacketSize int
	// Ready is called once, after Listen is bound. addr is the actual local address.
	Ready func(addr string)
}

type sessionHolder struct {
	mu      sync.Mutex
	sess    *smux.Session
	streams atomic.Int32
}

func (h *sessionHolder) beginStream() int { return int(h.streams.Add(1)) }
func (h *sessionHolder) endStream()       { h.streams.Add(-1) }
func (h *sessionHolder) streamCount() int { return int(h.streams.Load()) }

func (h *sessionHolder) current() *smux.Session {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.sess != nil && h.sess.IsClosed() {
		h.sess = nil
	}
	return h.sess
}

func (h *sessionHolder) wait(timeout time.Duration) *smux.Session {
	deadline := time.Now().Add(timeout)
	for {
		if sess := h.current(); sess != nil {
			return sess
		}
		if time.Now().After(deadline) {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (h *sessionHolder) set(sess *smux.Session) {
	h.mu.Lock()
	h.sess = sess
	h.mu.Unlock()
}

// minQueryMTU is the smallest KCP payload a session will run with.
const minQueryMTU = 80

// QueryMTU is the KCP payload carried in one DNS query.
// packetSize 0 selects the largest payload that fits under domain.
func QueryMTU(domain dns.Name, packetSize int) (int, error) {
	max := dnsNameCapacity(domain) - 8 - 1 - numPadding - 1 - keys.Overhead
	if max < minQueryMTU {
		return 0, fmt.Errorf("domain %s leaves only %d bytes for payload", domain, max)
	}
	if packetSize == 0 {
		return max, nil
	}
	if packetSize < minQueryMTU || packetSize > max {
		return 0, fmt.Errorf("packet-size %d is outside %d..%d", packetSize, minQueryMTU, max)
	}
	return packetSize, nil
}

// Serve binds Listen and keeps a DNS session up until ctx is cancelled.
// A dead session is restarted in-process.
func Serve(ctx context.Context, cfg Config) error {
	if _, err := QueryMTU(cfg.Domain, cfg.PacketSize); err != nil {
		return err
	}
	local, err := net.ResolveTCPAddr("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("local address: %w", err)
	}
	ln, err := net.ListenTCP("tcp", local)
	if err != nil {
		return fmt.Errorf("opening local listener: %w", err)
	}
	defer ln.Close()
	if cfg.Ready != nil {
		cfg.Ready(ln.Addr().String())
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	hold := &sessionHolder{}
	go acceptLocal(ln, hold)

	pubkey := noise.PubkeyFromPrivkey(keys.NoisePrivkey(cfg.EncKey))
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := runSession(ctx, cfg, pubkey, hold)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		log.Printf("dns client session ended: %v", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func acceptLocal(ln *net.TCPListener, hold *sessionHolder) {
	for {
		local, err := ln.AcceptTCP()
		if err != nil {
			return
		}
		go func() {
			defer local.Close()
			sess := hold.wait(30 * time.Second)
			if sess == nil {
				return
			}
			if err := handle(local, sess, hold); err != nil {
				log.Printf("handle: %v", err)
			}
		}()
	}
}

func runSession(ctx context.Context, cfg Config, pubkey []byte, hold *sessionHolder) error {
	fan, err := newFanout(cfg.Remote)
	if err != nil {
		return err
	}

	pconn := NewDNSPacketConn(fan, fan.remote, cfg.Domain, keys.QNameKey(cfg.EncKey), cfg.QType)
	defer func() {
		fan.Close()
		pconn.Close()
	}()

	mtu, err := QueryMTU(cfg.Domain, cfg.PacketSize)
	if err != nil {
		return err
	}
	log.Printf("effective MTU %d", mtu)
	log.Printf("dns handshake starting")

	conn, err := kcp.NewConn2(fan.remote, nil, 0, 0, pconn)
	if err != nil {
		return fmt.Errorf("opening KCP conn: %v", err)
	}
	defer conn.Close()
	conn.SetStreamMode(true)
	// Same settings as dnstt. KCP keeps one window of unacknowledged
	// segments and measures the real round trip. sendLoop separately
	// refuses to put more than maxInFlight DNS queries on the wire; that
	// wait does not discard a late reply.
	conn.SetNoDelay(
		0, // default nodelay
		0, // default interval
		0, // default resend
		1, // nc=1 => congestion window off
	)
	conn.SetWindowSize(turbotunnel.WindowSize, turbotunnel.WindowSize)
	if rc := conn.SetMtu(mtu); !rc {
		return fmt.Errorf("setting KCP MTU %d", mtu)
	}

	rw, err := noise.NewClient(conn, pubkey)
	if err != nil {
		return err
	}
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024
	sess, err := smux.Client(rw, smuxConfig)
	if err != nil {
		return fmt.Errorf("opening smux session: %v", err)
	}
	defer sess.Close()
	hold.set(sess)
	defer hold.set(nil)
	log.Printf("dns session ready")

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-sess.CloseChan():
			return fmt.Errorf("session closed")
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			sessionHealth(hold, pconn)
		}
	}
}

// sessionHealth logs the DNS path while it is busy. The session is left up
// across a slow patch of replies. dnstt does not restart it; KCP keeps the
// segments until the answers show up.
func sessionHealth(hold *sessionHolder, pconn *DNSPacketConn) {
	st := pconn.Stats()
	streams := hold.streamCount()
	busy := streams > 0 || st.SendQ > 0 || st.SendDrops > 0 || st.RecvDrops > 0
	if !busy {
		return
	}
	log.Printf("dns: streams=%d inflight=%d sendq=%d recvq=%d send-drop=%d recv-drop=%d queries=%d answers=%d payloads=%d answer=%s payload=%s",
		streams, pconn.InFlight(),
		st.SendQ, st.RecvQ, st.SendDrops, st.RecvDrops,
		st.Queries, st.Answers, st.Payloads,
		st.SinceAnswer.Round(time.Second), st.SincePayload.Round(time.Second))
}

func handle(local *net.TCPConn, sess *smux.Session, hold *sessionHolder) error {
	log.Printf("stream opening (%d active)", hold.streamCount())
	stream, err := sess.OpenStream()
	if err != nil {
		// Leave the session up. One open can time out while other streams
		// are still moving data; closing here is what forced the 20s
		// handshake before the next ping.
		return fmt.Errorf("opening stream: %v", err)
	}
	defer stream.Close()
	active := hold.beginStream()
	defer hold.endStream()
	log.Printf("stream %d open (%d active)", stream.ID(), active)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, err := io.Copy(stream, local)
		if err != nil && !isLocalClose(err) {
			log.Printf("stream %d upload ended bytes=%d: %v", stream.ID(), n, err)
		} else {
			log.Printf("stream %d upload ended bytes=%d", stream.ID(), n)
		}
		local.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		n, err := io.Copy(local, stream)
		if err != nil && !isLocalClose(err) {
			log.Printf("stream %d download ended bytes=%d: %v", stream.ID(), n, err)
		} else {
			log.Printf("stream %d download ended bytes=%d", stream.ID(), n)
		}
		local.CloseWrite()
	}()
	wg.Wait()
	return nil
}

// isLocalClose reports a local application hanging up. That is not a tunnel failure.
func isLocalClose(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) && localErrno(errno) {
		return true
	}
	return false
}

func localErrno(errno syscall.Errno) bool {
	switch errno {
	case syscall.ECONNRESET, syscall.ECONNABORTED, syscall.EPIPE:
		return true
	default:
		return extraLocalErrno(errno)
	}
}

// dnsNameCapacity returns the number of bytes remaining for encoded data after
// including domain in a DNS name.
func dnsNameCapacity(domain dns.Name) int {
	capacity := 255
	capacity -= 1
	for _, label := range domain {
		capacity -= len(label) + 1
	}
	capacity = capacity * 63 / 64
	capacity = capacity * 5 / 8
	return capacity
}
