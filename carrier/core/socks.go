package core

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/lord-aali/PT-Proxy/common/dualbind"
	"github.com/lord-aali/PT-Proxy/common/ptlog"
	"github.com/miekg/dns"
	"github.com/things-go/go-socks5"
)

type SocksConfig struct {
	Listen      string
	ReverseAddr string
	SkipUDP     bool
	LogTag      string
}

// RunClientSocks serves SOCKS5 (or raw forward if ReverseAddr set via reverse bind only).
// When ReverseAddr is non-empty, listen is the remote reverse bind and local SOCKS is skipped.
func RunClientSocks(sess *ClientSession, cfg SocksConfig) error {
	lg := ptlog.PTLog{LogTag: cfg.LogTag}
	if cfg.ReverseAddr != "" {
		bound, err := sess.RequestReverse(cfg.Listen)
		if err != nil {
			return err
		}
		lg.Info("carrier reverse published on", bound, "->", cfg.ReverseAddr)
		select {}
	}

	resolver := &carrierResolver{sess: sess}
	server := socks5.NewServer(
		socks5.WithResolver(resolver),
		socks5.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
			if strings.HasPrefix(network, "udp") {
				return sess.OpenUDP(addr)
			}
			return sess.OpenTCP(addr)
		}),
	)

	ln, udp, bound, err := dualbind.Listen(cfg.Listen)
	if err != nil {
		return err
	}
	lg.Info("carrier SOCKS5 on", bound)
	if udp != nil && !cfg.SkipUDP {
		go serveUDPAssociate(sess, udp, lg)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(conn net.Conn) {
			defer conn.Close()
			_ = server.ServeConn(conn)
		}(c)
	}
}

// RunClientForward pipes each accepted local TCP/UDP connection through the tunnel.
// Server uses its configured target (socks/http/external); open address may be empty.
func RunClientForward(sess *ClientSession, listen, target string, skipUDP bool, logTag string) error {
	lg := ptlog.PTLog{LogTag: logTag}
	ln, udp, bound, err := dualbind.Listen(listen)
	if err != nil {
		return err
	}
	lg.Info("carrier forward listen", bound)
	if udp != nil && !skipUDP {
		go forwardUDP(sess, udp, target, lg)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(local net.Conn) {
			defer local.Close()
			remote, err := sess.OpenTCP(target)
			if err != nil {
				return
			}
			defer remote.Close()
			pipe(local, remote)
		}(c)
	}
}

func forwardUDP(sess *ClientSession, pc *net.UDPConn, target string, lg ptlog.PTLog) {
	buf := make([]byte, 65535)
	var (
		remote net.Conn
		last   *net.UDPAddr
		mu     sync.Mutex
	)
	for {
		n, from, err := pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		mu.Lock()
		last = from
		mu.Unlock()
		if remote == nil {
			remote, err = sess.OpenUDP(target)
			if err != nil {
				lg.Error("open udp:", err)
				continue
			}
			go func(r net.Conn) {
				rbuf := make([]byte, 65535)
				for {
					rn, err := r.Read(rbuf)
					if rn > 0 {
						mu.Lock()
						dst := last
						mu.Unlock()
						if dst != nil {
							_, _ = pc.WriteToUDP(rbuf[:rn], dst)
						}
					}
					if err != nil {
						return
					}
				}
			}(remote)
		}
		_, _ = remote.Write(buf[:n])
	}
}

func pipe(a, b net.Conn) {
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

func serveUDPAssociate(sess *ClientSession, pc *net.UDPConn, lg ptlog.PTLog) {
	// Minimal: first datagram opens a UDP flow to destination encoded in SOCKS header is complex;
	// SOCKS UDP associate is handled by go-socks5 dial for TCP control path primarily.
	_ = sess
	_ = pc
	_ = lg
}

type carrierResolver struct {
	sess  *ClientSession
	mu    sync.Mutex
	cache map[string]cachedIP
}

type cachedIP struct {
	ip      net.IP
	expires time.Time
}

func (r *carrierResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	key := strings.ToLower(strings.TrimSuffix(name, "."))
	r.mu.Lock()
	if r.cache == nil {
		r.cache = map[string]cachedIP{}
	}
	if e, ok := r.cache[key]; ok && time.Now().Before(e.expires) {
		r.mu.Unlock()
		return ctx, e.ip, nil
	}
	r.mu.Unlock()

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.RecursionDesired = true
	packed, err := m.Pack()
	if err != nil {
		return ctx, nil, err
	}
	resp, err := r.sess.DNS(packed)
	if err != nil {
		return ctx, nil, err
	}
	var reply dns.Msg
	if err := reply.Unpack(resp); err != nil {
		return ctx, nil, err
	}
	for _, ans := range reply.Answer {
		if a, ok := ans.(*dns.A); ok {
			r.mu.Lock()
			r.cache[key] = cachedIP{ip: a.A, expires: time.Now().Add(60 * time.Second)}
			r.mu.Unlock()
			return ctx, a.A, nil
		}
	}
	return ctx, nil, fmt.Errorf("no A record for %s", name)
}
