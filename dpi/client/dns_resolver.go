package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/lord-aali/PT-Proxy/common/ptlog"
	"github.com/miekg/dns"
)

// tunneledResolver resolves names by sending DNS queries through the HTTP tunnel
// to an upstream resolver (IP address), avoiding local DNS poisoning.
type tunneledResolver struct {
	transport *Transport
	network   string // "tcp" or "udp"
	upstream  string // e.g. "1.1.1.1:53"
	timeout   time.Duration
	log       ptlog.PTLog
	verbose   bool
	cacheMu   sync.RWMutex
	cache     map[string]dnsCacheEntry
}

type dnsCacheEntry struct {
	ip      net.IP
	expires time.Time
}

func newTunneledResolver(t *Transport, network, upstream string, lg ptlog.PTLog, verbose bool) *tunneledResolver {
	if network != "tcp" && network != "udp" {
		network = "tcp"
	}
	return &tunneledResolver{
		transport: t,
		network:   network,
		upstream:  upstream,
		timeout:   10 * time.Second,
		log:       lg,
		verbose:   verbose,
		cache:     make(map[string]dnsCacheEntry),
	}
}

func (r *tunneledResolver) debugf(format string, v ...interface{}) {
	if r.verbose {
		r.log.Debug(fmt.Sprintf(format, v...))
	}
}

func (r *tunneledResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	cacheKey := strings.ToLower(strings.TrimSuffix(dns.Fqdn(name), "."))
	if ip, ok := r.cacheLookup(cacheKey); ok {
		r.debugf("Cache hit %s -> %s", cacheKey, ip.String())
		return ctx, ip, nil
	}

	r.debugf("Resolving %s via tunneled %s to %s", name, r.network, r.upstream)

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.RecursionDesired = true

	reply, err := r.exchange(ctx, m)
	if err != nil {
		return ctx, nil, err
	}

	for _, ans := range reply.Answer {
		if a, ok := ans.(*dns.A); ok {
			r.debugf("Resolved %s to %s", name, a.A.String())
			r.cacheStore(cacheKey, a.A, minTTLSeconds(reply, 60))
			return ctx, a.A, nil
		}
	}

	return ctx, nil, fmt.Errorf("no A record found for %s", name)
}

func (r *tunneledResolver) cacheLookup(name string) (net.IP, bool) {
	r.cacheMu.RLock()
	entry, ok := r.cache[name]
	r.cacheMu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expires) {
		r.cacheMu.Lock()
		delete(r.cache, name)
		r.cacheMu.Unlock()
		return nil, false
	}
	return append(net.IP(nil), entry.ip...), true
}

func (r *tunneledResolver) cacheStore(name string, ip net.IP, ttlSeconds uint32) {
	ttl := time.Duration(ttlSeconds) * time.Second
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	if ttl > 5*time.Minute {
		ttl = 5 * time.Minute
	}
	r.cacheMu.Lock()
	r.cache[name] = dnsCacheEntry{
		ip:      append(net.IP(nil), ip...),
		expires: time.Now().Add(ttl),
	}
	r.cacheMu.Unlock()
}

func minTTLSeconds(msg *dns.Msg, fallback uint32) uint32 {
	ttl := uint32(0)
	for _, ans := range msg.Answer {
		h := ans.Header()
		if h == nil {
			continue
		}
		if ttl == 0 || h.Ttl < ttl {
			ttl = h.Ttl
		}
	}
	if ttl == 0 {
		return fallback
	}
	return ttl
}

func (r *tunneledResolver) exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 && remaining < r.timeout {
			r.timeout = remaining
		}
	}

	connID, err := r.transport.Connect(r.network, r.upstream)
	if err != nil {
		return nil, fmt.Errorf("tunnel connect to %s: %w", r.upstream, err)
	}

	tc, err := newTunnelConn(r.transport, connID, r.log, false)
	if err != nil {
		r.transport.CloseConn(connID)
		return nil, fmt.Errorf("tunnel stream: %w", err)
	}
	defer tc.Close()

	query, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack DNS query: %w", err)
	}

	if r.network == "tcp" {
		return r.exchangeTCP(ctx, tc, query)
	}
	return r.exchangeUDP(ctx, tc, query)
}

func (r *tunneledResolver) exchangeTCP(ctx context.Context, tc net.Conn, query []byte) (*dns.Msg, error) {
	if len(query) > 0xffff {
		return nil, fmt.Errorf("DNS query too large for TCP")
	}
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
	copy(frame[2:], query)

	if _, err := tc.Write(frame); err != nil {
		return nil, fmt.Errorf("write DNS query: %w", err)
	}

	type result struct {
		reply *dns.Msg
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(tc, lenBuf); err != nil {
			ch <- result{nil, fmt.Errorf("read DNS length: %w", err)}
			return
		}
		respLen := binary.BigEndian.Uint16(lenBuf)
		if respLen == 0 {
			ch <- result{nil, fmt.Errorf("empty DNS TCP response")}
			return
		}
		respBuf := make([]byte, respLen)
		if _, err := io.ReadFull(tc, respBuf); err != nil {
			ch <- result{nil, fmt.Errorf("read DNS response: %w", err)}
			return
		}
		var reply dns.Msg
		if err := reply.Unpack(respBuf); err != nil {
			ch <- result{nil, fmt.Errorf("unpack DNS response: %w", err)}
			return
		}
		ch <- result{&reply, nil}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		return res.reply, res.err
	case <-time.After(r.timeout):
		return nil, fmt.Errorf("DNS query timed out after %s", r.timeout)
	}
}

func (r *tunneledResolver) exchangeUDP(ctx context.Context, tc net.Conn, query []byte) (*dns.Msg, error) {
	if _, err := tc.Write(query); err != nil {
		return nil, fmt.Errorf("write DNS query: %w", err)
	}

	type result struct {
		reply *dns.Msg
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		buf := make([]byte, dns.MaxMsgSize)
		n, err := tc.Read(buf)
		if err != nil {
			ch <- result{nil, fmt.Errorf("read DNS response: %w", err)}
			return
		}
		var reply dns.Msg
		if err := reply.Unpack(buf[:n]); err != nil {
			ch <- result{nil, fmt.Errorf("unpack DNS response: %w", err)}
			return
		}
		ch <- result{&reply, nil}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		return res.reply, res.err
	case <-time.After(r.timeout):
		return nil, fmt.Errorf("DNS query timed out after %s", r.timeout)
	}
}

// tunnelDialContext dials through the tunnel for SOCKS CONNECT (tcp) and UDP ASSOCIATE (udp).
// Android and other clients often send DNS as UDP to 8.8.8.8:53 via SOCKS UDP, not via Resolve().
func tunnelDialContext(transport *Transport, lg ptlog.PTLog, verbose bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		tunnelNet, err := tunnelNetwork(network)
		if err != nil {
			return nil, err
		}
		connID, err := transport.Connect(tunnelNet, addr)
		if err != nil {
			return nil, err
		}
		return newTunnelConn(transport, connID, lg, verbose)
	}
}

func tunnelNetwork(network string) (string, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return "tcp", nil
	case "udp", "udp4", "udp6":
		return "udp", nil
	default:
		return "", fmt.Errorf("tunneled dial: unsupported network %q", network)
	}
}
