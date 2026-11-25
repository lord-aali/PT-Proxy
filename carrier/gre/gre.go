package gre

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lord-aali/PT-Proxy/carrier/core"
	"github.com/lord-aali/PT-Proxy/common/ptlog"
)

const (
	netGRE         = "ip4:47"
	defaultFouPort = "4754" // GRE-in-UDP when raw protocol 47 is blocked
)

type Config struct {
	Listen      string
	Address     string
	Target      string
	EncKey      string
	GREKey      string
	ReverseAddr string
	SkipUDP     bool
	PadMax      int
	JitterMax   time.Duration
	LogTag      string
	DNSNetwork  string
	DNSUpstream string
}

func ParseKey(s string) (uint32, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 1, nil
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("gre-key: %w", err)
	}
	return uint32(n), nil
}

func hostOnly(s string) string {
	s = strings.TrimSpace(s)
	if host, _, err := net.SplitHostPort(s); err == nil {
		return host
	}
	return s
}

func peerIP(address string) (string, error) {
	host := hostOnly(address)
	if host == "" {
		return "", fmt.Errorf("gre address required")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil {
			return "", fmt.Errorf("gre requires an ipv4 peer")
		}
		return ip.To4().String(), nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	return "", fmt.Errorf("no ipv4 for %s", host)
}

func RunServer(cfg Config) error {
	lg := ptlog.PTLog{LogTag: cfg.LogTag}
	key, err := ParseKey(cfg.GREKey)
	if err != nil {
		return err
	}
	enc, err := core.NewEncryptor([]byte(cfg.EncKey))
	if err != nil {
		return err
	}
	pc, mode, err := listenOuter(cfg.Listen)
	if err != nil {
		return err
	}
	defer pc.Close()
	lg.Info("carrier gre server", mode, "key", key)

	type sess struct {
		inbox chan []byte
	}
	sessions := map[string]*sess{}
	var mu sync.Mutex
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		p, err := Decode(Body(buf[:n]))
		if err != nil || !p.HasKey || p.Key != key || len(p.Payload) == 0 {
			continue
		}
		if p.HasSeq && p.Seq%2 == 0 {
			continue // echo of a packet this server sent
		}
		ct := append([]byte(nil), p.Payload...)
		id := from.String()
		mu.Lock()
		s, ok := sessions[id]
		if !ok {
			inbox := make(chan []byte, 128)
			s = &sess{inbox: inbox}
			sessions[id] = s
			link := NewLink(pc, from, enc, key, cfg.PadMax, cfg.JitterMax, false, false)
			link.role = roleServer
			link.inbox = inbox
			go func(k string, lk *Link) {
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
			}(id, link)
		}
		select {
		case s.inbox <- ct:
		default:
		}
		mu.Unlock()
	}
}

func RunClient(cfg Config) error {
	lg := ptlog.PTLog{LogTag: cfg.LogTag}
	key, err := ParseKey(cfg.GREKey)
	if err != nil {
		return err
	}
	enc, err := core.NewEncryptor([]byte(cfg.EncKey))
	if err != nil {
		return err
	}
	for {
		c, mode, err := dialOuter(cfg.Address)
		if err != nil {
			lg.Error("dial gre:", err)
			time.Sleep(time.Second)
			continue
		}
		lg.Info("carrier gre client", mode)
		pc, ok := c.(net.PacketConn)
		if !ok {
			c.Close()
			return fmt.Errorf("gre dial: not a packet conn")
		}
		link := NewLink(pc, nil, enc, key, cfg.PadMax, cfg.JitterMax, true, true)
		link.role = roleClient
		link.readWait = 3 * time.Second
		if err := core.HandshakeClient(link); err != nil {
			lg.Error("handshake:", err)
			_ = link.Close()
			time.Sleep(time.Second)
			continue
		}
		link.readWait = 5 * time.Minute
		sess := core.NewClientSession(link, cfg.ReverseAddr)
		if cfg.ReverseAddr != "" {
			err = core.RunClientSocks(sess, core.SocksConfig{
				Listen:      cfg.Listen,
				ReverseAddr: cfg.ReverseAddr,
				SkipUDP:     cfg.SkipUDP,
				LogTag:      cfg.LogTag,
			})
		} else {
			err = core.RunClientForward(sess, cfg.Listen, "", cfg.SkipUDP, cfg.LogTag, "gre", cfg.Address)
		}
		_ = sess.Close()
		if err != nil {
			lg.Error("client:", err)
		}
		time.Sleep(time.Second)
	}
}

// listenOuter opens IP protocol 47. If the OS denies raw sockets, or listen
// includes a UDP port, it uses GRE-in-UDP (GRE header inside a UDP datagram).
func listenOuter(listen string) (net.PacketConn, string, error) {
	host, port, hasPort := splitHostPort(listen)
	if host == "" {
		host = "0.0.0.0"
	}
	if hasPort {
		pc, err := net.ListenPacket("udp", net.JoinHostPort(host, port))
		if err != nil {
			return nil, "", err
		}
		return pc, "GRE-in-UDP " + pc.LocalAddr().String(), nil
	}
	pc, err := net.ListenPacket(netGRE, host)
	if err == nil {
		return pc, "raw proto 47 on " + host, nil
	}
	rawErr := err
	udpAddr := net.JoinHostPort(host, defaultFouPort)
	pc, err = net.ListenPacket("udp", udpAddr)
	if err != nil {
		return nil, "", fmt.Errorf("raw GRE: %v; GRE-in-UDP: %w", rawErr, err)
	}
	return pc, "GRE-in-UDP " + pc.LocalAddr().String() + " (raw proto 47 denied)", nil
}

func dialOuter(address string) (net.Conn, string, error) {
	host, port, hasPort := splitHostPort(address)
	peer, err := peerIP(host)
	if err != nil {
		return nil, "", err
	}
	if hasPort {
		c, err := net.Dial("udp", net.JoinHostPort(peer, port))
		if err != nil {
			return nil, "", err
		}
		return c, "GRE-in-UDP " + net.JoinHostPort(peer, port), nil
	}
	c, err := net.Dial(netGRE, peer)
	if err == nil {
		return c, "raw proto 47 to " + peer, nil
	}
	rawErr := err
	dst := net.JoinHostPort(peer, defaultFouPort)
	c, err = net.Dial("udp", dst)
	if err != nil {
		return nil, "", fmt.Errorf("raw GRE: %v; GRE-in-UDP: %w", rawErr, err)
	}
	return c, "GRE-in-UDP " + dst + " (raw proto 47 denied)", nil
}

func splitHostPort(s string) (host, port string, hasPort bool) {
	s = strings.TrimSpace(s)
	if h, p, err := net.SplitHostPort(s); err == nil && p != "" {
		return h, p, true
	}
	return s, "", false
}
