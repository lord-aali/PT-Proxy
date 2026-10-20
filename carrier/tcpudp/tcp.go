package tcpudp

import (
	"net"
	"time"

	"github.com/lord-aali/PT-Proxy/carrier/core"
	"github.com/lord-aali/PT-Proxy/common/ptlog"
)

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

func RunTCPServer(cfg Config) error {
	lg := ptlog.PTLog{LogTag: cfg.LogTag}
	enc, err := core.NewEncryptor([]byte(cfg.EncKey))
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	lg.Info("carrier tcp server listen", cfg.Listen)
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(conn net.Conn) {
			defer conn.Close()
			link := core.NewLink(conn, enc, cfg.PadMax, cfg.JitterMax)
			core.Serve(link, core.ServerConfig{
				Target:      cfg.Target,
				SkipUDP:     cfg.SkipUDP,
				DNSNetwork:  cfg.DNSNetwork,
				DNSUpstream: cfg.DNSUpstream,
			})
		}(c)
	}
}

func RunTCPClient(cfg Config) error {
	lg := ptlog.PTLog{LogTag: cfg.LogTag}
	enc, err := core.NewEncryptor([]byte(cfg.EncKey))
	if err != nil {
		return err
	}
	for {
		conn, err := net.DialTimeout("tcp", cfg.Address, 30*time.Second)
		if err != nil {
			lg.Error("dial:", err)
			time.Sleep(time.Second)
			continue
		}
		link := core.NewLink(conn, enc, cfg.PadMax, cfg.JitterMax)
		if err := core.HandshakeClient(link); err != nil {
			lg.Error("handshake:", err)
			conn.Close()
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
			// Raw dualbind like obfs/muxpipe: apps speak SOCKS to listen;
			// server dials target (socks/http/external).
			err = core.RunClientForward(sess, cfg.Listen, "", cfg.SkipUDP, cfg.LogTag)
		}
		_ = sess.Close()
		if err != nil {
			lg.Error("client:", err)
		}
		time.Sleep(time.Second)
	}
}
