package client

import (
	"net"
	"strings"
	"time"

	"github.com/lord-aali/PT-Proxy/common/configuration"
	"github.com/lord-aali/PT-Proxy/common/dualbind"
	"github.com/lord-aali/PT-Proxy/common/muxpipe"
	"github.com/lord-aali/PT-Proxy/common/ptlog"
	"gitlab.com/yawning/obfs4.git/transports"
	"gitlab.com/yawning/obfs4.git/transports/base"
	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
	"golang.org/x/net/proxy"
)

type Client struct {
	LogTag      string
	log         ptlog.PTLog
	ReverseAddr string
	SkipUDP     bool
}

func (c Client) Setup(config configuration.JsonClientConfigImpl) (launched bool, listeners []net.Listener) {
	c.log = ptlog.PTLog{LogTag: c.LogTag}
	transport := config.Type
	t := transports.Get(transport)
	if t == nil {
		c.log.Fatal("no such transport is supported")
	}
	f, err := t.ClientFactory(configuration.WorkingDirectory)
	if err != nil {
		c.log.Fatal(transport, "failed to get ClientFactory")
	}

	args, err := obfsDialArgs(f, config)
	if err != nil {
		c.log.Fatal("dial args:", err)
	}

	dial := func() (net.Conn, error) {
		return f.Dial("tcp", config.Address, proxy.Direct.Dial, args)
	}

	if c.ReverseAddr != "" {
		go c.runReverse(dial, config)
		c.log.InfoDelayed(time.Second, "Client reverse-tag", config.ReverseTag, "remote listen", config.Listen)
		launched = true
		return
	}

	listen := config.Listen
	if strings.TrimSpace(listen) == "" {
		listen = "127.0.0.1:1080"
	}
	ln, udp, bound, err := dualbind.Listen(listen)
	if err != nil {
		c.log.Fatal(err)
	}
	c.log.InfoDelayed(time.Second, "Client started listening", bound, "forward via", transport)
	listeners = append(listeners, ln)
	go c.runForward(dial, ln, udp)
	launched = true
	return
}

func (c Client) runForward(dial func() (net.Conn, error), ln net.Listener, udp *net.UDPConn) {
	for {
		raw, err := dial()
		if err != nil {
			c.log.Error("dial:", err)
			time.Sleep(2 * time.Second)
			continue
		}
		sess, err := muxpipe.OpenClient(raw)
		if err != nil {
			raw.Close()
			c.log.Error("mux:", err)
			time.Sleep(2 * time.Second)
			continue
		}
		muxpipe.RunForwardClient(sess, ln, udp)
		sess.Close()
		raw.Close()
		time.Sleep(time.Second)
	}
}

func (c Client) runReverse(dial func() (net.Conn, error), config configuration.JsonClientConfigImpl) {
	for {
		raw, err := dial()
		if err != nil {
			c.log.Error("dial:", err)
			time.Sleep(2 * time.Second)
			continue
		}
		sess, err := muxpipe.OpenClient(raw)
		if err != nil {
			raw.Close()
			c.log.Error("mux:", err)
			time.Sleep(2 * time.Second)
			continue
		}
		bound, err := muxpipe.RequestReverseBind(sess, config.Listen)
		if err != nil || bound == "" {
			c.log.Error("reverse bind failed:", err)
			sess.Close()
			raw.Close()
			time.Sleep(2 * time.Second)
			continue
		}
		c.log.Info("reverse published on", bound)
		muxpipe.RunReverseClient(sess, c.ReverseAddr, c.SkipUDP)
		sess.Close()
		raw.Close()
		time.Sleep(time.Second)
	}
}

func obfsDialArgs(f base.ClientFactory, config configuration.JsonClientConfigImpl) (interface{}, error) {
	ptArgs := make(map[string][]string)
	if config.Type == "obfs4" {
		ptArgs["cert"] = []string{config.Cert}
		ptArgs["iat-mode"] = []string{configuration.ObfsIatMode}
	}
	args := pt.Args(ptArgs)
	return f.ParseArgs(&args)
}
