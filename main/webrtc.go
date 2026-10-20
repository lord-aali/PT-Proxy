package main

import (
	"strings"
	"time"

	carrierwebrtc "github.com/lord-aali/PT-Proxy/carrier/webrtc"
	"github.com/lord-aali/PT-Proxy/common/configuration"
	"github.com/lord-aali/PT-Proxy/common/ptlog"
)

func launchWebRTCServer(c configuration.JsonServerConfigImpl, tag, target string, skipUDP bool) bool {
	lg := ptlog.PTLog{LogTag: tag}
	listen := strings.TrimSpace(c.Listen)
	if listen == "" {
		listen = "0.0.0.0:8443"
	}
	cfg := carrierwebrtc.Config{
		Listen:      listen,
		Target:      target,
		EncKey:      dpiOrDefault(c.EncKey, carrierDefaultKey),
		SkipUDP:     skipUDP,
		PadMax:      c.PadMax,
		JitterMax:   time.Duration(c.JitterMS) * time.Millisecond,
		LogTag:      tag,
		DNSUpstream: "1.1.1.1:53",
		DNSNetwork:  "udp",
		STUN:        c.STUN,
		PublicIP:    c.PublicIP,
		Redirect:    c.Redirect,
		ServeDir:    c.ServeDir,
		Backend:     c.Backend,
	}
	go func() {
		if err := carrierwebrtc.RunServer(cfg); err != nil {
			lg.Error("webrtc server stopped:", err)
		}
	}()
	lg.Info("carrier webrtc server started (listen:", listen+")")
	return true
}

func launchWebRTCClient(c configuration.JsonClientConfigImpl, tag, reverseAddr string, skipUDP bool) bool {
	lg := ptlog.PTLog{LogTag: tag}
	if strings.TrimSpace(c.Address) == "" {
		lg.Error("webrtc client requires address (http://host:port)")
		return false
	}
	cfg := carrierwebrtc.Config{
		Listen:      dpiOrDefault(c.Listen, "127.0.0.1:1080"),
		Address:     c.Address,
		EncKey:      dpiOrDefault(c.EncKey, carrierDefaultKey),
		ReverseAddr: reverseAddr,
		SkipUDP:     skipUDP,
		PadMax:      c.PadMax,
		JitterMax:   time.Duration(c.JitterMS) * time.Millisecond,
		LogTag:      tag,
		STUN:        c.STUN,
	}
	go func() {
		if err := carrierwebrtc.RunClient(cfg); err != nil {
			lg.Error("webrtc client stopped:", err)
		}
	}()
	lg.Info("carrier webrtc client started (listen:", cfg.Listen, "address:", cfg.Address+")")
	return true
}
