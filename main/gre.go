package main

import (
	"strings"
	"time"

	"github.com/lord-aali/PT-Proxy/carrier/gre"
	"github.com/lord-aali/PT-Proxy/common/configuration"
	"github.com/lord-aali/PT-Proxy/common/ptlog"
)

func launchGREServer(c configuration.JsonServerConfigImpl, tag, target string, skipUDP bool) bool {
	lg := ptlog.PTLog{LogTag: tag}
	listen := strings.TrimSpace(c.Listen)
	if listen == "" {
		listen = "0.0.0.0"
	}
	cfg := gre.Config{
		Listen:      listen,
		Target:      target,
		EncKey:      dpiOrDefault(c.EncKey, carrierDefaultKey),
		GREKey:      c.GREKey,
		SkipUDP:     skipUDP,
		PadMax:      c.PadMax,
		JitterMax:   time.Duration(c.JitterMS) * time.Millisecond,
		LogTag:      tag,
		DNSUpstream: "1.1.1.1:53",
		DNSNetwork:  "udp",
	}
	go func() {
		if err := gre.RunServer(cfg); err != nil {
			lg.Error("gre server stopped:", err)
		}
	}()
	lg.Info("carrier gre server started (listen:", listen+")")
	return true
}

func launchGREClient(c configuration.JsonClientConfigImpl, tag, reverseAddr string, skipUDP bool) bool {
	lg := ptlog.PTLog{LogTag: tag}
	if strings.TrimSpace(c.Address) == "" {
		lg.Error("gre client requires address (peer ipv4)")
		return false
	}
	listen := dpiOrDefault(c.Listen, "127.0.0.1:1080")
	cfg := gre.Config{
		Listen:      listen,
		Address:     c.Address,
		EncKey:      dpiOrDefault(c.EncKey, carrierDefaultKey),
		GREKey:      c.GREKey,
		ReverseAddr: reverseAddr,
		SkipUDP:     skipUDP,
		PadMax:      c.PadMax,
		JitterMax:   time.Duration(c.JitterMS) * time.Millisecond,
		LogTag:      tag,
	}
	go func() {
		if err := gre.RunClient(cfg); err != nil {
			lg.Error("gre client stopped:", err)
		}
	}()
	return true
}
