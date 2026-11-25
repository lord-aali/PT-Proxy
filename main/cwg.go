package main

import (
	"strings"
	"time"

	carriercwg "github.com/lord-aali/PT-Proxy/carrier/cwg"
	"github.com/lord-aali/PT-Proxy/common/configuration"
	"github.com/lord-aali/PT-Proxy/common/ptlog"
)

func launchCWGServer(c configuration.JsonServerConfigImpl, tag, target string, skipUDP bool) bool {
	lg := ptlog.PTLog{LogTag: tag}
	listen := strings.TrimSpace(c.Listen)
	if listen == "" {
		listen = "0.0.0.0:4446"
	}
	cfg := carriercwg.Config{
		Listen:      listen,
		Target:      target,
		EncKey:      dpiOrDefault(c.EncKey, carrierDefaultKey),
		SkipUDP:     skipUDP,
		PadMax:      c.PadMax,
		JitterMax:   time.Duration(c.JitterMS) * time.Millisecond,
		LogTag:      tag,
		DNSUpstream: "1.1.1.1:53",
		DNSNetwork:  "udp",
	}
	go func() {
		if err := carriercwg.RunServer(cfg); err != nil {
			lg.Error("cwg server stopped:", err)
		}
	}()
	lg.Info("carrier cwg server started (listen:", listen+")")
	return true
}

func launchCWGClient(c configuration.JsonClientConfigImpl, tag, reverseAddr string, skipUDP bool) bool {
	lg := ptlog.PTLog{LogTag: tag}
	if strings.TrimSpace(c.Address) == "" {
		lg.Error("cwg client requires address (host:port)")
		return false
	}
	cfg := carriercwg.Config{
		Listen:      dpiOrDefault(c.Listen, "127.0.0.1:1080"),
		Address:     c.Address,
		EncKey:      dpiOrDefault(c.EncKey, carrierDefaultKey),
		ReverseAddr: reverseAddr,
		SkipUDP:     skipUDP,
		PadMax:      c.PadMax,
		JitterMax:   time.Duration(c.JitterMS) * time.Millisecond,
		LogTag:      tag,
	}
	go func() {
		if err := carriercwg.RunClient(cfg); err != nil {
			lg.Error("cwg client stopped:", err)
		}
	}()
	return true
}
