package main

import (
	"strings"
	"time"

	carriermoq "github.com/lord-aali/PT-Proxy/carrier/moq"
	"github.com/lord-aali/PT-Proxy/common/configuration"
	"github.com/lord-aali/PT-Proxy/common/ptlog"
)

func launchMoQServer(c configuration.JsonServerConfigImpl, tag, target string, skipUDP bool) bool {
	lg := ptlog.PTLog{LogTag: tag}
	listen := strings.TrimSpace(c.Listen)
	if listen == "" {
		listen = "0.0.0.0:4433"
	}
	cfg := carriermoq.Config{
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
		if err := carriermoq.RunServer(cfg); err != nil {
			lg.Error("moq server stopped:", err)
		}
	}()
	lg.Info("carrier moq server started (listen:", listen+")")
	return true
}

func launchMoQClient(c configuration.JsonClientConfigImpl, tag, reverseAddr string, skipUDP bool) bool {
	lg := ptlog.PTLog{LogTag: tag}
	if strings.TrimSpace(c.Address) == "" {
		lg.Error("moq client requires address (host:port)")
		return false
	}
	cfg := carriermoq.Config{
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
		if err := carriermoq.RunClient(cfg); err != nil {
			lg.Error("moq client stopped:", err)
		}
	}()
	return true
}
