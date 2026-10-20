package main

import (
	"strings"

	"github.com/lord-aali/PT-Proxy/carrier/tcpudp"
	"github.com/lord-aali/PT-Proxy/common/configuration"
	"github.com/lord-aali/PT-Proxy/common/ptlog"
)

const carrierDefaultKey = "change-me-please"

func launchCarrierServer(c configuration.JsonServerConfigImpl, tag, target string, skipUDP bool) bool {
	lg := ptlog.PTLog{LogTag: tag}
	listen := strings.TrimSpace(c.Listen)
	if listen == "" {
		if c.Type == "udp" {
			listen = "0.0.0.0:4444"
		} else {
			listen = "0.0.0.0:4443"
		}
	}
	cfg := tcpudp.Config{
		Listen:      listen,
		Target:      target,
		EncKey:      dpiOrDefault(c.EncKey, carrierDefaultKey),
		SkipUDP:     skipUDP,
		LogTag:      tag,
		DNSUpstream: "1.1.1.1:53",
		DNSNetwork:  "udp",
	}
	go func() {
		var err error
		if c.Type == "udp" {
			err = tcpudp.RunUDPServer(cfg)
		} else {
			err = tcpudp.RunTCPServer(cfg)
		}
		if err != nil {
			lg.Error("carrier server stopped:", err)
		}
	}()
	lg.Info("carrier", c.Type, "server started (listen:", cfg.Listen+")")
	return true
}

func launchCarrierClient(c configuration.JsonClientConfigImpl, tag, reverseAddr string, skipUDP bool) bool {
	lg := ptlog.PTLog{LogTag: tag}
	if strings.TrimSpace(c.Address) == "" {
		lg.Error("carrier client requires address")
		return false
	}
	listen := dpiOrDefault(c.Listen, "127.0.0.1:1080")
	cfg := tcpudp.Config{
		Listen:      listen,
		Address:     c.Address,
		EncKey:      dpiOrDefault(c.EncKey, carrierDefaultKey),
		ReverseAddr: reverseAddr,
		SkipUDP:     skipUDP,
		LogTag:      tag,
	}
	go func() {
		var err error
		if c.Type == "udp" {
			err = tcpudp.RunUDPClient(cfg)
		} else {
			err = tcpudp.RunTCPClient(cfg)
		}
		if err != nil {
			lg.Error("carrier client stopped:", err)
		}
	}()
	lg.Info("carrier", c.Type, "client started (listen:", cfg.Listen, "address:", cfg.Address+")")
	return true
}
