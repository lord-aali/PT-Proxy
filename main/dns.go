package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/lord-aali/PT-Proxy/common/configuration"
	"github.com/lord-aali/PT-Proxy/common/ptlog"
	dnsclient "github.com/lord-aali/PT-Proxy/dnstt/client"
	"github.com/lord-aali/PT-Proxy/dnstt/dns"
	dnsserver "github.com/lord-aali/PT-Proxy/dnstt/server"
)

func launchDNSServer(c configuration.JsonServerConfigImpl, tag, target string, skipUDP bool) bool {
	lg := ptlog.PTLog{LogTag: tag}
	if strings.TrimSpace(c.EncKey) == "" {
		lg.Error("dns server requires enc-key")
		return false
	}
	if strings.TrimSpace(c.Domain) == "" {
		lg.Error("dns server requires domain")
		return false
	}
	if target == "" {
		lg.Error("dns server requires target")
		return false
	}
	domain, err := dns.ParseName(c.Domain)
	if err != nil {
		lg.Error("dns server domain:", err)
		return false
	}
	listen := strings.TrimSpace(c.Listen)
	if listen == "" {
		listen = ":53"
	}
	_ = skipUDP
	cfg := dnsserver.Config{
		Listen:  listen,
		Domain:  domain,
		EncKey:  c.EncKey,
		Target:  target,
		UDPSize: c.MTU,
	}
	go func() {
		if err := dnsserver.Serve(context.Background(), cfg); err != nil {
			lg.Error("dns server stopped:", err)
		}
	}()
	lg.Info("dns server started (listen:", listen, "domain:", c.Domain+")")
	return true
}

func launchDNSClient(c configuration.JsonClientConfigImpl, tag, reverseAddr string, skipUDP bool) bool {
	lg := ptlog.PTLog{LogTag: tag}
	if reverseAddr != "" {
		lg.Error("dns client does not support reverse-tag")
		return false
	}
	_ = skipUDP
	if strings.TrimSpace(c.EncKey) == "" {
		lg.Error("dns client requires enc-key")
		return false
	}
	if strings.TrimSpace(c.Domain) == "" {
		lg.Error("dns client requires domain")
		return false
	}
	udp := strings.TrimSpace(c.UDP)
	direct := strings.TrimSpace(c.Direct)
	if udp != "" && direct != "" {
		lg.Error("dns client accepts only one of udp and direct")
		return false
	}
	remote := udp
	if remote == "" {
		remote = direct
	}
	if remote == "" {
		lg.Error("dns client requires udp or direct")
		return false
	}
	qtype, err := dns.ParseQType(c.QType)
	if err != nil {
		lg.Error("dns client qtype:", err)
		return false
	}
	domain, err := dns.ParseName(c.Domain)
	if err != nil {
		lg.Error("dns client domain:", err)
		return false
	}
	if _, err := dnsclient.QueryMTU(domain, c.PacketSize); err != nil {
		lg.Error("dns client packet-size:", err)
		return false
	}
	listen := strings.TrimSpace(c.Listen)
	if listen == "" {
		listen = "127.0.0.1:7000"
	}
	mode := "udp"
	if direct != "" {
		mode = "direct"
	}
	cfg := dnsclient.Config{
		Listen:     listen,
		Domain:     domain,
		EncKey:     c.EncKey,
		Remote:     remote,
		QType:      qtype,
		PacketSize: c.PacketSize,
		Ready: func(addr string) {
			lg.Info(fmt.Sprintf("Client started listening %s forward via DNS (%s, %s) to %s", addr, mode, dns.QTypeName(qtype), remote))
		},
	}
	go func() {
		if err := dnsclient.Serve(context.Background(), cfg); err != nil {
			lg.Error("dns client stopped:", err)
		}
	}()
	return true
}
