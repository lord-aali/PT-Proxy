package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/lord-aali/PT-Proxy/common/configuration"
	"github.com/lord-aali/PT-Proxy/common/ptlog"
	DpiClient "github.com/lord-aali/PT-Proxy/dpi/client"
	DpiCommon "github.com/lord-aali/PT-Proxy/dpi/common"
	DpiServer "github.com/lord-aali/PT-Proxy/dpi/server"
)

const (
	dpiDefaultEncKey    = "default-encryption-key-change-me"
	dpiDefaultProtocol  = "auto"
	dpiDefaultUplink    = "post-async"
	dpiDefaultSocksAddr = "127.0.0.1:1080"
)

func dpiOrDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func launchDpiServer(c configuration.JsonServerConfigImpl, tag, target string, skipUDP bool) bool {
	lg := ptlog.PTLog{LogTag: tag}

	cfg := DpiServer.Config{
		HTTPAddr:      c.HttpAddr,
		HTTPSAddr:     c.HttpsAddr,
		TLSCertFile:   c.TlsCertFile,
		TLSKeyFile:    c.TlsKeyFile,
		ACMEEmail:     c.AcmeEmail,
		ACMEDomain:    c.AcmeDomain,
		SelfSigned:    c.SelfSigned,
		RedirectURL:   c.Redirect,
		EncryptionKey: []byte(dpiOrDefault(c.EncKey, dpiDefaultEncKey)),
		CertDir:       c.CertDir,
		Protocol:      dpiOrDefault(c.Protocol, dpiDefaultProtocol),
		LogTag:        tag,
		Target:        target,
		SkipUDP:       skipUDP,
	}

	if cfg.HTTPAddr == "" && cfg.HTTPSAddr == "" {
		lg.Error("dpi server requires an http and/or https listen address")
		return false
	}
	if cfg.HTTPSAddr != "" && !cfg.SelfSigned && cfg.ACMEEmail == "" && cfg.TLSCertFile == "" {
		lg.Error("dpi https requires tls-cert/tls-key, acme-email + acme-domain, or self-signed")
		return false
	}

	srv, err := DpiServer.NewServer(cfg)
	if err != nil {
		lg.Error("dpi server init failed:", err)
		return false
	}
	if err := srv.Run(); err != nil {
		lg.Error("dpi server run failed:", err)
		return false
	}
	lg.Info("dpi server started (http:", dpiOrDefault(cfg.HTTPAddr, "-"), "https:", dpiOrDefault(cfg.HTTPSAddr, "-")+")")
	return true
}

func launchDpiClient(c configuration.JsonClientConfigImpl, tag, reverseAddr string, skipUDP bool) bool {
	lg := ptlog.PTLog{LogTag: tag}

	if strings.TrimSpace(c.Address) == "" {
		lg.Error("dpi client requires a server address (URL)")
		return false
	}

	u, err := url.Parse(c.Address)
	if err != nil {
		lg.Error("dpi client invalid server URL:", err)
		return false
	}

	dialIP, err := resolveServerIP(u)
	if err != nil {
		lg.Error("dpi client resolve server IP failed:", err)
		return false
	}

	encryptor, err := DpiCommon.NewEncryptor([]byte(dpiOrDefault(c.EncKey, dpiDefaultEncKey)))
	if err != nil {
		lg.Error("dpi client encryptor failed:", err)
		return false
	}

	sniOverride := c.Sni
	if sniOverride == "" {
		sniOverride = u.Hostname()
	}

	tlsConfig := &tls.Config{
		ServerName:         sniOverride,
		InsecureSkipVerify: c.Insecure,
	}

	followRedirects := true
	if c.FollowRedirect != nil {
		followRedirects = *c.FollowRedirect
	}

	uplink := dpiOrDefault(c.Uplink, dpiDefaultUplink)
	if reverseAddr != "" && uplink != DpiCommon.UplinkStream {
		uplink = DpiCommon.UplinkStream
	}
	transport, err := DpiClient.NewTransport(DpiClient.TransportConfig{
		ServerURL:       c.Address,
		Encryptor:       encryptor,
		TLSConfig:       tlsConfig,
		FollowRedirects: followRedirects,
		FrontHost:       c.FrontHost,
		DialIP:          dialIP,
		Protocol:        dpiOrDefault(c.Protocol, dpiDefaultProtocol),
		Uplink:          uplink,
		LogTag:          tag,
	})
	if err != nil {
		lg.Error("dpi client transport failed:", err)
		return false
	}

	socksAddr := dpiOrDefault(c.Listen, dpiDefaultSocksAddr)
	proxy := DpiClient.NewProxyServer(DpiClient.ProxyConfig{
		Transport: transport,
		SOCKSAddr: socksAddr,
		Verbose:   c.Verbose,
		LogTag:    tag,
		SkipUDP:   skipUDP,
	})
	if reverseAddr != "" {
		if err := proxy.RunReverse(c.Listen, reverseAddr); err != nil {
			lg.Error("dpi reverse:", err)
			return false
		}
		lg.InfoDelayed(time.Second, "dpi reverse", c.Listen, "->", reverseAddr)
		return true
	}
	if err := proxy.RunTCP(); err != nil {
		lg.Error("dpi client listen failed:", err)
		return false
	}
	lg.InfoDelayed(time.Second, "Client started listening", socksAddr, "forward via dpi")
	return true
}

func resolveServerIP(u *url.URL) (string, error) {
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("server URL has no hostname")
	}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
		return ip.String(), nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("lookup %s: %w", host, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("lookup %s: no addresses", host)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	return ips[0].String(), nil
}
