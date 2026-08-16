package main

import (
	"strings"

	"github.com/lord-aali/PT-Proxy/common/configuration"
	"github.com/lord-aali/PT-Proxy/common/ptlog"
	"github.com/lord-aali/PT-Proxy/common/service"
	"github.com/lord-aali/PT-Proxy/proxy/httpproxy"
	"github.com/lord-aali/PT-Proxy/proxy/socks5"
)

func isServiceType(t string) bool {
	switch t {
	case "socks", "http", "external":
		return true
	default:
		return false
	}
}

func listenForTag(c configuration.JsonServerConfigImpl) string {
	if c.Type == "dpi" {
		if strings.TrimSpace(c.HttpsAddr) != "" {
			return c.HttpsAddr
		}
		return c.HttpAddr
	}
	return c.Listen
}

func startService(c configuration.JsonServerConfigImpl) (tag string, ok bool) {
	lg := ptlog.PTLog{LogTag: dpiOrDefault(c.TrimTag(), c.Type)}
	kind := c.Type
	addr := strings.TrimSpace(c.Listen)
	if kind == "socks" && addr == "" {
		addr = "127.0.0.1:0"
	}
	if kind == "http" && addr == "" {
		addr = "127.0.0.1:0"
	}
	if kind == "external" && addr == "" {
		lg.Error("external requires listen (host:port of the backend)")
		return "", false
	}

	skipUDP := kind == "http"
	bound := addr
	var err error
	switch kind {
	case "socks":
		bound, err = socks5.Serve(addr, c.User, c.Pass, dpiOrDefault(c.TrimTag(), "socks"))
		if err != nil {
			lg.Error("socks:", err)
			return "", false
		}
	case "http":
		bound, err = httpproxy.Serve(addr, dpiOrDefault(c.TrimTag(), "http"))
		if err != nil {
			lg.Error("http:", err)
			return "", false
		}
	case "external":
		bound = addr
	}
	tag = c.TrimTag()
	if tag == "" {
		tag = service.AutoTag(kind, bound)
	}
	if err := service.Register(service.Entry{Tag: tag, Kind: kind, Addr: bound, SkipUDP: skipUDP}); err != nil {
		lg.Error(err)
		return "", false
	}
	lg.Info(kind, "tag", tag, "addr", bound)
	return tag, true
}

func resolveTarget(tag string) (addr string, skipUDP bool, err error) {
	e, ok := service.Lookup(tag)
	if !ok {
		return "", false, errTag(tag)
	}
	return e.Addr, e.SkipUDP, nil
}

type tagError string

func (e tagError) Error() string { return "unknown target tag: " + string(e) }

func errTag(tag string) error { return tagError(tag) }
