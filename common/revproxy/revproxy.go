package revproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

type inbound struct {
	host  string
	https bool
}

type inboundKey struct{}

// New reverse-proxies to raw.
//
// The incoming path is appended to the backend path, so a request for /blog
// with backend https://example.com fetches https://example.com/blog.
// When the backend host is a domain name, the outbound Host header is that
// name and, for HTTPS, TLS uses it as the server name. An IP backend keeps
// the incoming Host header and the default server name.
func New(raw string) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("backend url: %w", err)
	}
	if target.Host == "" || (target.Scheme != "http" && target.Scheme != "https") {
		return nil, fmt.Errorf("backend url: need an http or https URL with a host")
	}
	named := net.ParseIP(target.Hostname()) == nil
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			if named {
				pr.Out.Host = target.Host
			} else {
				pr.Out.Host = pr.In.Host
			}
			pr.Out = pr.Out.WithContext(context.WithValue(pr.Out.Context(), inboundKey{}, inbound{
				host:  pr.In.Host,
				https: pr.In.TLS != nil,
			}))
		},
		ModifyResponse: func(res *http.Response) error {
			res.Header.Del("Strict-Transport-Security")
			res.Header.Del("Alt-Svc")
			rewriteRedirect(res, target)
			return nil
		},
	}
	if named && target.Scheme == "https" {
		proxy.Transport = transportWithSNI(target.Hostname())
	}
	return proxy, nil
}

func transportWithSNI(serverName string) *http.Transport {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig:   &tls.Config{ServerName: serverName},
		}
	}
	tr := base.Clone()
	cfg := tr.TLSClientConfig
	if cfg == nil {
		cfg = &tls.Config{}
	} else {
		cfg = cfg.Clone()
	}
	cfg.ServerName = serverName
	tr.TLSClientConfig = cfg
	return tr
}

func rewriteRedirect(res *http.Response, target *url.URL) {
	in, _ := res.Request.Context().Value(inboundKey{}).(inbound)
	if in.host == "" {
		return
	}
	for _, header := range []string{"Location", "Content-Location"} {
		loc := res.Header.Get(header)
		if loc == "" {
			continue
		}
		u, err := url.Parse(loc)
		if err != nil || !sameSite(u, target) {
			continue
		}
		if in.https {
			u.Scheme = "https"
		} else {
			u.Scheme = "http"
		}
		u.Host = in.host
		res.Header.Set(header, u.String())
	}
}

func sameSite(loc, target *url.URL) bool {
	if loc.Host == "" || !strings.EqualFold(loc.Hostname(), target.Hostname()) {
		return false
	}
	if loc.Scheme == "" {
		return true
	}
	return loc.Scheme == "http" || loc.Scheme == "https"
}
