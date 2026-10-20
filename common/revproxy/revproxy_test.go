package revproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestNamedBackendHostSNIAndPath(t *testing.T) {
	p, err := New("https://meet.jit.si")
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := p.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil || tr.TLSClientConfig.ServerName != "meet.jit.si" {
		t.Fatalf("sni transport: %#v", p.Transport)
	}
	var got *http.Request
	p.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		got = r.Clone(r.Context())
		h := make(http.Header)
		h.Set("Location", "https://meet.jit.si/blog?x=1")
		h.Set("Strict-Transport-Security", "max-age=60")
		h.Set("Alt-Svc", `h3=":443"`)
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     h,
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    r,
		}, nil
	})
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8443/blog?x=1", nil)
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)
	if got == nil {
		t.Fatal("no outbound request")
	}
	if got.Host != "meet.jit.si" {
		t.Fatalf("host %q", got.Host)
	}
	if got.URL.Scheme != "https" || got.URL.Host != "meet.jit.si" || got.URL.Path != "/blog" || got.URL.RawQuery != "x=1" {
		t.Fatalf("url %s", got.URL)
	}
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "http://127.0.0.1:8443/blog?x=1" {
		t.Fatalf("status %d location %q", rr.Code, rr.Header().Get("Location"))
	}
	if rr.Header().Get("Strict-Transport-Security") != "" || rr.Header().Get("Alt-Svc") != "" {
		t.Fatalf("hsts %q alt-svc %q", rr.Header().Get("Strict-Transport-Security"), rr.Header().Get("Alt-Svc"))
	}
}

func TestIPBackendKeepsHost(t *testing.T) {
	p, err := New("http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	if p.Transport != nil {
		t.Fatal("ip backend should keep the default transport")
	}
	var got *http.Request
	p.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		got = r.Clone(r.Context())
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("ok")),
			Request:    r,
		}, nil
	})
	req := httptest.NewRequest(http.MethodGet, "http://10.1.2.3:8443/blog", nil)
	req.Host = "10.1.2.3:8443"
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)
	if got.Host != "10.1.2.3:8443" {
		t.Fatalf("host %q", got.Host)
	}
	if got.URL.Host != "127.0.0.1:8080" || got.URL.Path != "/blog" {
		t.Fatalf("url %s", got.URL)
	}
}
