package webrtc

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestSignalEndpoint(t *testing.T) {
	u, err := signalEndpoint("127.0.0.1:8443")
	if err != nil || u != "http://127.0.0.1:8443/webrtc" {
		t.Fatalf("%s %v", u, err)
	}
	u, err = signalEndpoint("http://127.0.0.1:8443/webrtc")
	if err != nil || u != "http://127.0.0.1:8443/webrtc" {
		t.Fatalf("%s %v", u, err)
	}
}

func TestCoverRedirect(t *testing.T) {
	h := newCover("https://example.com/", "", nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "https://example.com/" {
		t.Fatalf("status %d loc %q", rr.Code, rr.Header().Get("Location"))
	}
}

func TestCoverServeDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("hello-cover"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := newCover("", dir, nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || rr.Body.String() != "hello-cover" {
		t.Fatalf("status %d body %q", rr.Code, rr.Body.String())
	}
}

func TestCoverDefaultPage(t *testing.T) {
	h := newCover("", "", nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || rr.Body.Len() == 0 {
		t.Fatalf("status %d body %q", rr.Code, rr.Body.String())
	}
}
