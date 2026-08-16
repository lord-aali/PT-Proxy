package service

import (
	"fmt"
	"net"
	"strings"
	"sync"
)

// Entry is a named local service (socks, http, or external dial address).
type Entry struct {
	Tag     string
	Kind    string // socks, http, external
	Addr    string // host:port
	SkipUDP bool   // http CONNECT is TCP-only
}

var (
	mu      sync.RWMutex
	byTag   = map[string]*Entry{}
	counter int
)

func Register(e Entry) error {
	e.Tag = strings.TrimSpace(e.Tag)
	e.Addr = strings.TrimSpace(e.Addr)
	if e.Addr == "" {
		return fmt.Errorf("service %s: empty address", e.Kind)
	}
	if e.Tag == "" {
		e.Tag = AutoTag(e.Kind, e.Addr)
	}
	mu.Lock()
	defer mu.Unlock()
	if _, exists := byTag[e.Tag]; exists {
		return fmt.Errorf("duplicate tag %q", e.Tag)
	}
	cp := e
	byTag[e.Tag] = &cp
	return nil
}

func Lookup(tag string) (*Entry, bool) {
	mu.RLock()
	defer mu.RUnlock()
	e, ok := byTag[strings.TrimSpace(tag)]
	return e, ok
}

func AutoTag(kind, listen string) string {
	if _, port, err := net.SplitHostPort(strings.TrimSpace(listen)); err == nil && port != "" && port != "0" {
		return kind + "-" + port
	}
	mu.Lock()
	counter++
	n := counter
	mu.Unlock()
	return kind + "-" + fmt.Sprintf("%d", n)
}

func ListenPort(listen string) string {
	if listen == "" {
		return ""
	}
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return ""
	}
	return port
}
