package server

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/lord-aali/PT-Proxy/ftp/common"
)

// Payload that arrives before Open must still be written to the dialed target.
func TestDataBeforeOpenIsWritten(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4)
		_, _ = io.ReadFull(c, buf)
		got <- append([]byte(nil), buf...)
	}()

	token := "early"
	cfgTarget = ln.Addr().String()
	defer tcpRemoveAll(token)

	processFrame(token, &common.Frame{ConnID: 7, Type: common.TypeData, Data: []byte("ping")})
	if _, err := tcpDial(token, 7, "127.0.0.1:9"); err != nil {
		t.Fatal(err)
	}

	select {
	case b := <-got:
		if string(b) != "ping" {
			t.Fatalf("got %q", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("target never received bytes sent before dial")
	}
}
