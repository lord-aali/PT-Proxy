package moq

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/Eyevinn/moqtransport/quicmoq"
	"github.com/lord-aali/PT-Proxy/carrier/core"
	"github.com/quic-go/quic-go"
)

func TestHandshake(t *testing.T) {
	ln, err := listenQUIC("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cfg := Config{EncKey: "test-enc-key-change-me", LogTag: "moq-test"}
	go func() { _ = serveListener(ln, cfg) }()

	enc, err := core.NewEncryptor([]byte(cfg.EncKey))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{alpn},
	}, quicConfig())
	if err != nil {
		t.Fatal(err)
	}
	closeConn := closeOnce(conn)
	defer closeConn()
	link, err := attach(ctx, quicmoq.NewClient(conn), trackUp, trackDown, enc, cfg, closeConn)
	if err != nil {
		t.Fatal(err)
	}
	defer link.Close()
	link.readWait = 10 * time.Second
	if err := core.HandshakeClient(link); err != nil {
		t.Fatal(err)
	}
}

func TestParseAddr(t *testing.T) {
	u, err := parseAddr("moq://127.0.0.1:4433")
	if err != nil || u != "127.0.0.1:4433" {
		t.Fatalf("%s %v", u, err)
	}
	if _, err := parseAddr("localhost"); err == nil {
		t.Fatal("expected error")
	}
}
