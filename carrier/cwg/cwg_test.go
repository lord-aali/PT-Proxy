package cwg

import (
	"net"
	"testing"
	"time"

	"github.com/lord-aali/PT-Proxy/carrier/core"
)

func TestHandshake(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cfg := Config{EncKey: "test-enc-key-change-me", LogTag: "cwg-test"}
	go func() { _ = serve(conn, cfg) }()

	aead, err := newAEAD(cfg.EncKey)
	if err != nil {
		t.Fatal(err)
	}
	raddr := conn.LocalAddr().(*net.UDPAddr)
	client, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	link := &Link{
		conn:      client,
		remote:    raddr,
		aead:      aead,
		role:      roleClient,
		peerRole:  roleServer,
		connected: true,
	}
	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err := core.HandshakeClient(link); err != nil {
		t.Fatal(err)
	}
}
