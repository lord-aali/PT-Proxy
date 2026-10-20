package cwg

import (
	"encoding/binary"
	"testing"

	"github.com/lord-aali/PT-Proxy/carrier/core"
)

func TestPacketIsNotWireGuard(t *testing.T) {
	aead, err := newAEAD("test-enc-key-change-me")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := core.EncodeFrame(core.Frame{Type: core.TypeHello, Data: []byte{core.Version}})
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := seal(aead, roleClient, 1, plain)
	if err != nil {
		t.Fatal(err)
	}
	typ := binary.LittleEndian.Uint32(pkt[:4])
	if typ >= 1 && typ <= 4 {
		t.Fatalf("le type %d looks like wireguard", typ)
	}
	if len(pkt) == 64 || len(pkt) == 92 || len(pkt) == 148 || len(pkt)%16 == 0 {
		t.Fatalf("len %d matches a wireguard size", len(pkt))
	}
	if pkt[0] == 0x01 || pkt[0] == 0x02 || pkt[0] == 0x04 {
		t.Fatalf("marker %x", pkt[0])
	}
	got, counter, err := open(aead, roleClient, pkt)
	if err != nil || counter != 1 || string(got) != string(plain) {
		t.Fatalf("open %v counter %d", err, counter)
	}
	if _, _, err := open(aead, roleServer, pkt); err == nil {
		t.Fatal("peer role should not open")
	}
}

func TestReplayWindow(t *testing.T) {
	var w replay
	if !w.accept(1) || !w.accept(3) || !w.accept(2) {
		t.Fatal("reorder")
	}
	if w.accept(2) || w.accept(1) {
		t.Fatal("duplicate")
	}
	if !w.accept(80) {
		t.Fatal("advance")
	}
	if w.accept(1) {
		t.Fatal("too old")
	}
}

func TestChoosePadSkipsWireGuardSizes(t *testing.T) {
	for n := 0; n < 200; n++ {
		pad := choosePad(n, 0)
		total := headerLen + 7 + n + pad + 16
		if total == 64 || total == 92 || total == 148 || total%16 == 0 {
			t.Fatalf("data %d pad %d total %d", n, pad, total)
		}
	}
}
