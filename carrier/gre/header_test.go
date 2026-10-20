package gre

import (
	"bytes"
	"testing"
)

func TestGRERoundTrip(t *testing.T) {
	payload := []byte("encrypted-frame")
	pkt := Encode(42, 7, payload)
	if pkt[0] != 0x30 || pkt[1] != 0x00 {
		t.Fatalf("flags %x %x", pkt[0], pkt[1])
	}
	// Protocol type IPv4, the usual GRE tunnel value.
	if pkt[2] != 0x08 || pkt[3] != 0x00 {
		t.Fatalf("proto %x %x", pkt[2], pkt[3])
	}
	got, err := Decode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if !got.HasKey || got.Key != 42 || !got.HasSeq || got.Seq != 7 {
		t.Fatalf("header %+v", got)
	}
	if !bytes.Equal(got.Payload, payload) {
		t.Fatalf("payload %q", got.Payload)
	}
}

func TestStripIPv4Header(t *testing.T) {
	gre := Encode(1, 1, []byte("x"))
	ip := make([]byte, 20+len(gre))
	ip[0] = 0x45
	ip[9] = 47
	copy(ip[20:], gre)
	body := Body(ip)
	got, err := Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Payload) != "x" || got.Key != 1 {
		t.Fatalf("%+v", got)
	}
	if !bytes.Equal(Body(gre), gre) {
		t.Fatal("plain gre was stripped")
	}
}

func TestParseKeyDefault(t *testing.T) {
	k, err := ParseKey("")
	if err != nil || k != 1 {
		t.Fatalf("%d %v", k, err)
	}
	k, err = ParseKey("99")
	if err != nil || k != 99 {
		t.Fatalf("%d %v", k, err)
	}
}
