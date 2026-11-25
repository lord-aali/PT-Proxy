package client

import (
	"bytes"
	"testing"

	"github.com/lord-aali/PT-Proxy/dnstt/dns"
)

func TestQueryMTU(t *testing.T) {
	domain, err := dns.ParseName("t.example.com")
	if err != nil {
		t.Fatal(err)
	}
	max, err := QueryMTU(domain, 0)
	if err != nil {
		t.Fatal(err)
	}
	if max < minQueryMTU {
		t.Fatalf("max %d", max)
	}
	got, err := QueryMTU(domain, max)
	if err != nil || got != max {
		t.Fatalf("max accepted as %d, %v", got, err)
	}
	if _, err := QueryMTU(domain, max+1); err == nil {
		t.Fatal("oversized packet-size was accepted")
	}
	if _, err := QueryMTU(domain, minQueryMTU-1); err == nil {
		t.Fatal("undersized packet-size was accepted")
	}
}

func TestDNSNameCapacity(t *testing.T) {
	for domainLen := 0; domainLen < 255; domainLen++ {
		domain, err := dns.NewName(chunks(bytes.Repeat([]byte{'x'}, domainLen), 63))
		if err != nil {
			continue
		}
		capacity := dnsNameCapacity(domain)
		if capacity <= 0 {
			continue
		}
		prefix := []byte(base32Encoding.EncodeToString(bytes.Repeat([]byte{'y'}, capacity)))
		labels := append(chunks(prefix, 63), domain...)
		_, err = dns.NewName(labels)
		if err != nil {
			t.Errorf("length %v  capacity %v  %v", domainLen, capacity, err)
		}
	}
}
