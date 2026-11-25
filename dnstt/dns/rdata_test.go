package dns

import (
	"bytes"
	"testing"
)

func TestPackAddrRecordsRoundTrip(t *testing.T) {
	sealed := bytes.Repeat([]byte{0xab}, 30)
	for _, size := range []int{4, 16} {
		recs, err := PackAddrRecords(sealed, size)
		if err != nil {
			t.Fatal(err)
		}
		// A resolver is free to return address records in any order.
		if len(recs) > 1 {
			recs[0], recs[len(recs)-1] = recs[len(recs)-1], recs[0]
		}
		got, err := JoinAddrRecords(recs)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, sealed) {
			t.Fatalf("size %d: round trip mismatch", size)
		}
	}
}

func TestParseQType(t *testing.T) {
	txt, err := ParseQType("")
	if err != nil || txt != RRTypeTXT {
		t.Fatalf("empty: %d %v", txt, err)
	}
	aaaa, err := ParseQType("AAAA")
	if err != nil || aaaa != RRTypeAAAA {
		t.Fatalf("aaaa: %d %v", aaaa, err)
	}
	if _, err := ParseQType("mx"); err == nil {
		t.Fatal("mx should be rejected")
	}
}
