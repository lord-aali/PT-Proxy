package keys

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestSealMatchesTruncatedAEAD(t *testing.T) {
	key := QNameKey("shared-secret")
	plain := []byte("supercalifragilisticexpialidocious")
	var nonce [NonceSize]byte
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	got, err := seal(key, nonce[:], plain)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(plain)+Overhead {
		t.Fatalf("len %d", len(got))
	}

	var nonce12 [chacha20poly1305.NonceSize]byte
	copy(nonce12[4:], nonce[:])
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatal(err)
	}
	full := aead.Seal(nil, nonce12[:], plain, nil)
	if !bytes.Equal(got[NonceSize:len(got)-TagSize], full[:len(plain)]) {
		t.Fatal("ciphertext differs from ChaCha20-Poly1305")
	}
	if !bytes.Equal(got[len(got)-TagSize:], full[len(plain):len(plain)+TagSize]) {
		t.Fatal("tag is not the Poly1305 prefix")
	}

	opened, err := Open(key, got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plain) {
		t.Fatalf("open %q", opened)
	}
}

func TestOpenRejectsTamper(t *testing.T) {
	key := QNameKey("shared-secret")
	blob, err := Seal(key, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	blob[NonceSize] ^= 1
	if _, err := Open(key, blob); err == nil {
		t.Fatal("flipped ciphertext was accepted")
	}
	blob, err = Seal(key, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	blob[len(blob)-1] ^= 1
	if _, err := Open(key, blob); err == nil {
		t.Fatal("flipped tag was accepted")
	}
	if _, err := Open(QNameKey("other"), blob); err == nil {
		t.Fatal("other key was accepted")
	}
}
