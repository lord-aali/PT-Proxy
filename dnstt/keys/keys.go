// Package keys derives the Noise static key and the name cipher key from the
// shared enc-key string. The two digests are separate so one string is not
// used as two different keys.
package keys

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/poly1305"
)

const (
	// NonceSize is the random nonce stored with each encrypted blob.
	// It is placed in the last 8 bytes of the 12-byte ChaCha20 nonce.
	NonceSize = 8
	// TagSize is the truncated Poly1305 tag. Four bytes reject a rewritten
	// packet. The other twelve bytes of the tag are not sent.
	TagSize = 4
	// Overhead is the nonce plus the truncated tag on each query blob and answer.
	Overhead = NonceSize + TagSize
)

// NoisePrivkey is the Noise_NK static private key for encKey.
func NoisePrivkey(encKey string) []byte {
	sum := sha256.Sum256([]byte(encKey))
	out := make([]byte, len(sum))
	copy(out, sum[:])
	return out
}

// QNameKey is the ChaCha20 key for query names and answers.
func QNameKey(encKey string) []byte {
	h := sha256.New()
	h.Write([]byte("ptproxy-dns-qname\x00"))
	h.Write([]byte(encKey))
	return h.Sum(nil)
}

// Seal encrypts plaintext and returns nonce || ciphertext || truncated tag.
func Seal(key, plaintext []byte) ([]byte, error) {
	var nonce [NonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}
	return seal(key, nonce[:], plaintext)
}

// Open decrypts a blob produced by Seal.
func Open(key, blob []byte) ([]byte, error) {
	if len(key) != chacha20.KeySize {
		return nil, fmt.Errorf("bad key length")
	}
	if len(blob) < Overhead {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := blob[:NonceSize]
	ciphertext := blob[NonceSize : len(blob)-TagSize]
	tag := blob[len(blob)-TagSize:]

	s, polyKey, err := newStream(key, nonce)
	if err != nil {
		return nil, err
	}
	mac := polyTag(&polyKey, ciphertext)
	if subtle.ConstantTimeCompare(tag, mac[:TagSize]) != 1 {
		return nil, fmt.Errorf("chacha20poly1305: message authentication failed")
	}
	s.SetCounter(1)
	plain := make([]byte, len(ciphertext))
	s.XORKeyStream(plain, ciphertext)
	return plain, nil
}

func seal(key, nonce, plaintext []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("bad nonce length")
	}
	s, polyKey, err := newStream(key, nonce)
	if err != nil {
		return nil, err
	}
	out := make([]byte, NonceSize+len(plaintext)+TagSize)
	copy(out, nonce)
	ciphertext := out[NonceSize : NonceSize+len(plaintext)]
	s.SetCounter(1)
	s.XORKeyStream(ciphertext, plaintext)
	mac := polyTag(&polyKey, ciphertext)
	copy(out[NonceSize+len(plaintext):], mac[:TagSize])
	return out, nil
}

// newStream returns a ChaCha20 stream positioned at counter 0 and the
// Poly1305 one-time key taken from that first block.
func newStream(key, nonce8 []byte) (*chacha20.Cipher, [32]byte, error) {
	var polyKey [32]byte
	if len(key) != chacha20.KeySize {
		return nil, polyKey, fmt.Errorf("bad key length")
	}
	var nonce [chacha20.NonceSize]byte
	copy(nonce[4:], nonce8)
	s, err := chacha20.NewUnauthenticatedCipher(key, nonce[:])
	if err != nil {
		return nil, polyKey, err
	}
	s.XORKeyStream(polyKey[:], polyKey[:])
	return s, polyKey, nil
}

// polyTag is the RFC 8439 ChaCha20-Poly1305 tag for empty additional data.
func polyTag(key *[32]byte, ciphertext []byte) [16]byte {
	p := poly1305.New(key)
	writePad16(p, ciphertext)
	var buf [8]byte
	p.Write(buf[:]) // additional-data length is 0
	binary.LittleEndian.PutUint64(buf[:], uint64(len(ciphertext)))
	p.Write(buf[:])
	var out [16]byte
	p.Sum(out[:0])
	return out
}

func writePad16(p *poly1305.MAC, b []byte) {
	p.Write(b)
	if rem := len(b) % 16; rem != 0 {
		var buf [16]byte
		p.Write(buf[:16-rem])
	}
}
