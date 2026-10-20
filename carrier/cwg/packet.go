package cwg

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	headerLen  = 16
	marker     = 0xC7
	classData  = 0x93
	roleClient = 0x01
	roleServer = 0x02
)

func newAEAD(key string) (cipher.AEAD, error) {
	sum := sha256.Sum256([]byte(key))
	return chacha20poly1305.New(sum[:])
}

// seal wraps one plaintext in a datagram that is not a WireGuard message.
// The first byte is never a WireGuard type (1, 2, 3, or 4), there is no mac1
// or mac2 trailer, and the length is not 64, 92, or 148 and not a multiple of 16.
func seal(aead cipher.AEAD, role byte, counter uint64, plain []byte) ([]byte, error) {
	if counter == 0 {
		return nil, fmt.Errorf("cwg counter")
	}
	var hdr [headerLen]byte
	hdr[0] = marker
	hdr[1] = classData
	hdr[2] = role
	binary.BigEndian.PutUint64(hdr[4:12], counter)
	if _, err := io.ReadFull(rand.Reader, hdr[12:16]); err != nil {
		return nil, err
	}
	var nonce [chacha20poly1305.NonceSize]byte
	nonce[0] = role
	binary.BigEndian.PutUint64(nonce[4:], counter)
	ct := aead.Seal(nil, nonce[:], plain, hdr[:])
	out := make([]byte, headerLen+len(ct))
	copy(out, hdr[:])
	copy(out[headerLen:], ct)
	return out, nil
}

func open(aead cipher.AEAD, expectRole byte, packet []byte) (plain []byte, counter uint64, err error) {
	if len(packet) < headerLen+chacha20poly1305.Overhead {
		return nil, 0, fmt.Errorf("cwg short")
	}
	if packet[0] != marker || packet[1] != classData || packet[2] != expectRole {
		return nil, 0, fmt.Errorf("cwg header")
	}
	counter = binary.BigEndian.Uint64(packet[4:12])
	if counter == 0 {
		return nil, 0, fmt.Errorf("cwg counter")
	}
	var nonce [chacha20poly1305.NonceSize]byte
	nonce[0] = expectRole
	binary.BigEndian.PutUint64(nonce[4:], counter)
	plain, err = aead.Open(nil, nonce[:], packet[headerLen:], packet[:headerLen])
	if err != nil {
		return nil, 0, err
	}
	return plain, counter, nil
}

// choosePad picks inner padding so the datagram misses WireGuard's fixed
// handshake sizes and the 16-byte alignment of WireGuard transport data.
func choosePad(dataLen, padMax int) int {
	pad := 0
	if padMax > 0 {
		pad = int(randomN(padMax + 1))
	}
	for pad < 255 {
		n := headerLen + 7 + dataLen + pad + chacha20poly1305.Overhead
		if n != 64 && n != 92 && n != 148 && n%16 != 0 {
			return pad
		}
		pad++
	}
	return pad
}

func randomN(n int) uint32 {
	if n <= 1 {
		return 0
	}
	var b [4]byte
	_, _ = io.ReadFull(rand.Reader, b[:])
	return binary.BigEndian.Uint32(b[:]) % uint32(n)
}

// replay drops duplicate and too-old counters. A 64-packet window allows reordering.
type replay struct {
	max  uint64
	bits uint64
}

func (r *replay) accept(c uint64) bool {
	if c == 0 {
		return false
	}
	if r.max == 0 {
		r.max = c
		r.bits = 1
		return true
	}
	if c > r.max {
		shift := c - r.max
		if shift >= 64 {
			r.bits = 1
		} else {
			r.bits = (r.bits << shift) | 1
		}
		r.max = c
		return true
	}
	delta := r.max - c
	if delta >= 64 || r.bits&(1<<delta) != 0 {
		return false
	}
	r.bits |= 1 << delta
	return true
}
