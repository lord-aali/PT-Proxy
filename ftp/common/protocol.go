// Package common — wire protocol, crypto, naming, and shared types.
package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	mrand "math/rand"
	"strings"
)

// ─── Frame types ──────────────────────────────────────────────────────────────

const (
	TypeData        byte = 0x01
	TypeOpen        byte = 0x02
	TypeClose       byte = 0x03
	TypeAck         byte = 0x04
	TypeHB          byte = 0x05
	TypeHBAck       byte = 0x06
	TypeUDPData     byte = 0x07
	TypeDNSReq      byte = 0x08
	TypeDNSResp     byte = 0x09
	TypeHello       byte = 0x0A
	TypeReverseBind byte = 0x0B
	TypeReverseOpen byte = 0x0C
)

const (
	frameHeaderSize = 13 // 4+1+4+4
	BatchMagic      = uint32(0xFAB1C0DE)
	MaxFrameData    = 32 * 1024
)

// ─── Frame ────────────────────────────────────────────────────────────────────

type Frame struct {
	ConnID uint32
	Type   byte
	Seq    uint32
	Data   []byte
}

func EncodeUDPData(addr string, payload []byte) []byte {
	ab := []byte(addr)
	out := make([]byte, 1+len(ab)+len(payload))
	out[0] = byte(len(ab))
	copy(out[1:], ab)
	copy(out[1+len(ab):], payload)
	return out
}

func DecodeUDPData(data []byte) (string, []byte, error) {
	if len(data) < 1 {
		return "", nil, fmt.Errorf("udp data too short")
	}
	al := int(data[0])
	if len(data) < 1+al {
		return "", nil, fmt.Errorf("udp addr truncated")
	}
	return string(data[1 : 1+al]), data[1+al:], nil
}

func (f *Frame) encode() []byte {
	out := make([]byte, frameHeaderSize+len(f.Data))
	binary.BigEndian.PutUint32(out[0:4], f.ConnID)
	out[4] = f.Type
	binary.BigEndian.PutUint32(out[5:9], f.Seq)
	binary.BigEndian.PutUint32(out[9:13], uint32(len(f.Data)))
	copy(out[13:], f.Data)
	return out
}

func decodeFrame(b []byte) (*Frame, error) {
	if len(b) < frameHeaderSize {
		return nil, fmt.Errorf("frame too short: %d", len(b))
	}
	f := &Frame{
		ConnID: binary.BigEndian.Uint32(b[0:4]),
		Type:   b[4],
		Seq:    binary.BigEndian.Uint32(b[5:9]),
	}
	dl := binary.BigEndian.Uint32(b[9:13])
	if int(dl) > len(b)-frameHeaderSize {
		return nil, fmt.Errorf("frame data truncated")
	}
	if dl > 0 {
		f.Data = make([]byte, dl)
		copy(f.Data, b[frameHeaderSize:frameHeaderSize+int(dl)])
	}
	return f, nil
}

// ─── Crypto ───────────────────────────────────────────────────────────────────

func DeriveKey(passphrase string) []byte {
	h := sha256.Sum256([]byte(passphrase))
	return h[:]
}

func Encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func Decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(ciphertext) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return gcm.Open(nil, ciphertext[:ns], ciphertext[ns:], nil)
}

// ─── Batch encode / decode ────────────────────────────────────────────────────

func EncodeBatch(frames []*Frame, key []byte) ([]byte, error) {
	plain := make([]byte, 8)
	binary.BigEndian.PutUint32(plain[0:4], BatchMagic)
	binary.BigEndian.PutUint32(plain[4:8], uint32(len(frames)))
	for _, f := range frames {
		enc := f.encode()
		lb := make([]byte, 4)
		binary.BigEndian.PutUint32(lb, uint32(len(enc)))
		plain = append(plain, lb...)
		plain = append(plain, enc...)
	}
	pad := make([]byte, mrand.Intn(513))
	rand.Read(pad) //nolint:errcheck
	plain = append(plain, pad...)
	return Encrypt(key, plain)
}

func DecodeBatch(blob, key []byte) ([]*Frame, error) {
	plain, err := Decrypt(key, blob)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	if len(plain) < 8 {
		return nil, fmt.Errorf("batch too short")
	}
	if binary.BigEndian.Uint32(plain[0:4]) != BatchMagic {
		return nil, fmt.Errorf("bad magic")
	}
	count := binary.BigEndian.Uint32(plain[4:8])
	pos := 8
	out := make([]*Frame, 0, count)
	for i := uint32(0); i < count; i++ {
		if pos+4 > len(plain) {
			return nil, fmt.Errorf("truncated at frame %d", i)
		}
		fl := int(binary.BigEndian.Uint32(plain[pos : pos+4]))
		pos += 4
		if pos+fl > len(plain) {
			return nil, fmt.Errorf("frame %d data overrun", i)
		}
		f, err := decodeFrame(plain[pos : pos+fl])
		if err != nil {
			return nil, err
		}
		out = append(out, f)
		pos += fl
	}
	return out, nil
}

// ─── Camouflage filenames ─────────────────────────────────────────────────────

var webExts = []string{
	".html", ".css", ".js", ".json", ".png", ".jpg", ".svg", ".webp",
	".woff2", ".woff", ".ttf", ".ico", ".xml", ".txt", ".map",
}

var webPrefixes = [][]string{
	{"index", "main", "app", "page", "home", "about", "contact", "shell"},
	{"style", "theme", "base", "reset", "layout", "grid", "util", "vars"},
	{"chunk", "vendor", "runtime", "polyfill", "bundle", "lib", "esm"},
	{"logo", "icon", "hero", "banner", "avatar", "thumb", "bg", "sprite"},
	{"data", "config", "manifest", "sitemap", "robots", "feed", "schema"},
}

func NewSessionToken() string {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck
	return fmt.Sprintf("%x", b)
}

func RandomWebName(dir byte, token string) string {
	group := webPrefixes[mrand.Intn(len(webPrefixes))]
	prefix := group[mrand.Intn(len(group))]
	ext := webExts[mrand.Intn(len(webExts))]
	suffix := make([]byte, 5)
	rand.Read(suffix) //nolint:errcheck
	return fmt.Sprintf("%c%s-%s-%x%s", dir, token, prefix, suffix, ext)
}

func IsUploadName(name string) bool { return len(name) > 0 && name[0] == 'u' }

func IsMyDownload(name, token string) bool {
	return len(name) > 1+len(token) && name[0] == 'd' && name[1:1+len(token)] == token
}

func TokenFromUpload(name string) (string, bool) {
	if len(name) < 2 || name[0] != 'u' {
		return "", false
	}
	rest := name[1:]
	dash := strings.Index(rest, "-")
	if dash < 0 {
		return "", false
	}
	return rest[:dash], true
}
