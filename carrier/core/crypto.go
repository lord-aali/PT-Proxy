package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	NonceSize = 12
	TagSize   = 16
)

type Encryptor struct {
	aead cipher.AEAD
}

func NewEncryptor(key []byte) (*Encryptor, error) {
	hash := sha256.Sum256(key)
	return NewEncryptorRaw(hash[:])
}

// NewEncryptorRaw uses key as AES-256 material (must be 32 bytes).
func NewEncryptorRaw(key []byte) (*Encryptor, error) {
	if len(key) != 32 {
		hash := sha256.Sum256(key)
		key = hash[:]
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Encryptor{aead: aead}, nil
}

// NewChaChaEncryptor builds a ChaCha20-Poly1305 encryptor (12-byte nonce,
// 16-byte tag — same wire layout as the AES-GCM Encryptor). Key is hashed to
// 32 bytes if it is not already that length.
func NewChaChaEncryptor(key []byte) (*Encryptor, error) {
	if len(key) != chacha20poly1305.KeySize {
		hash := sha256.Sum256(key)
		key = hash[:]
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &Encryptor{aead: aead}, nil
}

func (e *Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return append(nonce, e.aead.Seal(nil, nonce, plaintext, nil)...), nil
}

func (e *Encryptor) Decrypt(data []byte) ([]byte, error) {
	if len(data) < NonceSize+TagSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return e.aead.Open(nil, data[:NonceSize], data[NonceSize:], nil)
}
