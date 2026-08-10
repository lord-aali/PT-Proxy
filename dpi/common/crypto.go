package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
)

const (
	NonceSize = 12
	TagSize   = 16
)

// Encryptor handles AES-GCM encryption/decryption with a shared key.
type Encryptor struct {
	aead cipher.AEAD
}

// NewEncryptor creates an encryptor from a key (any length, will be hashed to 32 bytes).
func NewEncryptor(key []byte) (*Encryptor, error) {
	hash := sha256.Sum256(key)
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Encryptor{aead: aead}, nil
}

// Encrypt encrypts plaintext and returns nonce||ciphertext.
func (e *Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := e.aead.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

// Decrypt decrypts nonce||ciphertext.
func (e *Encryptor) Decrypt(data []byte) ([]byte, error) {
	if len(data) < NonceSize+TagSize {
		return nil, ErrInvalidCiphertext
	}
	nonce := data[:NonceSize]
	ciphertext := data[NonceSize:]
	return e.aead.Open(nil, nonce, ciphertext, nil)
}

// EncryptStream encrypts data in chunks for streaming (each chunk is independently encrypted).
func (e *Encryptor) EncryptStream(data []byte) ([]byte, error) {
	return e.Encrypt(data)
}

// DecryptStream decrypts a stream chunk.
func (e *Encryptor) DecryptStream(data []byte) ([]byte, error) {
	return e.Decrypt(data)
}
