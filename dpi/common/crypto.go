package common

import (
	carriercore "github.com/lord-aali/PT-Proxy/carrier/core"
)

const (
	NonceSize = carriercore.NonceSize
	TagSize   = carriercore.TagSize
)

// Encryptor wraps carrier/core AES-GCM (shared with tcp/udp and FTP).
type Encryptor struct {
	inner *carriercore.Encryptor
}

func NewEncryptor(key []byte) (*Encryptor, error) {
	inner, err := carriercore.NewEncryptor(key)
	if err != nil {
		return nil, err
	}
	return &Encryptor{inner: inner}, nil
}

func (e *Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	return e.inner.Encrypt(plaintext)
}

func (e *Encryptor) Decrypt(data []byte) ([]byte, error) {
	pt, err := e.inner.Decrypt(data)
	if err != nil {
		return nil, ErrInvalidCiphertext
	}
	return pt, nil
}

func (e *Encryptor) EncryptStream(data []byte) ([]byte, error) {
	return e.Encrypt(data)
}

func (e *Encryptor) DecryptStream(data []byte) ([]byte, error) {
	return e.Decrypt(data)
}
