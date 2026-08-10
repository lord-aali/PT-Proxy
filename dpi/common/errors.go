package common

import "errors"

var (
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
	ErrInvalidPayload    = errors.New("invalid payload")
	ErrConnectionClosed  = errors.New("connection closed")
)
