package common

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// MaxChunkSize is the maximum size of a single encrypted chunk.
	MaxChunkSize = 64 * 1024

	// Protocol version
	Version = 1

	// MaxEncryptedFrame is the max accepted length-prefixed ciphertext size.
	MaxEncryptedFrame = 256 * 1024
)

// Message types
const (
	MsgConnect   = 0x01
	MsgData      = 0x02
	MsgClose     = 0x03
	MsgUDPAssoc  = 0x04
	MsgUDPPacket = 0x05
)

// Uplink modes (client).
const (
	UplinkPostAsync = "post-async"
	UplinkStream    = "stream"
)

// StreamHeader precedes each encrypted payload.
type StreamHeader struct {
	Version    uint8
	MsgType    uint8
	ConnID     uint32
	PayloadLen uint32
}

const StreamHeaderSize = 10

// BuildStreamHeader returns a 10-byte stream header.
func BuildStreamHeader(msgType uint8, connID uint32, payloadLen uint32) []byte {
	h := make([]byte, StreamHeaderSize)
	h[0] = Version
	h[1] = msgType
	binary.BigEndian.PutUint32(h[2:6], connID)
	binary.BigEndian.PutUint32(h[6:10], payloadLen)
	return h
}

// ParseStreamHeader parses a stream header from decrypted bytes.
func ParseStreamHeader(decrypted []byte) (StreamHeader, []byte, error) {
	var h StreamHeader
	if len(decrypted) < StreamHeaderSize {
		return h, nil, fmt.Errorf("payload too short for header")
	}
	h.Version = decrypted[0]
	h.MsgType = decrypted[1]
	h.ConnID = binary.BigEndian.Uint32(decrypted[2:6])
	h.PayloadLen = binary.BigEndian.Uint32(decrypted[6:10])
	return h, decrypted[StreamHeaderSize:], nil
}

// WriteStreamHeader writes a stream header.
func WriteStreamHeader(w io.Writer, msgType uint8, connID uint32, payloadLen uint32) error {
	_, err := w.Write(BuildStreamHeader(msgType, connID, payloadLen))
	return err
}

// ReadStreamHeader reads a stream header.
func ReadStreamHeader(r io.Reader) (StreamHeader, error) {
	buf := make([]byte, StreamHeaderSize)
	if _, err := io.ReadFull(r, buf); err != nil {
		return StreamHeader{}, err
	}
	h, _, err := ParseStreamHeader(buf)
	return h, err
}

// WriteLengthPrefixed writes a 4-byte big-endian length then data.
func WriteLengthPrefixed(w io.Writer, data []byte) error {
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))
	if _, err := w.Write(lenBuf); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// ReadLengthPrefixed reads a 4-byte length then that many bytes.
func ReadLengthPrefixed(r io.Reader) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf)
	if n == 0 || n > MaxEncryptedFrame {
		return nil, fmt.Errorf("invalid frame length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// ConnectRequest is sent when opening a new connection.
type ConnectRequest struct {
	Network string // "tcp" or "udp"
	Address string // "host:port"
}
