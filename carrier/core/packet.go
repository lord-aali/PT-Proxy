package core

import (
	"math/rand"
	"sync"
	"time"
)

// PacketIO is a datagram transport: one Write is one packet, one Read is one packet.
type PacketIO interface {
	WritePacket([]byte) error
	ReadPacket() ([]byte, error)
	Close() error
}

// PacketLink is a FrameConn where each datagram carries exactly one encrypted
// frame (no length prefix). Used by datagram carriers (UDP, GRE, custom-WG).
type PacketLink struct {
	io     PacketIO
	enc    *Encryptor
	padMax int
	jitter time.Duration
	wmu    sync.Mutex
}

func NewPacketLink(io PacketIO, enc *Encryptor, padMax int, jitter time.Duration) *PacketLink {
	return &PacketLink{io: io, enc: enc, padMax: padMax, jitter: jitter}
}

func (l *PacketLink) Close() error { return l.io.Close() }

func (l *PacketLink) WriteFrame(f Frame) error {
	pad := 0
	if l.padMax > 0 {
		pad = rand.Intn(l.padMax + 1)
	}
	plain, err := EncodeFramePadded(f, pad)
	if err != nil {
		return err
	}
	ct, err := l.enc.Encrypt(plain)
	if err != nil {
		return err
	}
	if l.jitter > 0 {
		time.Sleep(time.Duration(rand.Int63n(int64(l.jitter) + 1)))
	}
	l.wmu.Lock()
	defer l.wmu.Unlock()
	return l.io.WritePacket(ct)
}

func (l *PacketLink) ReadFrame() (Frame, error) {
	for {
		ct, err := l.io.ReadPacket()
		if err != nil {
			return Frame{}, err
		}
		plain, err := l.enc.Decrypt(ct)
		if err != nil {
			// Drop undecryptable datagrams (spoofed / stray) and keep reading.
			continue
		}
		return DecodeFrame(plain)
	}
}
