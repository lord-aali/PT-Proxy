package core

import (
	"encoding/binary"
	"fmt"
)

const (
	TypeHello       byte = 0x01
	TypeHelloOK     byte = 0x02
	TypeOpenTCP     byte = 0x03
	TypeOpenUDP     byte = 0x04
	TypeData        byte = 0x05
	TypeClose       byte = 0x06
	TypeDNSReq      byte = 0x07
	TypeDNSResp     byte = 0x08
	TypeReverseBind byte = 0x09
	TypeReverseOpen byte = 0x0A
	TypePad         byte = 0x0B
)

const (
	Version       = 1
	headerSize    = 7 // ver(1)+type(1)+connID(4)+padLen(1) then payload
	MaxFramePlain = 64 * 1024
	MaxCipherLen  = 256 * 1024
)

type Frame struct {
	Type   byte
	ConnID uint32
	Data   []byte
}

func EncodeFrame(f Frame) ([]byte, error) {
	if len(f.Data) > MaxFramePlain {
		return nil, fmt.Errorf("frame too large")
	}
	out := make([]byte, headerSize+len(f.Data))
	out[0] = Version
	out[1] = f.Type
	binary.BigEndian.PutUint32(out[2:6], f.ConnID)
	out[6] = 0
	copy(out[headerSize:], f.Data)
	return out, nil
}

func DecodeFrame(b []byte) (Frame, error) {
	var f Frame
	if len(b) < headerSize {
		return f, fmt.Errorf("short frame")
	}
	if b[0] != Version {
		return f, fmt.Errorf("bad version %d", b[0])
	}
	f.Type = b[1]
	f.ConnID = binary.BigEndian.Uint32(b[2:6])
	pad := int(b[6])
	rest := b[headerSize:]
	if pad > len(rest) {
		return f, fmt.Errorf("bad pad")
	}
	f.Data = rest[:len(rest)-pad]
	return f, nil
}

func EncodeFramePadded(f Frame, pad int) ([]byte, error) {
	if pad < 0 {
		pad = 0
	}
	if pad > 255 {
		pad = 255
	}
	if len(f.Data)+pad > MaxFramePlain {
		return nil, fmt.Errorf("frame too large")
	}
	out := make([]byte, headerSize+len(f.Data)+pad)
	out[0] = Version
	out[1] = f.Type
	binary.BigEndian.PutUint32(out[2:6], f.ConnID)
	out[6] = byte(pad)
	copy(out[headerSize:], f.Data)
	return out, nil
}
