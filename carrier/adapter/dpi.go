package adapter

import (
	"sync"

	"github.com/lord-aali/PT-Proxy/carrier/core"
	dpi "github.com/lord-aali/PT-Proxy/dpi/common"
)

// DPISession adapts DPI stream messages onto carrier/core.Engine while the
// HTTP(S) outer camouflage stays in dpi/server and dpi/client.
type DPISession struct {
	eng        *core.Engine
	enc        *dpi.Encryptor
	writePlain func([]byte) error // already-built stream plaintext (header+payload)
	mu         sync.Mutex
}

func NewDPIServerSession(cfg core.ServerConfig, enc *dpi.Encryptor, writePlain func([]byte) error) *DPISession {
	s := &DPISession{enc: enc, writePlain: writePlain}
	s.eng = core.NewServerEngine(cfg, s.emit)
	return s
}

func (s *DPISession) Close() {
	if s.eng != nil {
		s.eng.Close()
	}
}

func (s *DPISession) emit(f core.Frame) error {
	msg, id, payload := core.CoreToDPI(f)
	plain := dpi.BuildStreamHeader(msg, id, uint32(len(payload)))
	if len(payload) > 0 {
		plain = append(plain, payload...)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writePlain(plain)
}

// HandlePlain processes one decrypted DPI stream frame (header+payload).
func (s *DPISession) HandlePlain(decrypted []byte) {
	hdr, payload, err := dpi.ParseStreamHeader(decrypted)
	if err != nil {
		return
	}
	if int(hdr.PayloadLen) > len(payload) {
		return
	}
	payload = payload[:hdr.PayloadLen]
	network := "tcp"
	addr := payload
	if hdr.MsgType == dpi.MsgConnect {
		if req, err := dpi.DecodeConnectRequest(payload); err == nil {
			network = req.Network
			addr = []byte(req.Address)
		}
	}
	s.eng.Handle(core.DPIToCore(hdr.MsgType, hdr.ConnID, addr, network))
}
