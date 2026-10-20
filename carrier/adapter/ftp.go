package adapter

import (
	"sync"

	"github.com/lord-aali/PT-Proxy/carrier/core"
	ftp "github.com/lord-aali/PT-Proxy/ftp/common"
)

// FTPSession adapts FTP tunnel frames onto carrier/core.Engine. Outer FTP/PASV
// camouflage remains in ftp/server and ftp/client.
type FTPSession struct {
	eng   *core.Engine
	write func([]*ftp.Frame) error
	mu    sync.Mutex
	seq   uint32
}

func NewFTPServerSession(cfg core.ServerConfig, write func([]*ftp.Frame) error) *FTPSession {
	s := &FTPSession{write: write}
	s.eng = core.NewServerEngine(cfg, s.emit)
	return s
}

func (s *FTPSession) Close() {
	if s.eng != nil {
		s.eng.Close()
	}
}

func (s *FTPSession) emit(f core.Frame) error {
	t, id, data := core.CoreToFTP(f)
	s.mu.Lock()
	s.seq++
	seq := s.seq
	s.mu.Unlock()
	return s.write([]*ftp.Frame{{ConnID: id, Type: t, Seq: seq, Data: data}})
}

// HandleFrame routes one inbound FTP frame into the shared engine.
func (s *FTPSession) HandleFrame(f *ftp.Frame) {
	if f == nil {
		return
	}
	s.eng.Handle(core.FTPToCore(f.Type, f.ConnID, f.Data))
}
