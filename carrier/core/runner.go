package core

import (
	"time"

	"github.com/lord-aali/PT-Proxy/common/ptlog"
)

// RunConfig is the client-side behavior shared by every carrier.
type RunConfig struct {
	Listen      string
	ReverseAddr string
	SkipUDP     bool
	LogTag      string
}

// RunClientLoop dials a carrier, handshakes, then serves forward (raw listen)
// or reverse (publish on server), reconnecting on failure.
func RunClientLoop(dial func() (FrameConn, error), cfg RunConfig) {
	lg := ptlog.PTLog{LogTag: cfg.LogTag}
	for {
		fc, err := dial()
		if err != nil {
			lg.Error("dial:", err)
			time.Sleep(time.Second)
			continue
		}
		if err := HandshakeClient(fc); err != nil {
			lg.Error("handshake:", err)
			_ = fc.Close()
			time.Sleep(time.Second)
			continue
		}
		sess := NewClientSession(fc, cfg.ReverseAddr)
		if cfg.ReverseAddr != "" {
			err = RunClientSocks(sess, SocksConfig{
				Listen:      cfg.Listen,
				ReverseAddr: cfg.ReverseAddr,
				SkipUDP:     cfg.SkipUDP,
				LogTag:      cfg.LogTag,
			})
		} else {
			err = RunClientForward(sess, cfg.Listen, "", cfg.SkipUDP, cfg.LogTag)
		}
		_ = sess.Close()
		if err != nil {
			lg.Error("client:", err)
		}
		time.Sleep(time.Second)
	}
}
