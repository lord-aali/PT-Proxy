// common/metrics.go — lightweight atomic metrics with periodic logging.
package common

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/lord-aali/PT-Proxy/common/ptlog"
)

// Log is the shared PTLog used by ftp/common helpers.
var Log = ptlog.PTLog{LogTag: "ftp"}

// SetLog sets the shared logger for ftp/common helpers.
func SetLog(lg ptlog.PTLog) {
	Log = lg
}

// Metrics holds tunnel-wide counters (all atomic).
type Metrics struct {
	BytesUp       atomic.Int64
	BytesDown     atomic.Int64
	ActiveTCP     atomic.Int32
	ActiveUDP     atomic.Int32
	FramesSent    atomic.Int64
	FramesRecv    atomic.Int64
	Reconnects    atomic.Int32
	DroppedFrames atomic.Int64
}

// GlobalMetrics is the singleton used by both client and server.
var GlobalMetrics Metrics

// StartMetricsLogger logs metrics every interval.
func StartMetricsLogger(interval time.Duration) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			Log.Info(fmt.Sprintf("[metrics] up=%s down=%s tcp=%d udp=%d sent=%d recv=%d reconnects=%d dropped=%d",
				humanBytes(GlobalMetrics.BytesUp.Load()),
				humanBytes(GlobalMetrics.BytesDown.Load()),
				GlobalMetrics.ActiveTCP.Load(),
				GlobalMetrics.ActiveUDP.Load(),
				GlobalMetrics.FramesSent.Load(),
				GlobalMetrics.FramesRecv.Load(),
				GlobalMetrics.Reconnects.Load(),
				GlobalMetrics.DroppedFrames.Load(),
			))
		}
	}()
}

func humanBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(b)/float64(div), "KMGTPE"[exp])
}
