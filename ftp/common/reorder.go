// common/reorder.go
//
// ReorderBuffer provides ordered, reliable delivery of frames over an
// unreliable, out-of-order transport (our poll-based FTP channel).
//
// Algorithm:
//   - Each TCP virtual connection maintains its own ReorderBuffer.
//   - The buffer holds frames whose seq > nextExpected.
//   - When a frame arrives in order it is delivered immediately.
//   - When a gap is detected the buffer waits up to ReorderTimeout for
//     missing frames; after that it skips and delivers what it has.
//   - Duplicate frames (seq < nextExpected) are silently dropped.
package common

import (
	"sort"
	"sync"
	"time"
)

const ReorderTimeout = 80 * time.Millisecond

// ReorderBuffer buffers out-of-order frames and delivers them in seq order.
type ReorderBuffer struct {
	mu           sync.Mutex
	nextExpected uint32
	held         []*Frame // sorted by Seq
	out          chan *Frame
	timer        *time.Timer
}

// NewReorderBuffer creates a buffer that writes in-order frames to out.
func NewReorderBuffer(out chan *Frame) *ReorderBuffer {
	return &ReorderBuffer{
		nextExpected: 1,
		out:          out,
	}
}

// Push delivers a frame into the buffer.
func (r *ReorderBuffer) Push(f *Frame) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Duplicate / already-delivered
	if f.Seq < r.nextExpected {
		return
	}

	// In-order delivery
	if f.Seq == r.nextExpected {
		r.deliver(f)
		r.flushContiguous()
		if r.timer != nil && len(r.held) == 0 {
			r.timer.Stop()
			r.timer = nil
		}
		return
	}

	// Out-of-order: buffer it
	r.held = append(r.held, f)
	sort.Slice(r.held, func(i, j int) bool { return r.held[i].Seq < r.held[j].Seq })

	// Start a gap timer if not already running
	if r.timer == nil {
		r.timer = time.AfterFunc(ReorderTimeout, r.timeoutFlush)
	}
}

// deliver sends a single frame downstream (must hold mu).
func (r *ReorderBuffer) deliver(f *Frame) {
	r.nextExpected = f.Seq + 1
	select {
	case r.out <- f:
	default: // channel full: back-pressure, block briefly
		r.mu.Unlock()
		r.out <- f
		r.mu.Lock()
	}
}

// flushContiguous delivers all buffered frames that are now contiguous.
func (r *ReorderBuffer) flushContiguous() {
	for len(r.held) > 0 && r.held[0].Seq == r.nextExpected {
		r.deliver(r.held[0])
		r.held = r.held[1:]
	}
}

// timeoutFlush is called when ReorderTimeout expires; delivers everything held.
func (r *ReorderBuffer) timeoutFlush() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.timer = nil
	for len(r.held) > 0 {
		r.deliver(r.held[0])
		r.held = r.held[1:]
	}
}
