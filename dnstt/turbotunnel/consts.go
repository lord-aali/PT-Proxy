// Package turbotunnel is facilities for embedding packet-based reliability
// protocols inside other protocols.
//
// https://github.com/net4people/bbs/issues/9
package turbotunnel

import "errors"

// QueueSize is the depth of the send and receive queues between KCP and DNS.
// It is many times WindowSize so one round of retransmissions still fits
// while earlier segments wait for a free UDP query. Those queues used to
// discard a segment and report success once they were full, so KCP never
// slowed the writer and the session stayed wedged until the process restarted.
const QueueSize = 2048

// WindowSize is the KCP send and receive window, in segments. A writer blocks
// once this many segments are waiting for an acknowledgement. That is what
// slows a browser down. Keep it within the number of DNS queries the client
// can have in flight, or the extra segments only sit in the queue and get
// retransmitted on top of themselves.
const WindowSize = 64

var errClosedPacketConn = errors.New("operation on closed connection")
var errNotImplemented = errors.New("not implemented")

// DummyAddr is a placeholder net.Addr, for when a programming interface
// requires a net.Addr but there is none relevant. All DummyAddrs compare equal
// to each other.
type DummyAddr struct{}

func (addr DummyAddr) Network() string { return "dummy" }
func (addr DummyAddr) String() string  { return "dummy" }
