//go:build windows

package client

import (
	"net"
	"os"
	"syscall"
	"testing"
)

func TestIsLocalCloseWindowsReset(t *testing.T) {
	err := &net.OpError{
		Op: "writeto",
		Err: &net.OpError{
			Op: "read",
			Err: &os.SyscallError{
				Syscall: "wsarecv",
				Err:     syscall.WSAECONNRESET,
			},
		},
	}
	if !isLocalClose(err) {
		t.Fatal("WSAECONNRESET should be treated as the local application hanging up")
	}
}
