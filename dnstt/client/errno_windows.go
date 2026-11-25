//go:build windows

package client

import "syscall"

// Windows socket errors are WSA codes. syscall.ECONNRESET is a made-up value
// on this platform and does not match what the net package returns.
func extraLocalErrno(errno syscall.Errno) bool {
	switch errno {
	case syscall.WSAECONNRESET, syscall.WSAECONNABORTED,
		syscall.ERROR_BROKEN_PIPE, syscall.ERROR_NETNAME_DELETED,
		syscall.ERROR_OPERATION_ABORTED:
		return true
	default:
		return false
	}
}
