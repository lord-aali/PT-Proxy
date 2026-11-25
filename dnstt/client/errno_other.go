//go:build !windows

package client

import "syscall"

func extraLocalErrno(syscall.Errno) bool { return false }
