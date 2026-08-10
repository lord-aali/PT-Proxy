package termon

import (
	"fmt"
	"syscall"
)

func termMonitorInitLinux(m *TermMonitor) error {
	// Use prctl() to have the kernel deliver a SIGTERM if the parent
	// process dies.  This beats anything else that can be done before
	// #15435 is implemented.
	_, _, errno := syscall.Syscall(syscall.SYS_PRCTL, syscall.PR_SET_PDEATHSIG, uintptr(syscall.SIGTERM), 0)
	if errno != 0 {
		var err error = errno
		return fmt.Errorf("prctl(PR_SET_PDEATHSIG, SIGTERM) returned: %s", err)
	}
	return nil
}

func init() {
	termMonitorOSInit = termMonitorInitLinux
}
