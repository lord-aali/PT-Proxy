package termon

import (
	"net"
	"net/http"
	"syscall"
)

var TermMonHandler = TermMonHandlerImpl{}

type TermMonHandlerImpl struct {
	TermMon *TermMonitor
}

func (tm TermMonHandlerImpl) LaunchTermMonitorForListeners(listeners []net.Listener) {
	tm.TermMon = NewTermMonitor()

	if sig := tm.TermMon.Wait(false); sig == syscall.SIGTERM {
		return
	}

	for _, ln := range listeners {
		err := ln.Close()
		if err != nil {
			return
		}
	}
	tm.TermMon.Wait(true)
}

func (tm TermMonHandlerImpl) LaunchTermMonitorForServers(listeners []*http.Server) {
	tm.TermMon = NewTermMonitor()

	if sig := tm.TermMon.Wait(false); sig == syscall.SIGTERM {
		return
	}

	for _, ln := range listeners {
		err := ln.Close()
		if err != nil {
			return
		}
	}
	tm.TermMon.Wait(true)
}
