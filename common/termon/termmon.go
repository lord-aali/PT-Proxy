package termon

import (
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"gitlab.com/yawning/obfs4.git/common/log"
)

var termMonitorOSInit func(*TermMonitor) error

type TermMonitor struct {
	sigChan     chan os.Signal
	handlerChan chan int
	numHandlers int
}

func (m *TermMonitor) OnHandlerStart() {
	m.handlerChan <- 1
}

func (m *TermMonitor) OnHandlerFinish() {
	m.handlerChan <- -1
}

func (m *TermMonitor) Wait(termOnNoHandlers bool) os.Signal {
	// Block until a signal has been received, or (optionally) the
	// number of pending handlers has hit 0.  In the case of the
	// latter, treat it as if a SIGTERM has been received.
	for {
		select {
		case n := <-m.handlerChan:
			m.numHandlers += n
		case sig := <-m.sigChan:
			return sig
		}
		if termOnNoHandlers && m.numHandlers == 0 {
			return syscall.SIGTERM
		}
	}
}

func (m *TermMonitor) termOnStdinClose() {
	_, err := io.Copy(ioutil.Discard, os.Stdin)

	// io.Copy() will return a nil on EOF, since reaching EOF is
	// expected behavior.  No matter what, if this unblocks, assume
	// that stdin is closed, and treat that as having received a
	// SIGTERM.
	log.Noticef("Stdin is closed or unreadable: %v", err)
	m.sigChan <- syscall.SIGTERM
}

func (m *TermMonitor) termOnPPIDChange(ppid int) {
	// Under most if not all U*IX systems, the parent PID will change
	// to that of init once the parent dies.  There are several notable
	// exceptions (Slowlaris/Android), but the parent PID changes
	// under those platforms as well.
	//
	// Naturally we lose if the parent has died by the time when the
	// Getppid() call was issued in our parent, but, this is better
	// than nothing.
	const ppidPollInterval = 1 * time.Second
	for ppid == os.Getppid() {
		time.Sleep(ppidPollInterval)
	}

	// Treat the parent PID changing as the same as having received
	// a SIGTERM.
	log.Noticef("Parent pid changed: %d (was %d)", os.Getppid(), ppid)
	m.sigChan <- syscall.SIGTERM
}

func NewTermMonitor() (m *TermMonitor) {
	ppid := os.Getppid()
	m = new(TermMonitor)
	m.sigChan = make(chan os.Signal)
	m.handlerChan = make(chan int)
	signal.Notify(m.sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Instead of feature #15435, use various kludges and hacks:
	//  * Linux - Platform specific code that should always work.
	//  * Other U*IX - Somewhat generic code, that works unless the
	//    parent dies before the monitor is initialized.
	if termMonitorOSInit != nil {
		// Errors here are non-fatal, since it might still be
		// possible to fall back to a generic implementation.
		if err := termMonitorOSInit(m); err == nil {
			return
		}
	}
	if runtime.GOOS != "windows" {
		go m.termOnPPIDChange(ppid)
	}
	return
}
