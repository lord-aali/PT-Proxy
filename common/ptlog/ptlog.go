package ptlog

import (
	"fmt"
	"os"
	"time"
)

type PTLog struct {
	LogTag string
}

func (t PTLog) Fatal(v ...any) {
	fmt.Printf("[%s] - Fatal: ", t.LogTag)
	fmt.Println(v...)
	fmt.Println("exiting...")
	os.Exit(1)
}
func (t PTLog) Error(v ...any) {
	fmt.Printf("[%s] - Error: ", t.LogTag)
	fmt.Println(v...)
}

func (t PTLog) Warn(v ...any) {
	fmt.Printf("[%s] - Warn: ", t.LogTag)
	fmt.Println(v...)
}

func (t PTLog) Info(v ...any) {
	fmt.Printf("[%s] - Info: ", t.LogTag)
	fmt.Println(v...)
}

// InfoDelayed logs an Info message after delay without blocking the caller.
func (t PTLog) InfoDelayed(delay time.Duration, v ...any) {
	go func() {
		time.Sleep(delay)
		t.Info(v...)
	}()
}

func (t PTLog) Debug(v ...any) {
	fmt.Printf("[%s] - Debug: ", t.LogTag)
	fmt.Println(v...)
}
