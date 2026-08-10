package utils

import (
	"math/rand"
	"net"
	"time"
)

type PortTool struct {
}

func (pt *PortTool) IsTcpOpen(port string, host string) bool {
	timeout := time.Second
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		//port is closed
		return false
	}
	if conn != nil {
		defer conn.Close()
	}
	return true
}
func (pt *PortTool) GetRandomPort() int {
	return rand.Intn(35000-1025) + 1025
}
