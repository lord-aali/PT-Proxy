package socks5

import (
	"github.com/lord-aali/PT-Proxy/common/ptlog"
	"github.com/things-go/go-socks5"
	"log"
	"os"
)

func ServeSocks5(address string) {
	ptlg := ptlog.PTLog{LogTag: "SOCKS5"}
	// Create a SOCKS5 server
	server := socks5.NewServer(
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
	)

	// Create SOCKS5 proxy on localhost address
	if err := server.ListenAndServe("tcp", address); err != nil {
		ptlg.Fatal("Socks5 server listen err:", err)
	}
}
