package socks5

// ServeSocks5 keeps the old helper for callers that only need TCP SOCKS.
func ServeSocks5(address string) {
	if _, err := Serve(address, "", "", "SOCKS5"); err != nil {
		panic(err)
	}
	select {}
}
