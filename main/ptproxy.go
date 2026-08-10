package main

import (
	"flag"
	"fmt"
	"github.com/lord-aali/PT-Proxy/common/configuration"
	"github.com/lord-aali/PT-Proxy/common/constant"
	"github.com/lord-aali/PT-Proxy/common/ptlog"
	"github.com/lord-aali/PT-Proxy/common/termon"
	"github.com/lord-aali/PT-Proxy/common/utils"
	ObfsClient "github.com/lord-aali/PT-Proxy/obfs/client"
	ObfsServer "github.com/lord-aali/PT-Proxy/obfs/server"
	"github.com/lord-aali/PT-Proxy/proxy/socks5"
	"gitlab.com/yawning/obfs4.git/transports"
	"net"
	"os"
	"path"
	"strconv"
)

func main() {
	// Replace the global flag set so flags registered by imported libraries
	// (e.g. obfs4's -obfs4-distBias) are not exposed on our command line.
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	var version bool
	var genCert bool
	var configPath string
	var woringDirectory string
	flag.BoolVar(&version, "version", false, "show version")
	flag.BoolVar(&genCert, "gencert", false, "generate a new obfs4 certificate, print it, and exit")
	flag.StringVar(&configPath, "c", "./config.json", "config file path")
	flag.StringVar(&woringDirectory, "d", "./", "working directory path")

	flag.Parse()

	os.Setenv("PWD", woringDirectory)

	if version {
		fmt.Println("PT Proxy - censorship-circumvention tunnels.")
		fmt.Println("Version:", constant.APP_VERSION)
		fmt.Println("github: https://github.com/lord-aali/PT-Proxy")
		os.Exit(0)
	}

	if genCert {
		printGeneratedCert()
		os.Exit(0)
	}

	config := configuration.Load(configPath)
	ensureServerCerts(&config, configPath)
	initTransports()

	// listeners collects every obfs client/server endpoint to hand to the monitor.
	var listeners []net.Listener

	// internalSocksAddress is lazily started once and shared by every server entry
	// that does not point at an external service.
	internalSocksAddress := ""

	// noTagCounter provides a stable fallback suffix for entries whose Listen
	// address has no parsable port. It is shared across server and client loops.
	noTagCounter := 0

	for _, c := range config.Server {
		tag := buildTag(c.Type, c.Listen, &noTagCounter)

		if c.Type == "dpi" {
			launchDpiServer(c, tag)
			continue
		}

		if c.Type == "snowflake" {
			launchSnowflakeServer(c, tag)
			continue
		}

		if c.Type == "ftp" {
			launchFtpServer(c, tag)
			continue
		}

		if !c.UseExternalService {
			if internalSocksAddress == "" {
				internalSocksAddress = runInternalSocks()
			}
			c.ExternalServiceAddress = internalSocksAddress
		}

		obfsServer := ObfsServer.Server{LogTag: tag}
		if isLaunched, ls := obfsServer.Setup(c); isLaunched {
			listeners = append(listeners, ls...)
		}
	}

	for _, c := range config.Client {
		tag := buildTag(c.Type, c.Listen, &noTagCounter)

		if c.Type == "dpi" {
			launchDpiClient(c, tag)
			continue
		}

		if c.Type == "snowflake" {
			launchSnowflakeClient(c, tag)
			continue
		}

		if c.Type == "ftp" {
			launchFtpClient(c, tag)
			continue
		}

		obfsClient := ObfsClient.Client{LogTag: tag}
		if isLaunched, ls := obfsClient.Setup(c); isLaunched {
			listeners = append(listeners, ls...)
		}
	}

	termon.TermMonHandler.LaunchTermMonitorForListeners(listeners)
}

// buildTag derives a human-readable log tag from a transport type and its listen
// address. It uses the port when available, otherwise an incrementing counter.
func buildTag(transportType, listen string, noTagCounter *int) string {
	if _, port, err := net.SplitHostPort(listen); err == nil {
		return transportType + "-" + port
	}
	*noTagCounter++
	return transportType + "-" + strconv.Itoa(*noTagCounter)
}

// initTransports initializes the obfs4 pluggable transports and aborts the
// process if they cannot be set up.
func initTransports() {
	if err := transports.Init(); err != nil {
		_, execName := path.Split(os.Args[0])
		lg := ptlog.PTLog{"INIT"}
		lg.Fatal("%s - failed to initialize transports: %s", execName, err)
		os.Exit(-1)
	}
}

// runInternalSocks picks a free loopback port, starts a SOCKS5 server on it in a
// background goroutine, and returns the address it is listening on.
func runInternalSocks() (address string) {
	portTool := utils.PortTool{}

	// Keep drawing random ports until we find one that is not already in use.
	socksPort := strconv.Itoa(portTool.GetRandomPort())
	for portTool.IsTcpOpen(socksPort, "127.0.0.1") {
		socksPort = strconv.Itoa(portTool.GetRandomPort())
	}

	address = "127.0.0.1:" + socksPort
	go socks5.ServeSocks5(address)
	return address
}

// ensureServerCerts generates an obfs4 certificate for every obfs4 server entry
// that does not already have one, then persists the updated config back to disk
// so the certificate (and its private key) stay stable across restarts.
func ensureServerCerts(config *configuration.JsonConfigImpl, configPath string) {
	lg := ptlog.PTLog{"system"}
	dirty := false
	for i := range config.Server {
		s := &config.Server[i]
		if s.Type != "obfs4" || s.Cert != "" {
			continue
		}
		cert, privateKey, err := ObfsServer.GenerateIdentity()
		if err != nil {
			lg.Fatal("Failed to generate obfs4 certificate:", err)
		}
		s.Cert = cert
		s.PrivateKey = privateKey
		dirty = true
		lg.Info("Generated obfs4 certificate for", s.Listen)
	}
	if dirty {
		if err := configuration.Save(configPath, *config); err != nil {
			lg.Fatal("Failed to save generated certificates:", err)
		}
	}
}

// printGeneratedCert creates a brand-new obfs4 certificate and prints the
// config fields a user can paste into a server entry for a custom certificate.
func printGeneratedCert() {
	cert, privateKey, err := ObfsServer.GenerateIdentity()
	if err != nil {
		fmt.Println("Failed to generate certificate:", err)
		os.Exit(1)
	}
	fmt.Println("New obfs4 certificate generated. Add these fields to a server entry:")
	fmt.Println("  \"cert\": " + strconv.Quote(cert) + ",")
	fmt.Println("  \"private-key\": " + strconv.Quote(privateKey))
}
