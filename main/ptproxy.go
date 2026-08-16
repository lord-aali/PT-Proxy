package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/lord-aali/PT-Proxy/common/configuration"
	"github.com/lord-aali/PT-Proxy/common/constant"
	"github.com/lord-aali/PT-Proxy/common/ptlog"
	"github.com/lord-aali/PT-Proxy/common/service"
	"github.com/lord-aali/PT-Proxy/common/termon"
	ObfsClient "github.com/lord-aali/PT-Proxy/obfs/client"
	ObfsServer "github.com/lord-aali/PT-Proxy/obfs/server"
	"gitlab.com/yawning/obfs4.git/transports"
)

func main() {
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

	var listeners []net.Listener
	noTagCounter := 0

	var tunnels []configuration.JsonServerConfigImpl
	for _, c := range config.Server {
		if isServiceType(c.Type) {
			if _, ok := startService(c); !ok {
				continue
			}
			continue
		}
		tunnels = append(tunnels, c)
	}

	for _, c := range tunnels {
		tag := c.TrimTag()
		if tag == "" {
			tag = service.AutoTag(c.Type, listenForTag(c))
			if service.ListenPort(listenForTag(c)) == "0" || service.ListenPort(listenForTag(c)) == "" {
				tag = buildTag(c.Type, listenForTag(c), &noTagCounter)
			}
		}
		targetAddr := ""
		skipUDP := false
		if t := c.TrimTarget(); t != "" {
			var err error
			targetAddr, skipUDP, err = resolveTarget(t)
			if err != nil {
				lg := ptlog.PTLog{LogTag: tag}
				lg.Error(err)
				continue
			}
		}

		switch c.Type {
		case "dpi":
			launchDpiServer(c, tag, targetAddr, skipUDP)
		case "snowflake":
			launchSnowflakeServer(c, tag, targetAddr, skipUDP)
		case "ftp":
			launchFtpServer(c, tag, targetAddr, skipUDP)
		default:
			obfsServer := ObfsServer.Server{LogTag: tag, Target: targetAddr, SkipUDP: skipUDP}
			if isLaunched, ls := obfsServer.Setup(c); isLaunched {
				listeners = append(listeners, ls...)
			}
		}
	}

	for _, c := range config.Client {
		tag := c.TrimTag()
		if tag == "" {
			tag = buildTag(c.Type, c.Listen, &noTagCounter)
		}
		reverseAddr := ""
		skipUDP := false
		if rt := c.TrimReverseTag(); rt != "" {
			var err error
			reverseAddr, skipUDP, err = resolveTarget(rt)
			if err != nil {
				lg := ptlog.PTLog{LogTag: tag}
				lg.Error("reverse-tag:", err)
				continue
			}
		}

		switch c.Type {
		case "dpi":
			launchDpiClient(c, tag, reverseAddr, skipUDP)
		case "snowflake":
			launchSnowflakeClient(c, tag, reverseAddr, skipUDP)
		case "ftp":
			launchFtpClient(c, tag, reverseAddr, skipUDP)
		default:
			obfsClient := ObfsClient.Client{LogTag: tag, ReverseAddr: reverseAddr, SkipUDP: skipUDP}
			if isLaunched, ls := obfsClient.Setup(c); isLaunched {
				listeners = append(listeners, ls...)
			}
		}
	}

	termon.TermMonHandler.LaunchTermMonitorForListeners(listeners)
}

func buildTag(transportType, listen string, noTagCounter *int) string {
	if _, port, err := net.SplitHostPort(strings.TrimSpace(listen)); err == nil && port != "" && port != "0" {
		return transportType + "-" + port
	}
	*noTagCounter++
	return transportType + "-" + strconv.Itoa(*noTagCounter)
}

func initTransports() {
	if err := transports.Init(); err != nil {
		_, execName := path.Split(os.Args[0])
		lg := ptlog.PTLog{"INIT"}
		lg.Fatal("%s - failed to initialize transports: %s", execName, err)
		os.Exit(-1)
	}
}

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
