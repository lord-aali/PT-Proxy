package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/lord-aali/PT-Proxy/common/configuration"
	"github.com/lord-aali/PT-Proxy/common/ptlog"
	"github.com/lord-aali/PT-Proxy/common/urls"
	"github.com/lord-aali/PT-Proxy/common/utils"
	"gitlab.com/yawning/obfs4.git/common/drbg"
	"gitlab.com/yawning/obfs4.git/common/log"
	"gitlab.com/yawning/obfs4.git/common/ntor"
	"gitlab.com/yawning/obfs4.git/transports"
	"gitlab.com/yawning/obfs4.git/transports/base"
	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
)

const obfs4CertRawLength = ntor.NodeIDLength + ntor.PublicKeyLength

type Server struct {
	LogTag string
	log    ptlog.PTLog
}

func (s Server) Setup(config configuration.JsonServerConfigImpl) (launched bool, listeners []net.Listener) {
	s.log = ptlog.PTLog{LogTag: s.LogTag}
	portTool := utils.PortTool{}

	segments := strings.Split(config.Listen, ":")
	if len(segments) != 2 {
		s.log.Fatal("Invalid ipv4 service address format, should be <address>:<port>")
	}
	if portTool.IsTcpOpen(segments[1], segments[0]) {
		s.log.Fatal("Service port (" + segments[1] + ") already in use, consider changing or freeing the port.")
	}

	options := make(pt.Args)
	if config.Type == "obfs4" && config.Cert != "" {
		var err error
		if options, err = obfs4ArgsFromConfig(config.Cert, config.PrivateKey); err != nil {
			s.log.Fatal("Invalid obfs4 certificate/key:", err.Error())
		}
	}

	info := s.getPtServerInfo(config, options)

	bindAddr := info.Bindaddrs[0]
	transport := bindAddr.MethodName

	t := transports.Get(transport)
	if t == nil {
		s.log.Fatal(transport, "no such transport is supported")
	}

	// obfs4's ServerFactory unconditionally writes obfs4_state.json and
	// obfs4_bridgeline.txt into the state dir. Point it at a throwaway temp dir
	// so nothing lands in the working directory; the identity is supplied via
	// options above and persisted in config.json instead.
	stateDir, err := os.MkdirTemp("", "ptproxy-obfs4-")
	if err != nil {
		s.log.Fatal("Failed to create temporary state directory:", err.Error())
	}
	defer os.RemoveAll(stateDir)

	f, err := t.ServerFactory(stateDir, &bindAddr.Options)
	if err != nil {
		s.log.Fatal(transport, err.Error())
	}
	if f == nil {
		s.log.Fatal("Can't initiate server factory.")
	}

	ln, err := net.ListenTCP("tcp", info.Bindaddrs[0].Addr)

	go func() {
		_ = s.serverAcceptLoop(f, ln, &info)
	}()

	listeners = append(listeners, ln)
	launched = true

	s.log.Info("Server started listening on", config.Listen, "with underlying transport", config.Type)

	switch transport {
	case "obfs4":
		args := f.Args()
		cert, _ := args.Get("cert")
		iat, _ := args.Get("iat-mode")

		s.log.Info("cert=" + cert)
		s.log.Info("iat-mode=" + iat)
	}

	return
}

func (s Server) serverAcceptLoop(f base.ServerFactory, ln net.Listener, info *pt.ServerInfo) error {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				return err
			}
			continue
		}
		go s.serverHandler(f, conn, info)
	}
}

func (s Server) serverHandler(f base.ServerFactory, conn net.Conn, info *pt.ServerInfo) {
	defer conn.Close()
	//termon.TermMonHandler.TermMon.OnHandlerStart()
	//defer termon.TermMonHandler.TermMon.OnHandlerFinish()

	name := f.Transport().Name()
	addrStr := log.ElideAddr(conn.RemoteAddr().String())
	log.Infof("%s(%s) - new connection", name, addrStr)

	// Instantiate the server transport method and handshake.
	remote, err := f.WrapConn(conn)
	if err != nil {
		log.Warnf("%s(%s) - handshake failed: %s", name, addrStr, log.ElideError(err))
		return
	}

	// Connect to the orport.
	orConn, err := pt.DialOr(info, conn.RemoteAddr().String(), name)
	if err != nil {
		log.Errorf("%s(%s) - failed to connect to ORPort: %s", name, addrStr, log.ElideError(err))
		return
	}
	defer orConn.Close()

	if err = s.copyLoop(orConn, remote); err != nil {
		log.Warnf("%s(%s) - closed connection: %s", name, addrStr, log.ElideError(err))
	} else {
		log.Infof("%s(%s) - closed connection", name, addrStr)
	}
}

func (s Server) copyLoop(a net.Conn, b net.Conn) error {
	// Note: b is always the pt connection.  a is the SOCKS/ORPort connection.
	errChan := make(chan error, 2)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer b.Close()
		defer a.Close()
		_, err := io.Copy(b, a)
		errChan <- err
	}()
	go func() {
		defer wg.Done()
		defer a.Close()
		defer b.Close()
		_, err := io.Copy(a, b)
		errChan <- err
	}()

	wg.Wait()
	if len(errChan) > 0 {
		return <-errChan
	}

	return nil
}

func (s Server) getPtServerInfo(config configuration.JsonServerConfigImpl, options pt.Args) (info pt.ServerInfo) {
	addr, err := urls.ResolveAddr(config.Listen)
	if err != nil {
		s.log.Fatal(err)
	}

	bindAddr := pt.Bindaddr{
		Addr:       addr,
		MethodName: config.Type,
		Options:    options,
	}
	info.Bindaddrs = append(info.Bindaddrs, bindAddr)

	addr, err = urls.ResolveAddr(config.ExternalServiceAddress)
	if err != nil {
		s.log.Fatal(err)
	}
	info.OrAddr = addr
	info.ExtendedOrAddr = nil
	info.AuthCookiePath = ""
	return info
}

// GenerateIdentity creates a fresh obfs4 server identity and returns the
// client-facing certificate together with its matching private key, using the
// same encodings the config file stores. The node ID is bundled into the cert,
// so the cert plus private key are sufficient to relaunch the same server.
func GenerateIdentity() (cert string, privateKey string, err error) {
	rawID := make([]byte, ntor.NodeIDLength)
	if _, err = rand.Read(rawID); err != nil {
		return "", "", err
	}
	nodeID, err := ntor.NewNodeID(rawID)
	if err != nil {
		return "", "", err
	}
	keypair, err := ntor.NewKeypair(false)
	if err != nil {
		return "", "", err
	}
	return encodeObfs4Cert(nodeID, keypair.Public()), keypair.Private().Hex(), nil
}

// encodeObfs4Cert builds the base64 obfs4 certificate (node ID + public key)
// exactly as the obfs4 transport advertises it to clients.
func encodeObfs4Cert(nodeID *ntor.NodeID, public *ntor.PublicKey) string {
	raw := make([]byte, 0, obfs4CertRawLength)
	raw = append(raw, nodeID.Bytes()[:]...)
	raw = append(raw, public.Bytes()[:]...)
	return strings.TrimSuffix(base64.StdEncoding.EncodeToString(raw), "==")
}

// obfs4ArgsFromConfig rebuilds the pluggable-transport arguments needed to
// launch an obfs4 server from the stored certificate and private key. The node
// ID is recovered from the cert and a fresh length-obfuscation seed is drawn on
// every start (clients do not pin it, only the cert matters for connecting).
func obfs4ArgsFromConfig(cert, privateKey string) (pt.Args, error) {
	if privateKey == "" {
		return nil, fmt.Errorf("missing private-key for obfs4 certificate")
	}
	decoded, err := base64.StdEncoding.DecodeString(cert + "==")
	if err != nil {
		return nil, fmt.Errorf("failed to decode cert: %w", err)
	}
	if len(decoded) != obfs4CertRawLength {
		return nil, fmt.Errorf("cert length %d is invalid", len(decoded))
	}

	seed, err := drbg.NewSeed()
	if err != nil {
		return nil, err
	}

	args := pt.Args{}
	args.Add("node-id", hex.EncodeToString(decoded[:ntor.NodeIDLength]))
	args.Add("private-key", privateKey)
	args.Add("drbg-seed", seed.Hex())
	args.Add("iat-mode", configuration.ObfsIatMode)
	return args, nil
}
