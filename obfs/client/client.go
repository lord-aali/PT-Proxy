package client

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lord-aali/PT-Proxy/common/configuration"
	"github.com/lord-aali/PT-Proxy/common/ptlog"
	"github.com/lord-aali/PT-Proxy/common/utils"
	"gitlab.com/yawning/obfs4.git/common/log"
	"gitlab.com/yawning/obfs4.git/common/socks5"
	"gitlab.com/yawning/obfs4.git/transports"
	"gitlab.com/yawning/obfs4.git/transports/base"
	"golang.org/x/net/proxy"
)

type Client struct {
	LogTag string
	log    ptlog.PTLog
}

func (c Client) Setup(config configuration.JsonClientConfigImpl) (launched bool, listeners []net.Listener) {
	c.log = ptlog.PTLog{LogTag: c.LogTag}
	transport := config.Type
	t := transports.Get(transport)
	if t == nil {
		c.log.Fatal("no such transport is supported")
	}
	f, err := t.ClientFactory(configuration.WorkingDirectory)
	if err != nil {
		c.log.Fatal(transport, "failed to get ClientFactory")
	}

	portTool := utils.PortTool{}
	segments := strings.Split(config.Listen, ":")
	if len(segments) != 2 {
		c.log.Fatal("Invalid service ipv4 address <address>:<port>")
	}
	if portTool.IsTcpOpen(segments[1], segments[0]) {
		c.log.Fatal("Address", config.Listen, "is not usable, consider changing or freeing it")
	}

	if !config.UseExternalService {
		c.log.Info("Standalone mode detected.")
		c.log.Info("Configuring routes...")
		c.log.Info("----------------------------------------------")
		if transport == "obfs4" {
			c.log.Info(fmt.Sprintf("%s://%s?cert=%s&iat-mode=%s => socks5://%s", transport, config.Address, config.Cert, configuration.ObfsIatMode, config.Listen))
		} else {
			c.log.Info(fmt.Sprintf("%s://%s => socks5://%s", transport, config.Address, config.Listen))
		}
		c.log.Info("----------------------------------------------")

		middleDialerPort := strconv.Itoa(portTool.GetRandomPort())
		for {
			if portTool.IsTcpOpen(middleDialerPort, "127.0.0.1") {
				middleDialerPort = strconv.Itoa(portTool.GetRandomPort())
				continue
			}
			break
		}

		middleDialerAddress := "127.0.0.1:" + middleDialerPort

		obfs, err := net.Listen("tcp", middleDialerAddress)
		if err != nil {
			c.log.Fatal(transport, err.Error())
		}
		go func() {
			_ = c.clientAcceptLoop(f, obfs, false, config, nil)
		}()
		c.log.Info("obfuscate service: " + middleDialerAddress)
		listeners = append(listeners, obfs)

		main, err := net.Listen("tcp", config.Listen)
		if err != nil {
			c.log.Fatal(transport, err.Error())
		}

		middleDialerUrl := url.URL{
			Scheme: "socks5",
			Host:   middleDialerAddress,
			User:   url.UserPassword("cert="+config.Cert, ";iat-mode="+configuration.ObfsIatMode),
		}
		go func() {
			_ = c.clientAcceptLoop(f, main, true, config, &middleDialerUrl)
		}()
		c.log.InfoDelayed(time.Second, "Client started listening socks5 on", config.Listen, "with underlying transport", config.Type)
		listeners = append(listeners, main)

	} else {
		c.log.Info("3rd-party mode detected.")
		c.log.Info("How to use:")
		c.log.Info(" This service will deploy a socks5 service on desired address. bind this socks5 service as a proxy for your 3rd-party service.")
		if config.Type == "obfs4" {
			c.log.Info(" on obfs4 transport:")
			c.log.Info(" Configuration while using obfs4 transport is a little bit different.")
			c.log.Info(" You have to pass iat-mode and cert as username and password of socks5 service.")
			c.log.Info(" Use service address as socks5 address then provide cert and iat-mode like below:")
			c.log.Info("  address: socks5://" + config.Listen)
			c.log.Info("  username: cert=XXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
			c.log.Info("  password: ;iat-mode=#")
			c.log.Info(" Note: Don't forget to add 'cert=' as prefix in username and ';' in password.")
		} else {
			c.log.Info(" on " + config.Type + " transport:")
			c.log.Info(" Unlike obfs4 there is no username and password is required.")
			c.log.Info("  address: socks5://" + config.Listen)
		}

		main, err := net.Listen("tcp", config.Listen)
		if err != nil {
			c.log.Fatal(transport, err.Error())
		}
		go func() {
			_ = c.clientAcceptLoop(f, main, true, config, nil)
		}()
		c.log.InfoDelayed(time.Second, "Client started listening socks5 on", config.Listen, "with underlying transport", config.Type)
		listeners = append(listeners, main)

	}

	launched = true

	return
}

func (c Client) clientAcceptLoop(f base.ClientFactory, ln net.Listener, isInternal bool, config configuration.JsonClientConfigImpl, middleDialerUrl *url.URL) error {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				return err
			}
			continue
		}
		go c.clientHandler(f, conn, isInternal, config, middleDialerUrl)
	}
}

func (c Client) clientHandler(f base.ClientFactory, conn net.Conn, isInternal bool, config configuration.JsonClientConfigImpl, middleDialerUrl *url.URL) {
	defer conn.Close()
	//termon.TermMonHandler.TermMon.OnHandlerStart()
	//defer termon.TermMonHandler.TermMon.OnHandlerFinish()

	name := f.Transport().Name()
	if !config.UseExternalService {
		name = config.Address
	}

	// Read the client's SOCKS handshake.
	socksReq, err := socks5.Handshake(conn)
	if err != nil {
		c.log.Error(fmt.Sprintf("%s - client failed socks handshake: %s", name, err))
		return
	}

	addrStr := log.ElideAddr(socksReq.Target)

	var remote net.Conn

	if isInternal {
		obfuscateDialer, err := proxy.FromURL(middleDialerUrl, proxy.Direct)
		if err != nil {
			c.log.Error("failed to resolve middle obfuscate dialer")
			socksReq.Reply(socks5.ReplyGeneralFailure)
		}
		dialer, err := proxy.SOCKS5("tcp", config.Address, nil, obfuscateDialer)
		if err != nil {
			c.log.Error("failed to resolve socks5 dialer")
			socksReq.Reply(socks5.ReplyGeneralFailure)
		}
		remote, err = dialer.Dial("tcp", socksReq.Target)
		if err != nil {
			c.log.Error(fmt.Sprintf("%s(%s) - outgoing connection failed: %s", name, addrStr, log.ElideError(err)))
			_ = socksReq.Reply(socks5.ErrorToReplyCode(err))
			return
		}
	} else {
		args, err := f.ParseArgs(&socksReq.Args)
		if err != nil {
			c.log.Error(fmt.Sprintf("%s(%s) - invalid arguments: %s", name, addrStr, err))
			_ = socksReq.Reply(socks5.ReplyGeneralFailure)
			return
		}

		remote, err = f.Dial("tcp", socksReq.Target, proxy.Direct.Dial, args)
		if err != nil {
			c.log.Error(fmt.Sprintf("%s(%s) - outgoing connection failed: %s", name, addrStr, log.ElideError(err)))
			_ = socksReq.Reply(socks5.ErrorToReplyCode(err))
			return
		}
	}

	defer remote.Close()
	err = socksReq.Reply(socks5.ReplySucceeded)
	if err != nil {
		c.log.Error(fmt.Sprintf("%s(%s) - SOCKS reply failed: %s", name, addrStr, log.ElideError(err)))
		return
	}

	if err = c.copyLoop(conn, remote); err != nil {
		c.log.Warn(fmt.Sprintf("%s(%s) - closed connection: %s", name, addrStr, log.ElideError(err)))
	} else {
		//connection has been closed normally...
		//ptlog.Info(fmt.Sprintf("%s(%s) - closed connection", name, addrStr))
	}
}

func (c Client) copyLoop(a net.Conn, b net.Conn) error {
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
