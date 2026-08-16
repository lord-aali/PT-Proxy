package main

import (
	"context"
	"strings"
	"time"

	"github.com/lord-aali/PT-Proxy/common/configuration"
	"github.com/lord-aali/PT-Proxy/common/ptlog"
	FtpClient "github.com/lord-aali/PT-Proxy/ftp/client"
	FtpServer "github.com/lord-aali/PT-Proxy/ftp/server"
)

const (
	ftpDefaultListen     = "0.0.0.0:21"
	ftpDefaultSocks      = "127.0.0.1:1080"
	ftpDefaultUser       = "tunnel"
	ftpDefaultPass       = "secret"
	ftpDefaultKey        = "change-me-please"
	ftpDefaultUpPorts    = "8080-8800"
	ftpDefaultDownPorts  = "8080-8800"
	ftpDefaultUpChannels = 1
	ftpDefaultDownChans  = 1
)

func launchFtpServer(c configuration.JsonServerConfigImpl, tag, target string, skipUDP bool) bool {
	lg := ptlog.PTLog{LogTag: tag}

	cfg := FtpServer.Config{
		Listen:        dpiOrDefault(c.Listen, ftpDefaultListen),
		User:          dpiOrDefault(c.User, ftpDefaultUser),
		Pass:          dpiOrDefault(c.Pass, ftpDefaultPass),
		Key:           dpiOrDefault(c.EncKey, ftpDefaultKey),
		PasvIP:        c.PasvIP,
		UploadPorts:   dpiOrDefault(c.UploadPorts, ftpDefaultUpPorts),
		DownloadPorts: dpiOrDefault(c.DownloadPorts, ftpDefaultDownPorts),
		TLS:           c.TLS,
		Cert:          c.TlsCertFile,
		CertKey:       c.TlsKeyFile,
		Debug:         false,
		LogTag:        tag,
		Target:        target,
		SkipUDP:       skipUDP,
	}

	if cfg.TLS && (strings.TrimSpace(cfg.Cert) == "" || strings.TrimSpace(cfg.CertKey) == "") {
		lg.Error("ftp tls requires tls-cert and tls-key")
		return false
	}

	go func() {
		if err := FtpServer.Run(context.Background(), cfg); err != nil && err != context.Canceled {
			lg.Error("ftp server stopped:", err)
		}
	}()
	lg.Info("ftp server started (listen:", cfg.Listen, "up:", cfg.UploadPorts, "down:", cfg.DownloadPorts+")")
	return true
}

func launchFtpClient(c configuration.JsonClientConfigImpl, tag, reverseAddr string, skipUDP bool) bool {
	lg := ptlog.PTLog{LogTag: tag}
	_ = skipUDP

	if strings.TrimSpace(c.Address) == "" {
		lg.Error("ftp client requires a server address (FTP host:port)")
		return false
	}

	upChans := c.UploadChannels
	if upChans < 1 {
		upChans = ftpDefaultUpChannels
	}
	downChans := c.DownloadChannels
	if downChans < 1 {
		downChans = ftpDefaultDownChans
	}

	cfg := FtpClient.Config{
		Listen:           dpiOrDefault(c.Listen, ftpDefaultSocks),
		FTP:              c.Address,
		User:             dpiOrDefault(c.User, ftpDefaultUser),
		Pass:             dpiOrDefault(c.Pass, ftpDefaultPass),
		Key:              dpiOrDefault(c.EncKey, ftpDefaultKey),
		TLS:              c.TLS,
		UploadChannels:   upChans,
		DownloadChannels: downChans,
		OverrideUpAddr:   c.OverrideUpAddr,
		OverrideDownAddr: c.OverrideDownAddr,
		Decoy:            c.Decoy,
		Debug:            c.Verbose,
		LogTag:           tag,
		ReverseAddr:      reverseAddr,
	}

	go func() {
		if err := FtpClient.Run(context.Background(), cfg); err != nil && err != context.Canceled {
			lg.Error("ftp client stopped:", err)
		}
	}()
	lg.InfoDelayed(time.Second, "ftp client started (listen:", cfg.Listen, "ftp:", cfg.FTP+")")
	return true
}
