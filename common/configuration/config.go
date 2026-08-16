package configuration

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/lord-aali/PT-Proxy/common/ptlog"
)

const MODE_SERVER = "SERVER"
const MODE_CLIENT = "CLIENT"
const MODE_BRIDGE = "BRIDGE"
const MODE_INTERNAL = "INTERNAL"
const MODE_EXTERNAL = "EXTERNAL"
const TRANSPORT_OBFS = "OBFSx"

// ObfsIatMode is the fixed obfs4 inter-arrival-time mode used by this proxy.
// It is intentionally not configurable: only "0" (disabled) is supported.
const ObfsIatMode = "0"

var Mode = MODE_SERVER
var Transport = TRANSPORT_OBFS
var WorkingDirectory = "./"
var Config = JsonConfigImpl{}

type JsonConfigImpl struct {
	Server []JsonServerConfigImpl `json:"server"`
	Client []JsonClientConfigImpl `json:"client"`
}

type JsonServerConfigImpl struct {
	Type       string `json:"type"`             // socks, http, external, obfs2-4, dpi, snowflake, ftp
	Tag        string `json:"tag,omitempty"`    // handle for target / reverse-tag; default type-port
	Listen     string `json:"listen,omitempty"` // bind (tunnels, socks, http) or dial address (external)
	Target     string `json:"target,omitempty"` // tunnel server: pipe to this service tag
	Cert       string `json:"cert,omitempty"`
	PrivateKey string `json:"private-key,omitempty"`

	EncKey      string `json:"enc-key,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	HttpAddr    string `json:"http,omitempty"`
	HttpsAddr   string `json:"https,omitempty"`
	TlsCertFile string `json:"tls-cert,omitempty"`
	TlsKeyFile  string `json:"tls-key,omitempty"`
	AcmeEmail   string `json:"acme-email,omitempty"`
	AcmeDomain  string `json:"acme-domain,omitempty"`
	SelfSigned  bool   `json:"self-signed,omitempty"`
	Redirect    string `json:"redirect,omitempty"`
	CertDir     string `json:"cert-dir,omitempty"`

	User          string `json:"user,omitempty"`
	Pass          string `json:"pass,omitempty"`
	PasvIP        string `json:"pasv-ip,omitempty"`
	UploadPorts   string `json:"upload-ports,omitempty"`
	DownloadPorts string `json:"download-ports,omitempty"`
	TLS           bool   `json:"tls,omitempty"`
}

type JsonClientConfigImpl struct {
	Type       string `json:"type"`
	Tag        string `json:"tag,omitempty"`
	Listen     string `json:"listen"`                // local bind (forward) or remote bind (reverse)
	Address    string `json:"address"`               // tunnel server
	ReverseTag string `json:"reverse-tag,omitempty"` // service tag in this file's server array
	Cert       string `json:"cert,omitempty"`

	EncKey         string `json:"enc-key,omitempty"`
	Protocol       string `json:"protocol,omitempty"`
	Sni            string `json:"sni,omitempty"`
	Insecure       bool   `json:"insecure,omitempty"`
	FollowRedirect *bool  `json:"redirect-follow,omitempty"`
	FrontHost      string `json:"front-host,omitempty"`
	Uplink         string `json:"uplink,omitempty"`
	Verbose        bool   `json:"verbose,omitempty"`

	Proxy string `json:"proxy,omitempty"`

	User             string `json:"user,omitempty"`
	Pass             string `json:"pass,omitempty"`
	UploadChannels   int    `json:"upload-channels,omitempty"`
	DownloadChannels int    `json:"download-channels,omitempty"`
	OverrideUpAddr   string `json:"override-up-addr,omitempty"`
	OverrideDownAddr string `json:"override-down-addr,omitempty"`
	Decoy            bool   `json:"decoy,omitempty"`
	TLS              bool   `json:"tls,omitempty"`
}

func Load(path string) JsonConfigImpl {
	lg := ptlog.PTLog{"system"}
	lg.Info("Loading config file:", path)
	bytes, err := os.ReadFile(path)
	if err != nil {
		lg.Fatal("Can't access the config file", err)
	}

	err = json.Unmarshal(bytes, &Config)
	if err != nil {
		lg.Fatal("Failed to parse config file", err)
	}
	lg.Info("Loaded successfully...")
	return Config
}

func Save(path string, config JsonConfigImpl) error {
	lg := ptlog.PTLog{LogTag: "system"}
	bytes, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, bytes, 0o644); err != nil {
		return err
	}
	lg.Info("Saved config file:", path)
	return nil
}

func (c JsonServerConfigImpl) TrimTag() string {
	return strings.TrimSpace(c.Tag)
}

func (c JsonServerConfigImpl) TrimTarget() string {
	return strings.TrimSpace(c.Target)
}

func (c JsonClientConfigImpl) TrimReverseTag() string {
	return strings.TrimSpace(c.ReverseTag)
}

func (c JsonClientConfigImpl) TrimTag() string {
	return strings.TrimSpace(c.Tag)
}
