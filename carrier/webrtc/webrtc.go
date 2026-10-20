package webrtc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lord-aali/PT-Proxy/carrier/core"
	"github.com/lord-aali/PT-Proxy/common/ptlog"
	"github.com/lord-aali/PT-Proxy/common/revproxy"
	pion "github.com/pion/webrtc/v4"
)

const signalPath = "/webrtc"

type Config struct {
	Listen      string
	Address     string
	Target      string
	EncKey      string
	ReverseAddr string
	SkipUDP     bool
	PadMax      int
	JitterMax   time.Duration
	LogTag      string
	DNSNetwork  string
	DNSUpstream string
	STUN        string
	PublicIP    string
	Redirect    string
	ServeDir    string
	Backend     string
}

type signalMessage struct {
	Type string `json:"type"`
	SDP  string `json:"sdp"`
}

func RunServer(cfg Config) error {
	lg := ptlog.PTLog{LogTag: cfg.LogTag}
	enc, err := core.NewEncryptor([]byte(cfg.EncKey))
	if err != nil {
		return err
	}
	api := newAPI(cfg.PublicIP)
	var proxy http.Handler
	if strings.TrimSpace(cfg.Backend) != "" {
		proxy, err = revproxy.New(cfg.Backend)
		if err != nil {
			return err
		}
	}
	// /webrtc stays the signaling path. Every other path can be proxied.
	local := newCover(cfg.Redirect, cfg.ServeDir, nil)
	cover := newCover(cfg.Redirect, cfg.ServeDir, proxy)
	mux := http.NewServeMux()
	mux.HandleFunc(signalPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			local.ServeHTTP(w, r)
			return
		}
		answer, err := acceptOffer(api, enc, cfg, r)
		if err != nil {
			lg.Error("webrtc offer:", err)
			http.Error(w, "bad offer", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(answer)
	})
	mux.Handle("/", cover)
	lg.Info("carrier webrtc signaling", cfg.Listen+signalPath)
	return http.ListenAndServe(cfg.Listen, mux)
}

// newCover serves non-signaling requests the same way DPI does:
// redirect, then backend reverse proxy, then a static directory.
func newCover(redirect, serveDir string, proxy http.Handler) http.Handler {
	var files http.Handler
	if strings.TrimSpace(serveDir) != "" {
		files = http.FileServer(http.Dir(serveDir))
	}
	redirect = strings.TrimSpace(redirect)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if redirect != "" {
			http.Redirect(w, r, redirect, http.StatusFound)
			return
		}
		if proxy != nil {
			proxy.ServeHTTP(w, r)
			return
		}
		if files != nil {
			files.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><title>Service</title></head><body><h1>Service Unavailable</h1></body></html>`))
	})
}

func acceptOffer(api *pion.API, enc *core.Encryptor, cfg Config, r *http.Request) (signalMessage, error) {
	var offer signalMessage
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return signalMessage{}, err
	}
	if err := json.Unmarshal(body, &offer); err != nil {
		return signalMessage{}, err
	}
	if offer.SDP == "" {
		return signalMessage{}, fmt.Errorf("empty sdp")
	}
	pc, err := api.NewPeerConnection(pionConfig(cfg.STUN))
	if err != nil {
		return signalMessage{}, err
	}
	pc.OnDataChannel(func(dc *pion.DataChannel) {
		dc.OnOpen(func() {
			link := newLink(dc, enc, cfg.PadMax, cfg.JitterMax)
			go func() {
				core.Serve(link, core.ServerConfig{
					Target:      cfg.Target,
					SkipUDP:     cfg.SkipUDP,
					DNSNetwork:  cfg.DNSNetwork,
					DNSUpstream: cfg.DNSUpstream,
				})
				_ = pc.Close()
			}()
		})
	})
	if err := pc.SetRemoteDescription(pion.SessionDescription{
		Type: pion.SDPTypeOffer,
		SDP:  offer.SDP,
	}); err != nil {
		_ = pc.Close()
		return signalMessage{}, err
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		_ = pc.Close()
		return signalMessage{}, err
	}
	gather := pion.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(answer); err != nil {
		_ = pc.Close()
		return signalMessage{}, err
	}
	select {
	case <-gather:
	case <-time.After(15 * time.Second):
		_ = pc.Close()
		return signalMessage{}, fmt.Errorf("ice gather timeout")
	}
	local := pc.LocalDescription()
	if local == nil {
		_ = pc.Close()
		return signalMessage{}, fmt.Errorf("no local description")
	}
	return signalMessage{Type: "answer", SDP: local.SDP}, nil
}

func RunClient(cfg Config) error {
	lg := ptlog.PTLog{LogTag: cfg.LogTag}
	enc, err := core.NewEncryptor([]byte(cfg.EncKey))
	if err != nil {
		return err
	}
	signalURL, err := signalEndpoint(cfg.Address)
	if err != nil {
		return err
	}
	api := newAPI("")
	for {
		err := runClientOnce(api, enc, cfg, signalURL, lg)
		if err != nil {
			lg.Error("webrtc:", err)
		}
		time.Sleep(time.Second)
	}
}

func runClientOnce(api *pion.API, enc *core.Encryptor, cfg Config, signalURL string, lg ptlog.PTLog) error {
	pc, err := api.NewPeerConnection(pionConfig(cfg.STUN))
	if err != nil {
		return err
	}
	defer pc.Close()

	dc, err := pc.CreateDataChannel("ptproxy", nil)
	if err != nil {
		return err
	}
	opened := make(chan struct{})
	dc.OnOpen(func() {
		select {
		case <-opened:
		default:
			close(opened)
		}
	})

	offer, err := pc.CreateOffer(nil)
	if err != nil {
		return err
	}
	gather := pion.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(offer); err != nil {
		return err
	}
	select {
	case <-gather:
	case <-time.After(15 * time.Second):
		return fmt.Errorf("ice gather timeout")
	}
	local := pc.LocalDescription()
	if local == nil {
		return fmt.Errorf("no local description")
	}
	answer, err := postOffer(signalURL, signalMessage{Type: "offer", SDP: local.SDP})
	if err != nil {
		return err
	}
	if err := pc.SetRemoteDescription(pion.SessionDescription{
		Type: pion.SDPTypeAnswer,
		SDP:  answer.SDP,
	}); err != nil {
		return err
	}
	select {
	case <-opened:
	case <-time.After(20 * time.Second):
		return fmt.Errorf("datachannel timeout")
	}
	lg.Info("webrtc datachannel open")
	link := newLink(dc, enc, cfg.PadMax, cfg.JitterMax)
	link.readWait = 15 * time.Second
	if err := core.HandshakeClient(link); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	link.readWait = 0
	sess := core.NewClientSession(link, cfg.ReverseAddr)
	defer sess.Close()
	if cfg.ReverseAddr != "" {
		return core.RunClientSocks(sess, core.SocksConfig{
			Listen:      cfg.Listen,
			ReverseAddr: cfg.ReverseAddr,
			SkipUDP:     cfg.SkipUDP,
			LogTag:      cfg.LogTag,
		})
	}
	return core.RunClientForward(sess, cfg.Listen, "", cfg.SkipUDP, cfg.LogTag)
}

func postOffer(url string, offer signalMessage) (signalMessage, error) {
	body, err := json.Marshal(offer)
	if err != nil {
		return signalMessage{}, err
	}
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return signalMessage{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return signalMessage{}, fmt.Errorf("signaling %s", resp.Status)
	}
	var answer signalMessage
	if err := json.NewDecoder(resp.Body).Decode(&answer); err != nil {
		return signalMessage{}, err
	}
	if answer.SDP == "" {
		return signalMessage{}, fmt.Errorf("empty answer")
	}
	return answer, nil
}

func signalEndpoint(address string) (string, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", fmt.Errorf("webrtc address required")
	}
	if !strings.Contains(address, "://") {
		address = "http://" + address
	}
	if !strings.HasSuffix(strings.TrimRight(address, "/"), signalPath) {
		address = strings.TrimRight(address, "/") + signalPath
	}
	return address, nil
}

func newAPI(publicIP string) *pion.API {
	se := pion.SettingEngine{}
	se.SetIncludeLoopbackCandidate(true)
	se.SetNetworkTypes([]pion.NetworkType{pion.NetworkTypeUDP4})
	if ip := strings.TrimSpace(publicIP); ip != "" {
		se.SetNAT1To1IPs([]string{ip}, pion.ICECandidateTypeHost)
	}
	return pion.NewAPI(pion.WithSettingEngine(se))
}

func pionConfig(stun string) pion.Configuration {
	stun = strings.TrimSpace(stun)
	if stun == "" {
		return pion.Configuration{}
	}
	if !strings.Contains(stun, ":") {
		stun = "stun:" + stun
	}
	return pion.Configuration{
		ICEServers: []pion.ICEServer{{URLs: []string{stun}}},
	}
}
