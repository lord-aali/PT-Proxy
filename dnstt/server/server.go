package server

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/lord-aali/PT-Proxy/dnstt/dns"
	"github.com/lord-aali/PT-Proxy/dnstt/keys"
	"github.com/lord-aali/PT-Proxy/dnstt/noise"
	"github.com/lord-aali/PT-Proxy/dnstt/turbotunnel"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

const (
	// smux streams will be closed after this much time without receiving data.
	idleTimeout = 2 * time.Minute

	// How to set the TTL field in Answer resource records.
	responseTTL = 60

	// How long we may wait for downstream data before sending an empty
	// response. If another query comes in while we are waiting, we'll send
	// an empty response anyway and restart the delay timer for the next
	// response.
	//
	// This number should be less than 2 seconds, which in 2019 was reported
	// to be the query timeout of the Quad9 DoH server.
	// https://dnsencryption.info/imc19-doe.html Section 4.2, Finding 2.4
	// Short on purpose. The client only waits a couple of seconds for the
	// matching UDP reply; a one-second pause on every query lets a burst
	// from a browser miss that window and then retry forever.
	maxResponseDelay = 100 * time.Millisecond

	// How long to wait for a TCP connection to upstream to be established.
	upstreamDialTimeout = 30 * time.Second
)

// DefaultUDPPayload is the maximum DNS response UDP payload. 1280 is the
// minimum IPv6 MTU, 40 bytes is the IPv6 header, and 8 bytes is the UDP header.
// An EDNS buffer of 1232 avoids fragmentation on nearly all current networks.
const DefaultUDPPayload = 1280 - 40 - 8

// base32Encoding is a base32 encoding without padding.
var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func handleStream(stream *smux.Stream, upstream string, conv uint32) error {
	dialer := net.Dialer{
		Timeout: upstreamDialTimeout,
	}
	upstreamConn, err := dialer.Dial("tcp", upstream)
	if err != nil {
		return fmt.Errorf("stream %08x:%d connect upstream: %v", conv, stream.ID(), err)
	}
	defer upstreamConn.Close()
	upstreamTCPConn := upstreamConn.(*net.TCPConn)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, upstreamTCPConn)
		if err == io.EOF {
			// smux Stream.Write may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy streamâ†upstream: %v", conv, stream.ID(), err)
		}
		upstreamTCPConn.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(upstreamTCPConn, stream)
		if err == io.EOF {
			// smux Stream.WriteTo may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy upstreamâ†stream: %v", conv, stream.ID(), err)
		}
		upstreamTCPConn.CloseWrite()
	}()
	wg.Wait()

	return nil
}

// acceptStreams wraps a KCP session in a Noise channel and an smux.Session,
// then awaits smux streams. It passes each stream to handleStream.
func acceptStreams(conn *kcp.UDPSession, privkey []byte, upstream string) error {
	// Put a Noise channel on top of the KCP conn.
	rw, err := noise.NewServer(conn, privkey)
	if err != nil {
		return err
	}

	// Put an smux session on top of the encrypted Noise channel.
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024 // default is 65536
	sess, err := smux.Server(rw, smuxConfig)
	if err != nil {
		return err
	}
	defer sess.Close()

	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				log.Printf("AcceptStream temporary error: %v", err)
				continue
			}
			return err
		}
		log.Printf("begin stream %08x:%d", conn.GetConv(), stream.ID())
		go func() {
			defer func() {
				log.Printf("end stream %08x:%d", conn.GetConv(), stream.ID())
				stream.Close()
			}()
			err := handleStream(stream, upstream, conn.GetConv())
			if err != nil {
				log.Printf("stream %08x:%d handleStream: %v", conn.GetConv(), stream.ID(), err)
			}
		}()
	}
}

// acceptSessions listens for incoming KCP connections and passes them to
// acceptStreams.
func acceptSessions(ln *kcp.Listener, privkey []byte, caps answerCaps, upstream string) error {
	for {
		conn, err := ln.AcceptKCP()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				log.Printf("AcceptKCP temporary error: %v", err)
				continue
			}
			return err
		}
		log.Printf("begin session %08x", conn.GetConv())
		// Permit coalescing the payloads of consecutive sends.
		conn.SetStreamMode(true)
		// Disable the dynamic congestion window (limit only by the
		// maximum of local and remote static windows).
		conn.SetNoDelay(
			0,   // default nodelay
			200, // millisecond update; 0 becomes 10 and retransmits faster than DNS can answer
			0,   // default resend
			1,   // nc=1 => congestion window off
		)
		conn.SetWindowSize(turbotunnel.WindowSize, turbotunnel.WindowSize)
		conn.SetACKNoDelay(true)
		mtu := caps.mtu(qtypeOf(conn.RemoteAddr()))
		if rc := conn.SetMtu(mtu); !rc {
			log.Printf("session %08x: MTU %d rejected", conn.GetConv(), mtu)
			conn.Close()
			continue
		}
		go func() {
			defer func() {
				log.Printf("end session %08x", conn.GetConv())
				conn.Close()
			}()
			err := acceptStreams(conn, privkey, upstream)
			if err != nil && !errors.Is(err, io.ErrClosedPipe) {
				log.Printf("session %08x acceptStreams: %v", conn.GetConv(), err)
			}
		}()
	}
}

// nextPacket reads the next length-prefixed packet from r, ignoring padding. It
// returns a nil error only when a packet was read successfully. It returns
// io.EOF only when there were 0 bytes remaining to read from r. It returns
// io.ErrUnexpectedEOF when EOF occurs in the middle of an encoded packet.
//
// The prefixing scheme is as follows. A length prefix L < 0xe0 means a data
// packet of L bytes. A length prefix L >= 0xe0 means padding of L - 0xe0 bytes
// (not counting the length of the length prefix itself).
func nextPacket(r *bytes.Reader) ([]byte, error) {
	// Convert io.EOF to io.ErrUnexpectedEOF.
	eof := func(err error) error {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}

	for {
		prefix, err := r.ReadByte()
		if err != nil {
			// We may return a real io.EOF only here.
			return nil, err
		}
		if prefix >= 224 {
			paddingLen := prefix - 224
			_, err := io.CopyN(io.Discard, r, int64(paddingLen))
			if err != nil {
				return nil, eof(err)
			}
		} else {
			p := make([]byte, int(prefix))
			_, err = io.ReadFull(r, p)
			return p, eof(err)
		}
	}
}

// responseFor constructs a response dns.Message that is appropriate for query.
// Along with the dns.Message, it returns the query's decoded data payload. If
// the returned dns.Message is nil, it means that there should be no response to
// this query. If the returned dns.Message has an Rcode() of dns.RcodeNoError,
// the message is a candidate for for carrying downstream data in a TXT record.
func responseFor(query *dns.Message, domain dns.Name, minPayload int) (*dns.Message, []byte) {
	resp := &dns.Message{
		ID:       query.ID,
		Flags:    0x8000, // QR = 1, RCODE = no error
		Question: query.Question,
	}

	if query.Flags&0x8000 != 0 {
		// QR != 0, this is not a query. Don't even send a response.
		return nil, nil
	}

	// Check for EDNS(0) support. Include our own OPT RR only if we receive
	// one from the requester.
	// https://tools.ietf.org/html/rfc6891#section-6.1.1
	// "Lack of presence of an OPT record in a request MUST be taken as an
	// indication that the requester does not implement any part of this
	// specification and that the responder MUST NOT include an OPT record
	// in its response."
	payloadSize := 0
	for _, rr := range query.Additional {
		if rr.Type != dns.RRTypeOPT {
			continue
		}
		if len(resp.Additional) != 0 {
			// https://tools.ietf.org/html/rfc6891#section-6.1.1
			// "If a query message with more than one OPT RR is
			// received, a FORMERR (RCODE=1) MUST be returned."
			resp.Flags |= dns.RcodeFormatError
			log.Printf("FORMERR: more than one OPT RR")
			return resp, nil
		}
		resp.Additional = append(resp.Additional, dns.RR{
			Name:  dns.Name{},
			Type:  dns.RRTypeOPT,
			Class: 4096, // responder's UDP payload size
			TTL:   0,
			Data:  []byte{},
		})
		additional := &resp.Additional[0]

		version := (rr.TTL >> 16) & 0xff
		if version != 0 {
			// https://tools.ietf.org/html/rfc6891#section-6.1.1
			// "If a responder does not implement the VERSION level
			// of the request, then it MUST respond with
			// RCODE=BADVERS."
			resp.Flags |= dns.ExtendedRcodeBadVers & 0xf
			additional.TTL = (dns.ExtendedRcodeBadVers >> 4) << 24
			log.Printf("BADVERS: EDNS version %d != 0", version)
			return resp, nil
		}

		payloadSize = int(rr.Class)
	}
	if payloadSize < 512 {
		// https://tools.ietf.org/html/rfc6891#section-6.1.1 "Values
		// lower than 512 MUST be treated as equal to 512."
		payloadSize = 512
	}
	// We will return RcodeFormatError if payloadSize is too small, but
	// first, check the name in order to set the AA bit properly.

	// There must be exactly one question.
	if len(query.Question) != 1 {
		resp.Flags |= dns.RcodeFormatError
		log.Printf("FORMERR: too few or too many questions (%d)", len(query.Question))
		return resp, nil
	}
	question := query.Question[0]
	// Check the name to see if it ends in our chosen domain, and extract
	// all that comes before the domain if it does. If it does not, we will
	// return RcodeNameError below, but prefer to return RcodeFormatError
	// for payload size if that applies as well.
	prefix, ok := question.Name.TrimSuffix(domain)
	if !ok {
		// Not a name we are authoritative for.
		resp.Flags |= dns.RcodeNameError
		log.Printf("NXDOMAIN: not authoritative for %s", question.Name)
		return resp, nil
	}
	resp.Flags |= 0x0400 // AA = 1

	if query.Opcode() != 0 {
		// We don't support OPCODE != QUERY.
		resp.Flags |= dns.RcodeNotImplemented
		log.Printf("NOTIMPL: unrecognized OPCODE %d", query.Opcode())
		return resp, nil
	}

	switch question.Type {
	case dns.RRTypeTXT, dns.RRTypeA, dns.RRTypeAAAA:
	default:
		// Resolvers also ask for NS and similar while looking up the name.
		// Those are not tunnel queries.
		resp.Flags |= dns.RcodeNameError
		return resp, nil
	}

	encoded := bytes.ToUpper(bytes.Join(prefix, nil))
	payload := make([]byte, base32Encoding.DecodedLen(len(encoded)))
	n, err := base32Encoding.Decode(payload, encoded)
	if err != nil {
		// Base32 error, make like the name doesn't exist.
		resp.Flags |= dns.RcodeNameError
		log.Printf("NXDOMAIN: base32 decoding: %v", err)
		return resp, nil
	}
	payload = payload[:n]

	// We require clients to support EDNS(0) with a minimum payload size;
	// otherwise we would have to set a small KCP MTU (only around 200
	// bytes). https://tools.ietf.org/html/rfc6891#section-7 "If there is a
	// problem with processing the OPT record itself, such as an option
	// value that is badly formatted or that includes out-of-range values, a
	// FORMERR MUST be returned."
	if payloadSize < minPayload {
		resp.Flags |= dns.RcodeFormatError
		log.Printf("FORMERR: requester payload size %d is too small (minimum %d)", payloadSize, minPayload)
		return resp, nil
	}

	return resp, payload
}

// record represents a DNS message appropriate for a response to a previously
// received query, along with metadata necessary for sending the response.
// recvLoop sends instances of record to sendLoop via a channel. sendLoop
// receives instances of record and may fill in the message's Answer section
// before sending it.
type record struct {
	Resp     *dns.Message
	Addr     net.Addr
	ClientID turbotunnel.ClientID
}

// recvLoop repeatedly calls dnsConn.ReadFrom, extracts the packets contained in
// the incoming DNS queries, and puts them on ttConn's incoming queue. Whenever
// a query calls for a response, constructs a partial response and passes it to
// sendLoop over ch. A response is never discarded: it is the only way the
// client learns that its segments arrived. stop unblocks the waits on shutdown.
func recvLoop(domain dns.Name, minPayload int, aeadKey []byte, dnsConn net.PacketConn, ttConn *turbotunnel.QueuePacketConn, ch chan<- *record, stop <-chan struct{}) error {
	for {
		var buf [4096]byte
		n, addr, err := dnsConn.ReadFrom(buf[:])
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			// A transient UDP error, including Windows reporting
			// ICMP port unreachable as a connection reset, must not
			// tear the session down.
			log.Printf("dns read: %v", err)
			continue
		}

		// Got a UDP packet. Try to parse it as a DNS message.
		query, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil {
			log.Printf("cannot parse DNS query: %v", err)
			continue
		}

		resp, payload := responseFor(&query, domain, minPayload)
		if len(payload) > 0 {
			plain, err := keys.Open(aeadKey, payload)
			if err != nil {
				log.Printf("NXDOMAIN: query decrypt: %v", err)
				payload = nil
				if resp != nil && resp.Rcode() == dns.RcodeNoError {
					resp.Flags |= dns.RcodeNameError
				}
			} else {
				payload = plain
			}
		}
		// Extract the ClientID from the payload.
		var clientID turbotunnel.ClientID
		n = copy(clientID[:], payload)
		payload = payload[n:]
		if n == len(clientID) {
			if len(query.Question) == 1 {
				noteQType(clientID, query.Question[0].Type)
			}
			// Discard padding and pull out the packets contained in
			// the payload.
			r := bytes.NewReader(payload)
			for {
				p, err := nextPacket(r)
				if err != nil {
					break
				}
				// Feed the incoming packet to KCP.
				if !ttConn.QueueIncoming(p, clientID, stop) {
					return net.ErrClosed
				}
			}
		} else {
			// Payload is not long enough to contain a ClientID.
			if resp != nil && resp.Rcode() == dns.RcodeNoError {
				resp.Flags |= dns.RcodeNameError
				log.Printf("NXDOMAIN: %d bytes are too short to contain a ClientID", n)
			}
		}
		// Every accepted query gets a response. Dropping it here is what
		// left the client retransmitting into a full queue: the payload
		// was already handed to KCP, but the acknowledgement never left.
		if resp != nil {
			select {
			case ch <- &record{resp, addr, clientID}:
			case <-stop:
				return net.ErrClosed
			}
		}
	}
}

// sendLoop repeatedly receives records from ch. Those that represent an error
// response, it sends on the network immediately. Those that represent a
// response capable of carrying data, it packs full of as many packets as will
// fit while keeping the total size under maxEncodedPayload, then sends it.
func sendLoop(dnsConn net.PacketConn, ttConn *turbotunnel.QueuePacketConn, ch <-chan *record, caps answerCaps, udpLimit int, aeadKey []byte, stop <-chan struct{}) error {
	var nextRec *record
	for {
		rec := nextRec
		nextRec = nil

		if rec == nil {
			var ok bool
			select {
			case <-stop:
				return net.ErrClosed
			case rec, ok = <-ch:
				if !ok {
					return nil
				}
			}
		}

		if rec.Resp.Rcode() == dns.RcodeNoError && len(rec.Resp.Question) == 1 {
			// If it's a non-error response, we can fill the Answer
			// section with downstream packets.

			// Any changes to how responses are built need to happen
			// also in computeMaxEncodedPayload.
			rec.Resp.Answer = []dns.RR{
				{
					Name:  rec.Resp.Question[0].Name,
					Type:  rec.Resp.Question[0].Type,
					Class: rec.Resp.Question[0].Class,
					TTL:   responseTTL,
					Data:  nil, // will be filled in below
				},
			}

			var payload bytes.Buffer
			// Ciphertext is plaintext plus the nonce and tag, and that
			// ciphertext is what has to fit in this query's answer type.
			qtype := rec.Resp.Question[0].Type
			limit := caps.forType(qtype) - keys.Overhead
			// We loop and bundle as many packets from OutgoingQueue
			// into the response as will fit. Any packet that would
			// overflow the capacity of the DNS response, we stash
			// to be bundled into a future response.
			timer := time.NewTimer(maxResponseDelay)
			timerExpired := false
			for {
				var p []byte
				unstash := ttConn.Unstash(rec.ClientID)
				outgoing := ttConn.OutgoingQueue(rec.ClientID)
				// Prioritize taking a packet first from the
				// stash, then from the outgoing queue, then
				// finally check for the expiration of the timer
				// or for a receive on ch (indicating a new
				// query that we must respond to).
				select {
				case p = <-unstash:
				default:
					select {
					case p = <-unstash:
					case p = <-outgoing:
					default:
						select {
						case p = <-unstash:
						case p = <-outgoing:
						case <-timer.C:
							timerExpired = true
						case nextRec = <-ch:
						case <-stop:
							if !timer.Stop() {
								select {
								case <-timer.C:
								default:
								}
							}
							return net.ErrClosed
						}
					}
				}
				// We wait for the first packet in a bundle
				// only. The second and later packets must be
				// immediately available or they will be omitted
				// from this bundle.
				if !timerExpired && !timer.Stop() {
					<-timer.C
				}
				timer.Reset(0)
				timerExpired = false

				if len(p) == 0 {
					// timer expired or receive on ch, we
					// are done with this response.
					break
				}

				limit -= 2 + len(p)
				if payload.Len() == 0 {
					// No packet length check for the first
					// packet; if it's too large, we allow
					// it to be truncated and dropped by the
					// receiver.
				} else if limit < 0 {
					// Stash this packet to send in the next
					// response.
					ttConn.Stash(p, rec.ClientID)
					break
				}
				if int(uint16(len(p))) != len(p) {
					panic(len(p))
				}
				binary.Write(&payload, binary.BigEndian, uint16(len(p)))
				payload.Write(p)
			}
			if !timerExpired && !timer.Stop() {
				<-timer.C
			}

			sealed, err := keys.Seal(aeadKey, payload.Bytes())
			if err != nil {
				log.Printf("answer encrypt: %v", err)
				continue
			}
			rec.Resp.Answer = answerRRs(rec.Resp.Question[0].Name, qtype, rec.Resp.Question[0].Class, responseTTL, sealed)
		}

		buf, err := rec.Resp.WireFormat()
		if err != nil {
			log.Printf("resp WireFormat: %v", err)
			continue
		}
		// Truncate if necessary.
		// https://tools.ietf.org/html/rfc1035#section-4.1.1
		if len(buf) > udpLimit {
			log.Printf("truncating response of %d bytes to max of %d", len(buf), udpLimit)
			buf = buf[:udpLimit]
			buf[2] |= 0x02 // TC = 1
		}

		// Now we actually send the message as a UDP packet.
		_, err = dnsConn.WriteTo(buf, rec.Addr)
		if err != nil {
			// net.ErrClosed means we'll never be able to send on
			// dnsConn, so terminate the loop. Treat all other
			// errors as temporary and simply log them.
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			log.Printf("WriteTo error: %v", err)
			continue
		}
	}
	return nil
}

// answerCaps is the largest sealed blob that fits in one answer of each type,
// for a maximum-length query name.
type answerCaps struct {
	txt, a, aaaa int
}

func (c answerCaps) forType(qtype uint16) int {
	switch qtype {
	case dns.RRTypeA:
		return c.a
	case dns.RRTypeAAAA:
		return c.aaaa
	default:
		return c.txt
	}
}

func (c answerCaps) mtu(qtype uint16) int {
	n := c.forType(qtype) - keys.Overhead - 2
	if n < 0 {
		return 0
	}
	return n
}

// answerRRs encodes a sealed blob into one TXT record, or a run of A or AAAA
// records. Each address starts with its position so a resolver can reorder
// the records without changing the ciphertext.
func answerRRs(name dns.Name, qtype, class uint16, ttl uint32, sealed []byte) []dns.RR {
	if qtype != dns.RRTypeA && qtype != dns.RRTypeAAAA {
		return []dns.RR{{
			Name:  name,
			Type:  qtype,
			Class: class,
			TTL:   ttl,
			Data:  dns.EncodeRDataTXT(sealed),
		}}
	}
	chunk := 4
	if qtype == dns.RRTypeAAAA {
		chunk = 16
	}
	parts, err := dns.PackAddrRecords(sealed, chunk)
	if err != nil {
		return nil
	}
	rrs := make([]dns.RR, 0, len(parts))
	for _, part := range parts {
		rrs = append(rrs, dns.RR{
			Name:  name,
			Type:  qtype,
			Class: class,
			TTL:   ttl,
			Data:  part,
		})
	}
	return rrs
}

var clientQType sync.Map

func noteQType(id turbotunnel.ClientID, qtype uint16) {
	clientQType.Store(id.String(), qtype)
}

func qtypeOf(addr net.Addr) uint16 {
	if addr == nil {
		return dns.RRTypeTXT
	}
	v, ok := clientQType.Load(addr.String())
	if !ok {
		return dns.RRTypeTXT
	}
	qtype, ok := v.(uint16)
	if !ok {
		return dns.RRTypeTXT
	}
	return qtype
}

// computeSealedCap is the largest sealed blob that fits in an answer of qtype
// under limit, when the question name is the maximum length. It stays in sync
// with answerRRs.
func computeSealedCap(qtype uint16, limit int) int {
	maxLengthName, err := dns.NewName([][]byte{
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
	})
	if err != nil {
		panic(err)
	}
	queryLimit := uint16(limit)
	if int(queryLimit) != limit {
		queryLimit = 0xffff
	}
	resp := &dns.Message{
		Flags: 0x8400,
		Question: []dns.Question{{
			Name:  maxLengthName,
			Type:  qtype,
			Class: dns.ClassIN,
		}},
		Additional: []dns.RR{{
			Name:  dns.Name{},
			Type:  dns.RRTypeOPT,
			Class: queryLimit,
			TTL:   0,
			Data:  []byte{},
		}},
	}
	low := 0
	high := 4096
	for low+1 < high {
		mid := (low + high) / 2
		resp.Answer = answerRRs(maxLengthName, qtype, dns.ClassIN, responseTTL, make([]byte, mid))
		if len(resp.Answer) == 0 {
			high = mid
			continue
		}
		buf, err := resp.WireFormat()
		if err != nil {
			panic(err)
		}
		if len(buf) <= limit {
			low = mid
		} else {
			high = mid
		}
	}
	return low
}

// Config is an authoritative DNS listener that forwards each smux stream to Target.
type Config struct {
	Listen  string
	Domain  dns.Name
	EncKey  string
	Target  string
	UDPSize int // 0 uses DefaultUDPPayload
}

// Serve listens on a fresh UDP socket for each session. When a loop exits, the
// socket is closed and the session is started again instead of ending the process.
func Serve(ctx context.Context, cfg Config) error {
	if cfg.UDPSize <= 0 {
		cfg.UDPSize = DefaultUDPPayload
	}
	privkey := keys.NoisePrivkey(cfg.EncKey)
	aeadKey := keys.QNameKey(cfg.EncKey)
	log.Printf("dns pubkey %x", noise.PubkeyFromPrivkey(privkey))

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		dnsConn, err := net.ListenPacket("udp", cfg.Listen)
		if err != nil {
			return fmt.Errorf("opening UDP listener: %w", err)
		}
		stop := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				dnsConn.Close()
			case <-stop:
			}
		}()
		err = runSession(cfg, privkey, aeadKey, dnsConn)
		close(stop)
		dnsConn.Close()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		log.Printf("dns session ended: %v", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func runSession(cfg Config, privkey, aeadKey []byte, dnsConn net.PacketConn) error {
	// Downstream packets have to fit in an answer even when the question
	// name is as long as DNS allows. TXT fits the most. A and AAAA fit
	// less, and a session uses the size of the type its client asked for.
	caps := answerCaps{
		txt:  computeSealedCap(dns.RRTypeTXT, cfg.UDPSize),
		a:    computeSealedCap(dns.RRTypeA, cfg.UDPSize),
		aaaa: computeSealedCap(dns.RRTypeAAAA, cfg.UDPSize),
	}
	mtu := caps.mtu(dns.RRTypeTXT)
	if mtu < 80 || caps.mtu(dns.RRTypeAAAA) < 80 || caps.mtu(dns.RRTypeA) < 80 {
		return fmt.Errorf("maximum UDP payload size of %d leaves txt=%d aaaa=%d a=%d bytes for payload", cfg.UDPSize, mtu, caps.mtu(dns.RRTypeAAAA), caps.mtu(dns.RRTypeA))
	}
	log.Printf("effective MTU txt=%d aaaa=%d a=%d", mtu, caps.mtu(dns.RRTypeAAAA), caps.mtu(dns.RRTypeA))

	// Start up the virtual PacketConn for turbotunnel.
	ttConn := turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, idleTimeout*2)
	defer ttConn.Close()
	ln, err := kcp.ServeConn(nil, 0, 0, ttConn)
	if err != nil {
		return fmt.Errorf("opening KCP listener: %v", err)
	}
	defer ln.Close()

	// We will run acceptSessions, sendLoop, and recvLoop concurrently. The
	// first one to finish closes the done channel.
	doneChan := make(chan struct{})
	var doneOnce sync.Once
	done := func() { doneOnce.Do(func() { close(doneChan) }) }

	go func() {
		defer done()
		err := acceptSessions(ln, privkey, caps, cfg.Target)
		if err != nil {
			log.Printf("acceptSessions: %v", err)
		}
	}()

	// Large enough for a burst of queries. recvLoop blocks when it is full
	// instead of forgetting the query, which is what pushes back on the client.
	ch := make(chan *record, 256)

	go func() {
		defer done()
		err := sendLoop(dnsConn, ttConn, ch, caps, cfg.UDPSize, aeadKey, doneChan)
		if err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("sendLoop: %v", err)
		}
	}()

	go func() {
		defer done()
		err := recvLoop(cfg.Domain, cfg.UDPSize, aeadKey, dnsConn, ttConn, ch, doneChan)
		if err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("recvLoop: %v", err)
		}
	}()

	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		var prev uint64
		for {
			select {
			case <-doneChan:
				return
			case <-t.C:
				sendDrops, recvDrops := ttConn.Dropped()
				total := sendDrops + recvDrops
				if total == 0 || total == prev {
					continue
				}
				prev = total
				log.Printf("dns server: send-drop=%d recv-drop=%d", sendDrops, recvDrops)
			}
		}
	}()

	// A loop exiting used to end the process. Restart instead.
	<-doneChan
	return nil
}
