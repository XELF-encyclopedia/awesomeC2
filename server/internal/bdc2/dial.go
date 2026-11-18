package bdc2

// Native TLS / WSS dialer for operators.
//
// The frozen BDC2 v1 wire format does not change here: this file only adds the
// transport below the WebSocket handshake, so an operator can speak
// wss://c2-operator.example.com/ws straight through Cloudflare + nginx without a
// local TLS bridge. Everything (URL, SNI, pin, dial address) is injected by
// the caller; no host name or IP is compiled in.

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// DialOptions configures DialEndpoint. The zero value is a plain ws:// dial
// with a 10s timeout, system roots and no pinning.
type DialOptions struct {
	Timeout  time.Duration
	MaxFrame int

	// Path is used when the endpoint URL carries no path.
	Path string
	// SNI overrides the TLS server name (and the HTTP Host header) while the
	// TCP connection may still target a different address. Useful for pinning
	// a deployment to an IP family or a loopback test endpoint.
	SNI string
	// DialAddr overrides the TCP dial target (host:port); the URL host is
	// still used for SNI/Host unless SNI is set.
	DialAddr string
	// Family limits address resolution: "auto" (default), "4"/"ipv4", "6"/"ipv6".
	Family string

	Insecure  bool
	TLSCAFile string
	// TLSPin is the SHA-256 of the leaf certificate DER, hex (":" optional)
	// or base64. When set, the peer certificate must match exactly.
	TLSPin string
}

// Endpoint describes a parsed operator endpoint.
type Endpoint struct {
	URL    *url.URL
	TLS    bool
	Host   string
	Port   string
	Path   string
	Family string
}

func (e *Endpoint) String() string {
	scheme := "ws"
	if e.TLS {
		scheme = "wss"
	}
	return scheme + "://" + e.URL.Host + e.Path
}

// ParseEndpoint accepts
//
//	wss://oprand.example.com/ws
//	ws://127.0.0.1:9910/ws
//	oprand.example.com:443          (treated as ws:// for back-compat)
//	127.0.0.1:9910
//
// and normalises it. A bare host:port keeps the historical plaintext default;
// TLS must be requested explicitly with the wss:// scheme.
func ParseEndpoint(endpoint, defPath, family string) (*Endpoint, error) {
	raw := strings.TrimSpace(endpoint)
	if raw == "" {
		return nil, errors.New("empty endpoint")
	}
	if !strings.Contains(raw, "://") {
		raw = "ws://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("endpoint: %w", err)
	}
	tlsOn := false
	switch strings.ToLower(u.Scheme) {
	case "ws":
	case "wss":
		tlsOn = true
	default:
		return nil, fmt.Errorf("endpoint scheme must be ws or wss, got %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("endpoint %q has no host", endpoint)
	}
	port := u.Port()
	if port == "" {
		if tlsOn {
			port = "443"
		} else {
			port = "80"
		}
	}
	path := u.RequestURI()
	if path == "" || path == "/" {
		if defPath == "" {
			defPath = "/ws"
		}
		path = defPath
	}
	fam := strings.ToLower(strings.TrimSpace(family))
	switch fam {
	case "", "auto":
		fam = "auto"
	case "4", "v4", "ipv4":
		fam = "4"
	case "6", "v6", "ipv6":
		fam = "6"
	default:
		return nil, fmt.Errorf("family must be auto|4|6, got %q", family)
	}
	return &Endpoint{URL: u, TLS: tlsOn, Host: host, Port: port, Path: path, Family: fam}, nil
}

func dialNetwork(family string) string {
	switch family {
	case "4":
		return "tcp4"
	case "6":
		return "tcp6"
	default:
		return "tcp"
	}
}

// DialEndpoint connects to a ws:// or wss:// endpoint, performs the native TLS
// handshake (for wss) and then the RFC6455 client handshake.
func DialEndpoint(endpoint string, opt DialOptions) (*WSConn, *Endpoint, error) {
	ep, err := ParseEndpoint(endpoint, opt.Path, opt.Family)
	if err != nil {
		return nil, nil, err
	}
	timeout := opt.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dialAddr := strings.TrimSpace(opt.DialAddr)
	if dialAddr == "" {
		dialAddr = net.JoinHostPort(ep.Host, ep.Port)
	} else if _, _, err := net.SplitHostPort(dialAddr); err != nil {
		dialAddr = net.JoinHostPort(dialAddr, ep.Port)
	}

	conn, err := net.DialTimeout(dialNetwork(ep.Family), dialAddr, timeout)
	if err != nil {
		return nil, ep, fmt.Errorf("dial %s/%s: %w", dialNetwork(ep.Family), dialAddr, err)
	}
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}
	if ep.TLS {
		cfg, err := buildTLSConfig(ep.Host, opt)
		if err != nil {
			conn.Close()
			return nil, ep, err
		}
		tc := tls.Client(conn, cfg)
		if err := tc.Handshake(); err != nil {
			conn.Close()
			return nil, ep, fmt.Errorf("tls handshake %s (sni=%q): %w", dialAddr, cfg.ServerName, err)
		}
		conn = tc
	}

	hostName := ep.Host
	if opt.SNI != "" {
		hostName = opt.SNI
	}
	defPort := "80"
	if ep.TLS {
		defPort = "443"
	}
	hostHeader := hostName
	if ep.Port != defPort {
		hostHeader = net.JoinHostPort(hostName, ep.Port)
	}

	max := opt.MaxFrame
	if max <= 0 {
		max = MaxFrame
	}
	ws, err := wsClientHandshake(conn, hostHeader, ep.Path, timeout, max)
	if err != nil {
		conn.Close()
		return nil, ep, err
	}
	return ws, ep, nil
}

func buildTLSConfig(host string, opt DialOptions) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	// ServerName drives both certificate verification and (for DNS names) SNI.
	// crypto/tls suppresses SNI automatically for IP literals while still
	// verifying IP SANs, so an IP target works without -insecure.
	cfg.ServerName = host
	if opt.SNI != "" {
		cfg.ServerName = opt.SNI
	}
	if opt.Insecure {
		cfg.InsecureSkipVerify = true
	}
	if opt.TLSCAFile != "" {
		pem, err := os.ReadFile(opt.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("tls-ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("tls-ca %s: no valid PEM certificates", opt.TLSCAFile)
		}
		cfg.RootCAs = pool
	}
	if opt.TLSPin != "" {
		want, err := ParsePin(opt.TLSPin)
		if err != nil {
			return nil, err
		}
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("tls pin: no peer certificate")
			}
			got := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(got[:], want) != 1 {
				return fmt.Errorf("tls pin mismatch: got sha256:%x", got)
			}
			return nil
		}
	}
	return cfg, nil
}

// ParsePin decodes a SHA-256 certificate fingerprint given as hex (colons and
// spaces optional, "sha256:" prefix optional) or standard/URL base64.
func ParsePin(s string) ([]byte, error) {
	v := strings.TrimSpace(s)
	v = strings.TrimPrefix(strings.ToLower(v), "sha256:")
	compact := strings.NewReplacer(":", "", " ", "", "-", "").Replace(v)
	if b, err := hex.DecodeString(compact); err == nil && len(b) == sha256.Size {
		return b, nil
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(strings.TrimSpace(s)); err == nil && len(b) == sha256.Size {
			return b, nil
		}
	}
	return nil, errors.New("tls-pin must be a 32-byte SHA-256 in hex or base64")
}

func wsClientHandshake(conn net.Conn, hostHeader, path string, timeout time.Duration, maxFrame int) (*WSConn, error) {
	kb := make([]byte, 16)
	randRead(kb)
	key := base64.StdEncoding.EncodeToString(kb)
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", path, hostHeader, key)
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(conn, 32*1024)
	status, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if !strings.Contains(status, "101") {
		return nil, fmt.Errorf("ws handshake failed: %s", strings.TrimSpace(status))
	}
	var headers []string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
		headers = append(headers, line)
	}
	want := wsAccept(key)
	got := ""
	for _, l := range headers {
		if strings.HasPrefix(strings.ToLower(l), "sec-websocket-accept:") {
			got = strings.TrimSpace(l[len("sec-websocket-accept:"):])
		}
	}
	if got != want {
		return nil, errors.New("ws handshake: bad accept")
	}
	_ = conn.SetDeadline(time.Time{})
	return newWSConn(conn, br, true, maxFrame), nil
}

// TLSVersionName is a small helper for operator logging.
func TLSVersionName(conn net.Conn) string {
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return ""
	}
	cs := tc.ConnectionState()
	switch cs.Version {
	case tls.VersionTLS13:
		return "TLSv1.3"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS10:
		return "TLSv1.0"
	default:
		return "TLS(" + strconv.Itoa(int(cs.Version)) + ")"
	}
}
