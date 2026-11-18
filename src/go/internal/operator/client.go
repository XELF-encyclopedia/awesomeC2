// Package operator implements the operator-side client for C2V2.
package operator

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"c2v2/internal/protocol"
)

// Client is an authenticated operator connection.
type Client struct {
	conn  io.ReadWriteCloser
	keys  *protocol.Keys
	User  string
	Role  string
	Tenant string
	SID   string

	mu      sync.Mutex
	req     uint64
	pending map[uint64]chan *protocol.OpResp

	presMu   sync.RWMutex
	presence []protocol.PresenceEntry

	errMu sync.Mutex
	err   error

	closed chan struct{}
	once   sync.Once
}

// Options configures Dial.
type Options struct {
	User     string
	Key      []byte
	Insecure bool
	PinSHA256 string // hex SHA256 of the server certificate DER
	Timeout  time.Duration
	Path     string
}

// Dial connects to tls://host:port, tcp://, ws:// or wss:// and authenticates.
func Dial(ctx context.Context, rawURL string, opt Options) (*Client, error) {
	if opt.Timeout == 0 {
		opt.Timeout = 10 * time.Second
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	scheme := strings.ToLower(u.Scheme)
	host := u.Host
	path := u.Path
	if opt.Path != "" {
		path = opt.Path
	}
	if path == "" {
		path = "/op"
	}
	dialer := &net.Dialer{Timeout: opt.Timeout}
	var rw io.ReadWriteCloser
	switch scheme {
	case "tcp", "tls":
		conn, err := dialer.DialContext(ctx, "tcp", host)
		if err != nil {
			return nil, err
		}
		if scheme == "tls" {
			tconn := tls.Client(conn, clientTLS(host, opt))
			if err := tconn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, err
			}
			rw = tconn
		} else {
			rw = conn
		}
	case "ws", "wss":
		conn, err := dialer.DialContext(ctx, "tcp", host)
		if err != nil {
			return nil, err
		}
		if scheme == "wss" {
			tconn := tls.Client(conn, clientTLS(host, opt))
			if err := tconn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, err
			}
			conn = tconn
		}
		ws, err := protocol.DialWebSocket(conn, u.Host, path)
		if err != nil {
			conn.Close()
			return nil, err
		}
		rw = ws
	default:
		return nil, fmt.Errorf("unsupported scheme %q", scheme)
	}
	return handshake(rw, opt)
}

func clientTLS(host string, opt Options) *tls.Config {	hostOnly := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostOnly = h
	}
	cfg := &tls.Config{ServerName: hostOnly, MinVersion: tls.VersionTLS12}
	if opt.PinSHA256 != "" {
		pin := strings.ToLower(strings.TrimSpace(opt.PinSHA256))
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no peer certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			if hex.EncodeToString(sum[:]) != pin {
				return fmt.Errorf("certificate pin mismatch")
			}
			return nil
		}
	} else if opt.Insecure {
		cfg.InsecureSkipVerify = true
	}
	return cfg
}

func handshake(rw io.ReadWriteCloser, opt Options) (*Client, error) {
	priv, err := protocol.NewEphemeral()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 32)
	if _, err := readRand(nonce); err != nil {
		return nil, err
	}
	pub := protocol.PublicRaw(priv)
	ts := time.Now().Unix()
	hello := protocol.OpHello{
		V: protocol.Version, T: protocol.TOpHello, User: opt.User,
		Nonce: protocol.B64(nonce), Pub: protocol.B64(pub), TS: ts,
		MAC: protocol.HMACSign(opt.Key, opt.User, protocol.B64(nonce), protocol.B64(pub), strconv.FormatInt(ts, 10)),
	}
	b, _ := json.Marshal(hello)
	setWriteDeadline(rw, time.Now().Add(15*time.Second))
	if err := protocol.WriteStreamFrame(rw, b); err != nil {
		return nil, err
	}
	setReadDeadline(rw, time.Now().Add(15*time.Second))
	frame, err := protocol.ReadStreamFrame(rw)
	if err != nil {
		return nil, err
	}
	var ack protocol.OpHelloAck
	if err := json.Unmarshal(frame, &ack); err != nil {
		return nil, err
	}
	if ack.Error != "" {
		return nil, errors.New("operator auth: " + ack.Error)
	}
	if ack.T != protocol.TOpHelloAck {
		return nil, errors.New("unexpected handshake reply")
	}
	nonceS, err := protocol.DecodeB64(ack.Nonce)
	if err != nil {
		return nil, err
	}
	pubS, err := protocol.DecodeB64(ack.Pub)
	if err != nil {
		return nil, err
	}
	shared, err := protocol.SharedRaw(priv, pubS)
	if err != nil {
		return nil, err
	}
	keys, err := protocol.DeriveKeys(shared, opt.Key, nonce, nonceS, protocol.CipherAES256GCM)
	if err != nil {
		return nil, err
	}
	c := &Client{
		conn: rw, keys: keys, User: ack.User, Role: ack.Role, Tenant: ack.Tenant, SID: ack.SID,
		pending: map[uint64]chan *protocol.OpResp{}, closed: make(chan struct{}),
	}
	_ = setReadDeadline(rw, time.Time{})
	_ = setWriteDeadline(rw, time.Time{})
	go c.readLoop()
	return c, nil
}

func (c *Client) readLoop() {
	defer c.Close()
	for {
		frame, err := protocol.ReadStreamFrame(c.conn)
		if err != nil {
			c.setErr(err)
			return
		}
		plain, err := c.keys.Open(protocol.DirServerToClient, frame)
		if err != nil {
			c.setErr(err)
			return
		}
		switch protocol.MessageType(plain) {
		case protocol.TOpResp:
			var resp protocol.OpResp
			if err := json.Unmarshal(plain, &resp); err != nil {
				continue
			}
			c.mu.Lock()
			ch := c.pending[resp.Req]
			delete(c.pending, resp.Req)
			c.mu.Unlock()
			if ch != nil {
				select {
				case ch <- &resp:
				default:
				}
			}
		case protocol.TPresence:
			var p protocol.Presence
			if err := json.Unmarshal(plain, &p); err == nil {
				c.presMu.Lock()
				c.presence = p.Operators
				c.presMu.Unlock()
			}
		}
	}
}

func (c *Client) setErr(err error) {
	c.errMu.Lock()
	if c.err == nil {
		c.err = err
	}
	c.errMu.Unlock()
}

// Presence returns the last presence snapshot.
func (c *Client) Presence() []protocol.PresenceEntry {
	c.presMu.RLock()
	defer c.presMu.RUnlock()
	return append([]protocol.PresenceEntry{}, c.presence...)
}

// Err returns the terminal connection error, if any.
func (c *Client) Err() error {
	c.errMu.Lock()
	defer c.errMu.Unlock()
	return c.err
}

// Call performs one command round trip.
func (c *Client) Call(ctx context.Context, cmd string, args any) (json.RawMessage, error) {
	var raw json.RawMessage
	if args != nil {
		b, err := json.Marshal(args)
		if err != nil {
			return nil, err
		}
		raw = b
	}
	c.mu.Lock()
	if c.req == 0 {
		c.req = 1
	}
	req := c.req
	c.req++
	ch := make(chan *protocol.OpResp, 1)
	c.pending[req] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, req)
		c.mu.Unlock()
	}()
	msg := protocol.OpCmd{T: protocol.TOpCmd, Req: req, Cmd: cmd, Args: raw, TS: time.Now().Unix()}
	b, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	env, err := c.keys.Seal(protocol.DirClientToServer, b)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	err = protocol.WriteStreamFrame(c.conn, env)
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	select {
	case resp := <-ch:
		if !resp.OK {
			return nil, errors.New(resp.Err)
		}
		return resp.Data, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		if e := c.Err(); e != nil {
			return nil, e
		}
		return nil, errors.New("connection closed")
	}
}

// Close closes the operator connection.
func (c *Client) Close() error {
	var err error
	c.once.Do(func() {
		close(c.closed)
		err = c.conn.Close()
	})
	return err
}
