// Package client is the reusable BDC2 v1 operator connection used by the TUI
// and the no-TTY fallback.
//
// It speaks the frozen wire protocol exactly as the existing operator CLI
// (mvp/server/cmd/operator): native TLS/WSS, operator AUTH, sealed
// OP_* request/response frames, chunked file transfer and NOTICE(sub=tunnel)
// demultiplexing. No new frame types, fields or crypto are introduced.
package client

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"

	"backd/c2/mvp/internal/bdc2"
)

// Notice is a decoded asynchronous NOTICE(sub=tunnel) event.
type Notice struct {
	FType uint8
	TID   uint32
	Data  []byte
}

// State describes the transport state for the UI indicator.
type State int

const (
	StateDisconnected State = iota
	StateConnecting
	StateConnected
	StateReconnecting
)

func (s State) String() string {
	switch s {
	case StateConnecting:
		return "connecting"
	case StateConnected:
		return "connected"
	case StateReconnecting:
		return "reconnecting"
	default:
		return "disconnected"
	}
}

// Options are the transport settings, all externally supplied.
type Options struct {
	Endpoint string
	User     string
	PSK      string
	SNI      string
	DialIP   string
	Family   string
	TLSCA    string
	TLSPin   string
	Insecure bool
	Timeout  time.Duration

	OnNotice func(Notice)
	OnState  func(State, string)
}

// Session mirrors a server session-list entry.
type Session struct {
	ID       uint64 `json:"id"`
	ClientID string `json:"client_id"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Ver      string `json:"ver"`
	Addr     string `json:"addr"`
	LastSeen string `json:"last_seen"`
}

// Name is the human label used by the session table (the client_id carries the
// host name announced by the client).
func (s Session) Name() string {
	if s.ClientID != "" {
		return s.ClientID
	}
	return strconv.FormatUint(s.ID, 10)
}

// TaskResult is the payload of one OP_RESULT task reply.
type TaskResult struct {
	Status  string
	Out     []byte
	Err     string
	Session string
}

// PushResult is the reply to an OP_FILE_PUSH.
type PushResult struct {
	Status string
	SHA    string
	Err    string
}

// PullResult describes a server-staged pull.
type PullResult struct {
	Xfer string
	Size int64
	SHA  string
}

// RemoteError is an application-level error returned by the server.
type RemoteError struct{ Msg string }

func (e *RemoteError) Error() string { return "server: " + e.Msg }

// protocolError marks a transport/desync error: the caller must drop the
// connection because unread frames may still be in flight.
type protocolError struct{ msg string }

func (e *protocolError) Error() string { return "protocol: " + e.msg }

// MaxPushPayload keeps the sealed frame below the 1 MiB server frame cap.
const MaxPushPayload = (1 << 20) - 4096

// Client owns one re-connectable operator channel.
type Client struct {
	opts Options

	sem chan struct{} // serialises all operator requests
	mu  sync.Mutex
	c   *conn
}

// New returns a client; it does not dial.
func New(opts Options) *Client {
	if opts.Timeout <= 0 {
		opts.Timeout = 45 * time.Second
	}
	if opts.Family == "" {
		opts.Family = "auto"
	}
	return &Client{opts: opts, sem: make(chan struct{}, 1)}
}

// Options returns the configured transport options (read-only use).
func (c *Client) Options() Options { return c.opts }

func (c *Client) emit(s State, detail string) {
	if c.opts.OnState != nil {
		c.opts.OnState(s, detail)
	}
}

func (c *Client) acquire(ctx context.Context) error {
	select {
	case c.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) release() { <-c.sem }

// Connect dials and authenticates if not already connected. It may be called
// repeatedly to implement reconnect backoff.
func (c *Client) Connect(ctx context.Context) error {
	if err := c.acquire(ctx); err != nil {
		return err
	}
	defer c.release()
	return c.connectLocked(ctx)
}

// Connected reports whether a live channel exists.
func (c *Client) Connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.c != nil && !c.c.isClosed()
}

// Close tears the channel down; it can be reconnected afterwards.
func (c *Client) Close() {
	c.mu.Lock()
	cn := c.c
	c.c = nil
	c.mu.Unlock()
	if cn != nil {
		cn.fail(errors.New("closed by operator"))
	}
}

func (c *Client) connectLocked(ctx context.Context) error {
	c.mu.Lock()
	if c.c != nil && !c.c.isClosed() {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.opts.validate(); err != nil {
		return err
	}
	c.emit(StateConnecting, c.opts.Endpoint)

	psk, err := bdc2.DecodePSK(c.opts.PSK)
	if err != nil {
		return fmt.Errorf("decode psk: %w", err)
	}
	dialTimeout := 20 * time.Second
	if c.opts.Timeout > 0 && c.opts.Timeout < dialTimeout {
		dialTimeout = c.opts.Timeout
	}
	ws, ep, err := bdc2.DialEndpoint(c.opts.Endpoint, bdc2.DialOptions{
		Timeout:   dialTimeout,
		MaxFrame:  1 << 20,
		Path:      "/ws",
		SNI:       c.opts.SNI,
		DialAddr:  c.opts.DialIP,
		Family:    c.opts.Family,
		Insecure:  c.opts.Insecure,
		TLSCAFile: c.opts.TLSCA,
		TLSPin:    c.opts.TLSPin,
	})
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		ws.Close()
		return err
	}
	mac := bdc2.OperatorAuthMAC(psk, c.opts.User, nonce)
	auth := bdc2.EncodeTLV([]bdc2.KV{
		bdc2.S("user", c.opts.User),
		bdc2.B("nonce", nonce),
		bdc2.B("mac", mac),
	})
	frame, err := bdc2.SealFrame(nil, bdc2.TypeAuth, bdc2.FlagCleartext, 0, 0, bdc2.DirOperToServer, auth)
	if err != nil {
		ws.Close()
		return err
	}
	key, err := bdc2.OperatorKey(psk, c.opts.User)
	if err != nil {
		ws.Close()
		return err
	}
	if err := ws.WriteBinary(frame); err != nil {
		ws.Close()
		return fmt.Errorf("send auth: %w", err)
	}
	_ = ws.SetReadDeadline(time.Now().Add(dialTimeout))
	_, data, err := ws.ReadMessage()
	if err != nil {
		ws.Close()
		return fmt.Errorf("auth rejected or server closed: %w", err)
	}
	typ, _, _, _, payload, err := bdc2.OpenFrame(key, data, bdc2.DirServerToOper)
	if err != nil {
		ws.Close()
		return fmt.Errorf("open auth reply: %w", err)
	}
	if typ != bdc2.TypeAuthOK {
		ws.Close()
		return fmt.Errorf("auth rejected (type=%d)", typ)
	}
	_ = ws.SetReadDeadline(time.Time{})
	_ = payload

	cn := &conn{
		ws:       ws,
		key:      key,
		timeout:  c.opts.Timeout,
		msgs:     make(chan incoming, 8),
		done:     make(chan struct{}),
		onNotice: c.opts.OnNotice,
	}
	c.mu.Lock()
	c.c = cn
	c.mu.Unlock()
	go cn.pump()
	go func() {
		<-cn.done
		c.mu.Lock()
		current := c.c == cn
		if current {
			c.c = nil
		}
		c.mu.Unlock()
		if current {
			c.emit(StateDisconnected, errText(cn.closeErr()))
		}
	}()

	tlsName := ws.TLSVersion()
	if tlsName == "" {
		tlsName = "plaintext"
	}
	c.emit(StateConnected, ep.String()+" tls="+tlsName)
	return nil
}

func (o *Options) validate() error {
	switch {
	case o.Endpoint == "":
		return errors.New("endpoint is required")
	case o.User == "":
		return errors.New("operator user is required")
	case o.PSK == "":
		return errors.New("operator PSK is required")
	}
	return nil
}

// ---------------------------------------------------------------------------
// request plumbing
// ---------------------------------------------------------------------------

type incoming struct {
	typ uint8
	kv  map[string][]byte
}

type conn struct {
	ws      *bdc2.WSConn
	key     []byte
	timeout time.Duration

	// sendSeq is only touched while the Client request semaphore is held, or
	// by connect (single goroutine), so no extra lock is needed.
	sendSeq uint32
	recvSeq uint32

	msgs     chan incoming
	done     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	err      error
	onNotice func(Notice)
}

func (cn *conn) isClosed() bool {
	select {
	case <-cn.done:
		return true
	default:
		return false
	}
}

func (cn *conn) fail(err error) {
	cn.once.Do(func() {
		cn.mu.Lock()
		cn.err = err
		cn.mu.Unlock()
		close(cn.done)
		_ = cn.ws.Close()
	})
}

func (cn *conn) closeErr() error {
	cn.mu.Lock()
	defer cn.mu.Unlock()
	return cn.err
}

func (cn *conn) pump() {
	for {
		_, data, err := cn.ws.ReadMessage()
		if err != nil {
			cn.fail(err)
			return
		}
		typ, _, _, seq, payload, err := bdc2.OpenFrame(cn.key, data, bdc2.DirServerToOper)
		if err != nil {
			cn.fail(fmt.Errorf("open frame: %w", err))
			return
		}
		if seq <= cn.recvSeq {
			cn.fail(fmt.Errorf("replayed or out-of-order server seq %d", seq))
			return
		}
		cn.recvSeq = seq
		kv, err := bdc2.DecodeTLV(payload)
		if err != nil {
			cn.fail(fmt.Errorf("decode tlv: %w", err))
			return
		}
		if typ == bdc2.TypeNotice {
			if tn, ok := bdc2.ParseTunnelNotice(kv); ok && cn.onNotice != nil {
				cn.onNotice(Notice{FType: tn.FType, TID: tn.TID, Data: tn.Data})
			}
			continue
		}
		select {
		case cn.msgs <- incoming{typ: typ, kv: kv}:
		case <-cn.done:
			return
		}
	}
}

func (cn *conn) send(typ uint8, kvs []bdc2.KV) error {
	cn.sendSeq++
	frame, err := bdc2.SealFrame(cn.key, typ, 0, 0, cn.sendSeq, bdc2.DirOperToServer, bdc2.EncodeTLV(kvs))
	if err != nil {
		return err
	}
	return cn.ws.WriteBinary(frame)
}

func (cn *conn) recv(ctx context.Context) (incoming, error) {
	select {
	case m := <-cn.msgs:
		return m, nil
	case <-cn.done:
		err := cn.closeErr()
		if err == nil {
			err = errors.New("connection closed")
		}
		return incoming{}, err
	case <-ctx.Done():
		return incoming{}, ctx.Err()
	}
}

func (c *Client) do(ctx context.Context, timeout time.Duration, typ uint8, kvs []bdc2.KV,
	handle func(incoming) (bool, error)) error {

	if err := c.acquire(ctx); err != nil {
		return err
	}
	defer c.release()

	c.mu.Lock()
	cn := c.c
	c.mu.Unlock()
	if cn == nil || cn.isClosed() {
		if err := c.connectLocked(ctx); err != nil {
			return err
		}
		c.mu.Lock()
		cn = c.c
		c.mu.Unlock()
	}
	if cn == nil {
		return errors.New("not connected")
	}
	if err := cn.send(typ, kvs); err != nil {
		cn.fail(err)
		return err
	}
	if timeout <= 0 {
		timeout = c.opts.Timeout
	}
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	for {
		rctx, cancel := context.WithTimeout(ctx, timeout)
		m, err := cn.recv(rctx)
		cancel()
		if err != nil {
			// A late reply would desynchronise the next RPC, so any receive
			// failure (including a local timeout/cancel) drops the channel.
			cn.fail(err)
			return err
		}
		done, err := handle(m)
		if err != nil {
			var pe *protocolError
			if errors.As(err, &pe) {
				cn.fail(err)
			}
			return err
		}
		if done {
			return nil
		}
	}
}

// ---------------------------------------------------------------------------
// operator RPCs
// ---------------------------------------------------------------------------

// List fetches the session list and server stats.
func (c *Client) List(ctx context.Context) ([]Session, map[string]any, error) {
	return c.list(ctx, nil)
}

// Reload asks the server to re-read its configuration.
func (c *Client) Reload(ctx context.Context, configPath string) ([]Session, map[string]any, error) {
	kv := []bdc2.KV{bdc2.S("reload", "1")}
	if configPath != "" {
		kv = append(kv, bdc2.S("config", configPath))
	}
	return c.list(ctx, kv)
}

func (c *Client) list(ctx context.Context, extra []bdc2.KV) ([]Session, map[string]any, error) {
	var sessions []Session
	stats := map[string]any{}
	var remoteErr error
	err := c.do(ctx, 0, bdc2.TypeOpList, extra, func(m incoming) (bool, error) {
		switch m.typ {
		case bdc2.TypeOpListResult:
			if b := m.kv["sessions"]; len(b) > 0 {
				if e := json.Unmarshal(b, &sessions); e != nil {
					return true, e
				}
			}
			if b := m.kv["stats"]; len(b) > 0 {
				_ = json.Unmarshal(b, &stats)
			}
			if e := string(m.kv["reload_err"]); e != "" {
				remoteErr = fmt.Errorf("reload: %s", e)
			}
			return true, nil
		case bdc2.TypeError:
			return true, &RemoteError{Msg: string(m.kv["msg"])}
		default:
			return true, &protocolError{msg: fmt.Sprintf("unexpected frame %d for list", m.typ)}
		}
	})
	if err != nil {
		return nil, nil, err
	}
	return sessions, stats, remoteErr
}

// Task runs one task kind on a session.
func (c *Client) Task(ctx context.Context, session string, kind, args string,
	timeoutS int, extra ...bdc2.KV) (TaskResult, error) {

	if timeoutS <= 0 {
		timeoutS = 60
	}
	kvs := []bdc2.KV{
		bdc2.S("session", session),
		bdc2.S("kind", kind),
		bdc2.S("args", args),
		bdc2.S("timeout", strconv.Itoa(timeoutS)),
	}
	kvs = append(kvs, extra...)
	var r TaskResult
	err := c.do(ctx, time.Duration(timeoutS+15)*time.Second, bdc2.TypeOpTask, kvs,
		func(m incoming) (bool, error) {
			switch m.typ {
			case bdc2.TypeOpResult:
				r = TaskResult{
					Status:  string(m.kv["status"]),
					Out:     m.kv["out"],
					Err:     string(m.kv["err"]),
					Session: string(m.kv["session"]),
				}
				return true, nil
			case bdc2.TypeError:
				return true, &RemoteError{Msg: string(m.kv["msg"])}
			default:
				return true, &protocolError{msg: fmt.Sprintf("unexpected frame %d for task", m.typ)}
			}
		})
	return r, err
}

// Kill drops a client session.
func (c *Client) Kill(ctx context.Context, session string) error {
	err := c.do(ctx, 0, bdc2.TypeOpKill, []bdc2.KV{bdc2.S("session", session)},
		func(m incoming) (bool, error) {
			switch m.typ {
			case bdc2.TypeOpResult:
				if string(m.kv["status"]) != "ok" {
					return true, &RemoteError{Msg: string(m.kv["err"])}
				}
				return true, nil
			case bdc2.TypeError:
				return true, &RemoteError{Msg: string(m.kv["msg"])}
			default:
				return true, &protocolError{msg: fmt.Sprintf("unexpected frame %d for kill", m.typ)}
			}
		})
	return err
}

// Push uploads data to remote at the given absolute offset (resume).
func (c *Client) Push(ctx context.Context, session, remote string, data []byte, offset int64) (PushResult, error) {
	if len(data) > MaxPushPayload {
		return PushResult{}, fmt.Errorf("payload %d exceeds the %d-byte single-frame limit; split the file",
			len(data), MaxPushPayload)
	}
	kvs := []bdc2.KV{
		bdc2.S("session", session),
		bdc2.S("file", remote),
		bdc2.B("data", data),
	}
	if offset > 0 {
		kvs = append(kvs, bdc2.S("off", strconv.FormatInt(offset, 10)))
	}
	var r PushResult
	err := c.do(ctx, 0, bdc2.TypeOpFilePush, kvs, func(m incoming) (bool, error) {
		switch m.typ {
		case bdc2.TypeOpResult:
			r = PushResult{
				Status: string(m.kv["status"]),
				SHA:    string(m.kv["sha"]),
				Err:    string(m.kv["err"]),
			}
			return true, nil
		case bdc2.TypeError:
			return true, &RemoteError{Msg: string(m.kv["msg"])}
		default:
			return true, &protocolError{msg: fmt.Sprintf("unexpected frame %d for push", m.typ)}
		}
	})
	return r, err
}

// Pull asks the client to stage a remote file on the server.
func (c *Client) Pull(ctx context.Context, session, remote string) (PullResult, error) {
	var r PullResult
	err := c.do(ctx, 0, bdc2.TypeOpFilePull, []bdc2.KV{
		bdc2.S("session", session), bdc2.S("file", remote),
	}, func(m incoming) (bool, error) {
		switch m.typ {
		case bdc2.TypeOpResult:
			if string(m.kv["status"]) != "ok" {
				msg := string(m.kv["err"])
				if msg == "" {
					msg = string(m.kv["status"])
				}
				return true, &RemoteError{Msg: msg}
			}
			r.Xfer = string(m.kv["xfer"])
			r.SHA = string(m.kv["sha"])
			r.Size, _ = strconv.ParseInt(string(m.kv["size"]), 10, 64)
			return true, nil
		case bdc2.TypeError:
			return true, &RemoteError{Msg: string(m.kv["msg"])}
		default:
			return true, &protocolError{msg: fmt.Sprintf("unexpected frame %d for pull", m.typ)}
		}
	})
	return r, err
}

// Fetch streams a staged transfer into w. total may be 0 when unknown.
func (c *Client) Fetch(ctx context.Context, xfer string, w io.Writer, total int64,
	progress func(done, total int64)) (int64, string, error) {

	var n int64
	var sha string
	err := c.do(ctx, 0, bdc2.TypeOpFileFetch, []bdc2.KV{bdc2.S("xfer", xfer)},
		func(m incoming) (bool, error) {
			switch m.typ {
			case bdc2.TypeOpFileChunk:
				data := m.kv["data"]
				if len(data) > 0 {
					if _, e := w.Write(data); e != nil {
						return true, &protocolError{msg: "local write failed: " + e.Error()}
					}
					n += int64(len(data))
					if progress != nil {
						progress(n, total)
					}
				}
				return false, nil
			case bdc2.TypeOpFileDone:
				sha = string(m.kv["sha"])
				if progress != nil {
					progress(n, total)
				}
				return true, nil
			case bdc2.TypeError:
				return true, &RemoteError{Msg: string(m.kv["msg"])}
			default:
				return true, &protocolError{msg: fmt.Sprintf("unexpected frame %d for fetch", m.typ)}
			}
		})
	return n, sha, err
}

// AuditVerify checks the local server audit hash chain.
func AuditVerify(path string) (verified, broken int, err error) {
	return bdc2.VerifyAuditChain(path)
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
