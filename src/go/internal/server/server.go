package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"c2v2/internal/aiassist"
	"c2v2/internal/modules"
	"c2v2/internal/protocol"
	"c2v2/internal/store"
)

// Session is a live client connection.
type Session struct {
	SID       string
	ClientID  string
	Host      string
	OS        string
	Arch      string
	User      string
	Machine   protocol.Machine
	Transport string
	Tenant    string
	Caps      []string
	Keys      *protocol.Keys
	Created   int64
	LastSeen  int64
	Seq       uint64

	Stream   io.Writer
	streamMu sync.Mutex

	dq [][]byte
	dm sync.Mutex

	Mu   sync.Mutex
	Note string
}

// Online reports whether the session heartbeat is fresh.
func (s *Session) Online(sleepSec int) bool {
	if sleepSec <= 0 {
		sleepSec = 60
	}
	return time.Now().Unix()-s.LastSeen < int64(sleepSec*3+10)
}

// Server is the C2V2 server.
type Server struct {
	cfg       *Config
	st        store.Store
	psk       []byte
	killKey   []byte
	updateKey []byte
	logger    *log.Logger

	mu       sync.RWMutex
	sessions map[string]*Session

	opMu sync.Mutex
	ops  map[*OpConn]struct{}

	pending  map[string]chan *protocol.Result
	killWait map[string]chan *protocol.KillAck

	tunMu   sync.Mutex
	tunnels map[string]*Tunnel

	cert   tls.Certificate
	certFP string
	frags  *protocol.Reassembler

	pendMu sync.Mutex
	killMu sync.Mutex

	opKeysMu sync.RWMutex
	opKeys   map[string][]byte
	opCfg    map[string]OperatorConfig

	modReg *modules.Registry

	updMu   sync.Mutex
	updPin  string
	updOk   map[string]bool

	ai *aiassist.Assistant

	closers []io.Closer
	stop    chan struct{}
	once    sync.Once
	bound   map[string]string
	boundMu sync.Mutex

	// metrics
	mSessions uint64
	mTasks    uint64
	mBytesIn  uint64
	mBytesOut uint64
	startedAt time.Time
}

// New builds a server from config.
func New(cfg *Config, logger *log.Logger) (*Server, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if logger == nil {
		logger = log.Default()
	}
	st, err := store.Open(cfg.Storage, cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	s := &Server{
		cfg:      cfg,
		st:       st,
		logger:   logger,
		sessions: map[string]*Session{},
		ops:      map[*OpConn]struct{}{},
		pending:  map[string]chan *protocol.Result{},
		killWait: map[string]chan *protocol.KillAck{},
		tunnels:  map[string]*Tunnel{},
		stop:     make(chan struct{}),
		startedAt: time.Now(),
		opKeys:   map[string][]byte{},
		opCfg:    map[string]OperatorConfig{},
		bound:    map[string]string{},
		updOk:    map[string]bool{},
	}
	s.psk, _ = DecodeKey(cfg.PSKB64)
	s.killKey, _ = DecodeKey(cfg.KillKeyB64)
	s.updateKey, _ = DecodeKey(cfg.UpdateKeyB64)
	s.updPin = cfg.UpdatePin

	// Pluggable modules: builtin catalog + manifests from cfg.ModulesDir.
	s.modReg = modules.New()
	if loaded, err := s.modReg.LoadDir(cfg.ModulesDir); err != nil {
		logger.Printf("modules: %v (loaded=%v)", err, loaded)
	} else if len(loaded) > 0 {
		logger.Printf("modules: loaded external manifests: %v", loaded)
	}

	// Optional AI assistant (provider agnostic, OpenAI-compatible).
	if cfg.AI.Enabled && cfg.AI.BaseURL != "" {
		model := cfg.AI.Model
		if model == "" {
			model = "gpt-4o-mini"
		}
		key := os.Getenv(cfg.AI.KeyEnv)
		prov := &aiassist.OpenAIProvider{BaseURL: cfg.AI.BaseURL, APIKey: key, Model: model}
		s.ai = aiassist.New(prov, model)
		if cfg.AI.AutoReadOnly != nil {
			s.ai.AutoRead = *cfg.AI.AutoReadOnly
		}
		if cfg.AI.MaxRounds > 0 {
			s.ai.MaxRounds = cfg.AI.MaxRounds
		}
		s.ai.Audit = func(actor, action, target, detail string) { s.audit(actor, action, target, detail) }
		s.buildAITools()
		logger.Printf("ai: assistant enabled (model=%s base=%s)", model, cfg.AI.BaseURL)
	}
	for _, o := range cfg.Operators {
		key, err := DecodeKey(o.KeyB64)
		if err != nil || key == nil {
			return nil, fmt.Errorf("operator %s: missing/invalid key", o.User)
		}
		if o.Role != "admin" && o.Role != "operator" && o.Role != "viewer" {
			return nil, fmt.Errorf("operator %s: invalid role %q", o.User, o.Role)
		}
		sum := protocol.HMACSign([]byte("c2v2-op-key-hash"), o.User, string(key))
		s.opKeys[o.User] = key
		s.opCfg[o.User] = o
		if err := st.UpsertOperator(context.Background(), store.Operator{
			User: o.User, Role: o.Role, Tenant: o.Tenant, KeyHash: sum, Created: time.Now().Unix(),
		}); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Store exposes the backend for tooling/tests.
func (s *Server) Store() store.Store { return s.st }

// Sessions returns a snapshot of live sessions.
func (s *Server) Sessions() []*Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Session, 0, len(s.sessions))
	for _, x := range s.sessions {
		out = append(out, x)
	}
	return out
}

// GetSession looks a session up.
func (s *Server) GetSession(sid string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	x, ok := s.sessions[sid]
	return x, ok
}

// Config returns the server config.
func (s *Server) Config() *Config { return s.cfg }

// Stats returns counters.
func (s *Server) Stats() map[string]any {
	s.mu.RLock()
	n := len(s.sessions)
	s.mu.RUnlock()
	s.opMu.Lock()
	nops := len(s.ops)
	s.opMu.Unlock()
	return map[string]any{
		"sessions": n,
		"operators": nops,
		"tasks": s.mTasks,
		"uptime_secs": int64(time.Since(s.startedAt).Seconds()),
		"cert_fp": s.certFP,
	}
}

func (s *Server) audit(actor, action, target, detail string) {
	if _, err := s.st.Audit(context.Background(), actor, action, target, detail); err != nil {
		s.logger.Printf("audit error: %v", err)
	}
}

// ---------------- client handshake / stream ----------------

func (s *Server) register(sess *Session) {
	s.mu.Lock()
	// Drop stale siblings with the same client id.
	for sid, old := range s.sessions {
		if old.ClientID == sess.ClientID && sid != sess.SID {
			delete(s.sessions, sid)
		}
	}
	s.sessions[sess.SID] = sess
	s.mSessions++
	s.mu.Unlock()
	_ = s.st.UpsertSession(context.Background(), store.Session{
		SID: sess.SID, ClientID: sess.ClientID, Host: sess.Host, OS: sess.OS, Arch: sess.Arch,
		User: sess.User, Transport: sess.Transport, Tenant: sess.Tenant,
		FirstSeen: sess.Created, LastSeen: sess.LastSeen, State: "online",
		Meta: mustJSON(sess.Machine), Caps: mustJSON(sess.Caps),
	})
	s.audit("system", "session.register", sess.SID, fmt.Sprintf("client=%s host=%s transport=%s", sess.ClientID, sess.Host, sess.Transport))
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func (s *Server) handshake(hello *protocol.Hello, transport string) (*Session, *protocol.HelloAck, error) {
	if hello.V != protocol.Version {
		return nil, nil, fmt.Errorf("unsupported protocol version %d", hello.V)
	}
	if hello.ClientID == "" {
		return nil, nil, errors.New("missing client_id")
	}
	nonceC, err := protocol.DecodeB64(hello.Nonce)
	if err != nil || len(nonceC) != 32 {
		return nil, nil, errors.New("bad client nonce")
	}
	pubC, err := protocol.DecodeB64(hello.Pub)
	if err != nil || len(pubC) != 32 {
		return nil, nil, errors.New("bad client public key")
	}
	now := time.Now().Unix()
	if hello.TS != 0 && (hello.TS < now-86400 || hello.TS > now+3600) {
		return nil, nil, errors.New("clock skew too large")
	}
	if len(s.psk) > 0 {
		want := protocol.HMACSign(s.psk, hello.ClientID, hello.Nonce, fmt.Sprint(hello.TS))
		if !protocol.HMACVerify(s.psk, hello.NonceSig, hello.ClientID, hello.Nonce, fmt.Sprint(hello.TS)) {
			_ = want
			return nil, nil, errors.New("psk authentication failed")
		}
	}
	privS, err := protocol.NewEphemeral()
	if err != nil {
		return nil, nil, err
	}
	shared, err := protocol.SharedRaw(privS, pubC)
	if err != nil {
		return nil, nil, err
	}
	nonceS := make([]byte, 32)
	if _, err := readRand(nonceS); err != nil {
		return nil, nil, err
	}
	cipher := protocol.ParseCipher(hello.Cipher)
	keys, err := protocol.DeriveKeys(shared, s.psk, nonceC, nonceS, cipher)
	if err != nil {
		return nil, nil, err
	}
	// Ensure SID uniqueness.
	s.mu.RLock()
	if _, clash := s.sessions[keys.SID]; clash {
		keys.SID = keys.SID[:12] + protocol.RandomHex(4)
	}
	s.mu.RUnlock()

	tenant := s.cfg.Tenant
	sess := &Session{
		SID: keys.SID, ClientID: hello.ClientID, Host: hello.Machine.Host, OS: hello.Machine.OS,
		Arch: hello.Machine.Arch, User: hello.Machine.User, Machine: hello.Machine,
		Transport: transport, Tenant: tenant, Caps: hello.Caps, Keys: keys,
		Created: now, LastSeen: now,
	}
	ack := &protocol.HelloAck{
		V: protocol.Version, T: protocol.THelloAck, Nonce: protocol.B64(nonceS),
		Pub: protocol.B64(protocol.PublicRaw(privS)), Cipher: cipher.String(), SID: keys.SID,
		ServerTime: now, Sleep: s.cfg.Sleep, Jitter: s.cfg.Jitter,
		Protocol: protocol.Version, Tenant: tenant,
	}
	return sess, ack, nil
}

// ServeStream handles a stream transport connection (TLS, TCP, WS, WSS).
func (s *Server) ServeStream(rw io.ReadWriteCloser, transport string) {
	defer rw.Close()
	_ = setDeadline(rw, time.Now().Add(30*time.Second))
	frame, err := protocol.ReadStreamFrame(rw)
	if err != nil {
		return
	}
	body, err := protocol.ParsePlain(frame)
	if err != nil {
		return
	}
	var hello protocol.Hello
	if err := json.Unmarshal(body, &hello); err != nil || hello.T != protocol.THello {
		_ = protocol.WriteStreamFrame(rw, mustFrame(protocol.Error{T: protocol.TError, Msg: "expected hello"}))
		return
	}
	sess, ack, err := s.handshake(&hello, transport)
	if err != nil {
		b, _ := json.Marshal(protocol.Error{T: protocol.TError, Msg: err.Error()})
		_ = protocol.WriteStreamFrame(rw, protocol.PlainEnvelope(b))
		s.logger.Printf("handshake failed from %s: %v", transport, err)
		return
	}
	sess.Stream = rw
	_ = setDeadline(rw, time.Time{})
	ackBytes, _ := protocol.EncodePlain(ack)
	if err := protocol.WriteStreamFrame(rw, ackBytes); err != nil {
		return
	}
	s.register(sess)
	defer s.markOffline(sess)
	for {
		frame, err := protocol.ReadStreamFrame(rw)
		if err != nil {
			return
		}
		plain, err := sess.Keys.Open(protocol.DirClientToServer, frame)
		if err != nil {
			s.logger.Printf("decrypt failed sid=%s: %v", sess.SID, err)
			return
		}
		s.handleClientMsg(sess, plain)
	}
}

func (s *Server) markOffline(sess *Session) {
	sess.LastSeen = time.Now().Unix()
	_ = s.st.UpsertSession(context.Background(), store.Session{
		SID: sess.SID, ClientID: sess.ClientID, Host: sess.Host, OS: sess.OS, Arch: sess.Arch,
		User: sess.User, Transport: sess.Transport, Tenant: sess.Tenant,
		FirstSeen: sess.Created, LastSeen: sess.LastSeen, State: "offline",
		Meta: mustJSON(sess.Machine), Caps: mustJSON(sess.Caps),
	})
	s.audit("system", "session.offline", sess.SID, "")
}

func (s *Server) handleClientMsg(sess *Session, plain []byte) {
	sess.LastSeen = time.Now().Unix()
	switch protocol.MessageType(plain) {
	case protocol.THB:
		var hb protocol.HB
		if err := json.Unmarshal(plain, &hb); err != nil {
			return
		}
		sess.Mu.Lock()
		sess.Seq = hb.Seq
		sess.Mu.Unlock()
		_ = s.SendMsg(sess, protocol.HBAck{T: protocol.THBAck, TS: time.Now().Unix()})
	case protocol.TResult:
		s.mTasks++
		var res protocol.Result
		if err := json.Unmarshal(plain, &res); err != nil {
			return
		}
		s.resolveTask(sess, &res)
	case protocol.TFrag:
		var f protocol.Frag
		if err := json.Unmarshal(plain, &f); err != nil {
			return
		}
		if s.frags == nil {
			s.frags = protocol.NewReassembler()
		}
		if full, ok, err := s.frags.Add(&f); err == nil && ok {
			s.handleClientMsg(sess, full)
		}
	case protocol.TKillAck:
		var a protocol.KillAck
		if err := json.Unmarshal(plain, &a); err == nil {
			s.killMu.Lock()
			ch := s.killWait[sess.SID]
			s.killMu.Unlock()
			if ch != nil {
				select {
				case ch <- &a:
				default:
				}
			}
			s.audit("client", "kill.ack", sess.SID, fmt.Sprintf("ok=%v note=%s", a.OK, a.Note))
		}
	case protocol.TUpdateResult:
		var u protocol.UpdateResult
		if err := json.Unmarshal(plain, &u); err == nil {
			s.audit(sess.ClientID, "update.result", sess.SID, fmt.Sprintf("v=%s state=%s %s", u.Version, u.State, u.Note))
		}
	case protocol.TTunnelData:
		var d protocol.TunnelData
		if err := json.Unmarshal(plain, &d); err == nil {
			s.tunnelData(d.TID, d.Data, d.FIN)
		}
	case protocol.TError:
		var e protocol.Error
		if err := json.Unmarshal(plain, &e); err == nil {
			s.logger.Printf("client error sid=%s: %s", sess.SID, e.Msg)
		}
	}
}

// fragments reassembly state.
func (s *Server) initFrags() {
	if s.frags == nil {
		s.frags = protocol.NewReassembler()
	}
}

func (s *Server) resolveTask(sess *Session, res *protocol.Result) {
	s.pendMu.Lock()
	ch := s.pending[res.ID]
	s.pendMu.Unlock()
	if ch != nil {
		select {
		case ch <- res:
		default:
		}
	}
	_ = s.st.FinishTask(context.Background(), store.Task{
		ID: res.ID, SID: sess.SID, State: pick(res.OK, "done", "failed"),
		Finished: time.Now().Unix(), Result: string(res.Data), Err: res.Err,
	})
	s.audit("client", "task.result", sess.SID, fmt.Sprintf("id=%s ok=%v err=%s", res.ID, res.OK, res.Err))
}

func pick(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

// SendMsg marshals and sends a control message.
func (s *Server) SendMsg(sess *Session, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.SendPlain(sess, b)
}

// SendPlain encrypts and sends a plaintext JSON payload.
func (s *Server) SendPlain(sess *Session, plain []byte) error {
	if sess.Stream != nil {
		env, err := sess.Keys.Seal(protocol.DirServerToClient, plain)
		if err != nil {
			return err
		}
		sess.streamMu.Lock()
		defer sess.streamMu.Unlock()
		return protocol.WriteStreamFrame(sess.Stream, env)
	}
	parts, err := protocol.FragmentJSON(plain, s.datagramFragSize(sess), protocol.RandomHex(6))
	if err != nil {
		return err
	}
	sess.dm.Lock()
	sess.dq = append(sess.dq, parts...)
	sess.dm.Unlock()
	return nil
}

func (s *Server) datagramFragSize(sess *Session) int {
	switch sess.Transport {
	case "dns":
		return 90
	case "doh":
		return 2000
	default:
		return 900
	}
}

// drainQueue seals queued plaintexts into sid-prefixed datagrams.
func (s *Server) drainQueue(sess *Session, max int) [][]byte {
	sess.dm.Lock()
	n := len(sess.dq)
	if max > 0 && n > max {
		n = max
	}
	items := append([][]byte{}, sess.dq[:n]...)
	sess.dq = sess.dq[n:]
	sess.dm.Unlock()
	var out [][]byte
	for _, plain := range items {
		env, err := sess.Keys.Seal(protocol.DirServerToClient, plain)
		if err != nil {
			continue
		}
		out = append(out, wrapDatagram(sess.SID, env))
	}
	return out
}

func wrapDatagram(sid string, env []byte) []byte {
	if len(sid) > 32 {
		sid = sid[:32]
	}
	out := make([]byte, 0, 2+len(sid)+len(env))
	out = append(out, protocol.Version, byte(len(sid)))
	out = append(out, sid...)
	out = append(out, env...)
	return out
}

func mustFrame(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return protocol.PlainEnvelope([]byte(`{"t":"error","msg":"marshal"}`))
	}
	return protocol.PlainEnvelope(b)
}

// RunTask dispatches a module and waits for the result.
func (s *Server) RunTask(ctx context.Context, sess *Session, name string, args json.RawMessage, actor string, timeout time.Duration) (*protocol.Result, error) {
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	id := protocol.RandomHex(8)
	task := protocol.Task{T: protocol.TTask, ID: id, Name: name, Args: args, TimeoutMS: int(timeout / time.Millisecond), Op: actor, Created: time.Now().Unix()}
	ch := make(chan *protocol.Result, 1)
	s.pendMu.Lock()
	s.pending[id] = ch
	s.pendMu.Unlock()
	defer func() {
		s.pendMu.Lock()
		delete(s.pending, id)
		s.pendMu.Unlock()
	}()
	_ = s.st.CreateTask(context.Background(), store.Task{
		ID: id, SID: sess.SID, Name: name, Args: string(args), State: "queued",
		Created: time.Now().Unix(), Op: actor,
	})
	if err := s.SendMsg(sess, task); err != nil {
		_ = s.st.FinishTask(context.Background(), store.Task{ID: id, SID: sess.SID, State: "send_failed", Finished: time.Now().Unix(), Err: err.Error()})
		return nil, err
	}
	select {
	case res := <-ch:
		return res, nil
	case <-time.After(timeout):
		_ = s.st.FinishTask(context.Background(), store.Task{ID: id, SID: sess.SID, State: "timeout", Finished: time.Now().Unix(), Err: "timeout"})
		return nil, errors.New("task timeout")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// KillSession performs the two-step signed kill-switch.
func (s *Server) KillSession(ctx context.Context, sess *Session, actor, reason string, uninstall bool) (*protocol.KillAck, error) {
	if len(s.killKey) == 0 {
		return nil, errors.New("kill key not configured")
	}
	nonce := protocol.RandomHex(12)
	expires := time.Now().Add(2 * time.Minute).Unix()
	if err := s.SendMsg(sess, protocol.KillPrepare{T: protocol.TKillPrepare, Nonce: nonce, Expires: expires, Issuer: actor, Reason: reason}); err != nil {
		return nil, err
	}
	kill := &protocol.Kill{T: protocol.TKill, Nonce: nonce, Expires: expires, WipeKeys: true, Uninstall: uninstall, Issuer: actor}
	kill.Sig = protocol.HMACSign(s.killKey, sess.SID, nonce, fmt.Sprint(expires), fmt.Sprint(kill.WipeKeys), fmt.Sprint(kill.Uninstall))
	ch := make(chan *protocol.KillAck, 1)
	s.killMu.Lock()
	s.killWait[sess.SID] = ch
	s.killMu.Unlock()
	defer func() {
		s.killMu.Lock()
		delete(s.killWait, sess.SID)
		s.killMu.Unlock()
	}()
	if err := s.SendMsg(sess, kill); err != nil {
		return nil, err
	}
	s.audit(actor, "kill.send", sess.SID, "reason="+reason)
	select {
	case a := <-ch:
		return a, nil
	case <-time.After(30 * time.Second):
		return nil, errors.New("kill ack timeout")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// PublishUpdate signs and stores a manifest, pushing it to matching clients.
func (s *Server) PublishUpdate(ctx context.Context, m protocol.UpdateManifest, actor string) (string, int, error) {
	if len(s.updateKey) == 0 {
		return "", 0, errors.New("update key not configured")
	}
	if m.Version == "" || m.Platform == "" || m.SHA256 == "" {
		return "", 0, errors.New("version, platform and sha256 are required")
	}
	if m.Rollout < 0 || m.Rollout > 100 {
		return "", 0, errors.New("rollout must be 0..100")
	}
	m.Created = time.Now().Unix()
	sig := protocol.HMACSign(s.updateKey, m.Version, m.Platform, m.Arch, m.URL, m.SHA256, fmt.Sprint(m.Rollout), m.MinVersion, m.Rollback)
	if err := s.st.SaveManifest(ctx, store.Manifest{Version: m.Version, Platform: m.Platform, Arch: m.Arch, URL: m.URL, SHA256: m.SHA256, Sig: sig, Rollout: m.Rollout, Created: m.Created}); err != nil {
		return "", 0, err
	}
	// Staged only: pushing requires an explicit `update-approve` by an admin so
	// an accidental publish never reaches fleets.
	s.audit(actor, "update.publish", m.Version, fmt.Sprintf("platform=%s arch=%s rollout=%d staged=true", m.Platform, m.Arch, m.Rollout))
	return sig, 0, nil
}

// ---------- datagrams ----------

// HandleDatagram processes one datagram frame and returns response blobs.
func (s *Server) HandleDatagram(req []byte, transport string) ([][]byte, error) {
	if len(req) < 2 || req[0] != protocol.Version {
		return nil, errors.New("bad datagram header")
	}
	sidLen := int(req[1])
	if len(req) < 2+sidLen {
		return nil, errors.New("truncated datagram")
	}
	sid := string(req[2 : 2+sidLen])
	env := req[2+sidLen:]
	if len(env) == 0 {
		// poll
		sess, ok := s.GetSession(sid)
		if !ok {
			return nil, errors.New("unknown sid")
		}
		return s.drainQueue(sess, 8), nil
	}
	if len(env) >= 2 && env[1] == protocol.KindPlain {
		body, err := protocol.ParsePlain(env)
		if err != nil {
			return nil, err
		}
		var hello protocol.Hello
		if err := json.Unmarshal(body, &hello); err != nil || hello.T != protocol.THello {
			return nil, errors.New("expected hello")
		}
		sess, ack, err := s.handshake(&hello, transport)
		if err != nil {
			b, _ := json.Marshal(protocol.Error{T: protocol.TError, Msg: err.Error()})
			return [][]byte{wrapDatagram("", protocol.PlainEnvelope(b))}, nil
		}
		ackBytes, _ := protocol.EncodePlain(ack)
		s.register(sess)
		out := [][]byte{wrapDatagram("", ackBytes)}
		return out, nil
	}
	sess, ok := s.GetSession(sid)
	if !ok {
		return nil, errors.New("unknown sid")
	}
	plain, err := sess.Keys.Open(protocol.DirClientToServer, env)
	if err != nil {
		return nil, err
	}
	s.handleClientMsg(sess, plain)
	return s.drainQueue(sess, 8), nil
}

// encodeBatch packs datagrams into a single blob.
func encodeBatch(items [][]byte) []byte {
	if len(items) > 65535 {
		items = items[:65535]
	}
	out := make([]byte, 0, 2)
	out = append(out, byte(len(items)>>8), byte(len(items)))
	for _, it := range items {
		if len(it) > 65535 {
			continue
		}
		out = append(out, byte(len(it)>>8), byte(len(it)))
		out = append(out, it...)
	}
	return out
}

// DecodeBatch unpacks a batch blob.
func DecodeBatch(buf []byte) ([][]byte, error) {
	if len(buf) < 2 {
		return nil, errors.New("short batch")
	}
	n := int(buf[0])<<8 | int(buf[1])
	off := 2
	out := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		if off+2 > len(buf) {
			return nil, errors.New("truncated batch length")
		}
		l := int(buf[off])<<8 | int(buf[off+1])
		off += 2
		if off+l > len(buf) {
			return nil, errors.New("truncated batch item")
		}
		out = append(out, append([]byte{}, buf[off:off+l]...))
		off += l
	}
	return out, nil
}

// ---------- tunnels ----------

// Tunnel is a local listener bridged to an agent.
type Tunnel struct {
	TID  string
	SID  string
	Host string
	Port int
	Ln   net.Listener
	mu   sync.Mutex
	conns map[string]net.Conn
}

// OpenTunnel starts a local TCP listener forwarding through the agent.
func (s *Server) OpenTunnel(sess *Session, host string, port, local int) (*Tunnel, error) {
	if local == 0 {
		local = port
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", local))
	if err != nil {
		return nil, err
	}
	t := &Tunnel{TID: protocol.RandomHex(6), SID: sess.SID, Host: host, Port: port, Ln: ln, conns: map[string]net.Conn{}}
	s.tunMu.Lock()
	s.tunnels[t.TID] = t
	s.tunMu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			cid := protocol.RandomHex(6)
			t.mu.Lock()
			t.conns[cid] = c
			t.mu.Unlock()
			_ = s.SendMsg(sess, protocol.TunnelOpen{T: protocol.TTunnelOpen, TID: cid, Host: host, Port: port})
			go s.pumpTunnel(cid, c, sess)
		}
	}()
	s.audit("operator", "tunnel.open", sess.SID, fmt.Sprintf("%s:%d local=%d tid=%s", host, port, local, t.TID))
	return t, nil
}

func (s *Server) pumpTunnel(tid string, c net.Conn, sess *Session) {
	buf := make([]byte, 8000)
	br := bufio.NewReader(c)
	for {
		n, err := br.Read(buf)
		if n > 0 {
			if e := s.SendMsg(sess, protocol.TunnelData{T: protocol.TTunnelData, TID: tid, Data: protocol.B64(buf[:n])}); e != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	_ = s.SendMsg(sess, protocol.TunnelData{T: protocol.TTunnelData, TID: tid, FIN: true})
	_ = c.Close()
	s.tunMu.Lock()
	for _, t := range s.tunnels {
		t.mu.Lock()
		delete(t.conns, tid)
		t.mu.Unlock()
	}
	s.tunMu.Unlock()
}

func (s *Server) tunnelData(tid, data string, fin bool) {
	var conn net.Conn
	s.tunMu.Lock()
	for _, t := range s.tunnels {
		t.mu.Lock()
		if c, ok := t.conns[tid]; ok {
			conn = c
		}
		t.mu.Unlock()
		if conn != nil {
			break
		}
	}
	s.tunMu.Unlock()
	if conn == nil {
		return
	}
	if data != "" {
		b, err := protocol.DecodeB64(data)
		if err == nil {
			_, _ = conn.Write(b)
		}
	}
	if fin {
		_ = conn.Close()
	}
}

// CloseTunnel closes a tunnel and its listener.
func (s *Server) CloseTunnel(tid string) error {
	s.tunMu.Lock()
	t, ok := s.tunnels[tid]
	if ok {
		delete(s.tunnels, tid)
	}
	s.tunMu.Unlock()
	if !ok {
		return sql.ErrNoRows
	}
	_ = t.Ln.Close()
	t.mu.Lock()
	for _, c := range t.conns {
		_ = c.Close()
	}
	t.mu.Unlock()
	return nil
}

// ---------- misc ----------

func readRand(b []byte) (int, error) { return io.ReadFull(rand.Reader, b) }

func setDeadline(c io.ReadWriteCloser, t time.Time) error {
	if dc, ok := c.(interface{ SetReadDeadline(time.Time) error }); ok {
		return dc.SetReadDeadline(t)
	}
	return nil
}

// PendingCount reports in-flight tasks (for tests).
func (s *Server) PendingCount() int {
	s.pendMu.Lock()
	defer s.pendMu.Unlock()
	return len(s.pending)
}

