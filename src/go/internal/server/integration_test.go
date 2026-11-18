package server

// End-to-end integration tests for the C2V2 control plane.
//
// These tests start the real server (dual listeners, TLS/WS/UDP/DNS/DoH) on
// 127.0.0.1:0, implement a minimal Go client that speaks the same wire format
// as the Rust client, and drive the real operator API.  Nothing here touches a
// network target; everything is loopback.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"c2v2/internal/operator"
	"c2v2/internal/protocol"
	"c2v2/internal/store"
)

// ---------------- fake client ----------------

type fakeClient struct {
	t       *testing.T
	rw      io.ReadWriteCloser
	keys    *protocol.Keys
	sid     string
	psk     []byte
	killKey []byte
	updateKey []byte

	mu       sync.Mutex
	prepare  *protocol.KillPrepare
	kills    []protocol.Kill
	acks     []protocol.KillAck
	updates  []protocol.Update
	updSigOK []bool
	tasks    []string
	closed   chan struct{}
}

func (c *fakeClient) loop() {
	defer close(c.closed)
	for {
		frame, err := protocol.ReadStreamFrame(c.rw)
		if err != nil {
			return
		}
		if len(frame) < 2 {
			return
		}
		plain, err := c.keys.Open(protocol.DirServerToClient, frame)
		if err != nil {
			c.t.Errorf("client decrypt: %v", err)
			return
		}
		switch protocol.MessageType(plain) {
		case protocol.TTask:
			var task protocol.Task
			if err := json.Unmarshal(plain, &task); err != nil {
				continue
			}
			c.mu.Lock()
			c.tasks = append(c.tasks, task.Name)
			c.mu.Unlock()
			data, _ := json.Marshal(map[string]any{"echo": task.Name, "sid": c.sid})
			c.send(protocol.Result{T: protocol.TResult, ID: task.ID, OK: true, Data: data})
		case protocol.THBAck:
			// ignore
		case protocol.TKillPrepare:
			var kp protocol.KillPrepare
			if err := json.Unmarshal(plain, &kp); err == nil {
				c.mu.Lock()
				c.prepare = &kp
				c.mu.Unlock()
			}
		case protocol.TKill:
			var k protocol.Kill
			if err := json.Unmarshal(plain, &k); err != nil {
				continue
			}
			ok := protocol.HMACVerify(c.killKey, k.Sig, k.Canonical(c.sid))
			c.mu.Lock()
			c.kills = append(c.kills, k)
			c.mu.Unlock()
			c.send(protocol.KillAck{T: protocol.TKillAck, Nonce: k.Nonce, OK: ok, Note: "fake-client"})
		case protocol.TUpdate:
			var u protocol.Update
			if err := json.Unmarshal(plain, &u); err != nil {
				continue
			}
			sigOK := protocol.HMACVerify(c.updateKey, u.Sig, u.Manifest.Canonical())
			c.mu.Lock()
			c.updates = append(c.updates, u)
			c.updSigOK = append(c.updSigOK, sigOK)
			c.mu.Unlock()
			c.send(protocol.UpdateResult{T: protocol.TUpdateResult, Version: u.Manifest.Version, State: "staged", Note: "fake-client"})
		}
	}
}

// pskUpdateKey is kept for backwards compatibility with older test helpers.
func (c *fakeClient) pskUpdateKey() []byte { return c.updateKey }

func (c *fakeClient) send(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		c.t.Errorf("marshal: %v", err)
		return
	}
	env, err := c.keys.Seal(protocol.DirClientToServer, b)
	if err != nil {
		c.t.Errorf("seal: %v", err)
		return
	}
	_ = protocol.WriteStreamFrame(c.rw, env)
}

func (c *fakeClient) snapshot() (tasks []string, kills []protocol.Kill, acks []protocol.KillAck, updates []protocol.Update, sigOK []bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string{}, c.tasks...), append([]protocol.Kill{}, c.kills...), append([]protocol.KillAck{}, c.acks...),
		append([]protocol.Update{}, c.updates...), append([]bool{}, c.updSigOK...)
}

// ---------------- harness ----------------

type harness struct {
	s       *Server
	cfg     *Config
	psk     []byte
	killKey []byte
	updKey  []byte
	opKey   []byte
}

func newHarness(t *testing.T, streams []string, datagrams bool, aiURL string) *harness {
	t.Helper()
	psk := bytes.Repeat([]byte{0x11}, 32)
	killKey := bytes.Repeat([]byte{0x22}, 32)
	updKey := bytes.Repeat([]byte{0x33}, 32)
	opKey := bytes.Repeat([]byte{0x44}, 32)
	cfg := DefaultConfig()
	cfg.PSKB64 = protocol.B64(psk)
	cfg.KillKeyB64 = protocol.B64(killKey)
	cfg.UpdateKeyB64 = protocol.B64(updKey)
	cfg.Tenant = "test"
	cfg.Storage = "memory"
	cfg.Sleep = 5
	cfg.Listeners = nil
	for _, tr := range streams {
		cfg.Listeners = append(cfg.Listeners, ListenerConfig{Transport: tr, Addr: "127.0.0.1:0", Path: "/ws"})
	}
	if datagrams {
		cfg.Listeners = append(cfg.Listeners,
			ListenerConfig{Transport: "udp", Addr: "127.0.0.1:0"},
			ListenerConfig{Transport: "dns", Addr: "127.0.0.1:0", Suffix: "test.example.com"},
			ListenerConfig{Transport: "doh", Addr: "127.0.0.1:0", Path: "/doh"})
	}
	cfg.OperatorListener = ListenerConfig{Transport: "tls", Addr: "127.0.0.1:0"}
	cfg.Operators = []OperatorConfig{{User: "tester", Role: "admin", Tenant: "test", KeyB64: protocol.B64(opKey)}}
	cfg.ModulesDir = t.TempDir()
	cfg.AI = AIConfig{Enabled: aiURL != "", BaseURL: aiURL, Model: "test-model", KeyEnv: "C2V2_TEST_AI_KEY", MaxRounds: 4}
	logger := log.New(os.Stderr, "[itest] ", log.LstdFlags)
	s, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return &harness{s: s, cfg: cfg, psk: psk, killKey: killKey, updKey: updKey, opKey: opKey}
}

func (h *harness) dialStream(t *testing.T, transport string) *fakeClient {
	t.Helper()
	addr := h.s.BoundAddrs()[transport]
	if addr == "" {
		t.Fatalf("transport %s not bound", transport)
	}
	var rw io.ReadWriteCloser
	switch transport {
	case "tcp", "tls":
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %s: %v", transport, err)
		}
		if transport == "tls" {
			tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "test.example.com"})
			if err := tc.Handshake(); err != nil {
				conn.Close()
				t.Fatalf("tls handshake %s: %v", transport, err)
			}
			rw = tc
		} else {
			rw = conn
		}
	case "ws", "wss":
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %s: %v", transport, err)
		}
		if transport == "wss" {
			tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "test.example.com"})
			if err := tc.Handshake(); err != nil {
				conn.Close()
				t.Fatalf("tls handshake %s: %v", transport, err)
			}
			conn = tc
		}
		ws, err := protocol.DialWebSocket(conn, addr, "/ws")
		if err != nil {
			conn.Close()
			t.Fatalf("ws dial %s: %v", transport, err)
		}
		rw = ws
	default:
		t.Fatalf("unsupported stream %s", transport)
	}
	return h.handshakeOver(t, rw, transport)
}

func (h *harness) handshakeOver(t *testing.T, rw io.ReadWriteCloser, transport string) *fakeClient {
	t.Helper()
	priv, err := protocol.NewEphemeral()
	if err != nil {
		t.Fatalf("ephemeral: %v", err)
	}
	nonceC := make([]byte, 32)
	_, _ = rand.Read(nonceC)
	clientID := "fake-" + transport + "-" + protocol.RandomHex(3)
	hello := protocol.Hello{
		V: protocol.Version, T: protocol.THello, ClientID: clientID, Nonce: protocol.B64(nonceC),
		Pub: protocol.B64(protocol.PublicRaw(priv)), Cipher: protocol.CipherAES256GCM.String(),
		Transport: transport, Caps: []string{"shell", "fs_cat", "ai_context"},
		TS: time.Now().Unix(),
		Machine: protocol.Machine{Host: "fake-" + transport, OS: "linux", Arch: "amd64", User: "tester"},
	}
	hello.NonceSig = protocol.HMACSign(h.psk, clientID, hello.Nonce, fmt.Sprint(hello.TS))
	env, err := protocol.EncodePlain(hello)
	if err != nil {
		t.Fatalf("encode hello: %v", err)
	}
	_ = setRWDeadline(rw, time.Now().Add(10 * time.Second))
	if err := protocol.WriteStreamFrame(rw, env); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	frame, err := protocol.ReadStreamFrame(rw)
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	body, err := protocol.ParsePlain(frame)
	if err != nil {
		t.Fatalf("parse ack: %v", err)
	}
	var ack protocol.HelloAck
	if err := json.Unmarshal(body, &ack); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	if ack.Error != "" {
		t.Fatalf("server rejected handshake: %s", ack.Error)
	}
	nonceS, err := base64.StdEncoding.DecodeString(ack.Nonce)
	if err != nil {
		t.Fatalf("nonceS: %v", err)
	}
	pubS, err := base64.StdEncoding.DecodeString(ack.Pub)
	if err != nil {
		t.Fatalf("pubS: %v", err)
	}
	shared, err := protocol.SharedRaw(priv, pubS)
	if err != nil {
		t.Fatalf("shared: %v", err)
	}
	keys, err := protocol.DeriveKeys(shared, h.psk, nonceC, nonceS, protocol.ParseCipher(ack.Cipher))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if keys.SID != ack.SID {
		t.Fatalf("sid mismatch: %s != %s", keys.SID, ack.SID)
	}
	_ = setRWDeadline(rw, time.Time{})
	c := &fakeClient{t: t, rw: rw, keys: keys, sid: ack.SID, psk: h.psk, killKey: h.killKey, updateKey: h.updKey, closed: make(chan struct{})}
	go c.loop()
	return c
}

// ---------------- tests ----------------

func TestStreamHandshakeAndTaskAllTransports(t *testing.T) {
	h := newHarness(t, []string{"tls", "tcp", "ws", "wss"}, true, "")
	transports := []string{"tls", "tcp", "ws", "wss"}
	clients := map[string]*fakeClient{}
	for _, tr := range transports {
		c := h.dialStream(t, tr)
		clients[tr] = c
		if len(h.s.Sessions()) < 1 {
			t.Fatalf("session not registered for %s", tr)
		}
	}
	if got := len(h.s.Sessions()); got != len(transports) {
		t.Fatalf("want %d sessions, got %d", len(transports), got)
	}
	for tr, c := range clients {
		sess, ok := h.s.GetSession(c.sid)
		if !ok {
			t.Fatalf("server lost session for %s", tr)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		res, err := h.s.RunTask(ctx, sess, "sysinfo", json.RawMessage(`{}`), "tester", 5*time.Second)
		cancel()
		if err != nil {
			t.Fatalf("run task %s: %v", tr, err)
		}
		if !res.OK {
			t.Fatalf("task %s failed: %s", tr, res.Err)
		}
		if !strings.Contains(string(res.Data), "sysinfo") {
			t.Fatalf("task %s unexpected data: %s", tr, res.Data)
		}
	}
	// No transport may leak another session's task.
	for tr, c := range clients {
		tasks, _, _, _, _ := c.snapshot()
		if len(tasks) != 1 {
			t.Fatalf("%s received %d tasks: %v", tr, len(tasks), tasks)
		}
		c.rw.Close()
		_ = c
	}
}

func TestDatagramHelloUDPDoH(t *testing.T) {
	h := newHarness(t, nil, true, "")
	// UDP
	udpAddr := h.s.BoundAddrs()["udp"]
	uc, err := net.Dial("udp", udpAddr)
	if err != nil {
		t.Fatalf("udp dial: %v", err)
	}
	defer uc.Close()
	priv, _ := protocol.NewEphemeral()
	nonceC := make([]byte, 32)
	_, _ = rand.Read(nonceC)
	hello := protocol.Hello{V: protocol.Version, T: protocol.THello, ClientID: "fake-udp", Nonce: protocol.B64(nonceC),
		Pub: protocol.B64(protocol.PublicRaw(priv)), Cipher: protocol.CipherAES256GCM.String(), Transport: "udp",
		TS: time.Now().Unix(), Machine: protocol.Machine{Host: "fake-udp", OS: "linux", Arch: "amd64", User: "t"}}
	hello.NonceSig = protocol.HMACSign(h.psk, hello.ClientID, hello.Nonce, fmt.Sprint(hello.TS))
	env, _ := protocol.EncodePlain(hello)
	dg := append([]byte{byte(protocol.Version), 0}, env...)
	if _, err := uc.Write(dg); err != nil {
		t.Fatalf("udp write: %v", err)
	}
	_ = uc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 65535)
	n, err := uc.Read(buf)
	if err != nil {
		t.Fatalf("udp read: %v", err)
	}
	if n < 3 {
		t.Fatalf("bad udp response: %x", buf[:min(n, 8)])
	}
	udpItems, err := DecodeBatch(buf[:n])
	if err != nil || len(udpItems) == 0 {
		t.Fatalf("udp batch: %v (raw=%x)", err, buf[:min(n, 16)])
	}
	udpEnv, udpSID, err := datagramEnv(udpItems[0])
	if err != nil {
		t.Fatalf("udp envelope: %v", err)
	}
	ackBody, err := protocol.ParsePlain(udpEnv)
	if err != nil {
		t.Fatalf("udp ack parse: %v", err)
	}
	var ack protocol.HelloAck
	if err := json.Unmarshal(ackBody, &ack); err != nil || ack.Error != "" {
		t.Fatalf("udp ack: %v %+v", err, ack)
	}
	_ = udpSID
	if ack.SID == "" {
		t.Fatalf("udp handshake returned empty sid")
	}

	// DoH (POST binary batch)
	dohAddr := h.s.BoundAddrs()["doh"]
	priv2, _ := protocol.NewEphemeral()
	nonce2 := make([]byte, 32)
	_, _ = rand.Read(nonce2)
	hello2 := protocol.Hello{V: protocol.Version, T: protocol.THello, ClientID: "fake-doh", Nonce: protocol.B64(nonce2),
		Pub: protocol.B64(protocol.PublicRaw(priv2)), Cipher: protocol.CipherAES256GCM.String(), Transport: "doh",
		TS: time.Now().Unix(), Machine: protocol.Machine{Host: "fake-doh", OS: "linux", Arch: "amd64", User: "t"}}
	hello2.NonceSig = protocol.HMACSign(h.psk, hello2.ClientID, hello2.Nonce, fmt.Sprint(hello2.TS))
	env2, _ := protocol.EncodePlain(hello2)
	dg2 := append([]byte{byte(protocol.Version), 0}, env2...)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Post("https://"+dohAddr+"/doh", "application/octet-stream", bytes.NewReader(dg2))
	if err != nil {
		t.Fatalf("doh post: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	items, err := DecodeBatch(raw)
	if err != nil || len(items) == 0 {
		t.Fatalf("doh batch: %v (%d bytes)", err, len(raw))
	}
	envFromItem, _, err := datagramEnv(items[0])
	if err != nil {
		t.Fatalf("doh item: %v", err)
	}
	ackBody2, err := protocol.ParsePlain(envFromItem)
	if err != nil {
		t.Fatalf("doh ack: %v", err)
	}
	var ack2 protocol.HelloAck
	if err := json.Unmarshal(ackBody2, &ack2); err != nil || ack2.SID == "" {
		t.Fatalf("doh handshake failed: %v %+v", err, ack2)
	}

	// DNS TXT transport
	dnsAddr := h.s.BoundAddrs()["dns"]
	priv3, _ := protocol.NewEphemeral()
	nonce3 := make([]byte, 32)
	_, _ = rand.Read(nonce3)
	hello3 := protocol.Hello{V: protocol.Version, T: protocol.THello, ClientID: "fake-dns", Nonce: protocol.B64(nonce3),
		Pub: protocol.B64(protocol.PublicRaw(priv3)), Cipher: protocol.CipherAES256GCM.String(), Transport: "dns",
		TS: time.Now().Unix(), Machine: protocol.Machine{Host: "fake-dns", OS: "linux", Arch: "amd64", User: "t"}}
	hello3.NonceSig = protocol.HMACSign(h.psk, hello3.ClientID, hello3.Nonce, fmt.Sprint(hello3.TS))
	env3, _ := protocol.EncodePlain(hello3)
	dg3 := append([]byte{byte(protocol.Version), 0}, env3...)
	q := protocol.EncodeDNSQuery(dg3, "test.example.com", 50)
	dc, err := net.Dial("udp", dnsAddr)
	if err != nil {
		t.Fatalf("dns dial: %v", err)
	}
	defer dc.Close()
	if _, err := dc.Write(q); err != nil {
		t.Fatalf("dns write: %v", err)
	}
	_ = dc.SetReadDeadline(time.Now().Add(5 * time.Second))
	rbuf := make([]byte, 65535)
	rn, err := dc.Read(rbuf)
	if err != nil {
		t.Fatalf("dns read: %v", err)
	}
	dr, err := protocol.ParseTXTResponse(rbuf[:rn])
	if err != nil {
		t.Fatalf("dns parse: %v", err)
	}
	var joined []byte
	for _, ch := range dr.Chunks {
		joined = append(joined, ch...)
	}
	ditems, err := DecodeBatch(joined)
	if err != nil || len(ditems) == 0 {
		t.Fatalf("dns batch: %v (%d chunks)", err, len(dr.Chunks))
	}
	envFromItem3, _, err := datagramEnv(ditems[0])
	if err != nil {
		t.Fatalf("dns item: %v", err)
	}
	ackBody3, err := protocol.ParsePlain(envFromItem3)
	if err != nil {
		t.Fatalf("dns ack: %v", err)
	}
	var ack3 protocol.HelloAck
	if err := json.Unmarshal(ackBody3, &ack3); err != nil || ack3.SID == "" {
		t.Fatalf("dns handshake failed: %v %+v", err, ack3)
	}
}

func TestOperatorAPIAndAuditChain(t *testing.T) {
	h := newHarness(t, []string{"tls"}, false, "")
	c := h.dialStream(t, "tls")
	op, err := operator.Dial(context.Background(), "tls://"+h.s.BoundAddrs()["operator"], operator.Options{
		User: "tester", Key: h.opKey, Insecure: true, Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("operator dial: %v", err)
	}
	defer op.Close()

	raw, err := op.Call(context.Background(), "list", map[string]any{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var listed []map[string]any
	if err := json.Unmarshal(raw, &listed); err != nil {
		t.Fatalf("list unmarshal: %v (%s)", err, raw)
	}
	if len(listed) < 1 {
		t.Fatalf("operator list saw no sessions: %s", raw)
	}
	// module registry via operator
	raw, err = op.Call(context.Background(), "module-search", map[string]any{"q": "shell"})
	if err != nil {
		t.Fatalf("module-search: %v", err)
	}
	if !bytes.Contains(raw, []byte("shell")) {
		t.Fatalf("module-search did not return shell: %s", raw)
	}
	raw, err = op.Call(context.Background(), "module-show", map[string]any{"name": "ai_context"})
	if err != nil {
		t.Fatalf("module-show: %v", err)
	}
	if !bytes.Contains(raw, []byte("builtin")) {
		t.Fatalf("module-show ai_context: %s", raw)
	}
	// run a task via operator
	raw, err = op.Call(context.Background(), "run", map[string]any{"name": "whoami", "sid": c.sid, "args": map[string]any{}})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !bytes.Contains(raw, []byte("whoami")) {
		t.Fatalf("run result: %s", raw)
	}
	// tasks history
	raw, err = op.Call(context.Background(), "tasks", map[string]any{"sid": c.sid, "limit": 20})
	if err != nil {
		t.Fatalf("tasks: %v", err)
	}
	if !bytes.Contains(raw, []byte("whoami")) {
		t.Fatalf("tasks missing whoami: %s", raw)
	}
	// audit chain verification
	raw, err = op.Call(context.Background(), "verify-audit", map[string]any{})
	if err != nil {
		t.Fatalf("verify-audit: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"ok":true`)) {
		t.Fatalf("audit chain not ok: %s", raw)
	}
	// tampering must be detected by the store-level verifier
	ents, err := h.s.st.ListAudit(context.Background(), 1000)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(ents) < 3 {
		t.Fatalf("expected audit entries, got %d", len(ents))
	}
	for i := 1; i < len(ents); i++ {
		if ents[i].PrevHash != ents[i-1].Hash {
			t.Fatalf("audit chain broken at %d", i)
		}
	}
	bad := ents[0]
	bad.Detail = bad.Detail + "tampered"
	if store.HashEntry(bad.PrevHash, fmt.Sprint(bad.TS), bad.Actor, bad.Action, bad.Target, bad.Detail) == bad.Hash {
		t.Fatalf("tamper detection failed: recomputed hash equals stored hash")
	}
}

func TestSignedUpdateApprovalPinAndRollback(t *testing.T) {
	h := newHarness(t, []string{"tls"}, false, "")
	c := h.dialStream(t, "tls")
	op, err := operator.Dial(context.Background(), "tls://"+h.s.BoundAddrs()["operator"], operator.Options{
		User: "tester", Key: h.opKey, Insecure: true, Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("operator dial: %v", err)
	}
	defer op.Close()

	// publish v2 (staged, not pushed)
	raw, err := op.Call(context.Background(), "update-publish", map[string]any{
		"version": "2.0.0", "platform": "linux", "arch": "amd64",
		"url": "https://downloads.example.com/c2/client-2.0.0", "sha256": strings.Repeat("ab", 32), "rollout": 100,
	})
	if err != nil {
		t.Fatalf("update-publish: %v", err)
	}
	if !bytes.Contains(raw, []byte("sig")) {
		t.Fatalf("publish response: %s", raw)
	}
	time.Sleep(150 * time.Millisecond)
	if tasks, kills, _, upd, _ := c.snapshot(); len(upd) != 0 {
		t.Fatalf("unapproved update leaked to client (tasks=%v kills=%v updates=%d)", tasks, kills, len(upd))
	}

	// push without approval is a no-op
	raw, err = op.Call(context.Background(), "update-push", map[string]any{"version": "2.0.0"})
	if err != nil {
		t.Fatalf("update-push: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"pushed":0`)) {
		t.Fatalf("expected zero pushed before approval: %s", raw)
	}
	// approve -> pushed
	raw, err = op.Call(context.Background(), "update-approve", map[string]any{"version": "2.0.0"})
	if err != nil {
		t.Fatalf("update-approve: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"pushed":1`)) {
		t.Fatalf("approve did not push: %s", raw)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, _, upd, _ := c.snapshot(); len(upd) == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	_, _, _, updates, sigOK := c.snapshot()
	if len(updates) != 1 {
		t.Fatalf("client got %d updates, want 1", len(updates))
	}
	if !sigOK[0] {
		t.Fatalf("client-side manifest signature verification failed")
	}
	if updates[0].Manifest.Version != "2.0.0" {
		t.Fatalf("bad version: %s", updates[0].Manifest.Version)
	}

	// pin 2.0.0 then publish+approve 3.0.0: push must be blocked
	raw, err = op.Call(context.Background(), "update-pin", map[string]any{"version": "2.0.0"})
	if err != nil {
		t.Fatalf("update-pin: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"pinned":"2.0.0"`)) {
		t.Fatalf("pin response: %s", raw)
	}
	if _, err := op.Call(context.Background(), "update-publish", map[string]any{
		"version": "3.0.0", "platform": "linux", "arch": "amd64",
		"url": "https://downloads.example.com/c2/client-3.0.0", "sha256": strings.Repeat("cd", 32), "rollout": 100,
	}); err != nil {
		t.Fatalf("publish 3.0.0: %v", err)
	}
	if _, err := op.Call(context.Background(), "update-approve", map[string]any{"version": "3.0.0"}); err == nil {
		t.Fatalf("approve 3.0.0 should be blocked by pin 2.0.0")
	} else if !strings.Contains(err.Error(), "pin") {
		t.Fatalf("unexpected approve error: %v", err)
	}
	if _, err := op.Call(context.Background(), "update-push", map[string]any{}); err != nil {
		t.Fatalf("pinned push: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	_, _, _, upd, _ := c.snapshot()
	for _, u := range upd {
		if u.Manifest.Version == "3.0.0" {
			t.Fatalf("pinned push leaked blocked version 3.0.0")
		}
	}
	before := len(upd)
	// rollback 3.0.0 -> 2.0.0 is always allowed
	raw, err = op.Call(context.Background(), "update-rollback", map[string]any{"version": "3.0.0", "target": "2.0.0"})
	if err != nil {
		t.Fatalf("update-rollback: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"pushed":1`)) {
		t.Fatalf("rollback did not push: %s", raw)
	}
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, _, u, _ := c.snapshot(); len(u) > before {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	_, _, _, updates, sigOK = c.snapshot()
	if len(updates) != before+1 || !sigOK[len(sigOK)-1] {
		t.Fatalf("rollback update missing or bad sig: %d %v", len(updates), sigOK)
	}
	last := updates[len(updates)-1]
	if last.Manifest.Rollback != "3.0.0" || last.Manifest.Version != "2.0.0" {
		t.Fatalf("rollback manifest wrong: %+v", last.Manifest)
	}
}

func TestTwoStepSignedKill(t *testing.T) {
	h := newHarness(t, []string{"tls"}, false, "")
	c := h.dialStream(t, "tls")
	sess, ok := h.s.GetSession(c.sid)
	if !ok {
		t.Fatalf("no session")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ack, err := h.s.KillSession(ctx, sess, "tester", "integration test", false)
	if err != nil {
		t.Fatalf("KillSession: %v", err)
	}
	if ack == nil || !ack.OK {
		t.Fatalf("kill ack: %+v", ack)
	}
	_, kills, _, _, _ := c.snapshot()
	if len(kills) != 1 {
		t.Fatalf("client saw %d kill messages", len(kills))
	}
	if !kills[0].WipeKeys {
		t.Fatalf("kill did not request key wipe")
	}
	var found bool
	for _, e := range mustAudit(t, h) {
		if e.Action == "kill.ack" && strings.Contains(e.Detail, "ok=true") {
			found = true
		}
	}
	if !found {
		t.Fatalf("kill ack not audited")
	}
}

func TestAIAssistantPolicyAndEvidence(t *testing.T) {
	var mu sync.Mutex
	var phases []string
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req)
		last := ""
		hasTool := false
		for _, m := range req.Messages {
			if m.Role == "tool" {
				hasTool = true
			}
			last = m.Content
		}
		mu.Lock()
		phases = append(phases, last)
		mu.Unlock()
		var msg map[string]any
		if hasTool {
			msg = map[string]any{"role": "assistant", "content": "Based on [list_sessions] there is 1 session."}
		} else if strings.Contains(last, "kill") {
			sid := last
			if i := strings.Index(sid, "sid="); i >= 0 {
				sid = sid[i+4:]
				if j := strings.IndexAny(sid, " ,"); j >= 0 {
					sid = sid[:j]
				}
			}
			msg = map[string]any{"role": "assistant", "content": "", "tool_calls": []map[string]any{{
				"id": "call_1", "type": "function", "function": map[string]any{
					"name": "kill_session", "arguments": fmt.Sprintf(`{"sid":%q,"reason":"ai test"}`, sid),
				}}}}
		} else {
			msg = map[string]any{"role": "assistant", "content": "", "tool_calls": []map[string]any{{
				"id": "call_0", "type": "function", "function": map[string]any{"name": "list_sessions", "arguments": "{}"},
			}}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []map[string]any{{"message": msg}}, "usage": map[string]int{"total_tokens": 42}})
	}))
	defer fake.Close()

	h := newHarness(t, []string{"tls"}, false, fake.URL)
	c := h.dialStream(t, "tls")
	op, err := operator.Dial(context.Background(), "tls://"+h.s.BoundAddrs()["operator"], operator.Options{
		User: "tester", Key: h.opKey, Insecure: true, Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("operator dial: %v", err)
	}
	defer op.Close()

	// read-only tool auto-executes
	raw, err := op.Call(context.Background(), "ai-ask", map[string]any{"prompt": "summarize sessions"})
	if err != nil {
		t.Fatalf("ai-ask: %v", err)
	}
	var res struct {
		Answer string `json:"answer"`
		Steps  []struct {
			Tool    string `json:"tool"`
			Allowed bool   `json:"allowed"`
			Result  any    `json:"result"`
		} `json:"steps"`
		Evidence []any `json:"evidence"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatalf("ai result: %v (%s)", err, raw)
	}
	if len(res.Steps) != 1 || res.Steps[0].Tool != "list_sessions" || !res.Steps[0].Allowed {
		t.Fatalf("read-only tool not executed: %s", raw)
	}
	if len(res.Evidence) == 0 {
		t.Fatalf("no evidence bundle: %s", raw)
	}

	// destructive tool must be blocked first ...
	raw, err = op.Call(context.Background(), "ai-ask", map[string]any{"prompt": "kill sid=" + c.sid})
	if err != nil {
		t.Fatalf("ai-ask kill: %v", err)
	}
	var res2 struct {
		NeedApprove []string `json:"need_approve"`
		Steps       []struct {
			Tool    string `json:"tool"`
			Allowed bool   `json:"allowed"`
		} `json:"steps"`
	}
	if err := json.Unmarshal(raw, &res2); err != nil {
		t.Fatalf("ai kill result: %v (%s)", err, raw)
	}
	if len(res2.NeedApprove) != 1 || res2.NeedApprove[0] != "kill_session" {
		t.Fatalf("expected approval requirement: %s", raw)
	}
	if len(res2.Steps) == 0 || res2.Steps[0].Allowed {
		t.Fatalf("destructive tool executed without approval: %s", raw)
	}
	if _, kills, _, _, _ := c.snapshot(); len(kills) != 0 {
		t.Fatalf("kill executed before approval")
	}

	// ... and execute only after explicit confirmation
	raw, err = op.Call(context.Background(), "ai-ask", map[string]any{"prompt": "kill sid=" + c.sid, "confirm": "kill_session"})
	if err != nil {
		t.Fatalf("ai-ask confirmed: %v", err)
	}
	var res3 struct {
		Steps []struct {
			Tool    string `json:"tool"`
			Allowed bool   `json:"allowed"`
		} `json:"steps"`
	}
	if err := json.Unmarshal(raw, &res3); err != nil {
		t.Fatalf("ai confirmed result: %v (%s)", err, raw)
	}
	if len(res3.Steps) == 0 || !res3.Steps[0].Allowed {
		t.Fatalf("confirmed tool did not run: %s", raw)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, kills, _, _, _ := c.snapshot(); len(kills) == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, kills, _, _, _ := c.snapshot(); len(kills) != 1 {
		t.Fatalf("confirmed kill did not reach client")
	}
	// every AI decision is audited
	var aiAudits int
	for _, e := range mustAudit(t, h) {
		if strings.HasPrefix(e.Action, "ai.") {
			aiAudits++
		}
	}
	if aiAudits < 3 {
		t.Fatalf("expected AI audit entries, got %d", aiAudits)
	}
}

// ---------------- helpers ----------------

func mustAudit(t *testing.T, h *harness) []auditEntryView {
	t.Helper()
	ents, err := h.s.st.ListAudit(context.Background(), 500)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	out := make([]auditEntryView, 0, len(ents))
	for _, e := range ents {
		out = append(out, auditEntryView{Action: e.Action, Detail: e.Detail})
	}
	return out
}

type auditEntryView struct{ Action, Detail string }

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}









func setRWDeadline(rw io.ReadWriteCloser, t time.Time) error {
	type deadlineSetter interface{ SetDeadline(time.Time) error }
	if d, ok := rw.(deadlineSetter); ok {
		return d.SetDeadline(t)
	}
	return nil
}

func datagramEnv(b []byte) (env []byte, sid string, err error) {
	if len(b) < 2 {
		return nil, "", fmt.Errorf("short datagram")
	}
	if b[0] != byte(protocol.Version) {
		return nil, "", fmt.Errorf("bad datagram version %d", b[0])
	}
	n := int(b[1])
	if len(b) < 2+n {
		return nil, "", fmt.Errorf("short sid (%d > %d)", n, len(b)-2)
	}
	return b[2+n:], string(b[2 : 2+n]), nil
}




