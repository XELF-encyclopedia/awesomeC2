package server

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"c2v2/internal/catalog"
	"c2v2/internal/protocol"
	"c2v2/internal/store"
)

// OpConn is a connected operator console.
type OpConn struct {
	srv       *Server
	User      string
	Role      string
	Tenant    string
	Transport string
	Keys      *protocol.Keys
	Stream    io.Writer
	mu        sync.Mutex
	Since     int64
	LastSeen  int64
}

func (o *OpConn) send(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	env, err := o.Keys.Seal(protocol.DirServerToClient, b)
	if err != nil {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return protocol.WriteStreamFrame(o.Stream, env)
}

func roleRank(r string) int {
	switch r {
	case "admin":
		return 3
	case "operator":
		return 2
	case "viewer":
		return 1
	default:
		return 0
	}
}

func (s *Server) startOperatorListener(l ListenerConfig) error {
	transport := strings.ToLower(l.Transport)
	switch transport {
	case "tls", "tcp":
		ln, err := net.Listen("tcp", l.Addr)
		if err != nil {
			return err
		}
		var srv net.Listener = ln
		if transport == "tls" {
			srv = tls.NewListener(ln, TLSConfig(s.cert))
		}
		s.noteBound("operator", ln.Addr())
		s.addCloser(srv)
		go func() {
			for {
				c, err := srv.Accept()
				if err != nil {
					select {
					case <-s.stop:
						return
					default:
						time.Sleep(50 * time.Millisecond)
						continue
					}
				}
				go s.ServeOperator(c, "op-"+transport)
			}
		}()
		return nil
	case "ws", "wss":
		path := l.Path
		if path == "" {
			path = "/op"
		}
		mux := http.NewServeMux()
		srv := &http.Server{Addr: l.Addr, Handler: mux, ReadHeaderTimeout: 15 * time.Second}
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			if !protocol.IsWebSocketUpgrade(r) {
				http.Error(w, "websocket upgrade required", http.StatusBadRequest)
				return
			}
			ws, err := protocol.UpgradeWebSocket(w, r)
			if err != nil {
				return
			}
			s.ServeOperator(ws, "op-"+transport)
		})
		var (
			ln  net.Listener
			err error
		)
		if transport == "wss" {
			ln, err = tls.Listen("tcp", l.Addr, TLSConfig(s.cert))
		} else {
			ln, err = net.Listen("tcp", l.Addr)
		}
		if err != nil {
			return err
		}
		s.addCloser(ln)
		go func() { _ = srv.Serve(ln) }()
		return nil
	default:
		return fmt.Errorf("unknown operator transport %q", l.Transport)
	}
}

// ServeOperator handles the operator handshake and command loop.
func (s *Server) ServeOperator(rw io.ReadWriteCloser, transport string) {
	defer rw.Close()
	frame, err := protocol.ReadStreamFrame(rw)
	if err != nil {
		return
	}
	var hello protocol.OpHello
	if err := json.Unmarshal(frame, &hello); err != nil || hello.T != protocol.TOpHello {
		return
	}
	fail := func(msg string) {
		b, _ := json.Marshal(protocol.OpHelloAck{V: protocol.Version, T: protocol.TOpHelloAck, Error: msg})
		_ = protocol.WriteStreamFrame(rw, b)
		s.audit(hello.User, "operator.login_failed", hello.User, msg)
	}
	if hello.V != protocol.Version || hello.User == "" {
		fail("bad op_hello")
		return
	}
	now := time.Now().Unix()
	if hello.TS < now-300 || hello.TS > now+300 {
		fail("clock skew")
		return
	}
	s.opKeysMu.RLock()
	key := s.opKeys[hello.User]
	cfg, hasCfg := s.opCfg[hello.User]
	s.opKeysMu.RUnlock()
	if len(key) == 0 || !hasCfg {
		fail("unknown operator")
		return
	}
	if !protocol.HMACVerify(key, hello.MAC, hello.User, hello.Nonce, hello.Pub, fmt.Sprint(hello.TS)) {
		fail("bad operator mac")
		return
	}
	nonceC, err := protocol.DecodeB64(hello.Nonce)
	if err != nil || len(nonceC) != 32 {
		fail("bad nonce")
		return
	}
	pubC, err := protocol.DecodeB64(hello.Pub)
	if err != nil || len(pubC) != 32 {
		fail("bad public key")
		return
	}
	privS, err := protocol.NewEphemeral()
	if err != nil {
		fail("server key error")
		return
	}
	shared, err := protocol.SharedRaw(privS, pubC)
	if err != nil {
		fail("ecdh failed")
		return
	}
	nonceS := make([]byte, 32)
	if _, err := readRand(nonceS); err != nil {
		fail("rand failed")
		return
	}
	keys, err := protocol.DeriveKeys(shared, key, nonceC, nonceS, protocol.CipherAES256GCM)
	if err != nil {
		fail("kdf failed")
		return
	}
	ack := protocol.OpHelloAck{
		V: protocol.Version, T: protocol.TOpHelloAck, User: hello.User, Role: cfg.Role,
		Tenant: cfg.Tenant,
		Nonce: protocol.B64(nonceS), Pub: protocol.B64(protocol.PublicRaw(privS)),
		SID: keys.SID, TS: now,
	}
	b, _ := json.Marshal(ack)
	if err := protocol.WriteStreamFrame(rw, b); err != nil {
		return
	}
	oc := &OpConn{srv: s, User: hello.User, Role: cfg.Role, Tenant: cfg.Tenant,
		Transport: transport, Keys: keys, Stream: rw, Since: now, LastSeen: now}
	s.opMu.Lock()
	s.ops[oc] = struct{}{}
	s.opMu.Unlock()
	s.audit(oc.User, "operator.login", oc.User, "role="+oc.Role+" transport="+transport)
	defer func() {
		s.opMu.Lock()
		delete(s.ops, oc)
		s.opMu.Unlock()
		s.audit(oc.User, "operator.logout", oc.User, "")
	}()
	s.broadcastPresence()
	defer s.broadcastPresence()
	for {
		frame, err := protocol.ReadStreamFrame(rw)
		if err != nil {
			return
		}
		plain, err := oc.Keys.Open(protocol.DirClientToServer, frame)
		if err != nil {
			return
		}
		var cmd protocol.OpCmd
		if err := json.Unmarshal(plain, &cmd); err != nil || cmd.T != protocol.TOpCmd {
			continue
		}
		oc.LastSeen = time.Now().Unix()
		data, err := s.opDispatch(context.Background(), oc, &cmd)
		resp := protocol.OpResp{T: protocol.TOpResp, Req: cmd.Req, OK: err == nil}
		if err != nil {
			resp.Err = err.Error()
		} else if data != nil {
			raw, e := json.Marshal(data)
			if e == nil {
				resp.Data = raw
			}
		}
		_ = oc.send(resp)
	}
}

func (s *Server) broadcastPresence() {
	s.opMu.Lock()
	list := make([]*OpConn, 0, len(s.ops))
	for o := range s.ops {
		list = append(list, o)
	}
	s.opMu.Unlock()
	entries := make([]protocol.PresenceEntry, 0, len(list))
	for _, o := range list {
		entries = append(entries, protocol.PresenceEntry{User: o.User, Role: o.Role, Tenant: o.Tenant, Since: o.Since, LastSeen: o.LastSeen})
	}
	msg := protocol.Presence{T: protocol.TPresence, Operators: entries, At: time.Now().Unix()}
	for _, o := range list {
		_ = o.send(msg)
	}
}

// ------------- command dispatch -------------

type opArgs map[string]json.RawMessage

func (a opArgs) str(k string) string {
	var s string
	if v, ok := a[k]; ok {
		_ = json.Unmarshal(v, &s)
	}
	return s
}

func (a opArgs) intv(k string, def int) int {
	var n int
	if v, ok := a[k]; ok {
		_ = json.Unmarshal(v, &n)
	}
	if n == 0 {
		return def
	}
	return n
}

func (a opArgs) boolv(k string) bool {
	var b bool
	if v, ok := a[k]; ok {
		_ = json.Unmarshal(v, &b)
	}
	return b
}

func (a opArgs) raw(k string) json.RawMessage { return a[k] }

type sessionView struct {
	SID       string   `json:"sid"`
	ClientID  string   `json:"client_id"`
	Host      string   `json:"host"`
	OS        string   `json:"os"`
	Arch      string   `json:"arch"`
	User      string   `json:"user"`
	Transport string   `json:"transport"`
	Tenant    string   `json:"tenant"`
	Online    bool     `json:"online"`
	LastSeen  int64    `json:"last_seen"`
	Caps      []string `json:"caps,omitempty"`
}

func (s *Server) sessionVisible(o *OpConn, sess *Session) bool {
	if roleRank(o.Role) >= 3 {
		return true
	}
	return sess.Tenant == o.Tenant
}

func (s *Server) pickSession(o *OpConn, sid string) (*Session, error) {
	sess, ok := s.GetSession(sid)
	if !ok {
		return nil, fmt.Errorf("session %q not found", sid)
	}
	if !s.sessionVisible(o, sess) {
		return nil, errors.New("session not in your tenant")
	}
	return sess, nil
}

func (s *Server) opDispatch(ctx context.Context, o *OpConn, cmd *protocol.OpCmd) (any, error) {
	var args opArgs
	if len(cmd.Args) > 0 {
		_ = json.Unmarshal(cmd.Args, &args)
	}
	need := func(min string) error {
		if roleRank(o.Role) < roleRank(min) {
			return fmt.Errorf("requires role %s", min)
		}
		return nil
	}
	audit := func(detail string) {
		s.audit(o.User, "op."+cmd.Cmd, args.str("sid"), detail)
	}

	switch cmd.Cmd {
	case "whoami":
		return map[string]any{"user": o.User, "role": o.Role, "tenant": o.Tenant}, nil

	case "stats":
		if err := need("viewer"); err != nil {
			return nil, err
		}
		return s.Stats(), nil

	case "presence":
		if err := need("viewer"); err != nil {
			return nil, err
		}
		s.opMu.Lock()
		defer s.opMu.Unlock()
		var out []protocol.PresenceEntry
		for x := range s.ops {
			out = append(out, protocol.PresenceEntry{User: x.User, Role: x.Role, Tenant: x.Tenant, Since: x.Since, LastSeen: x.LastSeen})
		}
		return out, nil

	case "list":
		if err := need("viewer"); err != nil {
			return nil, err
		}
		var out []sessionView
		for _, sess := range s.Sessions() {
			if !s.sessionVisible(o, sess) {
				continue
			}
			out = append(out, sessionView{
				SID: sess.SID, ClientID: sess.ClientID, Host: sess.Host, OS: sess.OS, Arch: sess.Arch,
				User: sess.User, Transport: sess.Transport, Tenant: sess.Tenant,
				Online: sess.Online(s.cfg.Sleep), LastSeen: sess.LastSeen, Caps: sess.Caps,
			})
		}
		audit("")
		return out, nil

	case "modules":
		if err := need("viewer"); err != nil {
			return nil, err
		}
		sid := args.str("sid")
		caps := []string{}
		if sid != "" {
			if sess, err := s.pickSession(o, sid); err == nil {
				caps = sess.Caps
			}
		}
		return map[string]any{"modules": s.modReg.All(), "session_caps": caps}, nil

	case "module-search":
		if err := need("viewer"); err != nil {
			return nil, err
		}
		hits := s.modReg.Search(args.str("q"))
		return map[string]any{"count": len(hits), "modules": hits}, nil

	case "module-show":
		if err := need("viewer"); err != nil {
			return nil, err
		}
		name := args.str("name")
		m, ok := s.modReg.Get(name)
		if !ok {
			return nil, fmt.Errorf("unknown module %q", name)
		}
		return m, nil

	case "module-run":
		// External (exec/wasm) modules run on the server host; builtin modules
		// are forwarded to a client exactly like `run`.
		if err := need("operator"); err != nil {
			return nil, err
		}
		name := args.str("name")
		m, ok := s.modReg.Get(name)
		if !ok {
			return nil, fmt.Errorf("unknown module %q", name)
		}
		if roleRank(o.Role) < roleRank(m.Role()) {
			return nil, fmt.Errorf("module %s requires role %s", name, m.Role())
		}
		modArgs := args.raw("args")
		if len(modArgs) == 0 || string(modArgs) == "null" {
			modArgs = json.RawMessage(`{}`)
		}
		if m.Kind == "builtin" {
			sess, err := s.pickSession(o, args.str("sid"))
			if err != nil {
				return nil, err
			}
			res, err := s.RunTask(ctx, sess, name, modArgs, o.User, time.Duration(args.intv("timeout_ms", 90000))*time.Millisecond)
			audit(fmt.Sprintf("builtin module=%s ok=%v", name, err == nil))
			return res, err
		}
		// Server-side execution is privileged: require admin and an explicit
		// confirm token when the manifest is destructive.
		if err := need("admin"); err != nil {
			return nil, err
		}
		if m.Destructive && args.str("confirm") != name {
			return nil, fmt.Errorf("module %s is destructive: pass confirm=%s", name, name)
		}
		res, err := s.modReg.RunExternal(ctx, m, modArgs)
		if err != nil {
			audit(fmt.Sprintf("external module=%s kind=%s err=%s", name, m.Kind, truncate(err.Error(), 200)))
			return nil, err
		}
		audit(fmt.Sprintf("external module=%s kind=%s ok=true", name, m.Kind))
		return map[string]any{"module": name, "kind": m.Kind, "result": res}, nil

	case "use":
		if err := need("operator"); err != nil {
			return nil, err
		}
		sess, err := s.pickSession(o, args.str("sid"))
		if err != nil {
			return nil, err
		}
		ttl := args.intv("ttl", 300)
		if l, err := s.st.GetLock(ctx, sess.SID); err == nil && l.Expires > time.Now().Unix() && l.Owner != o.User {
			if roleRank(o.Role) < 3 {
				return nil, fmt.Errorf("session locked by %s until %d", l.Owner, l.Expires)
			}
		}
		lock := store.Lock{SID: sess.SID, Owner: o.User, Expires: time.Now().Add(time.Duration(ttl) * time.Second).Unix()}
		if err := s.st.AcquireLock(ctx, lock); err != nil {
			return nil, err
		}
		audit(fmt.Sprintf("ttl=%d", ttl))
		return lock, nil

	case "release":
		if err := need("operator"); err != nil {
			return nil, err
		}
		sid := args.str("sid")
		if l, err := s.st.GetLock(ctx, sid); err == nil && l.Owner != o.User && roleRank(o.Role) < 3 {
			return nil, errors.New("lock owned by another operator")
		}
		if err := s.st.ReleaseLock(ctx, sid); err != nil {
			return nil, err
		}
		audit("")
		return map[string]bool{"released": true}, nil

	case "run", "shell", "ls", "cat", "get", "put", "rm":
		if err := need("operator"); err != nil {
			return nil, err
		}
		sid := args.str("sid")
		sess, err := s.pickSession(o, sid)
		if err != nil {
			return nil, err
		}
		if l, err := s.st.GetLock(ctx, sid); err == nil && l.Expires > time.Now().Unix() && l.Owner != o.User && roleRank(o.Role) < 3 {
			return nil, fmt.Errorf("session locked by %s", l.Owner)
		}
		name := args.str("name")
		var modArgs json.RawMessage = args.raw("args")
		switch cmd.Cmd {
		case "shell":
			name = "shell"
			modArgs, _ = json.Marshal(map[string]any{"cmd": args.str("cmd"), "timeout_ms": args.intv("timeout_ms", 30000)})
		case "ls":
			name = "fs_ls"
			modArgs, _ = json.Marshal(map[string]any{"path": args.str("path")})
		case "cat":
			name = "fs_cat"
			modArgs, _ = json.Marshal(map[string]any{"path": args.str("path"), "max": args.intv("max", 4<<20)})
		case "get":
			name = "fs_cat"
			modArgs, _ = json.Marshal(map[string]any{"path": args.str("path"), "max": args.intv("max", 4<<20)})
		case "put":
			name = "fs_put"
			modArgs, _ = json.Marshal(map[string]any{"path": args.str("path"), "data_b64": args.str("data_b64"), "append": args.boolv("append")})
		case "rm":
			name = "fs_rm"
			modArgs, _ = json.Marshal(map[string]any{"path": args.str("path")})
		}
		if name == "" {
			return nil, errors.New("run: missing module name")
		}
		if mod, ok := catalog.Find(name); ok {
			if roleRank(o.Role) < roleRank(mod.Operator) {
				return nil, fmt.Errorf("module %s requires role %s", name, mod.Operator)
			}
		}
		timeout := time.Duration(args.intv("timeout_ms", 60000)) * time.Millisecond
		res, err := s.RunTask(ctx, sess, name, modArgs, o.User, timeout)
		if err != nil {
			audit("module=" + name + " err=" + err.Error())
			return nil, err
		}
		audit(fmt.Sprintf("module=%s ok=%v", name, res.OK))
		return res, nil

	case "tasks":
		if err := need("viewer"); err != nil {
			return nil, err
		}
		return s.st.ListTasks(ctx, args.str("sid"), args.intv("limit", 50))

	case "audit":
		if err := need("viewer"); err != nil {
			return nil, err
		}
		return s.st.ListAudit(ctx, args.intv("limit", 500))

	case "verify-audit":
		if err := need("viewer"); err != nil {
			return nil, err
		}
		entries, err := s.st.ListAudit(ctx, 100000)
		if err != nil {
			return nil, err
		}
		ok, msg := store.VerifyAudit(entries)
		return map[string]any{"ok": ok, "message": msg, "entries": len(entries)}, nil

	case "kill":
		if err := need("admin"); err != nil {
			return nil, err
		}
		if args.str("confirm") != "KILL" {
			return nil, errors.New("kill requires confirm=KILL")
		}
		sess, err := s.pickSession(o, args.str("sid"))
		if err != nil {
			return nil, err
		}
		ack, err := s.KillSession(ctx, sess, o.User, args.str("reason"), args.boolv("uninstall"))
		if err != nil {
			return nil, err
		}
		return ack, nil

	case "update-publish":
		if err := need("admin"); err != nil {
			return nil, err
		}
		m := protocol.UpdateManifest{
			Version: args.str("version"), Platform: args.str("platform"), Arch: args.str("arch"),
			URL: args.str("url"), SHA256: args.str("sha256"), Rollout: args.intv("rollout", 100),
			MinVersion: args.str("min_version"), Rollback: args.str("rollback"), Notes: args.str("notes"),
		}
		sig, sent, err := s.PublishUpdate(ctx, m, o.User)
		if err != nil {
			return nil, err
		}
		return map[string]any{"sig": sig, "sent": sent, "version": m.Version}, nil

	case "update-list":
		if err := need("viewer"); err != nil {
			return nil, err
		}
		return s.st.ListManifests(ctx)

	case "update-push":
		if err := need("admin"); err != nil {
			return nil, err
		}
		mans, err := s.st.ListManifests(ctx)
		if err != nil {
			return nil, err
		}
		version := args.str("version")
		s.updMu.Lock()
		pin := s.updPin
		approved := make(map[string]bool, len(s.updOk))
		for k, v := range s.updOk {
			approved[k] = v
		}
		s.updMu.Unlock()
		if pin != "" {
			if version != "" && version != pin {
				return nil, fmt.Errorf("version %s is not the pinned version %s", version, pin)
			}
			version = pin
		}
		pushed := 0
		for _, m := range mans {
			if version != "" && m.Version != version {
				continue
			}
			if !approved[m.Version] {
				continue // never push unapproved manifests
			}
			um := protocol.UpdateManifest{Version: m.Version, Platform: m.Platform, Arch: m.Arch, URL: m.URL,
				SHA256: m.SHA256, Rollout: m.Rollout, Created: m.Created}
			for _, sess := range s.Sessions() {
				if !um.Matches(sess.ClientID, sess.OS, sess.Arch) {
					continue
				}
				if err := s.SendMsg(sess, protocol.Update{T: protocol.TUpdate, Manifest: um, Sig: m.Sig}); err == nil {
					pushed++
				}
			}
		}
		audit(fmt.Sprintf("version=%s pushed=%d", version, pushed))
		return map[string]int{"pushed": pushed}, nil

	case "update-approve":
		// Operator approval gate: nothing is pushed until a version is approved.
		if err := need("admin"); err != nil {
			return nil, err
		}
		version := args.str("version")
		if version == "" {
			return nil, errors.New("update-approve requires version")
		}
		s.updMu.Lock()
		pin := s.updPin
		s.updMu.Unlock()
		if pin != "" && version != pin {
			return nil, fmt.Errorf("version %s is blocked by pin %s (clear the pin with update-pin version=)", version, pin)
		}
		mans, err := s.st.ListManifests(ctx)
		if err != nil {
			return nil, err
		}
		var target *store.Manifest
		for i := range mans {
			if mans[i].Version == version {
				target = &mans[i]
				break
			}
		}
		if target == nil {
			return nil, fmt.Errorf("no published manifest for version %q", version)
		}
		s.updMu.Lock()
		s.updOk[version] = true
		s.updMu.Unlock()
		pushed := 0
		um := protocol.UpdateManifest{Version: target.Version, Platform: target.Platform, Arch: target.Arch,
			URL: target.URL, SHA256: target.SHA256, Rollout: target.Rollout, Created: target.Created}
		for _, sess := range s.Sessions() {
			if !um.Matches(sess.ClientID, sess.OS, sess.Arch) {
				continue
			}
			if err := s.SendMsg(sess, protocol.Update{T: protocol.TUpdate, Manifest: um, Sig: target.Sig}); err == nil {
				pushed++
			}
		}
		audit(fmt.Sprintf("version=%s pushed=%d", version, pushed))
		return map[string]any{"approved": version, "pushed": pushed}, nil

	case "update-pin":
		if err := need("admin"); err != nil {
			return nil, err
		}
		version := args.str("version") // empty clears the pin
		s.updMu.Lock()
		s.updPin = version
		s.updMu.Unlock()
		audit("pin=" + version)
		return map[string]any{"pinned": version}, nil

	case "update-rollback":
		// Push a previously published manifest as the rollback target and mark
		// the bad version as the rollback pointer for the client.
		if err := need("admin"); err != nil {
			return nil, err
		}
		bad := args.str("version")
		good := args.str("target")
		if bad == "" || good == "" {
			return nil, errors.New("update-rollback requires version (bad) and target (good)")
		}
		mans, err := s.st.ListManifests(ctx)
		if err != nil {
			return nil, err
		}
		var target *store.Manifest
		for i := range mans {
			if mans[i].Version == good {
				target = &mans[i]
				break
			}
		}
		if target == nil {
			return nil, fmt.Errorf("no published manifest for target %q", good)
		}
		pushed := 0
		um := protocol.UpdateManifest{Version: target.Version, Platform: target.Platform, Arch: target.Arch,
			URL: target.URL, SHA256: target.SHA256, Rollout: 100, Created: target.Created, Rollback: bad}
		// The stored signature covers the original manifest; adding the rollback
		// pointer changes the canonical form, so re-sign the rollback manifest.
		rbSig := protocol.HMACSign(s.updateKey, um.Canonical())
		for _, sess := range s.Sessions() {
			if !um.Matches(sess.ClientID, sess.OS, sess.Arch) {
				continue
			}
			if err := s.SendMsg(sess, protocol.Update{T: protocol.TUpdate, Manifest: um, Sig: rbSig}); err == nil {
				pushed++
			}
		}
		audit(fmt.Sprintf("rollback %s -> %s pushed=%d", bad, good, pushed))
		return map[string]any{"rollback_from": bad, "to": good, "pushed": pushed}, nil

	case "ai-status":
		if err := need("viewer"); err != nil {
			return nil, err
		}
		if !s.AIEnabled() {
			return map[string]any{"enabled": false, "note": "configure ai.enabled + ai.base_url in the server config"}, nil
		}
		return map[string]any{"enabled": true, "model": s.cfg.AI.Model, "tools": s.AITools()}, nil

	case "ai-tools":
		if err := need("viewer"); err != nil {
			return nil, err
		}
		return map[string]any{"enabled": s.AIEnabled(), "tools": s.AITools()}, nil

	case "ai-ask":
		// Only read-only tools run automatically; destructive tool calls come
		// back as need_approve and must be re-sent with confirm=<tool>.
		if err := need("operator"); err != nil {
			return nil, err
		}
		var confirmed []string
		if c := args.str("confirm"); c != "" {
			for _, part := range strings.Split(c, ",") {
				if p := strings.TrimSpace(part); p != "" {
					confirmed = append(confirmed, p)
				}
			}
		}
		audit("prompt=" + truncate(args.str("prompt"), 300))
		res, err := s.AIAsk(ctx, o, args.str("prompt"), confirmed)
		if err != nil {
			return nil, err
		}
		return res, nil

	case "op-list":
		if err := need("admin"); err != nil {
			return nil, err
		}
		return s.st.ListOperators(ctx, "")

	case "op-add":
		if err := need("admin"); err != nil {
			return nil, err
		}
		user := args.str("user")
		role := args.str("role")
		tenant := args.str("tenant")
		if tenant == "" {
			tenant = s.cfg.Tenant
		}
		key, err := DecodeKey(args.str("key_b64"))
		if user == "" || err != nil || key == nil {
			return nil, errors.New("op-add requires user and key_b64")
		}
		if roleRank(role) == 0 {
			return nil, errors.New("role must be admin|operator|viewer")
		}
		s.opKeysMu.Lock()
		s.opKeys[user] = key
		s.opCfg[user] = OperatorConfig{User: user, Role: role, Tenant: tenant, KeyB64: args.str("key_b64")}
		s.opKeysMu.Unlock()
		sum := protocol.HMACSign([]byte("c2v2-op-key-hash"), user, string(key))
		if err := s.st.UpsertOperator(ctx, store.Operator{User: user, Role: role, Tenant: tenant, KeyHash: sum, Created: time.Now().Unix()}); err != nil {
			return nil, err
		}
		audit("role=" + role)
		return map[string]any{"added": user, "note": "runtime only; persist in config to survive restart"}, nil

	case "op-del":
		if err := need("admin"); err != nil {
			return nil, err
		}
		user := args.str("user")
		if user == o.User {
			return nil, errors.New("cannot delete self")
		}
		s.opKeysMu.Lock()
		delete(s.opKeys, user)
		delete(s.opCfg, user)
		s.opKeysMu.Unlock()
		if err := s.st.DeleteOperator(ctx, user); err != nil {
			return nil, err
		}
		audit("")
		return map[string]bool{"deleted": true}, nil

	case "tunnel-open":
		if err := need("operator"); err != nil {
			return nil, err
		}
		sess, err := s.pickSession(o, args.str("sid"))
		if err != nil {
			return nil, err
		}
		host := args.str("host")
		port := args.intv("port", 0)
		local := args.intv("local", 0)
		if host == "" || port == 0 {
			return nil, errors.New("tunnel-open requires host and port")
		}
		t, err := s.OpenTunnel(sess, host, port, local)
		if err != nil {
			return nil, err
		}
		return map[string]any{"tid": t.TID, "local": fmt.Sprintf("127.0.0.1:%d", portOr(local, port)), "target": fmt.Sprintf("%s:%d", host, port)}, nil

	case "tunnel-close":
		if err := need("operator"); err != nil {
			return nil, err
		}
		if err := s.CloseTunnel(args.str("tid")); err != nil {
			return nil, err
		}
		return map[string]bool{"closed": true}, nil

	case "module-catalog":
		if err := need("viewer"); err != nil {
			return nil, err
		}
		return catalog.Modules, nil

	default:
		return nil, fmt.Errorf("unknown command %q", cmd.Cmd)
	}
}

func portOr(a, b int) int {
	if a != 0 {
		return a
	}
	return b
}

var _ = sql.ErrNoRows

