package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"c2v2/internal/aiassist"
	"c2v2/internal/catalog"
)

// aiCtx carries the calling operator's identity into AI tool calls.
type aiCtx struct {
	User   string
	Role   string
	Tenant string
}

type aiCtxKey struct{}

func withAIIdentity(ctx context.Context, o *OpConn) context.Context {
	return context.WithValue(ctx, aiCtxKey{}, aiCtx{User: o.User, Role: o.Role, Tenant: o.Tenant})
}

func aiIdent(ctx context.Context) aiCtx {
	if v, ok := ctx.Value(aiCtxKey{}).(aiCtx); ok {
		return v
	}
	return aiCtx{Role: "viewer"}
}

func requireRole(ctx context.Context, min string) error {
	if roleRank(aiIdent(ctx).Role) < roleRank(min) {
		return fmt.Errorf("assistant tool requires role %s (caller is %s)", min, aiIdent(ctx).Role)
	}
	return nil
}

// visibleSession returns a session the caller may see under tenant isolation.
func (s *Server) visibleSession(ctx context.Context, sid string) (*Session, error) {
	sess, ok := s.GetSession(sid)
	if !ok {
		return nil, fmt.Errorf("no such session %q", sid)
	}
	id := aiIdent(ctx)
	if roleRank(id.Role) < roleRank("admin") && sess.Tenant != "" && id.Tenant != "" && sess.Tenant != id.Tenant {
		return nil, errors.New("session belongs to another tenant")
	}
	return sess, nil
}

func schema(props string, required ...string) json.RawMessage {
	req := "[]"
	if len(required) > 0 {
		b, _ := json.Marshal(required)
		req = string(b)
	}
	return json.RawMessage(`{"type":"object","properties":{` + props + `},"required":` + req + `}`)
}

// buildAITools registers the assistant's bounded tool set.  Every tool either
// reads state or executes through the same audited paths the operator CLI uses.
func (s *Server) buildAITools() {
	ai := s.ai
	ai.Register(aiassist.Tool{
		Name: "list_sessions", Risk: aiassist.RiskRead,
		Description: "List active sessions (host, os, user, sid, online), scoped to the caller's tenant.",
		Params:      schema(``),
		Call: func(ctx context.Context, _ json.RawMessage) (any, error) {
			id := aiIdent(ctx)
			out := []map[string]any{}
			for _, sess := range s.Sessions() {
				if roleRank(id.Role) < roleRank("admin") && sess.Tenant != "" && id.Tenant != "" && sess.Tenant != id.Tenant {
					continue
				}
				out = append(out, map[string]any{
					"sid": sess.SID, "client_id": sess.ClientID, "host": sess.Host, "os": sess.OS,
					"arch": sess.Arch, "user": sess.User, "transport": sess.Transport, "tenant": sess.Tenant,
					"online": sess.Online(s.cfg.Sleep), "last_seen": sess.LastSeen, "caps": sess.Caps,
				})
			}
			return map[string]any{"count": len(out), "sessions": out}, nil
		},
	})
	ai.Register(aiassist.Tool{
		Name: "session_tasks", Risk: aiassist.RiskRead,
		Description: "Recent task history (module, state, result) for one session.",
		Params:      schema(`"sid":{"type":"string"},"limit":{"type":"integer"}`, "sid"),
		Call: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a struct {
				SID   string `json:"sid"`
				Limit int    `json:"limit"`
			}
			_ = json.Unmarshal(raw, &a)
			if _, err := s.visibleSession(ctx, a.SID); err != nil {
				return nil, err
			}
			if a.Limit <= 0 {
				a.Limit = 20
			}
			return s.st.ListTasks(ctx, a.SID, a.Limit)
		},
	})
	ai.Register(aiassist.Tool{
		Name: "module_catalog", Risk: aiassist.RiskRead,
		Description: "Search modules (builtin client modules plus external exec/wasm manifests) by name/summary.",
		Params:      schema(`"q":{"type":"string"}`),
		Call: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a struct {
				Q string `json:"q"`
			}
			_ = json.Unmarshal(raw, &a)
			return s.modReg.Search(a.Q), nil
		},
	})
	ai.Register(aiassist.Tool{
		Name: "audit_tail", Risk: aiassist.RiskRead,
		Description: "Tail the hash-chained audit log (most recent N entries) as evidence.",
		Params:      schema(`"limit":{"type":"integer"}`),
		Call: func(ctx context.Context, raw json.RawMessage) (any, error) {
			if err := requireRole(ctx, "viewer"); err != nil {
				return nil, err
			}
			var a struct {
				Limit int `json:"limit"`
			}
			_ = json.Unmarshal(raw, &a)
			if a.Limit <= 0 || a.Limit > 200 {
				a.Limit = 50
			}
			return s.st.ListAudit(ctx, a.Limit)
		},
	})
	ai.Register(aiassist.Tool{
		Name: "fs_cat", Risk: aiassist.RiskRead,
		Description: "Read a file from a session (base64, size limited). Read-only; cite the path and size.",
		Params:      schema(`"sid":{"type":"string"},"path":{"type":"string"},"max":{"type":"integer"}`, "sid", "path"),
		Call: func(ctx context.Context, raw json.RawMessage) (any, error) {
			if err := requireRole(ctx, "operator"); err != nil {
				return nil, err
			}
			var a struct {
				SID  string `json:"sid"`
				Path string `json:"path"`
				Max  int    `json:"max"`
			}
			_ = json.Unmarshal(raw, &a)
			sess, err := s.visibleSession(ctx, a.SID)
			if err != nil {
				return nil, err
			}
			if a.Max <= 0 || a.Max > 4<<20 {
				a.Max = 64 << 10 // keep evidence compact
			}
			args, _ := json.Marshal(map[string]any{"path": a.Path, "max": a.Max})
			res, err := s.RunTask(ctx, sess, "fs_cat", args, aiIdent(ctx).User, 60*time.Second)
			if err != nil {
				return nil, err
			}
			return res, nil
		},
	})
	ai.Register(aiassist.Tool{
		Name: "client_ai_context", Risk: aiassist.RiskRead,
		Description: "Ask the client for its read-only evidence bundle (host, os, net, top processes). Use it before proposing any post-exploitation step.",
		Params:      schema(`"sid":{"type":"string"}`, "sid"),
		Call: func(ctx context.Context, raw json.RawMessage) (any, error) {
			if err := requireRole(ctx, "viewer"); err != nil {
				return nil, err
			}
			var a struct {
				SID string `json:"sid"`
			}
			_ = json.Unmarshal(raw, &a)
			sess, err := s.visibleSession(ctx, a.SID)
			if err != nil {
				return nil, err
			}
			return s.RunTask(ctx, sess, "ai_context", json.RawMessage(`{}`), aiIdent(ctx).User, 60*time.Second)
		},
	})
	ai.Register(aiassist.Tool{
		Name: "vector_store_sessions", Risk: aiassist.RiskRead,
		Description: "Identify sessions whose last-seen age exceeds the expected beacon interval, to spot dead or jailed hosts.",
		Params:      schema(``),
		Call: func(ctx context.Context, _ json.RawMessage) (any, error) {
			id := aiIdent(ctx)
			var stale []map[string]any
			now := time.Now().Unix()
			for _, sess := range s.Sessions() {
				if roleRank(id.Role) < roleRank("admin") && sess.Tenant != "" && id.Tenant != "" && sess.Tenant != id.Tenant {
					continue
				}
				age := now - sess.LastSeen
				if !sess.Online(s.cfg.Sleep) || age > int64(3*s.cfg.Sleep+60) {
					stale = append(stale, map[string]any{"sid": sess.SID, "host": sess.Host, "age_secs": age})
				}
			}
			return map[string]any{"stale": stale, "count": len(stale)}, nil
		},
	})
	ai.Register(aiassist.Tool{
		Name: "run_module", Risk: aiassist.RiskDestructive,
		Description: "Execute a builtin client module on a session. Destructive: requires explicit operator approval. Requires module, sid and args.",
		Params:      schema(`"sid":{"type":"string"},"module":{"type":"string"},"args":{"type":"object"}`, "sid", "module"),
		Call: func(ctx context.Context, raw json.RawMessage) (any, error) {
			if err := requireRole(ctx, "operator"); err != nil {
				return nil, err
			}
			var a struct {
				SID    string          `json:"sid"`
				Module string          `json:"module"`
				Args   json.RawMessage `json:"args"`
			}
			_ = json.Unmarshal(raw, &a)
			sess, err := s.visibleSession(ctx, a.SID)
			if err != nil {
				return nil, err
			}
			if mod, ok := catalog.Find(a.Module); ok && roleRank(aiIdent(ctx).Role) < roleRank(mod.Operator) {
				return nil, fmt.Errorf("module %s requires role %s", a.Module, mod.Operator)
			}
			res, err := s.RunTask(ctx, sess, a.Module, a.Args, aiIdent(ctx).User, 90*time.Second)
			if err != nil {
				return nil, err
			}
			return res, nil
		},
	})
	ai.Register(aiassist.Tool{
		Name: "shell", Risk: aiassist.RiskDestructive,
		Description: "Run a shell command on a session. Destructive: requires explicit operator approval and is audited.",
		Params:      schema(`"sid":{"type":"string"},"cmd":{"type":"string"}`, "sid", "cmd"),
		Call: func(ctx context.Context, raw json.RawMessage) (any, error) {
			if err := requireRole(ctx, "operator"); err != nil {
				return nil, err
			}
			var a struct {
				SID string `json:"sid"`
				Cmd string `json:"cmd"`
			}
			_ = json.Unmarshal(raw, &a)
			sess, err := s.visibleSession(ctx, a.SID)
			if err != nil {
				return nil, err
			}
			args, _ := json.Marshal(map[string]any{"cmd": a.Cmd, "timeout_ms": 60000})
			return s.RunTask(ctx, sess, "shell", args, aiIdent(ctx).User, 90*time.Second)
		},
	})
	ai.Register(aiassist.Tool{
		Name: "kill_session", Risk: aiassist.RiskDestructive,
		Description: "Issue the two-step signed KILL to a session (wipes keys, stops persistence, optional uninstall). Destructive and irreversible.",
		Params:      schema(`"sid":{"type":"string"},"reason":{"type":"string"},"uninstall":{"type":"boolean"}`, "sid"),
		Call: func(ctx context.Context, raw json.RawMessage) (any, error) {
			if err := requireRole(ctx, "admin"); err != nil {
				return nil, err
			}
			var a struct {
				SID       string `json:"sid"`
				Reason    string `json:"reason"`
				Uninstall bool   `json:"uninstall"`
			}
			_ = json.Unmarshal(raw, &a)
			sess, err := s.visibleSession(ctx, a.SID)
			if err != nil {
				return nil, err
			}
			return s.KillSession(ctx, sess, aiIdent(ctx).User, a.Reason, a.Uninstall)
		},
	})
}

// AITools exposes the tool descriptions for the operator CLI/GUI.
func (s *Server) AITools() []map[string]any {
	if s.ai == nil {
		return nil
	}
	return s.ai.Describe()
}

// AIEnabled reports whether the assistant is configured.
func (s *Server) AIEnabled() bool { return s.ai != nil }

// AIAsk runs one assistant turn bound to the calling operator.
func (s *Server) AIAsk(ctx context.Context, o *OpConn, prompt string, confirmed []string) (*aiassist.Result, error) {
	if s.ai == nil {
		return nil, errors.New("ai assistant is not enabled (set ai.enabled and ai.base_url in the server config)")
	}
	if strings.TrimSpace(prompt) == "" {
		return nil, errors.New("ai: empty prompt")
	}
	return s.ai.Ask(withAIIdentity(ctx, o), o.User, prompt, confirmed)
}

// moduleNames is used for stable logging/UI ordering.
func moduleNames(ms []string) string {
	sort.Strings(ms)
	return strings.Join(ms, ",")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
