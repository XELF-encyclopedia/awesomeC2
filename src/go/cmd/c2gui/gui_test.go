package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type recordingBridge struct {
	mu    sync.Mutex
	calls []string
	args  []map[string]any
}

func (b *recordingBridge) Call(_ context.Context, cmd string, args map[string]any) (json.RawMessage, error) {
	b.mu.Lock()
	b.calls = append(b.calls, cmd)
	b.args = append(b.args, args)
	b.mu.Unlock()
	switch cmd {
	case "list":
		return json.RawMessage(`[{"sid":"s1","host":"h1","os":"linux","arch":"amd64","online":true}]`), nil
	case "modules":
		return json.RawMessage(`{"modules":[]}`), nil
	case "audit":
		return json.RawMessage(`[]`), nil
	case "ai-status":
		return json.RawMessage(`{"enabled":true}`), nil
	case "update-list":
		return json.RawMessage(`[]`), nil
	default:
		b, _ := json.Marshal(map[string]any{"ok": true, "cmd": cmd})
		return b, nil
	}
}
func (b *recordingBridge) Close() error { return nil }

func testGUI(t *testing.T) (*httptest.Server, *recordingBridge) {
	t.Helper()
	rb := &recordingBridge{}
	g := &gui{b: rb, log: log.New(io.Discard, "", 0)}
	ts := httptest.NewServer(g.routes())
	t.Cleanup(ts.Close)
	return ts, rb
}

func TestIndexServesPanels(t *testing.T) {
	ts, _ := testGUI(t)
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	html := string(body)
	for _, want := range []string{"C2V2", "Sessions", "Terminal", "Files", "Builder", "Modules", "Audit", "Presence", "X-C2-Confirm"} {
		if !strings.Contains(html, want) {
			t.Fatalf("index missing %q", want)
		}
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("index must not be cached")
	}
}

func TestStateAggregatesPanels(t *testing.T) {
	ts, rb := testGUI(t)
	resp, err := http.Get(ts.URL + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"sessions", "modules", "audit", "ai", "updates"} {
		if _, ok := body[k]; !ok {
			t.Fatalf("state missing %q: %v", k, body)
		}
	}
	rb.mu.Lock()
	defer rb.mu.Unlock()
	if len(rb.calls) < 5 {
		t.Fatalf("expected 5 backend calls, got %v", rb.calls)
	}
}

func TestDestructiveConfirmationEnforced(t *testing.T) {
	ts, rb := testGUI(t)
	post := func(body, confirm string) (int, string) {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/cmd", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if confirm != "" {
			req.Header.Set("X-C2-Confirm", confirm)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, _ := post(`{"action":"shell","args":{"sid":"s1","cmd":"id"}}`, ""); code != 428 {
		t.Fatalf("shell without confirm = %d", code)
	}
	if code, body := post(`{"action":"shell","args":{"sid":"s1","cmd":"id"}}`, "yes"); code != 200 || !strings.Contains(body, `"ok":true`) {
		t.Fatalf("confirmed shell = %d %s", code, body)
	}
	if code, _ := post(`{"action":"kill","args":{}}`, "y"); code != 428 {
		t.Fatalf("wrong confirm token accepted (%d)", code)
	}
	if code, _ := post(`{"action":"rm -rf","args":{}}`, "yes"); code != 400 {
		t.Fatalf("unknown action accepted (%d)", code)
	}
	if code, _ := post(`{"action":"list","args":{}}`, ""); code != 200 {
		t.Fatalf("read-only action blocked (%d)", code)
	}
	rb.mu.Lock()
	defer rb.mu.Unlock()
	for _, c := range rb.calls {
		if c == "kill" {
			t.Fatalf("blocked action reached the bridge")
		}
	}
}

func TestFileEndpoints(t *testing.T) {
	ts, rb := testGUI(t)
	resp, err := http.Get(ts.URL + "/api/file?sid=s1&path=/etc/hosts")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("download status %d", resp.StatusCode)
	}
	// upload requires confirmation
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/file", strings.NewReader(`{"sid":"s1","path":"/tmp/x","b64":"aGk="}`))
	req.Header.Set("Content-Type", "application/json")
	r2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()
	if r2.StatusCode != 428 {
		t.Fatalf("upload without confirm = %d", r2.StatusCode)
	}
	req2, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/file", strings.NewReader(`{"sid":"s1","path":"/tmp/x","b64":"aGk="}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-C2-Confirm", "yes")
	r3, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	r3.Body.Close()
	if r3.StatusCode != 200 {
		t.Fatalf("confirmed upload = %d", r3.StatusCode)
	}
	rb.mu.Lock()
	defer rb.mu.Unlock()
	if len(rb.calls) != 2 || rb.calls[0] != "run" || rb.calls[1] != "run" {
		t.Fatalf("file endpoints did not proxy through run: %v", rb.calls)
	}
	if rb.args[0]["name"] != "fs_cat" || rb.args[1]["name"] != "fs_put" {
		t.Fatalf("unexpected module args: %v", rb.args)
	}
}
