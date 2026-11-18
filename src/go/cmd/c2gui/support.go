package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
)

func decodeB64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		// tolerate URL-safe / unpadded input from env vars
		if b2, err2 := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s)); err2 == nil {
			return b2, nil
		}
	}
	return b, err
}

// stubBridge backs the offline self-test; it never touches the network.
type stubBridge struct{}

func (stubBridge) Call(_ context.Context, cmd string, args map[string]any) (json.RawMessage, error) {
	switch cmd {
	case "list":
		return json.RawMessage(`[{"sid":"stub-session","host":"stub-host","os":"windows","online":true}]`), nil
	case "modules":
		return json.RawMessage(`{"modules":[{"name":"shell","kind":"builtin"}]}`), nil
	case "audit":
		return json.RawMessage(`[{"action":"selftest","hash":"deadbeef"}]`), nil
	case "ai-status":
		return json.RawMessage(`{"enabled":false}`), nil
	case "update-list":
		return json.RawMessage(`[]`), nil
	default:
		b, _ := json.Marshal(map[string]any{"stub": true, "cmd": cmd, "args": args})
		return b, nil
	}
}
func (stubBridge) Close() error { return nil }

func newTestServer(h http.Handler) *httptest.Server { return httptest.NewServer(h) }

func httpGet(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return string(b), nil
}

func httpPost(url, body, confirm string) (int, string) {
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return 0, err.Error()
	}
	req.Header.Set("Content-Type", "application/json")
	if confirm == "yes" {
		req.Header.Set("X-C2-Confirm", "yes")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(b)
}
