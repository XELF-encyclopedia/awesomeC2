package tui

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"backd/c2/mvp/tui/internal/client"
	"backd/c2/mvp/tui/internal/config"
)

func TestNewBuildsLoginAndMainPages(t *testing.T) {
	cfg := config.Defaults()
	cfg.Endpoint = "wss://operator.example/ws"
	cfg.PSK = "base64:AAAA"
	app := New(cfg, filepath.Join(t.TempDir(), "config.json"), false)
	if app == nil || app.login == nil || app.main == nil {
		t.Fatal("TUI graph was not built")
	}
	if front, _ := app.pages.GetFrontPage(); front != "login" {
		t.Fatalf("front page = %q, want login", front)
	}
	if !app.cfg.Complete() {
		t.Fatal("complete config should enable one-click connect")
	}
}

func TestCompleteConfigFocusesConnectButton(t *testing.T) {
	incomplete := config.Defaults()
	if incomplete.Complete() {
		t.Fatal("defaults must be incomplete")
	}
	a := New(incomplete, "", false)
	if focus := a.app.GetFocus(); focus != a.login.endpoint {
		t.Fatal("incomplete config should focus the endpoint field")
	}
}

func TestFormatHelpers(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	s := client.Session{LastSeen: now.Add(-3 * time.Second).Format(time.RFC3339)}
	if got := SessionState(s, now, 4*time.Second); got != "online" {
		t.Fatalf("state = %q, want online", got)
	}
	s.LastSeen = now.Add(-2 * time.Minute).Format(time.RFC3339)
	if got := SessionState(s, now, 4*time.Second); got != "stale" {
		t.Fatalf("state = %q, want stale", got)
	}
	if got := SessionState(client.Session{LastSeen: ""}, now, 4*time.Second); got != "unknown" {
		t.Fatalf("state = %q, want unknown", got)
	}
	if got := HumanAge(3 * time.Second); got != "3s" {
		t.Fatalf("HumanAge = %q", got)
	}
	if got := HumanBytes(1536); got != "1.5 KiB" {
		t.Fatalf("HumanBytes = %q", got)
	}
	if got := LastSeenAge(now.Add(-5*time.Second).Format(time.RFC3339), now); got != "5s ago" {
		t.Fatalf("LastSeenAge = %q", got)
	}
	if got := StatsLine(map[string]any{"sessions": 1}); !strings.Contains(got, "sessions=1") {
		t.Fatalf("StatsLine = %q", got)
	}
}
