package client_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"backd/c2/mvp/tui/internal/client"
	"backd/c2/mvp/tui/internal/testutil"
)

func newClient(t *testing.T, m *testutil.Mock, tweak func(*client.Options)) (*client.Client, <-chan string) {
	t.Helper()
	states := make(chan string, 64)
	opts := client.Options{
		Endpoint: m.URL(),
		User:     m.User,
		PSK:      "hex:" + hex.EncodeToString(m.PSK),
		Family:   "4",
		Timeout:  8 * time.Second,
		OnState: func(s client.State, detail string) {
			select {
			case states <- s.String() + "|" + detail:
			default:
			}
		},
	}
	if tweak != nil {
		tweak(&opts)
	}
	return client.New(opts), states
}

func TestListTaskAndStats(t *testing.T) {
	m := testutil.NewMock(t)
	c, _ := newClient(t, m, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()

	sessions, stats, err := c.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(sessions) != 1 || sessions[0].ID != 1 || sessions[0].Name() != "HOST-TEST" {
		t.Fatalf("unexpected sessions: %+v", sessions)
	}
	if stats["sessions"] == nil {
		t.Fatalf("missing stats: %+v", stats)
	}

	res, err := c.Task(ctx, "1", "shell", "whoami /all", 5)
	if err != nil {
		t.Fatalf("task: %v", err)
	}
	if res.Status != "ok" || string(res.Out) != "mock-out:shell" {
		t.Fatalf("unexpected task result: %+v out=%q", res, res.Out)
	}
	if reqs := m.Requests(); !contains(reqs, "task 1 shell whoami /all") {
		t.Fatalf("task not recorded: %v", reqs)
	}
}

func TestAuthReject(t *testing.T) {
	m := testutil.NewMock(t)
	m.RejectAuth = true
	c, _ := newClient(t, m, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err == nil {
		t.Fatal("expected authentication failure")
	}
}

func TestTunnelNoticeDemux(t *testing.T) {
	m := testutil.NewMock(t)
	m.NoticeAfterAuth = true
	notices := make(chan client.Notice, 4)
	c, _ := newClient(t, m, func(o *client.Options) {
		o.OnNotice = func(n client.Notice) { notices <- n }
	})
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()
	select {
	case n := <-notices:
		if n.TID != 7 || string(n.Data) != "hello-tunnel" || n.FType != 0x41 {
			t.Fatalf("unexpected notice: %+v %q", n, n.Data)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no tunnel notice received")
	}
	// The notice must not be mistaken for an RPC reply.
	if _, _, err := c.List(ctx); err != nil {
		t.Fatalf("list after notice: %v", err)
	}
}

func TestPushResumeAndPullFetch(t *testing.T) {
	m := testutil.NewMock(t)
	m.Files[`C:\data\a.bin`] = []byte("abcdefghij")
	c, _ := newClient(t, m, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()

	if _, err := c.Push(ctx, "1", `C:\up.bin`, []byte("456789"), 4); err != nil {
		t.Fatalf("push: %v", err)
	}
	pushes := m.Pushes()
	if len(pushes) != 1 || pushes[0].Off != 4 || string(pushes[0].Data) != "456789" {
		t.Fatalf("unexpected push record: %+v", pushes)
	}

	pull, err := c.Pull(ctx, "1", `C:\data\a.bin`)
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if pull.Size != 10 || pull.SHA == "" || pull.Xfer == "" {
		t.Fatalf("unexpected pull: %+v", pull)
	}
	var buf bytes.Buffer
	var lastDone, lastTotal int64
	n, sha, err := c.Fetch(ctx, pull.Xfer, &buf, pull.Size, func(done, total int64) {
		lastDone, lastTotal = done, total
	})
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if n != 10 || buf.String() != "abcdefghij" {
		t.Fatalf("fetch mismatch n=%d data=%q", n, buf.String())
	}
	if sha != pull.SHA || lastDone != 10 || lastTotal != 10 {
		t.Fatalf("sha/progress mismatch sha=%s pull=%s done=%d/%d", sha, pull.SHA, lastDone, lastTotal)
	}
}

func TestKillAndReloadError(t *testing.T) {
	m := testutil.NewMock(t)
	c, _ := newClient(t, m, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()
	if err := c.Kill(ctx, "1"); err != nil {
		t.Fatalf("kill: %v", err)
	}
	if reqs := m.Requests(); !contains(reqs, "kill 1") {
		t.Fatalf("kill not recorded: %v", reqs)
	}
	if _, _, err := c.Reload(ctx, "bad"); err == nil || !strings.Contains(err.Error(), "mock reload failure") {
		t.Fatalf("expected reload error, got %v", err)
	}
}

func TestReconnect(t *testing.T) {
	m := testutil.NewMock(t)
	m.SetCloseAfter(1)
	c, states := newClient(t, m, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, _, err := c.List(ctx); err != nil {
		t.Fatalf("first list: %v", err)
	}
	waitState(t, states, "disconnected")
	m.SetCloseAfter(0)
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	if _, _, err := c.List(ctx); err != nil {
		t.Fatalf("second list: %v", err)
	}
	c.Close()
}

func TestPushTooLarge(t *testing.T) {
	m := testutil.NewMock(t)
	c, _ := newClient(t, m, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()
	if _, err := c.Push(ctx, "1", "x", make([]byte, client.MaxPushPayload+1), 0); err == nil {
		t.Fatal("expected size error")
	}
}

func waitState(t *testing.T, ch <-chan string, want string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case s := <-ch:
			if strings.HasPrefix(s, want+"|") {
				return
			}
		case <-deadline:
			t.Fatalf("state %q not observed", want)
		}
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
