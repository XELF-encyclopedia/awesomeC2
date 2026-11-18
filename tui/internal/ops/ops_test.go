package ops_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"backd/c2/mvp/tui/internal/client"
	"backd/c2/mvp/tui/internal/ops"
	"backd/c2/mvp/tui/internal/testutil"
)

type fakeEmitter struct {
	mu       sync.Mutex
	lines    []string
	statuses []string
	sessions []client.Session
	stats    map[string]any
	confirms []string
	answer   bool
	progress []string
}

func (f *fakeEmitter) Printf(format string, a ...any) {
	f.mu.Lock()
	f.lines = append(f.lines, fmt.Sprintf(format, a...))
	f.mu.Unlock()
}

func (f *fakeEmitter) Status(s string) {
	f.mu.Lock()
	f.statuses = append(f.statuses, s)
	f.mu.Unlock()
}

func (f *fakeEmitter) Progress(done, total int64, label string) {
	f.mu.Lock()
	f.progress = append(f.progress, fmt.Sprintf("%s %d/%d", label, done, total))
	f.mu.Unlock()
}

func (f *fakeEmitter) Clear() {}

func (f *fakeEmitter) Confirm(title, prompt string) bool {
	f.mu.Lock()
	f.confirms = append(f.confirms, title)
	ans := f.answer
	f.mu.Unlock()
	return ans
}

func (f *fakeEmitter) SetSessions(s []client.Session, st map[string]any) {
	f.mu.Lock()
	f.sessions = s
	f.stats = st
	f.mu.Unlock()
}

func (f *fakeEmitter) Tunnel(client.Notice) {}

func (f *fakeEmitter) setAnswer(v bool) {
	f.mu.Lock()
	f.answer = v
	f.mu.Unlock()
}

func (f *fakeEmitter) text() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.lines, "\n")
}

func (f *fakeEmitter) confirmCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.confirms)
}

func newDispatcher(t *testing.T) (*ops.Dispatcher, *testutil.Mock, *fakeEmitter) {
	t.Helper()
	m := testutil.NewMock(t)
	em := &fakeEmitter{answer: true}
	cli := client.New(client.Options{
		Endpoint: m.URL(),
		User:     m.User,
		PSK:      "hex:" + hex.EncodeToString(m.PSK),
		Family:   "4",
		Timeout:  8 * time.Second,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := cli.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(cli.Close)
	return ops.New(cli, em, t.TempDir(), func() uint64 { return 1 }), m, em
}

func TestDispatcherListUseShell(t *testing.T) {
	d, m, em := newDispatcher(t)
	ctx := context.Background()

	if err := d.Exec(ctx, "list"); err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(em.sessions) != 1 || em.sessions[0].Name() != "HOST-TEST" {
		t.Fatalf("sessions not delivered to the UI: %+v", em.sessions)
	}
	if err := d.Exec(ctx, "use 1"); err != nil {
		t.Fatalf("use: %v", err)
	}
	if d.Session() != 1 {
		t.Fatalf("session = %d, want 1", d.Session())
	}
	if err := d.Exec(ctx, "shell whoami /all"); err != nil {
		t.Fatalf("shell: %v", err)
	}
	if reqs := m.Requests(); !contains(reqs, "task 1 shell whoami /all") {
		t.Fatalf("shell task not sent: %v", reqs)
	}
	if !strings.Contains(em.text(), "mock-out:shell") {
		t.Fatalf("task output not rendered: %q", em.text())
	}
}

func TestDispatcherUploadResumeAndDownload(t *testing.T) {
	d, m, em := newDispatcher(t)
	ctx := context.Background()

	local := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(local, []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(local, " ") {
		t.Skipf("test path contains spaces and the command parser is whitespace-based: %q", local)
	}
	args := fmt.Sprintf("upload %s C:\\up.bin 4", local)
	if err := d.Exec(ctx, args); err != nil {
		t.Fatalf("upload: %v", err)
	}
	pushes := m.Pushes()
	if len(pushes) != 1 || pushes[0].Off != 4 || string(pushes[0].Data) != "456789" {
		t.Fatalf("resume upload mismatch: %+v", pushes)
	}

	m.Files[`C:\data\a.bin`] = []byte("abcdefghij")
	if err := d.Exec(ctx, `download C:\data\a.bin`); err != nil {
		t.Fatalf("download: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(d.Home, "a.bin"))
	if err != nil {
		t.Fatalf("downloaded file: %v", err)
	}
	if string(got) != "abcdefghij" {
		t.Fatalf("downloaded content = %q", got)
	}
	if len(em.progress) == 0 {
		t.Fatal("download produced no progress events")
	}
}

func TestDangerCommandsRequireConfirmation(t *testing.T) {
	d, m, em := newDispatcher(t)
	ctx := context.Background()
	if err := d.Exec(ctx, "use 1"); err != nil {
		t.Fatal(err)
	}
	em.setAnswer(false)

	if err := d.Exec(ctx, "kill 1"); err != nil {
		t.Fatalf("kill: %v", err)
	}
	if em.confirmCount() != 1 {
		t.Fatalf("kill did not confirm (confirms=%d)", em.confirmCount())
	}
	if reqs := m.Requests(); contains(reqs, "kill 1") {
		t.Fatalf("kill was sent despite cancellation: %v", reqs)
	}

	for _, cmd := range []string{"selfdestruct", `cleanup C:\x`, "persist_disable"} {
		before := em.confirmCount()
		if err := d.Exec(ctx, cmd); err != nil {
			t.Fatalf("%s: %v", cmd, err)
		}
		if em.confirmCount() != before+1 {
			t.Fatalf("%s did not ask for confirmation", cmd)
		}
	}
	if reqs := m.Requests(); contains(reqs, "task 1 selfdestruct ") {
		t.Fatalf("selfdestruct was sent despite cancellation: %v", reqs)
	}

	// Answering yes lets the dangerous action through.
	em.setAnswer(true)
	if err := d.Exec(ctx, "kill 1"); err != nil {
		t.Fatalf("kill(confirmed): %v", err)
	}
	if reqs := m.Requests(); !contains(reqs, "kill 1") {
		t.Fatalf("confirmed kill was not sent: %v", reqs)
	}
}

func TestUnknownCommand(t *testing.T) {
	d, _, _ := newDispatcher(t)
	if err := d.Exec(context.Background(), "bogus"); err == nil {
		t.Fatal("expected an error for an unknown command")
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
