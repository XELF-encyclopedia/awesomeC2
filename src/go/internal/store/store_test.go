package store

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func auditChainOK(t *testing.T, ents []AuditEntry) {
	t.Helper()
	prev := ""
	for i, e := range ents {
		if e.PrevHash != prev {
			t.Fatalf("entry %d (%s) prev_hash=%q want %q", i, e.Action, e.PrevHash, prev)
		}
		if got := HashEntry(e.PrevHash, fmt.Sprint(e.TS), e.Actor, e.Action, e.Target, e.Detail); got != e.Hash {
			t.Fatalf("entry %d hash mismatch", i)
		}
		prev = e.Hash
	}
}

func TestMemoryAuditChainAndTamper(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	if err := m.Init(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		if _, err := m.Audit(ctx, "alice", "test.action", "target", "detail"); err != nil {
			t.Fatal(err)
		}
	}
	ents, err := m.ListAudit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 20 {
		t.Fatalf("entries=%d", len(ents))
	}
	auditChainOK(t, ents)
	// tampering with detail breaks the entry hash
	bad := ents[5]
	if HashEntry(bad.PrevHash, fmt.Sprint(bad.TS), bad.Actor, bad.Action, bad.Target, bad.Detail+"x") == bad.Hash {
		t.Fatalf("tamper not detected")
	}
	// tail limit returns the newest entries in order
	tail, _ := m.ListAudit(ctx, 5)
	if len(tail) != 5 || tail[4].Hash != ents[19].Hash {
		t.Fatalf("tail not returned in order: %d", len(tail))
	}
	for i := 0; i < len(tail); i++ {
		if HashEntry(tail[i].PrevHash, fmt.Sprint(tail[i].TS), tail[i].Actor, tail[i].Action, tail[i].Target, tail[i].Detail) != tail[i].Hash {
			t.Fatalf("tail entry %d hash mismatch", i)
		}
		if i > 0 && tail[i].PrevHash != tail[i-1].Hash {
			t.Fatalf("tail entry %d not linked", i)
		}
	}
}

func TestSQLiteAuditOrderingWithinSameSecond(t *testing.T) {
	ctx := context.Background()
	dsn := filepath.ToSlash(filepath.Join(t.TempDir(), "audit.db"))
	s, err := Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	// 40 entries inside the same second: id is a string and ts has second
	// granularity, so ordering must use insertion order (rowid).
	for i := 0; i < 40; i++ {
		if _, err := s.Audit(ctx, "bob", "burst", "t", "d"); err != nil {
			t.Fatalf("Audit %d: %v", i, err)
		}
	}
	ents, err := s.ListAudit(ctx, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 40 {
		t.Fatalf("entries=%d", len(ents))
	}
	auditChainOK(t, ents)
	tail, err := s.ListAudit(ctx, 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(tail) != 7 || tail[6].Hash != ents[39].Hash {
		t.Fatalf("sqlite tail wrong: %d", len(tail))
	}
}

func TestTaskLifecycleAndLocks(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	now := time.Now().Unix()
	task := Task{ID: "t1", SID: "s1", Name: "shell", Args: "{}", State: "queued", Created: now, Op: "alice"}
	if err := m.CreateTask(ctx, task); err != nil {
		t.Fatal(err)
	}
	task.State = "done"
	task.Result = `{"ok":true}`
	task.Finished = now + 1
	if err := m.FinishTask(ctx, task); err != nil {
		t.Fatal(err)
	}
	tasks, err := m.ListTasks(ctx, "s1", 10)
	if err != nil || len(tasks) != 1 {
		t.Fatalf("tasks=%v err=%v", tasks, err)
	}
	if tasks[0].State != "done" || tasks[0].Result == "" {
		t.Fatalf("task not finished: %+v", tasks[0])
	}
	if got, _ := m.ListTasks(ctx, "other", 10); len(got) != 0 {
		t.Fatalf("tasks leaked across sids: %v", got)
	}

	if err := m.AcquireLock(ctx, Lock{SID: "s1", Owner: "alice", Expires: now + 300}); err != nil {
		t.Fatal(err)
	}
	l, err := m.GetLock(ctx, "s1")
	if err != nil || l.Owner != "alice" {
		t.Fatalf("lock=%+v err=%v", l, err)
	}
	if err := m.ReleaseLock(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GetLock(ctx, "s1"); err == nil {
		t.Fatalf("lock still present after release")
	}
}

func TestSessionsAndManifests(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	_ = m.UpsertSession(ctx, Session{SID: "s1", Host: "a", Tenant: "t1", LastSeen: 1})
	_ = m.UpsertSession(ctx, Session{SID: "s2", Host: "b", Tenant: "t2", LastSeen: 2})
	all, _ := m.ListSessions(ctx, "")
	if len(all) != 2 {
		t.Fatalf("all=%d", len(all))
	}
	t1, _ := m.ListSessions(ctx, "t1")
	if len(t1) != 1 || t1[0].SID != "s1" {
		t.Fatalf("tenant filter broken: %+v", t1)
	}
	m.UpsertSession(ctx, Session{SID: "s1", Host: "a2", Tenant: "t1", LastSeen: 9})
	got, _ := m.GetSession(ctx, "s1")
	if got == nil || got.Host != "a2" {
		t.Fatalf("upsert did not update: %+v", got)
	}
	m.SaveManifest(ctx, Manifest{Version: "1.0.0", Platform: "linux", Arch: "amd64", URL: "https://example.com/c", SHA256: "aa", Sig: "ss", Rollout: 100})
	ms, _ := m.ListManifests(ctx)
	if len(ms) != 1 || ms[0].Version != "1.0.0" {
		t.Fatalf("manifests: %+v", ms)
	}
}


