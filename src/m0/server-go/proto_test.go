package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := writeFrame(&buf, msg{"t": "hello", "client_id": "c1", "pid": 42}); err != nil {
		t.Fatalf("write: %v", err)
	}
	m, err := readFrame(bufio.NewReader(&buf))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if str(m, "t") != "hello" || str(m, "client_id") != "c1" || num(m, "pid") != 42 {
		t.Fatalf("unexpected frame: %#v", m)
	}
}

func TestFrameRejectsOversize(t *testing.T) {
	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(maxFrame+1))
	buf.Write(hdr[:])
	if _, err := readFrame(bufio.NewReader(&buf)); err == nil {
		t.Fatal("expected oversize error")
	}
}

func TestOpAuth(t *testing.T) {
	a := opAuth{enabled: true, user: "ops", secret: "unit-test-secret-value-0123456789"}
	if !a.check("ops", "unit-test-secret-value-0123456789") {
		t.Fatal("valid credentials rejected")
	}
	if a.check("ops", "wrong") {
		t.Fatal("wrong PSK accepted")
	}
	if a.check("root", "unit-test-secret-value-0123456789") {
		t.Fatal("wrong user accepted")
	}
	open := opAuth{enabled: false}
	if !open.check("anyone", "") {
		t.Fatal("disabled auth should accept")
	}
}

func TestRegistryReplace(t *testing.T) {
	r := newRegistry()
	s1 := newSession("c1")
	s2 := newSession("c1")
	r.add(s1)
	r.remove(s1)
	r.add(s2)
	if r.count() != 1 {
		t.Fatalf("expected 1 session, got %d", r.count())
	}
	if got := r.byClientID("c1"); got != s2 {
		t.Fatalf("registry returned stale session")
	}
}

func TestSessionDeliver(t *testing.T) {
	s := newSession("c")
	res := &Result{TaskID: "t1", Kind: "sysinfo", OK: true, Data: "os=test"}
	s.deliver(res)
	got, ok := s.await("t1", 0)
	if !ok || got.TaskID != "t1" || got.Data != "os=test" {
		t.Fatalf("await returned %#v ok=%v", got, ok)
	}
	if _, ok := s.await("missing", 10*1000*1000); ok {
		t.Fatal("await on missing task should time out")
	}
}
