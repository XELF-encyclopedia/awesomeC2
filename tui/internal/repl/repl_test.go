package repl

import (
	"io"
	"strings"
	"testing"
)

func TestCleanLineStripsBOM(t *testing.T) {
	cases := map[string]string{
		"\ufefflist":         "list",
		"\ufeff  use 1 \r\n": "use 1",
		"  shell whoami  ":   "shell whoami",
		"\ufeff":             "",
		"":                   "",
		"quit":               "quit",
	}
	for in, want := range cases {
		if got := cleanLine(in); got != want {
			t.Fatalf("cleanLine(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEmitterConfirm(t *testing.T) {
	em := NewEmitter(strings.NewReader("\ufeff YES \n"), io.Discard)
	if !em.Confirm("t", "p") {
		t.Fatal("BOM-prefixed YES should confirm")
	}
	em = NewEmitter(strings.NewReader("no\n"), io.Discard)
	if em.Confirm("t", "p") {
		t.Fatal("no should not confirm")
	}
}
