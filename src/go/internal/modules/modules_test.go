package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestHelperProcess is re-executed as an external module by the exec tests.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_MODULE_HELPER") != "1" {
		return
	}
	raw, _ := io.ReadAll(os.Stdin)
	var in map[string]any
	_ = json.Unmarshal(raw, &in)
	out := map[string]any{
		"ok":   true,
		"input": in,
		"argv": append([]string{}, os.Args[1:]...),
		"marker": os.Getenv("GO_MODULE_MARKER"),
	}
	b, _ := json.Marshal(out)
	fmt.Print(string(b))
	os.Exit(0)
}

func testExecSpec() *ExecSpec {
	return &ExecSpec{
		Path:    os.Args[0],
		Args:    []string{"-test.run=TestHelperProcess", "--", "{{tag}}"},
		Timeout: 20,
		EnvPass: []string{"GO_WANT_MODULE_HELPER", "GO_MODULE_MARKER", "PATH", "SYSTEMROOT"},
	}
}

func TestBuiltinCatalogAndSearch(t *testing.T) {
	r := New()
	all := r.All()
	if len(all) < 10 {
		t.Fatalf("builtin catalog too small: %d", len(all))
	}
	m, ok := r.Get("ai_context")
	if !ok || m.Kind != "builtin" {
		t.Fatalf("ai_context missing or not builtin: %+v", m)
	}
	if got := r.Search("file"); len(got) == 0 {
		t.Fatalf("search file returned nothing")
	}
	if _, ok := r.Get("does_not_exist"); ok {
		t.Fatalf("unknown module resolved")
	}
	// Running a builtin through the external path must be rejected.
	if _, err := r.RunExternal(context.Background(), m, json.RawMessage(`{}`)); err == nil {
		t.Fatalf("builtin module executed server-side")
	}
}

func TestLoadDirExecModuleAndRun(t *testing.T) {
	dir := t.TempDir()
	m := Manifest{
		Name: "ext_echo", Summary: "echo JSON stdin", Kind: "exec",
		Platforms: []string{"windows", "linux"}, MinRole: "operator", Destructive: false,
		Args: []Arg{{Name: "tag", Type: "string", Required: true}},
		Exec: testExecSpec(),
	}
	writeManifest(t, dir, m)
	r := New()
	loaded, err := r.LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(loaded) != 1 || loaded[0] != "ext_echo" {
		t.Fatalf("loaded=%v", loaded)
	}
	got, ok := r.Get("ext_echo")
	if !ok || got.Kind != "exec" {
		t.Fatalf("manifest not registered: %+v", got)
	}
	t.Setenv("GO_WANT_MODULE_HELPER", "1")
	t.Setenv("GO_MODULE_MARKER", "marker-42")
	out, err := r.RunExternal(context.Background(), got, json.RawMessage(`{"tag":"abc"}`))
	if err != nil {
		t.Fatalf("RunExternal: %v", err)
	}
	var parsed struct {
		OK     bool           `json:"ok"`
		Input  map[string]any `json:"input"`
		Argv   []string       `json:"argv"`
		Marker string         `json:"marker"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("exec output not JSON: %v (%s)", err, out)
	}
	if !parsed.OK || parsed.Input["tag"] != "abc" {
		t.Fatalf("exec did not receive stdin JSON: %+v", parsed)
	}
	if parsed.Marker != "marker-42" {
		t.Fatalf("EnvPass not honoured: %+v", parsed)
	}
	if len(parsed.Argv) == 0 || parsed.Argv[len(parsed.Argv)-1] != "abc" {
		t.Fatalf("arg templating failed: %v", parsed.Argv)
	}
}

func TestInvalidAndShadowingManifestsRejected(t *testing.T) {
	dir := t.TempDir()
	// bad kind
	writeRaw(t, dir, "bad.json", `{"name":"bad","kind":"magic","summary":"x"}`)
	// builtin shadow attempt
	writeRaw(t, dir, "shadow.json", `{"name":"shell","kind":"builtin","summary":"fake shell"}`)
	// missing exec path
	writeRaw(t, dir, "noexec.json", `{"name":"noexec","kind":"exec","summary":"x"}`)
	r := New()
	loaded, err := r.LoadDir(dir)
	if err == nil {
		t.Fatalf("expected load warnings, got none")
	}
	if len(loaded) != 0 {
		t.Fatalf("invalid manifests were loaded: %v", loaded)
	}
	m, _ := r.Get("shell")
	if m.Summary == "fake shell" {
		t.Fatalf("builtin was shadowed")
	}
	if _, ok := r.Get("bad"); ok {
		t.Fatalf("bad kind accepted")
	}
}

func TestWasmMissingRuntime(t *testing.T) {
	r := New()
	m := Manifest{Name: "w", Summary: "w", Kind: "wasm", Wasm: &WasmSpec{File: "x.wasm"}}
	if err := m.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if _, err := r.RunExternal(context.Background(), m, json.RawMessage(`{}`)); err == nil {
		t.Fatalf("wasm ran without a runtime")
	}
	// install a runtime: the extension point must work without core changes
	r.SetWasmRuntime(fakeWasm{})
	out, err := r.RunExternal(context.Background(), m, json.RawMessage(`{"x":1}`))
	if err != nil {
		t.Fatalf("wasm runtime: %v", err)
	}
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil || v["file"] != "x.wasm" {
		t.Fatalf("wasm output: %s", out)
	}
}

type fakeWasm struct{}

func (fakeWasm) Run(_ context.Context, file, _ string, args json.RawMessage) (json.RawMessage, error) {
	b, _ := json.Marshal(map[string]any{"file": file, "args": string(args)})
	return b, nil
}

func writeManifest(t *testing.T, dir string, m Manifest) {
	t.Helper()
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeRaw(t, dir, m.Name+".json", string(b))
}

func writeRaw(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
