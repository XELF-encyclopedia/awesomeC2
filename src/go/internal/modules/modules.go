// Package modules implements the pluggable module registry used by the C2V2
// server, operator CLI and GUI.
//
// Three kinds of modules are supported:
//
//	builtin - implemented inside the Rust client; the server forwards a task
//	exec    - an out-of-process helper executed *on the server host*; the
//	          server runs the binary named in the manifest with JSON on stdin
//	wasm    - a WebAssembly module; requires a WasmRuntime to be registered,
//	          otherwise execution is rejected with a clear error
//
// Knowing a manifest schema is therefore enough to add a module without
// touching the core: drop a JSON file into profiles/modules/ and it shows up
// in `modules`, `module-search`, `module-show` and can be invoked with
// `module-run`.  External manifests are only loaded from a directory the
// operator controls; they are never fetched from clients.
package modules

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"c2v2/internal/catalog"
)

// Arg describes one argument and its JSON type.
type Arg struct {
	Name     string `json:"name"`
	Type     string `json:"type"` // string|int|bool|b64|json
	Required bool   `json:"required"`
	Desc     string `json:"desc,omitempty"`
	Default  any    `json:"default,omitempty"`
}

// ExecSpec describes an out-of-process module.
type ExecSpec struct {
	Path    string   `json:"path"`              // binary path, no shell
	Args    []string `json:"args,omitempty"`    // static arguments (templated with {{name}})
	Timeout int      `json:"timeout_secs,omitempty"` // default 30s, max 600s
	WorkDir string   `json:"workdir,omitempty"`
	// EnvPass lists environment variables to inherit (default: none except PATH/HOME).
	EnvPass []string `json:"env_pass,omitempty"`
}

// WasmSpec describes a WebAssembly module.
type WasmSpec struct {
	File string `json:"file"` // path to .wasm on the server
	Func string `json:"func,omitempty"`
}

// Manifest is one module definition.
type Manifest struct {
	Name        string   `json:"name"`
	Summary     string   `json:"summary"`
	Kind        string   `json:"kind"` // builtin|exec|wasm
	Platforms   []string `json:"platforms,omitempty"`
	Capability  string   `json:"capability,omitempty"`
	Destructive bool     `json:"destructive"`
	MinRole     string   `json:"min_role"` // viewer|operator|admin
	Args        []Arg    `json:"args,omitempty"`
	Exec        *ExecSpec `json:"exec,omitempty"`
	Wasm        *WasmSpec `json:"wasm,omitempty"`
}

// Validate checks the manifest is internally consistent.
func (m Manifest) Validate() error {
	if strings.TrimSpace(m.Name) == "" {
		return errors.New("module name is empty")
	}
	if m.Kind != "builtin" && m.Kind != "exec" && m.Kind != "wasm" {
		return fmt.Errorf("module %s: kind must be builtin|exec|wasm", m.Name)
	}
	switch m.MinRole {
	case "", "viewer", "operator", "admin":
	default:
		return fmt.Errorf("module %s: invalid min_role %q", m.Name, m.MinRole)
	}
	if m.Kind == "exec" {
		if m.Exec == nil || strings.TrimSpace(m.Exec.Path) == "" {
			return fmt.Errorf("module %s: exec.path is required", m.Name)
		}
	}
	if m.Kind == "wasm" {
		if m.Wasm == nil || strings.TrimSpace(m.Wasm.File) == "" {
			return fmt.Errorf("module %s: wasm.file is required", m.Name)
		}
	}
	return nil
}

// Role returns the effective minimum role.
func (m Manifest) Role() string {
	if m.MinRole == "" {
		return "operator"
	}
	return m.MinRole
}

// WasmRuntime is the extension point for WebAssembly modules.  Implement it
// and call Registry.SetWasmRuntime to enable kind=wasm manifests.
type WasmRuntime interface {
	Run(ctx context.Context, file string, fn string, args json.RawMessage) (json.RawMessage, error)
}

// Registry holds builtin + external manifests.
type Registry struct {
	mu      sync.RWMutex
	items   map[string]Manifest
	order   []string
	wasm    WasmRuntime
	execRun func(ctx context.Context, m Manifest, args json.RawMessage) (json.RawMessage, error)
}

// New builds a registry pre-populated with the built-in client catalog.
func New() *Registry {
	r := &Registry{items: map[string]Manifest{}}
	for _, c := range catalog.Modules {
		args := make([]Arg, 0, len(c.Args))
		for _, a := range c.Args {
			args = append(args, Arg{Name: a.Name, Type: a.Type, Required: a.Required, Desc: a.Desc})
		}
		r.add(Manifest{
			Name: c.Name, Summary: c.Summary, Kind: "builtin", Platforms: c.Platforms,
			Capability: c.Capability, Destructive: c.Destructive, MinRole: c.Operator, Args: args,
		})
	}
	r.execRun = runExec
	return r
}

func (r *Registry) add(m Manifest) {
	if _, exists := r.items[m.Name]; !exists {
		r.order = append(r.order, m.Name)
	}
	r.items[m.Name] = m
}

// SetWasmRuntime installs the optional WASM extension.
func (r *Registry) SetWasmRuntime(w WasmRuntime) {
	r.mu.Lock()
	r.wasm = w
	r.mu.Unlock()
}

// LoadDir loads every *.json manifest in dir.  Missing directories are not an
// error.  A conflicting external name replaces a builtin only when kind is
// explicitly set to something other than builtin; otherwise the builtin wins
// so an operator cannot silently shadow a client capability.
func (r *Registry) LoadDir(dir string) ([]string, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var loaded []string
	var errs []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", e.Name(), err))
			continue
		}
		var m Manifest
		if err := json.Unmarshal(raw, &m); err != nil {
			errs = append(errs, fmt.Sprintf("%s: parse: %v", e.Name(), err))
			continue
		}
		if err := m.Validate(); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", e.Name(), err))
			continue
		}
		if existing, ok := r.Get(m.Name); ok && existing.Kind == "builtin" && m.Kind == "builtin" {
			errs = append(errs, fmt.Sprintf("%s: refusing to shadow builtin %s", e.Name(), m.Name))
			continue
		}
		r.mu.Lock()
		r.add(m)
		r.mu.Unlock()
		loaded = append(loaded, m.Name)
	}
	sort.Strings(loaded)
	if len(errs) > 0 {
		return loaded, fmt.Errorf("module load warnings: %s", strings.Join(errs, "; "))
	}
	return loaded, nil
}

// Get looks up a manifest by name.
func (r *Registry) Get(name string) (Manifest, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.items[name]
	return m, ok
}

// All returns manifests in insertion order.
func (r *Registry) All() []Manifest {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Manifest, 0, len(r.order))
	for _, n := range r.order {
		out = append(out, r.items[n])
	}
	return out
}

// Search performs a case-insensitive match over name/summary/capability.
func (r *Registry) Search(q string) []Manifest {
	q = strings.ToLower(strings.TrimSpace(q))
	var out []Manifest
	for _, m := range r.All() {
		if q == "" {
			out = append(out, m)
			continue
		}
		hay := strings.ToLower(m.Name + " " + m.Summary + " " + m.Capability + " " + strings.Join(m.Platforms, " "))
		if strings.Contains(hay, q) {
			out = append(out, m)
		}
	}
	return out
}

// RunExternal executes a non-builtin manifest.  Builtin modules must be
// dispatched by the server to a client instead.
func (r *Registry) RunExternal(ctx context.Context, m Manifest, args json.RawMessage) (json.RawMessage, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	switch m.Kind {
	case "exec":
		r.mu.RLock()
		fn := r.execRun
		r.mu.RUnlock()
		if fn == nil {
			return nil, errors.New("exec runner not configured")
		}
		return fn(ctx, m, args)
	case "wasm":
		r.mu.RLock()
		w := r.wasm
		r.mu.RUnlock()
		if w == nil {
			return nil, errors.New("wasm runtime not configured on this server")
		}
		return w.Run(ctx, m.Wasm.File, m.Wasm.Func, args)
	case "builtin":
		return nil, fmt.Errorf("module %s is builtin and must run on a client", m.Name)
	default:
		return nil, fmt.Errorf("unknown module kind %q", m.Kind)
	}
}

func runExec(ctx context.Context, m Manifest, args json.RawMessage) (json.RawMessage, error) {
	timeout := time.Duration(m.Exec.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if timeout > 10*time.Minute {
		timeout = 10 * time.Minute
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Template {{arg}} placeholders in static args from the JSON object.
	var vals map[string]any
	if len(args) > 0 {
		_ = json.Unmarshal(args, &vals)
	}
	argv := make([]string, 0, len(m.Exec.Args))
	for _, a := range m.Exec.Args {
		argv = append(argv, templateArg(a, vals))
	}
	cmd := exec.CommandContext(cctx, m.Exec.Path, argv...)
	if m.Exec.WorkDir != "" {
		cmd.Dir = m.Exec.WorkDir
	}
	env := []string{}
	for _, k := range m.Exec.EnvPass {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	cmd.Env = env

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Stdin = bytes.NewReader(args)
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		if msg != "" {
			return nil, fmt.Errorf("exec module %s: %v: %s", m.Name, err, truncate(msg, 800))
		}
		return nil, fmt.Errorf("exec module %s: %v", m.Name, err)
	}
	out := bytes.TrimSpace(stdout.Bytes())
	if len(out) == 0 {
		return json.RawMessage(`{"ok":true,"note":"module produced no output"}`), nil
	}
	if !json.Valid(out) {
		b, _ := json.Marshal(map[string]string{"raw": string(out)})
		return b, nil
	}
	return json.RawMessage(out), nil
}

func templateArg(s string, vals map[string]any) string {
	for k, v := range vals {
		s = strings.ReplaceAll(s, "{{"+k+"}}", fmt.Sprint(v))
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
