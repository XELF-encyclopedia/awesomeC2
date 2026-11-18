package main

// c2builder — M0 profile/builder CLI for the authorized red-team C2 v2 project.
//
// M0 scope: validate a build request, emit a machine-readable profile plus a
// client-consumable flat config, and (optionally) launch the Rust client against
// the same loopback endpoint so the whole chain can be demoed from one command.
//
// Real artifact generation (exe/elf/macho/apk/dll/service) is intentionally NOT
// implemented in M0 — `--format exe` prints exactly what is missing and exits 4.
// Nothing here pretends a binary was produced.
//
// Safety: by default the builder refuses non-documentation hosts (only
// localhost, *.example.com and 203.0.113.0/24 are accepted). Use --allow-any-host
// for an explicitly authorized target, and never commit the resulting profile.

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const builderVersion = "0.1.0-m0"

type Profile struct {
	Name       string `json:"name"`
	Platform   string `json:"platform"`
	Arch       string `json:"arch"`
	Transport  string `json:"transport"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	SNI        string `json:"sni,omitempty"`
	Path       string `json:"path,omitempty"`
	SleepSecs  int    `json:"sleep_secs"`
	JitterPct  int    `json:"jitter_pct"`
	Suite      string `json:"suite"`
	ClientID   string `json:"client_id"`
	Format     string `json:"format"`
	Notes      string `json:"notes"`
	Builder    string `json:"builder_version"`
	CreatedUTC string `json:"created_utc"`
}

var (
	validPlatforms  = []string{"windows", "linux", "darwin", "android"}
	validArches     = []string{"amd64", "arm64", "386", "armv7", "universal"}
	validTransports = []string{"tcp", "tls", "ws", "wss", "dns", "udp", "doh"}
	validSuites     = []string{"plaintext", "v2"}
	validFormats    = []string{"profile", "exe", "elf", "macho", "apk", "dll", "service"}
)

func main() {
	var (
		platform  = flag.String("platform", "", "target platform: windows|linux|darwin|android")
		arch      = flag.String("arch", "", "target arch: amd64|arm64|386|armv7|universal")
		transport = flag.String("transport", "tcp", "transport: tcp|tls|ws|wss|dns|udp|doh")
		host      = flag.String("host", "127.0.0.1", "callback host (default loopback)")
		port      = flag.Int("port", 9909, "callback port")
		sni       = flag.String("sni", "", "TLS SNI (optional)")
		path      = flag.String("path", "", "HTTP path for ws/wss (optional)")
		name      = flag.String("name", "", "profile name (default derived)")
		format    = flag.String("format", "profile", "output format: profile|exe|elf|macho|apk|dll|service")
		clientID  = flag.String("client-id", "", "client id baked into the profile")
		sleep     = flag.Int("sleep", 20, "beacon sleep seconds")
		jitter    = flag.Int("jitter", 20, "beacon jitter percent (0-90)")
		suite     = flag.String("suite", "plaintext", "session suite: plaintext|v2")
		outDir    = flag.String("out", "profiles", "output directory for generated profiles")
		allowAny  = flag.Bool("allow-any-host", false, "allow non-documentation callback hosts (authorized targets only)")
		launch    = flag.Bool("launch", false, "launch the Rust client against the generated profile")
		clientBin = flag.String("client-bin", "", "path to c2client binary (required with --launch)")
		jsonOut   = flag.Bool("json", false, "print the profile as JSON to stdout")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `c2builder %s (M0)

usage: c2builder --platform windows --arch amd64 --transport tcp \
                 --host 127.0.0.1 --port 9909 --name demo [--format profile] \
                 [--launch --client-bin path\to\c2client.exe]

M0 emits a profile + client config; it does NOT compile implant binaries yet.
See docs/BUILD.md and NEXT.md for the M1 build matrix.
`, builderVersion)
		flag.PrintDefaults()
	}
	flag.Parse()

	if *platform == "" {
		*platform = "windows"
	}
	if *arch == "" {
		*arch = "amd64"
	}
	if err := validate(*platform, *arch, *transport, *suite, *format, *jitter); err != nil {
		fatalf(2, "%v", err)
	}
	if !*allowAny && !isDocumentationHost(*host) {
		fatalf(2, "host %q is not a documentation/loopback address; use example.com, *.example.com, 203.0.113.x or 127.0.0.1 (or pass --allow-any-host for an authorized target)", *host)
	}
	if *format != "profile" {
		fatalf(4, "format %q requires a compiler pipeline that is not part of M0; only --format profile is implemented (%s)", *format, m1Hint(*format, *platform))
	}
	if *launch && *clientBin == "" {
		fatalf(2, "--launch requires --client-bin <path to c2client>")
	}

	pname := *name
	if pname == "" {
		pname = fmt.Sprintf("%s-%s-%s", *platform, *arch, sanitizeName(*host))
	}
	cid := *clientID
	if cid == "" {
		cid = fmt.Sprintf("%s-%s-%s", *platform, *arch, pname)
	}

	p := Profile{
		Name:       pname,
		Platform:   *platform,
		Arch:       *arch,
		Transport:  *transport,
		Host:       *host,
		Port:       *port,
		SNI:        *sni,
		Path:       *path,
		SleepSecs:  *sleep,
		JitterPct:  *jitter,
		Suite:      *suite,
		ClientID:   cid,
		Format:     "profile",
		Notes:      "M0: profile only. No implant binary was compiled. See NEXT.md.",
		Builder:    builderVersion,
		CreatedUTC: time.Now().UTC().Format(time.RFC3339),
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fatalf(1, "create out dir: %v", err)
	}
	jsonPath := filepath.Join(*outDir, pname+".json")
	confPath := filepath.Join(*outDir, pname+".client.conf")
	metaPath := filepath.Join(*outDir, pname+".builder.json")

	jbuf, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		fatalf(1, "marshal profile: %v", err)
	}
	if err := os.WriteFile(jsonPath, append(jbuf, '\n'), 0o644); err != nil {
		fatalf(1, "write %s: %v", jsonPath, err)
	}

	// The client reads flat key=value lines (no JSON parser in the M0 client).
	conf := strings.Join([]string{
		"# generated by c2builder " + builderVersion + " — do not commit real targets",
		"addr=" + net.JoinHostPort(*host, fmt.Sprint(*port)),
		"client_id=" + cid,
		fmt.Sprintf("interval=%d", *sleep),
		"suite=" + *suite,
		"allow_exec=false",
		"retries=5",
		"",
	}, "\n")
	if err := os.WriteFile(confPath, []byte(conf), 0o644); err != nil {
		fatalf(1, "write %s: %v", confPath, err)
	}

	meta := map[string]any{
		"builder_version": builderVersion,
		"profile":         jsonPath,
		"client_conf":     confPath,
		"transport_note":  transportNote(*transport),
		"compiled":        false,
	}
	mbuf, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(metaPath, append(mbuf, '\n'), 0o644); err != nil {
		fatalf(1, "write %s: %v", metaPath, err)
	}

	if *jsonOut {
		fmt.Println(string(jbuf))
	} else {
		fmt.Printf("profile  : %s\n", jsonPath)
		fmt.Printf("client   : %s\n", confPath)
		fmt.Printf("metadata : %s\n", metaPath)
		fmt.Printf("transport: %s (%s)\n", *transport, transportNote(*transport))
	}

	if *launch {
		cmd := exec.Command(*clientBin, "--profile", confPath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		fmt.Printf("launching: %s --profile %s\n", *clientBin, confPath)
		if err := cmd.Start(); err != nil {
			fatalf(1, "launch client: %v", err)
		}
		fmt.Printf("client pid=%d (Ctrl+C stops this builder; client keeps running)\n", cmd.Process.Pid)
	}
}

func validate(platform, arch, transport, suite, format string, jitter int) error {
	if !contains(validPlatforms, platform) {
		return fmt.Errorf("platform %q not in %v", platform, validPlatforms)
	}
	if !contains(validArches, arch) {
		return fmt.Errorf("arch %q not in %v", arch, validArches)
	}
	if !contains(validTransports, transport) {
		return fmt.Errorf("transport %q not in %v", transport, validTransports)
	}
	if !contains(validSuites, suite) {
		return fmt.Errorf("suite %q not in %v", suite, validSuites)
	}
	if !contains(validFormats, format) {
		return fmt.Errorf("format %q not in %v", format, validFormats)
	}
	if jitter < 0 || jitter > 90 {
		return errors.New("jitter must be 0..90")
	}
	return nil
}

func isDocumentationHost(h string) bool {
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if h == "localhost" || h == "127.0.0.1" || h == "::1" {
		return true
	}
	if h == "example.com" || strings.HasSuffix(h, ".example.com") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil && ip.To4() != nil {
		return ip.To4()[0] == 203 && ip.To4()[1] == 0 && ip.To4()[2] == 113
	}
	return false
}

func sanitizeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

func transportNote(t string) string {
	switch t {
	case "tcp":
		return "plain TCP lab transport (M0 loopback)"
	case "tls", "wss":
		return "TLS transport lands in M1 (server TLS listeners + client rustls)"
	case "ws":
		return "WebSocket transport lands in M1 (framing over HTTP upgrade)"
	case "dns", "doh", "udp":
		return "DNS/UDP/DoH transports land in M3"
	}
	return "unknown transport"
}

func m1Hint(format, platform string) string {
	switch format {
	case "exe", "dll", "service":
		return "M1 adds `cargo build --release --target x86_64-pc-windows-msvc|gnu` + strip"
	case "elf":
		return "M1 adds `cargo build --release --target x86_64-unknown-linux-musl` (static)"
	case "macho":
		return "M1 adds the darwin targets + `lipo -create` for universal"
	case "apk":
		return "M3 adds the Android Gradle/NDK build"
	}
	return "see NEXT.md"
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func fatalf(code int, format string, a ...any) {
	fmt.Fprintf(os.Stderr, "c2builder: "+format+"\n", a...)
	os.Exit(code)
}
