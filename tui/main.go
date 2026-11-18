// Command c2tui is a human-friendly BDC2 v1 operator console.
//
// It reuses the frozen operator protocol (native TLS/WSS, HKDF-derived
// AES-128-GCM channel, OP_* frames) and adds only a terminal UI on top. Every address
// and credential is configuration-driven: nothing is compiled in.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"backd/c2/mvp/tui/internal/config"
	"backd/c2/mvp/tui/internal/repl"
	"backd/c2/mvp/tui/internal/tui"
)

var version = "dev"

func main() {
	fs := flag.NewFlagSet("c2tui", flag.ExitOnError)
	var (
		cfgPath     = fs.String("config", "", "config file (default: per-user config dir/backd-c2tui/config.json)")
		endpoint    = fs.String("endpoint", "", "operator endpoint, e.g. wss://<host>/ws")
		user        = fs.String("user", "", "operator user")
		psk         = fs.String("psk", "", "operator PSK (base64:… / hex:… / raw base64)")
		sni         = fs.String("sni", "", "optional TLS SNI override")
		dialIP      = fs.String("dial-ip", "", "optional dial address override (host:port)")
		family      = fs.String("family", "", "address family: auto|4|6")
		tlsca       = fs.String("tls-ca", "", "optional PEM CA file")
		tlspin      = fs.String("tls-pin", "", "optional SPKI sha256 pin")
		insecure    = fs.Bool("insecure", false, "allow insecure TLS (test only)")
		download    = fs.String("download-dir", "", "download directory")
		tunnelOut   = fs.String("tunnel-out", "", "directory for async tunnel payloads")
		timeoutS    = fs.Int("timeout", 0, "per-request timeout seconds")
		refreshS    = fs.Int("refresh", 0, "session refresh seconds")
		noTUI       = fs.Bool("no-tui", false, "force the plain line-mode fallback")
		autoConnect = fs.Bool("auto-connect", false, "connect immediately using the saved config")
		showVer     = fs.Bool("version", false, "print version and exit")
	)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "c2tui %s — BDC2 v1 operator console\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage: %s [flags]\n\nFlags:\n", os.Args[0])
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nEnvironment: C2_OPERATOR_ADDR, C2_OPERATOR_USER, C2_OPERATOR_PSK,\n"+
			"C2_OPERATOR_SNI, C2_OPERATOR_DIAL_IP, C2_OPERATOR_FAMILY, C2_OPERATOR_TLS_CA,\n"+
			"C2_OPERATOR_TLS_PIN, C2_OPERATOR_INSECURE=1, C2TUI_CONFIG, C2TUI_NO_TUI=1\n")
	}
	_ = fs.Parse(os.Args[1:])

	if *showVer {
		fmt.Printf("c2tui %s\n", version)
		return
	}

	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	path := *cfgPath
	if path == "" {
		path = os.Getenv("C2TUI_CONFIG")
	}
	cfg, path, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(2)
	}
	// Explicit flags win over file and environment.
	if set["endpoint"] {
		cfg.Endpoint = *endpoint
	}
	if set["user"] {
		cfg.User = *user
	}
	if set["psk"] {
		cfg.PSK = *psk
	}
	if set["sni"] {
		cfg.SNI = *sni
	}
	if set["dial-ip"] {
		cfg.DialIP = *dialIP
	}
	if set["family"] {
		cfg.Family = *family
	}
	if set["tls-ca"] {
		cfg.TLSCA = *tlsca
	}
	if set["tls-pin"] {
		cfg.TLSPin = *tlspin
	}
	if set["insecure"] {
		cfg.Insecure = *insecure
	}
	if set["download-dir"] {
		cfg.Download = *download
	}
	if set["tunnel-out"] {
		cfg.TunnelOut = *tunnelOut
	}
	if set["timeout"] {
		cfg.TimeoutS = *timeoutS
	}
	if set["refresh"] {
		cfg.RefreshS = *refreshS
	}
	if cfg.TimeoutS <= 0 {
		cfg.TimeoutS = 45
	}
	if cfg.RefreshS < 2 {
		cfg.RefreshS = 4
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	tty := isTTY() && os.Getenv("C2TUI_NO_TUI") != "1" && !*noTUI
	if !tty {
		if err := repl.Run(ctx, cfg, path); err != nil {
			fmt.Fprintf(os.Stderr, "c2tui: %v\n", err)
			os.Exit(1)
		}
		return
	}

	app := tui.New(cfg, path, *autoConnect)
	if err := app.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "c2tui: %v\n", err)
		os.Exit(1)
	}
}

// isTTY reports whether stdin/stdout are terminals. Under Windows Terminal or
// a real console they are character devices; under a pipe/redirect they are
// not and the line-mode fallback is used.
func isTTY() bool {
	for _, f := range []*os.File{os.Stdin, os.Stdout} {
		fi, err := f.Stat()
		if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
			return false
		}
	}
	return true
}
