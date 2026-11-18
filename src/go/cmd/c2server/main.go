// Command c2server runs the C2V2 server.
package main

import (
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"c2v2/internal/server"
)

func main() {
	cfgPath := flag.String("config", "config.json", "path to JSON config")
	initCfg := flag.Bool("init-config", false, "write an example config to -config and exit")
	listen := flag.String("listen", "", "comma list transport=addr overrides, e.g. tls=127.0.0.1:0,wss=127.0.0.1:0")
	opListen := flag.String("op-listen", "", "operator transport=addr, e.g. wss=127.0.0.1:0")
	storage := flag.String("storage", "", "sqlite|postgres|memory override")
	dsn := flag.String("dsn", "", "storage DSN override")
	psk := flag.String("psk", "", "base64 PSK override")
	stateFile := flag.String("state-file", "", "write bound addrs + cert fingerprint as JSON after start")
	flag.Parse()

	lg := log.New(os.Stdout, "[c2server] ", log.LstdFlags|log.LUTC)

	if *initCfg {
		cfg := server.DefaultConfig()
		b, _ := json.MarshalIndent(cfg, "", "  ")
		if err := os.WriteFile(*cfgPath, b, 0600); err != nil {
			lg.Fatalf("write config: %v", err)
		}
		fmt.Println(*cfgPath)
		return
	}

	cfg, err := server.LoadConfig(*cfgPath)
	if err != nil {
		lg.Fatalf("config: %v", err)
	}
	if *storage != "" {
		cfg.Storage = *storage
	}
	if *dsn != "" {
		cfg.DSN = *dsn
	}
	if *psk != "" {
		cfg.PSKB64 = *psk
	}
	if *listen != "" {
		cfg.Listeners = nil
		for _, part := range strings.Split(*listen, ",") {
			kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
			if len(kv) != 2 {
				lg.Fatalf("bad -listen item %q", part)
			}
			l := server.ListenerConfig{Transport: kv[0], Addr: kv[1]}
			if kv[0] == "dns" {
				l.Suffix = "c2.example.com"
			}
			if kv[0] == "doh" {
				l.Path = "/doh"
			}
			if kv[0] == "wss" || kv[0] == "ws" {
				l.Path = "/ws"
			}
			cfg.Listeners = append(cfg.Listeners, l)
		}
	}
	if *opListen != "" {
		kv := strings.SplitN(*opListen, "=", 2)
		if len(kv) != 2 {
			lg.Fatalf("bad -op-listen")
		}
		cfg.OperatorListener = server.ListenerConfig{Transport: kv[0], Addr: kv[1], Path: "/op"}
	}
	if len(cfg.Operators) == 1 && cfg.Operators[0].KeyB64 == "REPLACE_ME" {
		// Generate a lab operator key so the binary is runnable out of the box.
		key := make([]byte, 32)
		if _, err := readRandom(key); err == nil {
			cfg.Operators[0].KeyB64 = base64.StdEncoding.EncodeToString(key)
			lg.Printf("generated lab operator key for %s: %s", cfg.Operators[0].User, cfg.Operators[0].KeyB64)
		}
	}
	if cfg.PSKB64 == "REPLACE_ME" {
		lg.Printf("WARNING: PSK is a placeholder; only TLS transport security protects the handshake")
	}

	srv, err := server.New(cfg, lg)
	if err != nil {
		lg.Fatalf("server: %v", err)
	}
	if err := srv.Start(); err != nil {
		lg.Fatalf("start: %v", err)
	}
	state := map[string]any{
		"bound": srv.BoundAddrs(),
		"stats": srv.Stats(),
		"time":  time.Now().UTC().Format(time.RFC3339),
	}
	b, _ := json.MarshalIndent(state, "", "  ")
	lg.Printf("ready %s", string(b))
	if *stateFile != "" {
		_ = os.WriteFile(*stateFile, b, 0600)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	lg.Printf("shutting down")
	_ = srv.Close()
}

func readRandom(b []byte) (int, error) { return io.ReadFull(crand.Reader, b) }



var buildVersion = "dev"


