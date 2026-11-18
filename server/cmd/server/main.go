package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"backd/c2/mvp/internal/bdc2"
)

func main() {
	var cfgPath string
	flag.StringVar(&cfgPath, "config", os.Getenv("C2_CONFIG"), "path to config.json (env C2_CONFIG)")
	flag.Parse()

	cfg, err := bdc2.LoadConfig(cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	ck, err := cfg.ClientKeys()
	if err != nil {
		log.Fatalf("client keys: %v", err)
	}
	ok, err := cfg.OperatorKeys()
	if err != nil {
		log.Fatalf("operator keys: %v", err)
	}
	if len(ok) == 0 {
		log.Printf("WARNING: no operators configured; operator endpoint will reject everything")
	}
	audit, err := bdc2.NewAudit(cfg.AuditLog, cfg.HashChain())
	if err != nil {
		log.Fatalf("audit: %v", err)
	}
	defer audit.Close()

	hub, err := bdc2.NewHub(cfg, ck, ok, audit)
	if err != nil {
		log.Fatalf("hub: %v", err)
	}
	hub.SetConfigPath(cfgPath)
	log.Printf("config=%s proto=BDC2 v1 allow_shell=%v allow_advanced=%v audit_chain=%v",
		cfgPath, cfg.AllowShell, cfg.AllowAdvanced, cfg.HashChain())

	clientMux := http.NewServeMux()
	clientMux.HandleFunc("/ws", hub.ServeClient)
	clientMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok\n"))
	})
	opMux := http.NewServeMux()
	opMux.HandleFunc("/ws", hub.ServeOperator)
	opMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok\n"))
	})

	cs := &http.Server{
		Addr:              cfg.ClientListen,
		Handler:           clientMux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	osrv := &http.Server{
		Addr:              cfg.OperatorListen,
		Handler:           opMux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 2)
	go func() {
		log.Printf("client listener on %s (path /ws)", cfg.ClientListen)
		if cfg.TLS.Cert != "" && cfg.TLS.Key != "" {
			errCh <- cs.ListenAndServeTLS(cfg.TLS.Cert, cfg.TLS.Key)
			return
		}
		errCh <- cs.ListenAndServe()
	}()
	go func() {
		log.Printf("operator listener on %s (path /ws)", cfg.OperatorListen)
		if cfg.TLS.Cert != "" && cfg.TLS.Key != "" {
			errCh <- osrv.ListenAndServeTLS(cfg.TLS.Cert, cfg.TLS.Key)
			return
		}
		errCh <- osrv.ListenAndServe()
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	select {
	case s := <-sig:
		log.Printf("interrupt %v, exiting", s)
	case err := <-errCh:
		log.Printf("listener error: %v", err)
	}
	cs.Close()
	osrv.Close()
	hub.CloseAll()
	audit.Log("server", "exit", "", 0)
	_ = time.Now
}
