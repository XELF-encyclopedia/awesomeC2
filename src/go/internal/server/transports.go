package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"c2v2/internal/protocol"
)

// Start opens every configured listener plus the operator listener.
func (s *Server) Start() error {
	cert, fp, err := LoadOrGenerateCert(s.cfg.CertFile, s.cfg.KeyFile, s.cfg.CertNames)
	if err != nil {
		return fmt.Errorf("tls: %w", err)
	}
	s.cert = cert
	s.certFP = fp
	for _, l := range s.cfg.Listeners {
		if err := s.startClientListener(l); err != nil {
			return fmt.Errorf("listener %s/%s: %w", l.Transport, l.Addr, err)
		}
	}
	if s.cfg.OperatorListener.Addr != "" || s.cfg.OperatorListener.Transport != "" {
		if err := s.startOperatorListener(s.cfg.OperatorListener); err != nil {
			return fmt.Errorf("operator listener: %w", err)
		}
	}
	s.audit("system", "server.start", "", fmt.Sprintf("cert_fp=%s listeners=%d", s.certFP, len(s.cfg.Listeners)))
	go s.gcLoop()
	return nil
}

// ListenAddrs reports bound addresses (useful for tests with port 0).
func (s *Server) ListenAddrs() []string {
	var out []string
	for _, c := range s.closers {
		if l, ok := c.(interface{ Addr() net.Addr }); ok {
			out = append(out, l.Addr().String())
		}
	}
	return out
}

func (s *Server) addCloser(c io.Closer) { s.closers = append(s.closers, c) }

// BoundAddrs reports the actual listener addresses by transport name.
func (s *Server) BoundAddrs() map[string]string {
	out := map[string]string{}
	for k, v := range s.bound {
		out[k] = v
	}
	return out
}

func (s *Server) noteBound(transport string, addr net.Addr) {
	if addr == nil {
		return
	}
	s.bound[transport] = addr.String()
}

func (s *Server) startClientListener(l ListenerConfig) error {
	switch strings.ToLower(l.Transport) {
	case "tls":
		ln, err := net.Listen("tcp", l.Addr)
		if err != nil {
			return err
		}
		s.noteBound("tls", ln.Addr())
		tln := tls.NewListener(ln, TLSConfig(s.cert))
		s.addCloser(tln)
		go s.acceptLoop(tln, "tls")
	case "tcp":
		ln, err := net.Listen("tcp", l.Addr)
		if err != nil {
			return err
		}
		s.noteBound("tcp", ln.Addr())
		s.addCloser(ln)
		go s.acceptLoop(ln, "tcp")
	case "ws", "wss":
		return s.startHTTPTransport(l, false)
	case "udp":
		pc, err := net.ListenPacket("udp", l.Addr)
		if err != nil {
			return err
		}
		s.noteBound("udp", pc.LocalAddr())
		s.addCloser(pc)
		go s.udpLoop(pc, "udp")
	case "dns":
		pc, err := net.ListenPacket("udp", l.Addr)
		if err != nil {
			return err
		}
		s.noteBound("dns", pc.LocalAddr())
		s.addCloser(pc)
		go s.dnsLoop(pc, l.Suffix)
	case "doh":
		return s.startHTTPTransport(l, true)
	default:
		return fmt.Errorf("unknown transport %q", l.Transport)
	}
	return nil
}

func (s *Server) acceptLoop(ln net.Listener, transport string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-s.stop:
				return
			default:
			}
			s.logger.Printf("accept %s: %v", transport, err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go s.ServeStream(c, transport)
	}
}

func (s *Server) startHTTPTransport(l ListenerConfig, forceTLS bool) error {
	mux := http.NewServeMux()
	path := l.Path
	if path == "" {
		path = "/ws"
	}
	isTLS := forceTLS || strings.EqualFold(l.Transport, "wss")
	srv := &http.Server{Addr: l.Addr, Handler: mux, ReadHeaderTimeout: 15 * time.Second}
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if forceTLS || strings.EqualFold(l.Transport, "doh") {
			if r.Method != http.MethodPost {
				http.Error(w, "POST required", http.StatusMethodNotAllowed)
				return
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil {
				http.Error(w, "read", http.StatusBadRequest)
				return
			}
			items, err := s.HandleDatagram(body, "doh")
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(encodeBatch(items))
			return
		}
		if !protocol.IsWebSocketUpgrade(r) {
			http.Error(w, "websocket upgrade required", http.StatusBadRequest)
			return
		}
		ws, err := protocol.UpgradeWebSocket(w, r)
		if err != nil {
			return
		}
		transport := "ws"
		if isTLS {
			transport = "wss"
		}
		s.ServeStream(ws, transport)
	})
	// Health endpoint (no secrets).
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	var ln net.Listener
	var err error
	if isTLS {
		tc := TLSConfig(s.cert)
		ln, err = tls.Listen("tcp", l.Addr, tc)
	} else {
		ln, err = net.Listen("tcp", l.Addr)
	}
	if err != nil {
		return err
	}
	s.noteBound(l.Transport, ln.Addr())
	s.addCloser(ln)
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			select {
			case <-s.stop:
			default:
				s.logger.Printf("http serve %s: %v", l.Addr, err)
			}
		}
	}()
	return nil
}

func (s *Server) udpLoop(pc net.PacketConn, transport string) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-s.stop:
				return
			default:
				continue
			}
		}
		req := append([]byte{}, buf[:n]...)
		go func() {
			items, err := s.HandleDatagram(req, transport)
			if err != nil || len(items) == 0 {
				return
			}
			_, _ = pc.WriteTo(encodeBatch(items), addr)
		}()
	}
}

func (s *Server) dnsLoop(pc net.PacketConn, suffix string) {
	buf := make([]byte, 4096)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-s.stop:
				return
			default:
				continue
			}
		}
		query := append([]byte{}, buf[:n]...)
		go func() {
			name, err := protocol.ParseQueryName(query)
			if err != nil {
				return
			}
			payload, err := protocol.DecodeDNSName(name, suffix)
			if err != nil {
				return
			}
			var resp [][]byte
			resp, err = s.HandleDatagram(payload, "dns")
			if err != nil {
				return
			}
			batch := encodeBatch(resp)
			var chunks [][]byte
			for len(batch) > 0 {
				n := len(batch)
				if n > 255 {
					n = 255
				}
				chunks = append(chunks, batch[:n])
				batch = batch[n:]
			}
			if len(chunks) == 0 {
				chunks = append(chunks, []byte{})
			}
			out, err := protocol.BuildTXTResponse(query, chunks)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(out, addr)
		}()
	}
}

func (s *Server) gcLoop() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			cutoff := time.Now().Add(-time.Duration(s.cfg.Sleep*10) * time.Second).Unix()
			s.mu.Lock()
			for sid, sess := range s.sessions {
				if sess.LastSeen < cutoff {
					delete(s.sessions, sid)
				}
			}
			s.mu.Unlock()
		}
	}
}

// Close stops listeners and the store.
func (s *Server) Close() error {
	var err error
	s.once.Do(func() {
		close(s.stop)
		for _, c := range s.closers {
			if e := c.Close(); e != nil {
				err = e
			}
		}
		s.audit("system", "server.stop", "", "")
		if e := s.st.Close(); e != nil {
			err = e
		}
	})
	return err
}

// StartOperatorOnly is used by tests that only need the operator plane.
func (s *Server) StartOperatorOnly() error {
	cert, fp, err := LoadOrGenerateCert(s.cfg.CertFile, s.cfg.KeyFile, s.cfg.CertNames)
	if err != nil {
		return err
	}
	s.cert, s.certFP = cert, fp
	return s.startOperatorListener(s.cfg.OperatorListener)
}

// startOperatorListener is defined in operator.go.

// WaitHealthy blocks until ctx is done or the server closes.
func (s *Server) WaitHealthy(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.stop:
		return nil
	}
}
