package bdc2

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// WSConn is a minimal RFC6455 connection (binary messages only).
type WSConn struct {
	c    net.Conn
	br   *bufio.Reader
	mask bool // client side must mask
	wmu  sync.Mutex
	rmu  sync.Mutex
	max  int
}

func newWSConn(c net.Conn, br *bufio.Reader, mask bool, max int) *WSConn {
	if max <= 0 {
		max = MaxFrame
	}
	return &WSConn{c: c, br: br, mask: mask, max: max}
}

func (w *WSConn) SetDeadline(t time.Time) error     { return w.c.SetDeadline(t) }
func (w *WSConn) SetReadDeadline(t time.Time) error { return w.c.SetReadDeadline(t) }
func (w *WSConn) RemoteAddr() net.Addr              { return w.c.RemoteAddr() }
func (w *WSConn) Close() error                      { return w.c.Close() }

// UpgradeServer performs the server side of the WebSocket handshake.
func UpgradeServer(w http.ResponseWriter, r *http.Request, maxFrame int) (*WSConn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return nil, errors.New("not a websocket upgrade")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, errors.New("missing Sec-WebSocket-Key")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("hijack unsupported")
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	h := sha1.New()
	h.Write([]byte(key + wsGUID))
	accept := base64.StdEncoding.EncodeToString(h.Sum(nil))
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := brw.WriteString(resp); err != nil {
		conn.Close()
		return nil, err
	}
	if err := brw.Flush(); err != nil {
		conn.Close()
		return nil, err
	}
	return newWSConn(conn, brw.Reader, false, maxFrame), nil
}

func randRead(b []byte) {
	if _, err := rand.Read(b); err != nil {
		// crypto/rand must not fail; keep going with whatever was filled.
		return
	}
}

func wsAccept(key string) string {
	h := sha1.New()
	h.Write([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// DialWS connects to ws://host:port/path (plaintext). Native TLS/WSS lives in
// DialEndpoint (dial.go).
func DialWS(hostport, path string, timeout time.Duration, maxFrame int) (*WSConn, error) {
	conn, err := net.DialTimeout("tcp", hostport, timeout)
	if err != nil {
		return nil, err
	}
	if maxFrame <= 0 {
		maxFrame = MaxFrame
	}
	ws, err := wsClientHandshake(conn, hostport, path, timeout, maxFrame)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return ws, nil
}

func (w *WSConn) writeFrame(op byte, p []byte) error {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	hdr := make([]byte, 0, 14)
	hdr = append(hdr, 0x80|(op&0x0f))
	var mbit byte
	if w.mask {
		mbit = 0x80
	}
	switch {
	case len(p) < 126:
		hdr = append(hdr, mbit|byte(len(p)))
	case len(p) <= 0xffff:
		hdr = append(hdr, mbit|126, byte(len(p)>>8), byte(len(p)))
	default:
		hdr = append(hdr, mbit|127)
		for i := 7; i >= 0; i-- {
			hdr = append(hdr, byte(uint64(len(p))>>(8*uint(i))))
		}
	}
	body := p
	if w.mask {
		var mk [4]byte
		rand.Read(mk[:])
		hdr = append(hdr, mk[:]...)
		body = make([]byte, len(p))
		for i := range p {
			body[i] = p[i] ^ mk[i&3]
		}
	}
	if _, err := w.c.Write(hdr); err != nil {
		return err
	}
	if len(body) > 0 {
		if _, err := w.c.Write(body); err != nil {
			return err
		}
	}
	return nil
}

func (w *WSConn) WriteBinary(p []byte) error { return w.writeFrame(0x2, p) }

// TLSVersion reports the negotiated TLS version ("TLSv1.3", ...) or "" when the
// connection is plaintext.
func (w *WSConn) TLSVersion() string { return TLSVersionName(w.c) }

func (w *WSConn) writeControl(op byte, p []byte) error { return w.writeFrame(op, p) }

// ReadMessage returns the next data message (opcode 1/2). Control frames are
// handled internally (ping -> pong, close -> error).
func (w *WSConn) ReadMessage() (byte, []byte, error) {
	w.rmu.Lock()
	defer w.rmu.Unlock()
	var data []byte
	var dataOp byte
	for {
		var h [2]byte
		if _, err := io.ReadFull(w.br, h[:]); err != nil {
			return 0, nil, err
		}
		fin := h[0]&0x80 != 0
		op := h[0] & 0x0f
		masked := h[1]&0x80 != 0
		n := int(h[1] & 0x7f)
		switch n {
		case 126:
			var e [2]byte
			if _, err := io.ReadFull(w.br, e[:]); err != nil {
				return 0, nil, err
			}
			n = int(e[0])<<8 | int(e[1])
		case 127:
			var e [8]byte
			if _, err := io.ReadFull(w.br, e[:]); err != nil {
				return 0, nil, err
			}
			var v uint64
			for _, b := range e {
				v = v<<8 | uint64(b)
			}
			if v > uint64(w.max) {
				return 0, nil, ErrBadFrame
			}
			n = int(v)
		}
		if n < 0 || n > w.max {
			return 0, nil, ErrBadFrame
		}
		var mk [4]byte
		if masked {
			if _, err := io.ReadFull(w.br, mk[:]); err != nil {
				return 0, nil, err
			}
		}
		pl := make([]byte, n)
		if n > 0 {
			if _, err := io.ReadFull(w.br, pl); err != nil {
				return 0, nil, err
			}
			if masked {
				for i := range pl {
					pl[i] ^= mk[i&3]
				}
			}
		}
		switch op {
		case 0x8: // close
			return 0, nil, io.EOF
		case 0x9: // ping
			_ = w.writeControl(0xA, pl)
			continue
		case 0xA: // pong
			continue
		case 0x0:
			if dataOp == 0 {
				return 0, nil, ErrBadFrame
			}
			data = append(data, pl...)
		case 0x1, 0x2:
			if data != nil {
				return 0, nil, ErrBadFrame
			}
			dataOp = op
			data = append([]byte{}, pl...)
		default:
			return 0, nil, ErrBadFrame
		}
		if fin && dataOp != 0 {
			return dataOp, data, nil
		}
	}
}
