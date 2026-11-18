package protocol

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// WSConn is a minimal RFC6455 connection. Read/Write expose it as a byte
// stream where every Write becomes one binary message.
type WSConn struct {
	conn     net.Conn
	br       *bufio.Reader
	readBuf  []byte
	wmu      sync.Mutex
	isClient bool
	closed   bool
}

// IsWebSocketUpgrade reports whether the request is a websocket upgrade.
func IsWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// UpgradeWebSocket performs the server handshake and takes over the conn.
func UpgradeWebSocket(w http.ResponseWriter, r *http.Request) (*WSConn, error) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, errors.New("missing Sec-WebSocket-Key")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("response writer cannot hijack")
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	h := sha1.New()
	h.Write([]byte(key))
	h.Write([]byte(wsGUID))
	accept := base64.StdEncoding.EncodeToString(h.Sum(nil))
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := rw.WriteString(resp); err != nil {
		conn.Close()
		return nil, err
	}
	if err := rw.Flush(); err != nil {
		conn.Close()
		return nil, err
	}
	return &WSConn{conn: conn, br: rw.Reader, isClient: false}, nil
}

// DialWebSocket performs the client handshake over an established conn.
func DialWebSocket(conn net.Conn, host, path string) (*WSConn, error) {
	if path == "" {
		path = "/ws"
	}
	raw := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(raw)
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if !strings.Contains(line, "101") {
		return nil, fmt.Errorf("websocket upgrade failed: %s", strings.TrimSpace(line))
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if l == "\r\n" || l == "\n" {
			break
		}
	}
	return &WSConn{conn: conn, br: br, isClient: true}, nil
}

func (w *WSConn) dead() bool {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	return w.closed
}

// Read returns bytes from the current binary message, reading further
// messages as needed.
func (w *WSConn) Read(p []byte) (int, error) {
	for len(w.readBuf) == 0 {
		msg, err := w.readMessage()
		if err != nil {
			return 0, err
		}
		w.readBuf = msg
	}
	n := copy(p, w.readBuf)
	w.readBuf = w.readBuf[n:]
	return n, nil
}

// Write sends p as a single binary websocket message.
func (w *WSConn) Write(p []byte) (int, error) {
	if err := w.writeFrame(0x2, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Send sends an explicit binary message.
func (w *WSConn) Send(p []byte) error { _, err := w.Write(p); return err }

// Recv reads the next complete binary message.
func (w *WSConn) Recv() ([]byte, error) {
	for len(w.readBuf) > 0 {
		// Preserve any prefetched stream bytes; should not normally happen.
		buf := w.readBuf
		w.readBuf = nil
		return buf, nil
	}
	return w.readMessage()
}

func (w *WSConn) readMessage() ([]byte, error) {
	var out []byte
	for {
		var hdr [2]byte
		if _, err := io.ReadFull(w.br, hdr[:]); err != nil {
			return nil, err
		}
		fin := hdr[0]&0x80 != 0
		opcode := hdr[0] & 0x0f
		masked := hdr[1]&0x80 != 0
		n := uint64(hdr[1] & 0x7f)
		switch n {
		case 126:
			var ext [2]byte
			if _, err := io.ReadFull(w.br, ext[:]); err != nil {
				return nil, err
			}
			n = uint64(binary.BigEndian.Uint16(ext[:]))
		case 127:
			var ext [8]byte
			if _, err := io.ReadFull(w.br, ext[:]); err != nil {
				return nil, err
			}
			n = binary.BigEndian.Uint64(ext[:])
		}
		if n > MaxFrame {
			return nil, fmt.Errorf("websocket message too large: %d", n)
		}
		var mask [4]byte
		if masked {
			if _, err := io.ReadFull(w.br, mask[:]); err != nil {
				return nil, err
			}
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(w.br, payload); err != nil {
			return nil, err
		}
		if masked {
			for i := range payload {
				payload[i] ^= mask[i%4]
			}
		}
		switch opcode {
		case 0x8: // close
			_ = w.writeFrame(0x8, nil)
			return nil, io.EOF
		case 0x9: // ping
			_ = w.writeFrame(0xA, payload)
			continue
		case 0xA: // pong
			continue
		case 0x0, 0x1, 0x2:
			out = append(out, payload...)
			if fin {
				return out, nil
			}
		default:
			continue
		}
	}
}

func (w *WSConn) writeFrame(opcode byte, payload []byte) error {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	if w.closed {
		return io.ErrClosedPipe
	}
	var hdr []byte
	hdr = append(hdr, 0x80|opcode)
	maskBit := byte(0)
	if w.isClient {
		maskBit = 0x80
	}
	switch {
	case len(payload) < 126:
		hdr = append(hdr, maskBit|byte(len(payload)))
	case len(payload) <= 0xFFFF:
		hdr = append(hdr, maskBit|126, byte(len(payload)>>8), byte(len(payload)))
	default:
		hdr = append(hdr, maskBit|127)
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(payload)))
		hdr = append(hdr, l[:]...)
	}
	if w.isClient {
		var mask [4]byte
		if _, err := io.ReadFull(rand.Reader, mask[:]); err != nil {
			return err
		}
		hdr = append(hdr, mask[:]...)
		masked := make([]byte, len(payload))
		for i := range payload {
			masked[i] = payload[i] ^ mask[i%4]
		}
		payload = masked
	}
	buf := append(hdr, payload...)
	_ = w.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	_, err := w.conn.Write(buf)
	return err
}

// Close shuts the connection down.
func (w *WSConn) Close() error {
	w.wmu.Lock()
	already := w.closed
	w.closed = true
	w.wmu.Unlock()
	if already {
		return nil
	}
	_ = w.writeFrame(0x8, nil)
	return w.conn.Close()
}

// NetConn returns the underlying connection.
func (w *WSConn) NetConn() net.Conn { return w.conn }
