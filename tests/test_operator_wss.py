"""Operator native TLS/WSS + NOTICE demultiplex regression (intent #4851).

Covers, without touching the frozen BDC2 v1 frame layout:
  * operator -> wss:// endpoint with a CA file (native TLS, no local bridge)
  * SNI/Host override while dialing 127.0.0.1
  * leaf certificate SHA-256 pinning (good pin passes, bad pin fails)
  * NOTICE(type=12, sub=tunnel) demultiplexing: data/close/reason notices must
    not be treated as OP_RESULT and must not pollute task output
  * plaintext ws:// back-compat
  * a real Go server TLS listener (server config tls.cert/key)

Usage: python test_operator_wss.py
Writes verify/operator_wss_results.json and prints PASS/FAIL lines.
"""
import base64
import datetime
import hashlib
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
VERIFY = os.path.join(os.path.dirname(ROOT), "verify")
sys.path.insert(0, HERE)

import bdc2  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

OPERATOR = os.path.join(VERIFY, "operator.exe")
SERVER = os.path.join(VERIFY, "server.exe")
PSK = bytes(range(32))
PSK_ARG = "base64:" + base64.b64encode(PSK).decode()
USER = "ops"
TID = 4242
TUNNEL_PAYLOAD = b"PENG-I4851"

RESULTS = []
FAILS = []


def check(name, fn):
    t0 = time.time()
    try:
        detail = fn()
        RESULTS.append({"name": name, "ok": True, "detail": detail,
                        "sec": round(time.time() - t0, 3)})
        print(f"PASS  {name}  ({time.time()-t0:.2f}s) {detail or ''}")
    except Exception as e:  # noqa: BLE001
        FAILS.append({"name": name, "error": f"{e.__class__.__name__}: {e}",
                      "trace": traceback.format_exc()})
        RESULTS.append({"name": name, "ok": False, "error": str(e),
                        "sec": round(time.time() - t0, 3)})
        print(f"FAIL  {name}: {e}")


# --------------------------------------------------------------------------
# self-signed certificate (SAN covers the test SNI and loopback)
# --------------------------------------------------------------------------
def make_cert(cert_path, key_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "c2-operator.example.com"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("c2-operator.example.com"),
            x509.DNSName("localhost"),
            x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1")),
        ]), critical=False)
        .sign(key, hashes.SHA256())
    )
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


# --------------------------------------------------------------------------
# minimal RFC6455 server side
# --------------------------------------------------------------------------
class WSServerConn:
    def __init__(self, sock):
        self.s = sock
        self.buf = b""

    def _read_exact(self, n):
        while len(self.buf) < n:
            chunk = self.s.recv(65536)
            if not chunk:
                raise ConnectionError("eof")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def handshake(self):
        data = b""
        while b"\r\n\r\n" not in data:
            data += self.s.recv(4096)
        head, rest = data.split(b"\r\n\r\n", 1)
        self.buf = rest + self.buf
        lines = head.split(b"\r\n")
        self.request_line = lines[0].decode()
        self.headers = {}
        for line in lines[1:]:
            k, _, v = line.partition(b":")
            self.headers[k.decode().strip().lower()] = v.decode().strip()
        key = self.headers["sec-websocket-key"]
        accept = base64.b64encode(hashlib.sha1(
            (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        self.s.sendall(("HTTP/1.1 101 Switching Protocols\r\n"
                        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                        f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode())

    def send(self, payload, op=0x2):
        n = len(payload)
        hdr = bytearray([0x80 | op])
        if n < 126:
            hdr.append(n)
        elif n <= 0xFFFF:
            hdr.append(126)
            hdr += struct.pack(">H", n)
        else:
            hdr.append(127)
            hdr += struct.pack(">Q", n)
        self.s.sendall(bytes(hdr) + payload)

    def recv(self):
        h = self._read_exact(2)
        op = h[0] & 0xF
        masked = h[1] & 0x80
        n = h[1] & 0x7F
        if n == 126:
            n = struct.unpack(">H", self._read_exact(2))[0]
        elif n == 127:
            n = struct.unpack(">Q", self._read_exact(8))[0]
        mask = self._read_exact(4) if masked else None
        payload = self._read_exact(n) if n else b""
        if mask:
            payload = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
        if op == 0x8:
            raise ConnectionError("close")
        if op == 0x9:
            self.send(payload, 0xA)
            return self.recv()
        if op == 0xA:
            return self.recv()
        return payload


class MockOperatorServer:
    """TLS WSS endpoint that speaks the operator half of BDC2 v1."""

    def __init__(self, cert_path, key_path, tls=True, extra_notices=True):
        self.cert, self.key = cert_path, key_path
        self.tls_enabled = tls
        self.extra_notices = extra_notices
        self.stats = {"connections": 0, "auth_ok": 0, "op_list": 0, "op_task": 0,
                      "notices_sent": 0, "sni": None, "host": None, "path": None,
                      "send_seq": 0}
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(4)
        self.port = self.srv.getsockname()[1]
        self.ctx = None
        if tls:
            self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ctx.load_cert_chain(cert_path, key_path)

            def _sni_cb(_sock, server_name, _ctx):
                self.stats["sni"] = server_name
                return None

            self.ctx.set_servername_callback(_sni_cb)
        self.stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            while not self.stop:
                try:
                    raw, _ = self.srv.accept()
                except OSError:
                    return
                try:
                    if self.ctx:
                        raw = self.ctx.wrap_socket(raw, server_side=True)
                    self._session(raw)
                except Exception:  # noqa: BLE001
                    pass
                finally:
                    try:
                        raw.close()
                    except OSError:
                        pass
        finally:
            self.srv.close()

    def _session(self, raw):
        ws = WSServerConn(raw)
        ws.handshake()
        self.stats["connections"] += 1
        self.stats["host"] = ws.headers.get("host")
        self.stats["path"] = ws.request_line.split(" ")[1]
        if self.ctx:
            try:
                self.stats["tls_version"] = raw.version()
            except Exception:  # noqa: BLE001
                pass
        # AUTH (cleartext HELLO-like frame, direction O2S)
        frame = ws.recv()
        typ, _, _, _, payload = bdc2.open_frame(None, frame, bdc2.D_O2S)
        assert typ == bdc2.T_AUTH, f"expected AUTH, got {typ}"
        kv = bdc2.untlv(payload)
        user = kv["user"].decode()
        assert user == USER, user
        assert kv["mac"] == bdc2.op_mac(PSK, USER, kv["nonce"])
        key = bdc2.operator_key(PSK, USER)
        self.stats["auth_ok"] += 1
        self._send(ws, key, bdc2.T_AUTH_OK, [("heartbeat", "15")])

        while True:
            frame = ws.recv()
            typ, _, _, _, payload = bdc2.open_frame(key, frame, bdc2.D_O2S)
            kv = bdc2.untlv(payload)
            if typ == bdc2.T_OP_LIST:
                self.stats["op_list"] += 1
                if self.extra_notices:
                    # async tunnel data + close + a plain operator notice, all
                    # before the RPC result: the operator must demultiplex.
                    data = struct.pack(">I", TID) + TUNNEL_PAYLOAD
                    self._send(ws, key, bdc2.T_NOTICE,
                               [("sub", "tunnel"), ("ftype", "65"), ("data", data)],
                               notice=True)
                    self._send(ws, key, bdc2.T_NOTICE,
                               [("sub", "tunnel"), ("ftype", "66"),
                                ("data", struct.pack(">I", TID))], notice=True)
                    self._send(ws, key, bdc2.T_NOTICE,
                               [("reason", "unit-test notice")], notice=True)
                self._send(ws, key, bdc2.T_OP_LIST_RESULT,
                           [("sessions", "[]"), ("stats", "{}")])
            elif typ == bdc2.T_OP_TASK:
                self.stats["op_task"] += 1
                task = kv.get("task", kv.get("args", b""))
                self._send(ws, key, bdc2.T_OP_RESULT,
                           [("status", "ok"), ("out", b"echo:" + task)])
            elif typ == bdc2.T_OP_KILL:
                self._send(ws, key, bdc2.T_OP_RESULT, [("status", "ok")])
            else:
                self._send(ws, key, bdc2.T_ERROR, [("msg", "unknown op type")])

    def _send(self, ws, key, typ, pairs, notice=False):
        self.stats["send_seq"] += 1
        if notice:
            self.stats["notices_sent"] += 1
        ws.send(bdc2.seal(key, typ, 0, 0, self.stats["send_seq"], bdc2.D_S2O,
                          bdc2.tlv(pairs)))

    def close(self):
        self.stop = True
        try:
            self.srv.close()
        except OSError:
            pass


# --------------------------------------------------------------------------
# operator invocation
# --------------------------------------------------------------------------
def run_operator(extra_args, timeout=30):
    cmd = [OPERATOR] + extra_args
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def base_flags(addr, user=USER):
    return ["-addr", addr, "-user", user, "-psk", PSK_ARG, "-timeout", "10s"]


# --------------------------------------------------------------------------
# tests
# --------------------------------------------------------------------------
def test_mock_wss_demux(ctx):
    srv = MockOperatorServer(ctx["cert"], ctx["key"])
    try:
        rc, out, err = run_operator(base_flags(f"wss://127.0.0.1:{srv.port}/ws") + [
            "-sni", "c2-operator.example.com", "-tls-ca", ctx["cert"],
            "-tunnel-out", ctx["tunnel_dir"], "list"])
        assert rc == 0, f"rc={rc} err={err}"
        assert "TUNNEL ftype=data tid=4242" in out, out
        want_b64 = base64.b64encode(TUNNEL_PAYLOAD).decode()
        assert f"data_b64={want_b64}" in out, out
        assert "TUNNEL ftype=close tid=4242" in out, out
        assert "NOTICE reason=unit-test notice" in err, err
        # the RPC result must still be valid JSON after the interleaved notices
        assert out.rstrip().endswith("[]"), out
        assert srv.stats["auth_ok"] == 1 and srv.stats["op_list"] == 1, srv.stats
        assert srv.stats["host"].startswith("c2-operator.example.com"), srv.stats["host"]
        assert srv.stats["path"] == "/ws", srv.stats["path"]
        # tls1.3/1.2 negotiated and SNI sent
        assert srv.stats.get("tls_version") in ("TLSv1.2", "TLSv1.3"), srv.stats
        assert srv.stats.get("sni") == "c2-operator.example.com", srv.stats.get("sni")
        blob = open(os.path.join(ctx["tunnel_dir"], f"tunnel-{TID}.bin"), "rb").read()
        assert blob == TUNNEL_PAYLOAD, blob
        return {"tls": srv.stats.get("tls_version"), "host": srv.stats["host"],
                "tunnel_bytes": len(blob)}
    finally:
        srv.close()


def test_mock_wss_pin(ctx):
    srv = MockOperatorServer(ctx["cert"], ctx["key"], extra_notices=False)
    try:
        good = ["-sni", "c2-operator.example.com", "-tls-ca", ctx["cert"],
                "-tls-pin", ctx["pin"]]
        rc, out, err = run_operator(base_flags(f"wss://127.0.0.1:{srv.port}/ws") + good + ["list"])
        assert rc == 0, f"good pin rc={rc} err={err}"

        bad = ["-sni", "c2-operator.example.com", "-tls-ca", ctx["cert"],
               "-tls-pin", "00" * 32]
        rc2, out2, err2 = run_operator(base_flags(f"wss://127.0.0.1:{srv.port}/ws") + bad + ["list"])
        assert rc2 != 0, "bad pin must fail"
        assert "pin mismatch" in err2, err2

        # pin without CA still verifies the chain against system roots first,
        # so use -insecure for a pin-only mode (documented test path)
        rc3, out3, err3 = run_operator(base_flags(f"wss://127.0.0.1:{srv.port}/ws") +
                                       ["-sni", "c2-operator.example.com", "-insecure",
                                        "-tls-pin", ctx["pin"], "list"])
        assert rc3 == 0, f"pin+insecure rc={rc3} err={err3}"
        return {"good_rc": rc, "bad_rc": rc2, "pin_insecure_rc": rc3}
    finally:
        srv.close()


def test_plaintext_backcompat(ctx):
    srv = MockOperatorServer(ctx["cert"], ctx["key"], tls=False, extra_notices=False)
    try:
        rc, out, err = run_operator(base_flags(f"127.0.0.1:{srv.port}") + ["list"])
        assert rc == 0, f"rc={rc} err={err}"
        assert "CONNECT ws://" in err and "tls=plain" in err, err
        assert srv.stats["op_list"] == 1, srv.stats
        return {"rc": rc}
    finally:
        srv.close()


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _start_real_server(ctx, tls):
    op_port = _free_port()
    cl_port = _free_port()
    cfg = {
        "client_listen": f"127.0.0.1:{cl_port}",
        "operator_listen": f"127.0.0.1:{op_port}",
        "client_psk": PSK_ARG,
        "operators": [{"name": USER, "psk": PSK_ARG}],
        "heartbeat_sec": 15,
        "session_timeout_sec": 90,
        "files_dir": os.path.join(ctx["tmp"], f"files-{op_port}"),
        "audit_log": os.path.join(ctx["tmp"], f"audit-{op_port}.log"),
        "allow_shell": True,
        "allow_advanced": True,
        "tls": {"cert": ctx["cert"], "key": ctx["key"]} if tls else {"cert": "", "key": ""},
    }
    cfg_path = os.path.join(ctx["tmp"], f"server-{op_port}.json")
    with open(cfg_path, "w") as f:
        json.dump(cfg, f)
    log = open(os.path.join(ctx["tmp"], f"server-{op_port}.log"), "w")
    p = subprocess.Popen([SERVER, "-config", cfg_path], stdout=log, stderr=log)
    for _ in range(100):
        try:
            with socket.create_connection(("127.0.0.1", op_port), timeout=0.2):
                return p, op_port, log
        except OSError:
            time.sleep(0.05)
    p.kill()
    raise RuntimeError("server did not start")


def test_real_server_native_tls(ctx):
    p, port, log = _start_real_server(ctx, tls=True)
    try:
        rc, out, err = run_operator(base_flags(f"wss://127.0.0.1:{port}/ws") +
                                    ["-tls-ca", ctx["cert"], "list"])
        assert rc == 0, f"rc={rc} err={err}"
        assert "CONNECT wss://127.0.0.1:%d/ws" % port in err, err
        assert "TLSv1." in err, err
        assert out.strip() == "[]", out
        return {"rc": rc, "out": out.strip()}
    finally:
        p.terminate()
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()
        log.close()


def test_real_server_plaintext(ctx):
    p, port, log = _start_real_server(ctx, tls=False)
    try:
        rc, out, err = run_operator(base_flags(f"ws://127.0.0.1:{port}/ws") + ["list"])
        assert rc == 0, f"rc={rc} err={err}"
        assert out.strip() == "[]", out
        return {"rc": rc}
    finally:
        p.terminate()
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()
        log.close()


def main():
    if not os.path.exists(OPERATOR):
        print(f"missing {OPERATOR}")
        return 2
    if not os.path.exists(SERVER):
        print(f"missing {SERVER}")
        return 2
    tmp = tempfile.mkdtemp(prefix="i4851_")
    cert = os.path.join(tmp, "cert.pem")
    key = os.path.join(tmp, "key.pem")
    pin = make_cert(cert, key)
    ctx = {"cert": cert, "key": key, "pin": pin, "tmp": tmp,
           "tunnel_dir": os.path.join(tmp, "tunnel")}
    print(f"cert={cert} pin={pin}")

    check("mock wss native TLS + NOTICE(sub=tunnel) demux", lambda: test_mock_wss_demux(ctx))
    check("mock wss certificate pinning", lambda: test_mock_wss_pin(ctx))
    check("plaintext ws:// back-compat", lambda: test_plaintext_backcompat(ctx))
    check("real Go server native TLS (wss, CA file)", lambda: test_real_server_native_tls(ctx))
    check("real Go server plaintext ws", lambda: test_real_server_plaintext(ctx))

    res = {"results": RESULTS, "fails": FAILS, "cert_pin": pin,
           "summary": f"{len(RESULTS)-len(FAILS)}/{len(RESULTS)} passed"}
    os.makedirs(VERIFY, exist_ok=True)
    with open(os.path.join(VERIFY, "operator_wss_results.json"), "w") as f:
        json.dump(res, f, indent=2)
    print("\nSUMMARY:", res["summary"])
    return 0 if not FAILS else 1


if __name__ == "__main__":
    sys.exit(main())
