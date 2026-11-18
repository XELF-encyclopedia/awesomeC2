"""End-to-end / protocol / concurrency / reconnect test runner for the Backd C2 MVP.

Usage: python run_all.py [--clients 100]
Writes verify/test_results.json and prints a PASS/FAIL table.
"""
import argparse
import base64
import hashlib
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)              # .../i4836/mvp
VERIFY = os.path.join(os.path.dirname(ROOT), "verify")
sys.path.insert(0, HERE)

import bdc2  # noqa: E402

FAILS = []
RESULTS = []


def check(name, fn):
    t0 = time.time()
    try:
        detail = fn()
        RESULTS.append({"name": name, "ok": True, "detail": detail, "sec": round(time.time() - t0, 3)})
        print(f"PASS  {name}  ({time.time()-t0:.2f}s) {detail or ''}")
        return True
    except Exception as e:  # noqa: BLE001
        FAILS.append({"name": name, "error": f"{e.__class__.__name__}: {e}", "trace": traceback.format_exc()})
        RESULTS.append({"name": name, "ok": False, "error": str(e), "sec": round(time.time() - t0, 3)})
        print(f"FAIL  {name}: {e}")
        return False


class Servicer:
    """Background thread servicing server-pushed frames for a synthetic client."""

    def __init__(self, conn):
        self.c = conn
        self.stop_flag = False
        self.err = None
        self.t = threading.Thread(target=self.run, daemon=True)

    def run(self):
        while not self.stop_flag:
            try:
                typ, kv = self.c.recv_frame(timeout=0.5)
                self.c.handle(typ, kv)
            except socket.timeout:
                continue
            except (ConnectionError, OSError, ValueError) as e:
                if not self.stop_flag:
                    self.err = e
                return

    def start(self):
        self.t.start()
        return self

    def stop_svc(self):
        self.stop_flag = True
        self.t.join(2)


def load_cfg():
    p = os.path.join(VERIFY, "config.test.json")
    cfg = json.load(open(p))
    cfg["client_listen"] = "127.0.0.1:19909"
    cfg["operator_listen"] = "127.0.0.1:19910"
    cfg["files_dir"] = "./files"
    cfg["audit_log"] = "./audit.log"
    cfg["heartbeat_sec"] = 3
    cfg["session_timeout_sec"] = 20
    return cfg


def wait_port(host, port, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        try:
            s = socket.create_connection((host, port), timeout=1)
            s.close()
            return True
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"port {host}:{port} not up")


def psk_of(cfg):
    return base64.b64decode(cfg["client_psk"].split(":", 1)[1])


def op_of(cfg):
    return base64.b64decode(cfg["operators"][0]["psk"].split(":", 1)[1])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--clients", type=int, default=100)
    args = ap.parse_args()

    rundir = os.path.join(VERIFY, "run")
    shutil.rmtree(rundir, ignore_errors=True)
    os.makedirs(rundir, exist_ok=True)
    cfg = load_cfg()
    cfg_path = os.path.join(rundir, "config.json")
    json.dump(cfg, open(cfg_path, "w"), indent=2)

    logf = open(os.path.join(VERIFY, "server.test.log"), "w", encoding="utf-8")
    srv = subprocess.Popen([os.path.join(VERIFY, "server.exe"), "-config", cfg_path],
                           cwd=rundir, stdout=logf, stderr=subprocess.STDOUT)
    try:
        wait_port("127.0.0.1", 19909)
        wait_port("127.0.0.1", 19910)
        psk = psk_of(cfg)
        ops = op_of(cfg)

        # ---------------- crypto / protocol unit checks ----------------
        def t_vectors():
            # RFC 5869 test case 1
            ikm = bytes.fromhex("0b" * 22)
            salt = bytes.fromhex("000102030405060708090a0b0c")
            info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
            okm = bdc2.hkdf(ikm, salt, info, 42)
            assert okm.hex().startswith("3cb25f25faacd57a90434f64d0362f2a"), okm.hex()
            # AES-128-GCM NIST vector (96-bit IV, 60-byte PT)
            key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
            iv = bytes.fromhex("cafebabefacedbaddecaf888")
            pt = bytes.fromhex(
                "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
            aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            ct = AESGCM(key).encrypt(iv, pt, aad)
            assert ct.hex() == ("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
                                "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
                                "5bc94fbc3221a5db94fae95ae7121a47"), ct.hex()
            return "HKDF=RFC5869-TC1, AES-GCM=NIST-vector OK"

        def t_tlv():
            pairs = [("id", b"abc"), ("n", b"\x00\x01\x02"), ("e", b"")]
            assert bdc2.untlv(bdc2.tlv(pairs)) == {"id": b"abc", "n": b"\x00\x01\x02", "e": b""}
            return "roundtrip 3 pairs"

        def t_bad_mac():
            try:
                c = bdc2.ClientConn("127.0.0.1", 19909, "bad-mac", b"\x00" * 32)
                c.connect()
            except (ConnectionError, OSError):
                return "server rejected wrong PSK"
            c.close()
            raise AssertionError("server accepted wrong PSK")

        def t_echo():
            c = bdc2.ClientConn("127.0.0.1", 19909, "echo-01", psk).connect()
            sv = Servicer(c).start()
            try:
                o = bdc2.OperatorConn("127.0.0.1", 19910, "ops", ops).connect()
                sessions = [s for s in o.list() if s["client_id"] == "echo-01"]
                assert len(sessions) == 1, sessions
                sid = sessions[0]["id"]
                typ, kv = o.task(sid, "echo", b"hello-backd")
                assert kv["status"] == b"ok", kv
                assert kv["out"] == b"hello-backd", kv
                o.close()
                return f"task roundtrip sid={sid}"
            finally:
                sv.stop_svc()
                c.close()

        def t_ping():
            c = bdc2.ClientConn("127.0.0.1", 19909, "ping-01", psk).connect()
            try:
                for i in range(3):
                    ok, echoed = c.ping()
                    assert ok and echoed is not None, (ok, echoed)
                return "3x PING/PONG"
            finally:
                c.close()

        def t_replay():
            c = bdc2.ClientConn("127.0.0.1", 19909, "replay-01", psk).connect()
            try:
                c.send_seq += 1
                frame = bdc2.seal(c.key, bdc2.T_PING, 0, c.sid, c.send_seq, bdc2.D_C2S,
                                  bdc2.tlv([("t", b"1")]))
                c.ws.send(2, frame)
                c.ws.send(2, frame)
                c.recv_frame(timeout=5)
                closed = False
                try:
                    c.recv_frame(timeout=5)
                except (ConnectionError, OSError):
                    closed = True
                assert closed, "server accepted replayed frame"
                return "replayed seq -> connection closed"
            finally:
                c.close()

        # ---------------- concurrency ----------------
        def t_concurrency():
            n = args.clients
            conns = []
            errs = []
            lock = threading.Lock()

            def worker(i):
                try:
                    cl = bdc2.ClientConn("127.0.0.1", 19909, f"conc-{i:03d}", psk).connect()
                    for _ in range(2):
                        ok, _ = cl.ping()
                        assert ok
                    with lock:
                        conns.append(cl)
                except Exception as e:  # noqa: BLE001
                    with lock:
                        errs.append(f"{i}: {e}")

            ts = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
            t0 = time.time()
            for t in ts:
                t.start()
            for t in ts:
                t.join(30)
            dt = time.time() - t0
            if errs:
                for c in conns:
                    c.close()
                raise AssertionError(f"{len(errs)}/{n} failed, e.g. {errs[:3]}")
            o = bdc2.OperatorConn("127.0.0.1", 19910, "ops", ops).connect()
            got = {s["client_id"] for s in o.list() if s["client_id"].startswith("conc-")}
            o.close()
            for c in conns:
                c.close()
            assert len(got) >= n - 2, f"only {len(got)}/{n} sessions visible"
            return f"{len(conns)}/{n} concurrent clients, {dt:.2f}s, {n/max(dt,1e-6):.1f} conn/s"

        def t_files():
            src = os.path.join(rundir, "pull_src.bin")
            payload = os.urandom(300 * 1024)
            open(src, "wb").write(payload)
            c = bdc2.ClientConn("127.0.0.1", 19909, "files-01", psk).connect()
            sv = Servicer(c).start()
            try:
                o = bdc2.OperatorConn("127.0.0.1", 19910, "ops", ops).connect()
                sid = [s for s in o.list() if s["client_id"] == "files-01"][0]["id"]
                typ, kv = o.pull(sid, src)
                assert kv["status"] == b"ok", kv
                local = os.path.join(rundir, "fetched.bin")
                n, sha = o.fetch_stream(kv["xfer"].decode(), local)
                data = open(local, "rb").read()
                assert data == payload, "content mismatch"
                assert sha == hashlib.sha256(payload).hexdigest(), "sha mismatch"
                dst = os.path.join(rundir, "pushed_to_client.bin")
                typ, kv2 = o.push(sid, dst, payload)
                assert kv2["status"] == b"ok", kv2
                time.sleep(0.5)
                got = open(dst, "rb").read()
                assert got == payload, "push content mismatch"
                o.close()
                return f"pull {n} bytes sha ok; push ok"
            finally:
                sv.stop_svc()
                c.close()

        def t_reconnect():
            c = bdc2.ClientConn("127.0.0.1", 19909, "recon-01", psk).connect()
            first_sid = c.sid
            c.close()
            time.sleep(1.0)
            c2 = bdc2.ClientConn("127.0.0.1", 19909, "recon-01", psk).connect()
            try:
                ok, _ = c2.ping()
                assert ok
                sv = Servicer(c2).start()
                o = bdc2.OperatorConn("127.0.0.1", 19910, "ops", ops).connect()
                got = [s for s in o.list() if s["client_id"] == "recon-01"]
                o.close()
                assert len(got) == 1, got
                return f"reconnect new sid={got[0]['id']} (old {first_sid})"
            finally:
                sv.stop_svc()
                c2.close()

        def t_bad_tamper():
            c = bdc2.ClientConn("127.0.0.1", 19909, "tamper-01", psk).connect()
            try:
                c.send_seq += 1
                frame = bytearray(bdc2.seal(c.key, bdc2.T_PING, 0, c.sid, c.send_seq, bdc2.D_C2S,
                                            bdc2.tlv([("t", b"1")])))
                frame[-1] ^= 0xFF
                c.ws.send(2, bytes(frame))
                closed = False
                try:
                    c.recv_frame(timeout=5)
                except (ConnectionError, OSError, ValueError):
                    closed = True
                assert closed, "tampered frame was accepted"
                return "tampered ciphertext -> connection dropped"
            finally:
                c.close()

        for name, fn in [
            ("crypto_vectors", t_vectors),
            ("tlv_roundtrip", t_tlv),
            ("hello_bad_psk_rejected", t_bad_mac),
            ("ping_pong", t_ping),
            ("task_echo", t_echo),
            ("replay_protection", t_replay),
            ("tamper_detection", t_bad_tamper),
            ("file_transfer", t_files),
            ("reconnect", t_reconnect),
            ("concurrency", t_concurrency),
        ]:
            check(name, fn)
    finally:
        srv.terminate()
        try:
            srv.wait(5)
        except subprocess.TimeoutExpired:
            srv.kill()
        logf.close()

    out = {"passed": sum(1 for r in RESULTS if r["ok"]), "failed": len(FAILS),
           "results": RESULTS, "failures": FAILS}
    json.dump(out, open(os.path.join(VERIFY, "test_results.json"), "w"), indent=2)
    print(f"\n=== {out['passed']} passed, {out['failed']} failed ===")
    return 0 if not FAILS else 1


if __name__ == "__main__":
    sys.exit(main())
