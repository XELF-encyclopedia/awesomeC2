"""Native C client end-to-end test against the Go server.

Verifies: HELLO/HKDF/AES-GCM interop, sysinfo/echo tasks, push+pull file
transfer with SHA256, and automatic reconnect after a server restart.
"""
import base64
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
VERIFY = os.path.join(os.path.dirname(ROOT), "verify")
sys.path.insert(0, HERE)
import bdc2  # noqa: E402

RESULTS = []


def rec(name, ok, detail=""):
    RESULTS.append({"name": name, "ok": ok, "detail": detail})
    print(("%s  %s  %s" % ("PASS" if ok else "FAIL", name, detail)).rstrip())


def wait_port(port, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def start_server(cfg_path, rundir, logname):
    log = open(os.path.join(VERIFY, logname), "w", encoding="utf-8")
    p = subprocess.Popen([os.path.join(VERIFY, "server.exe"), "-config", cfg_path],
                         cwd=rundir, stdout=log, stderr=subprocess.STDOUT)
    assert wait_port(19909) and wait_port(19910), "server did not open test ports"
    return p, log


def wait_session(ops, cid, timeout=25):
    end = time.time() + timeout
    while time.time() < end:
        try:
            o = bdc2.OperatorConn("127.0.0.1", 19910, "ops", ops).connect()
            got = [s for s in o.list() if s["client_id"] == cid]
            o.close()
            if got:
                return got[0]
        except OSError:
            pass
        time.sleep(0.5)
    return None


def main():
    cfg = json.load(open(os.path.join(VERIFY, "config.test.json")))
    cfg.update({"client_listen": "127.0.0.1:19909", "operator_listen": "127.0.0.1:19910",
                "files_dir": "./files", "audit_log": "./audit.log",
                "heartbeat_sec": 3, "session_timeout_sec": 20})
    rundir = os.path.join(VERIFY, "run_c")
    shutil.rmtree(rundir, ignore_errors=True)
    os.makedirs(rundir, exist_ok=True)
    cfg_path = os.path.join(rundir, "config.json")
    json.dump(cfg, open(cfg_path, "w"), indent=2)
    psk = base64.b64decode(cfg["client_psk"].split(":", 1)[1])
    ops = base64.b64decode(cfg["operators"][0]["psk"].split(":", 1)[1])
    cid = "c-client-01"

    srv, srvlog = start_server(cfg_path, rundir, "server.cclient.log")
    cli = None
    try:
        cli_log = open(os.path.join(VERIFY, "client.log"), "w", encoding="utf-8")
        cli = subprocess.Popen([os.path.join(VERIFY, "backd-client.exe"),
                                "--host", "127.0.0.1", "--port", "19909",
                                "--id", cid, "--psk", psk.hex(), "-v"],
                               cwd=rundir, stdout=cli_log, stderr=subprocess.STDOUT)
        sess = wait_session(ops, cid)
        rec("hello_handshake", sess is not None, str(sess))

        if sess:
            sid = sess["id"]
            o = bdc2.OperatorConn("127.0.0.1", 19910, "ops", ops).connect()
            typ, kv = o.task(sid, "sysinfo")
            out = kv.get("out", b"").decode(errors="replace")
            rec("sysinfo_task", kv.get("status") == b"ok" and cid in out and "os=" in out, out)
            typ, kv = o.task(sid, "echo", b"hello-native")
            rec("echo_task", kv.get("status") == b"ok" and kv.get("out") == b"hello-native",
                repr(kv.get("out")))

            payload = os.urandom(200 * 1024)
            dst = os.path.join(rundir, "pushed_to_native.bin")
            typ, kv = o.push(sid, dst, payload)
            time.sleep(0.8)
            got = open(dst, "rb").read() if os.path.exists(dst) else b""
            rec("push_file_to_native", kv.get("status") == b"ok" and got == payload,
                "server=%s local=%d/%d" % (kv.get("status"), len(got), len(payload)))

            src = os.path.join(rundir, "native_pull_src.bin")
            open(src, "wb").write(payload)
            typ, kv = o.pull(sid, src)
            ok = kv.get("status") == b"ok"
            sha = ""
            if ok:
                outpath = os.path.join(rundir, "native_pull_out.bin")
                n, sha = o.fetch_stream(kv["xfer"].decode(), outpath)
                data = open(outpath, "rb").read()
                ok = data == payload and sha == hashlib.sha256(payload).hexdigest()
            rec("pull_file_from_native", ok, "xfer=%s sha=%s" % (kv.get("xfer", b"").decode(), sha[:16]))
            o.close()

        # reconnect: stop server, start it again, native client must come back
        srv.terminate()
        try:
            srv.wait(5)
        except subprocess.TimeoutExpired:
            srv.kill()
        time.sleep(2)
        srv, srvlog = start_server(cfg_path, rundir, "server.cclient2.log")
        sess2 = wait_session(ops, cid, timeout=40)
        rec("auto_reconnect", sess2 is not None, str(sess2))
        if sess2:
            o = bdc2.OperatorConn("127.0.0.1", 19910, "ops", ops).connect()
            typ, kv = o.task(sess2["id"], "echo", b"after-reconnect")
            rec("task_after_reconnect", kv.get("status") == b"ok" and kv.get("out") == b"after-reconnect",
                repr(kv.get("out")))
            o.close()
    finally:
        if cli:
            cli.terminate()
            try:
                cli.wait(5)
            except subprocess.TimeoutExpired:
                cli.kill()
        srv.terminate()
        try:
            srv.wait(5)
        except subprocess.TimeoutExpired:
            srv.kill()
        srvlog.close()

    out = {"passed": sum(1 for r in RESULTS if r["ok"]),
           "failed": sum(1 for r in RESULTS if not r["ok"]), "results": RESULTS}
    json.dump(out, open(os.path.join(VERIFY, "c_client_results.json"), "w"), indent=2)
    print("=== %d passed, %d failed ===" % (out["passed"], out["failed"]))
    return 0 if out["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
