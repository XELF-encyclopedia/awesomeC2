"""Merged-capability regression: BDC2 v1 baseline + #4833/#4834/#4835 features.

Covers:
  * operator CLI (stats / reload / push with resume / audit verify)
  * hot config reload (allow_advanced flipped at runtime)
  * advanced task kinds through the native C client (env/ps/persist_status/
    keylog/tunnel)
  * server-side gating of advanced modules and selfdestruct confirmation
  * file push resume using the existing FILE_META/FILE_CHUNK offset fields

Requires verify/server.exe, verify/operator.exe and verify/backd-client.exe.
"""
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
VERIFY = os.path.join(os.path.dirname(ROOT), "verify")
sys.path.insert(0, HERE)
import bdc2  # noqa: E402

RESULTS = []
SERVER = os.path.join(VERIFY, "server.exe")
OPERATOR = os.path.join(VERIFY, "operator.exe")
CLIENT = os.path.join(VERIFY, "backd-client.exe")


def rec(name, ok, detail=""):
    RESULTS.append({"name": name, "ok": ok, "detail": detail})
    print(("%s  %s  %s" % ("PASS" if ok else "FAIL", name, detail)).rstrip())


def wait_port(port, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


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


def op_cli(ops_psk_str, *args, timeout=60):
    p = subprocess.run([OPERATOR, "-addr", "127.0.0.1:19910", "-user", "ops",
                        "-psk", ops_psk_str] + list(args),
                       capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout + p.stderr


def main():
    for b in (SERVER, OPERATOR, CLIENT):
        if not os.path.exists(b):
            print("missing binary:", b)
            return 2
    base = json.load(open(os.path.join(VERIFY, "config.test.json")))
    base.update({"client_listen": "127.0.0.1:19909", "operator_listen": "127.0.0.1:19910",
                 "files_dir": "./files", "audit_log": "./audit.log",
                 "heartbeat_sec": 3, "session_timeout_sec": 20,
                 "allow_shell": False, "allow_advanced": False,
                 "audit_hash_chain": True, "task_max_inflight": 2,
                 "task_max_attempts": 2, "client_msgs_per_sec": 500,
                 "operator_msgs_per_sec": 200})
    rundir = os.path.join(VERIFY, "run_m")
    shutil.rmtree(rundir, ignore_errors=True)
    os.makedirs(rundir, exist_ok=True)
    cfg_path = os.path.join(rundir, "config.json")
    json.dump(base, open(cfg_path, "w"), indent=2)

    ops_psk_str = base["operators"][0]["psk"]
    ops_psk = __import__("base64").b64decode(ops_psk_str.split(":", 1)[1])
    client_psk = base["client_psk"]
    log = open(os.path.join(VERIFY, "server.merged.log"), "w", encoding="utf-8")
    srv = subprocess.Popen([SERVER, "-config", cfg_path], cwd=rundir,
                           stdout=log, stderr=subprocess.STDOUT)
    cli = None
    try:
        assert wait_port(19909) and wait_port(19910), "server ports not up"
        cli_log = open(os.path.join(VERIFY, "client.merged.log"), "w", encoding="utf-8")
        cli = subprocess.Popen([CLIENT, "--host", "127.0.0.1", "--port", "19909",
                                "--id", "m-adv-01", "--psk", client_psk,
                                "--allow-adv", "-v"], stdout=cli_log, stderr=subprocess.STDOUT)
        s = wait_session(ops_psk, "m-adv-01")
        assert s, "native client did not register"
        sid = s["id"]

        # 1) operator stats exposes the merged runtime config.
        rc, out = op_cli(ops_psk_str, "stats")
        rec("operator_stats", rc == 0 and '"proto": "BDC2 v1"' in out
            and '"allow_advanced": false' in out, out.strip().splitlines()[-1][:120])

        # 2) advanced modules must be rejected while disabled.
        o = bdc2.OperatorConn("127.0.0.1", 19910, "ops", ops_psk).connect()
        typ, kv = o.task(sid, "env", b"")
        rec("advanced_gated", kv.get("status") == b"error"
            and b"advanced modules disabled" in kv.get("err", b""), kv.get("err", b"").decode())
        o.close()

        # 3) hot reload flips allow_advanced without restarting listeners.
        base["allow_advanced"] = True
        json.dump(base, open(cfg_path, "w"), indent=2)
        rc, out = op_cli(ops_psk_str, "reload", cfg_path)
        rec("hot_reload", rc == 0 and "STATUS ok" in out and '"reloaded":true' in out,
            out.strip().splitlines()[0][:120])

        o = bdc2.OperatorConn("127.0.0.1", 19910, "ops", ops_psk).connect()
        # 4) merged advanced kinds against the real native client.
        typ, kv = o.task(sid, "env", b"", timeout=20)
        rec("adv_env", kv.get("status") == b"ok" and len(kv.get("out", b"")) > 32,
            "%d bytes" % len(kv.get("out", b"")))

        typ, kv = o.task(sid, "ps", b"", timeout=20)
        rec("adv_ps", kv.get("status") == b"ok" and b"PID" in kv.get("out", b""),
            "%d bytes" % len(kv.get("out", b"")))

        typ, kv = o.task(sid, "persist_status", b"", timeout=20)
        rec("adv_persist_status", kv.get("status") == b"ok" and b"name=" in kv.get("out", b""),
            kv.get("out", b"").decode(errors="replace").splitlines()[0][:80])

        typ, kv = o.task(sid, "keylog_start", b"", timeout=20)
        ok1 = kv.get("status") == b"ok"
        time.sleep(0.3)
        typ, kv = o.task(sid, "keylog_dump", b"", timeout=20)
        ok2 = kv.get("status") == b"ok"
        typ, kv = o.task(sid, "keylog_stop", b"", timeout=20)
        ok3 = kv.get("status") == b"ok"
        rec("adv_keylog", ok1 and ok2 and ok3, "start/dump/stop ok")

        # 5) pull-based TCP tunnel to a local echo service.
        esrv = socket.socket()
        esrv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        esrv.bind(("127.0.0.1", 0))
        esrv.listen(1)
        eport = esrv.getsockname()[1]

        def echo():
            try:
                c, _ = esrv.accept()
                d = c.recv(64)
                c.sendall(d)
                c.close()
            except OSError:
                pass
        threading.Thread(target=echo, daemon=True).start()
        typ, kv = o.task(sid, "tunnel_open", ("127.0.0.1:%d" % eport).encode(), timeout=20)
        tid = kv.get("out", b"").decode(errors="replace").strip().split("=")[-1]
        typ, kv = o.task(sid, "tunnel_send", ("%s hello-tunnel" % tid).encode(), timeout=20)
        time.sleep(0.2)
        typ, kv = o.task(sid, "tunnel_recv", ("%s 64" % tid).encode(), timeout=20)
        got = kv.get("out", b"")
        typ, kv2 = o.task(sid, "tunnel_close", tid.encode(), timeout=20)
        esrv.close()
        rec("adv_tunnel", got == b"hello-tunnel" and kv2.get("status") == b"ok", repr(got))

        # 6) selfdestruct requires explicit confirmation.
        typ, kv = o.task(sid, "selfdestruct", b"", timeout=20)
        rec("selfdestruct_guard", kv.get("status") == b"error"
            and b"confirm=yes" in kv.get("err", b""), kv.get("err", b"").decode())

        # 7) resume: push head, then push tail with an offset.
        remote = os.path.join(rundir, "resume.bin")
        full = os.urandom(300 * 1024)
        head, tail = full[:100 * 1024], full[100 * 1024:]
        headp = os.path.join(rundir, "head.bin")
        tailp = os.path.join(rundir, "tail.bin")
        open(headp, "wb").write(head)
        open(tailp, "wb").write(tail)
        rc1, out1 = op_cli(ops_psk_str, "push", str(sid), headp, remote)
        rc2, out2 = op_cli(ops_psk_str, "push", str(sid), tailp, remote, "102400")
        time.sleep(0.3)
        typ, kv = o.pull(sid, remote)
        fetched = os.path.join(rundir, "fetched.bin")
        n, sha = o.fetch_stream(kv["xfer"].decode(), fetched) if kv.get("status") == b"ok" else (0, "")
        data = open(fetched, "rb").read() if os.path.exists(fetched) else b""
        rec("file_resume", rc1 == 0 and rc2 == 0 and data == full,
            "status1=%s status2=%s size=%d" % (out1.split()[0], out2.split()[0], len(data)))
        o.close()

        # 8) audit hash chain verifies after all of the above.
        rc, out = op_cli(ops_psk_str, "audit", os.path.join(rundir, "audit.log"))
        rec("audit_chain", rc == 0 and "AUDIT OK" in out, out.strip()[:120])

        # 9) tamper detection: flip a byte in a copied log.
        tampered = os.path.join(rundir, "audit_tampered.log")
        lines = open(os.path.join(rundir, "audit.log"), "rb").read().splitlines()
        if lines:
            lines[0] = lines[0].replace(b'"action":"', b'"action":"X', 1)
        open(tampered, "wb").write(b"\n".join(lines) + b"\n")
        rc, out = op_cli(ops_psk_str, "audit", tampered)
        rec("audit_tamper_detected", rc != 0 and "AUDIT FAIL" in out, out.strip()[:120])
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        rec("exception", False, str(e))
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
        log.close()

    passed = sum(1 for r in RESULTS if r["ok"])
    failed = len(RESULTS) - passed
    out = {"passed": passed, "failed": failed, "results": RESULTS}
    json.dump(out, open(os.path.join(VERIFY, "merged_results.json"), "w"), indent=2)
    print("\n=== %d passed, %d failed ===" % (passed, failed))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
