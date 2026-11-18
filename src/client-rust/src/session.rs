use crate::config::Profile;
use crate::crypto::{self, Keys};
use crate::transport::Link;
use crate::wire::{self, Reassembler};
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{json, Value};
use std::io::ErrorKind;
use std::time::Duration;

pub struct SessionInfo {
    pub sid: String,
    pub sleep: u32,
    pub jitter: u32,
    pub tenant: String,
    pub server_time: i64,
}

pub struct Session {
    pub keys: Keys,
    pub link: Link,
    pub sid: String,
    reasm: Reassembler,
    max: usize,
    datagram: bool,
}

pub fn handshake(mut link: Link, prof: &Profile) -> Result<(Session, SessionInfo), String> {
    let secret = crypto::new_secret();
    let pub_c = crypto::public_bytes(&secret);
    let mut nonce_c = vec![0u8; 32];
    OsRng.fill_bytes(&mut nonce_c);
    let ts = wire::now();
    let nonce_b64 = wire::b64(&nonce_c);
    let psk = wire::unb64(&prof.psk_b64).unwrap_or_default();
    let nonce_sig = crypto::hmac_hex(&psk, &[&prof.client_id, &nonce_b64, &ts.to_string()]);
    let machine = crate::platform::machine();
    let hello = json!({
        "v": 2u8,
        "t": "hello",
        "client_id": prof.client_id,
        "nonce": nonce_b64,
        "pub": wire::b64(&pub_c),
        "cipher": "aes256gcm",
        "transport": link.kind(),
        "caps": prof.caps(),
        "ts": ts,
        "machine": machine,
        "nonce_sig": nonce_sig,
    });
    let body = serde_json::to_vec(&hello).map_err(|e| e.to_string())?;
    link.send_env(&crypto::plain_envelope(&body))
        .map_err(|e| format!("send hello: {}", e))?;

    // Read one plain envelope (server errors also arrive plaintext).
    let env = link.recv_env().map_err(|e| format!("recv hello_ack: {}", e))?;
    let body = crypto::parse_plain(&env).map_err(|e| format!("hello_ack: {}", e))?;
    let ack: Value = serde_json::from_slice(body).map_err(|e| format!("hello_ack json: {}", e))?;
    if let Some(err) = ack.get("error").and_then(|v| v.as_str()) {
        if !err.is_empty() {
            return Err(format!("server rejected handshake: {}", err));
        }
    }
    if ack.get("t").and_then(|v| v.as_str()) != Some("hello_ack") {
        return Err(format!(
            "unexpected handshake reply: {}",
            String::from_utf8_lossy(body).chars().take(200).collect::<String>()
        ));
    }
    let nonce_s = wire::unb64(ack.get("nonce").and_then(|v| v.as_str()).unwrap_or(""))?;
    let pub_s = wire::unb64(ack.get("pub").and_then(|v| v.as_str()).unwrap_or(""))?;
    if nonce_s.len() != 32 || pub_s.len() != 32 {
        return Err("hello_ack: bad nonce/public key length".into());
    }
    let cipher = match ack.get("cipher").and_then(|v| v.as_str()).unwrap_or("aes256gcm") {
        "chacha20poly1305" | "chacha20-poly1305" | "chacha" => crypto::CIPHER_CHACHA,
        _ => crypto::CIPHER_AES,
    };
    let shared = crypto::shared_secret(&secret, &pub_s)?;
    let keys = crypto::derive_keys(&shared, &psk, &nonce_c, &nonce_s, cipher);
    let sid = ack.get("sid").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if sid.is_empty() {
        return Err("hello_ack: empty sid".into());
    }
    if sid != keys.sid {
        // Server may disambiguate a SID clash; trust the server value for framing.
    }
    let sleep = ack.get("sleep").and_then(|v| v.as_u64()).unwrap_or(prof.sleep as u64) as u32;
    let jitter = ack.get("jitter").and_then(|v| v.as_u64()).unwrap_or(prof.jitter as u64) as u32;
    let tenant = ack.get("tenant").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let server_time = ack.get("server_time").and_then(|v| v.as_i64()).unwrap_or(0);

    link.set_sid(&sid);
    let datagram = link.is_datagram();
    let max = link.max_datagram();
    let info = SessionInfo { sid: sid.clone(), sleep, jitter, tenant, server_time };
    Ok((
        Session { keys, link, sid, reasm: Reassembler::default(), max, datagram },
        info,
    ))
}

impl Session {
    pub fn send_value(&mut self, v: &Value) -> Result<(), String> {
        let body = serde_json::to_vec(v).map_err(|e| e.to_string())?;
        let parts = if self.datagram {
            wire::fragment_json(&body, self.max)?
        } else {
            wire::fragment_json(&body, wire::MAX_FRAME)?
        };
        for p in parts {
            let env = crypto::seal(&self.keys, crypto::DIR_C2S, &p)?;
            self.link.send_env(&env).map_err(|e| format!("send: {}", e))?;
        }
        Ok(())
    }

    pub fn send_plain(&mut self, v: &Value) -> Result<(), String> {
        let body = serde_json::to_vec(v).map_err(|e| e.to_string())?;
        self.link
            .send_env(&crypto::plain_envelope(&body))
            .map_err(|e| format!("send plain: {}", e))
    }

    /// Returns Ok(None) on read timeout.
    pub fn recv_value(&mut self, timeout: Duration) -> Result<Option<Value>, String> {
        self.link.set_read_timeout(Some(timeout));
        loop {
            match self.link.recv_env() {
                Ok(env) => {
                    let plain = crypto::open(&self.keys, crypto::DIR_S2C, &env)?;
                    let v: Value = serde_json::from_slice(&plain)
                        .map_err(|e| format!("bad server json: {}", e))?;
                    if wire::message_type(&v) == "frag" {
                        if let Some(full) = self.reasm.add(&v)? {
                            let inner: Value = serde_json::from_slice(&full)
                                .map_err(|e| format!("bad reassembled json: {}", e))?;
                            return Ok(Some(inner));
                        }
                        continue;
                    }
                    return Ok(Some(v));
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                    return Ok(None)
                }
                Err(e) => return Err(format!("recv: {}", e)),
            }
        }
    }
}
