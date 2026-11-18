use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{self, Read, Write};

pub const MAX_FRAME: usize = 8 << 20;

pub fn rand_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

pub fn b64(b: &[u8]) -> String {
    B64.encode(b)
}

pub fn unb64(s: &str) -> Result<Vec<u8>, String> {
    B64.decode(s).map_err(|e| format!("base64: {}", e))
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn write_frame<W: Write>(w: &mut W, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "frame too large"));
    }
    w.write_all(&(payload.len() as u32).to_be_bytes())?;
    w.write_all(payload)?;
    w.flush()
}

pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut hdr = [0u8; 4];
    r.read_exact(&mut hdr)?;
    let n = u32::from_be_bytes(hdr) as usize;
    if n == 0 || n > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad frame length"));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Frag {
    pub t: String,
    pub fid: String,
    pub idx: usize,
    pub total: usize,
    pub data: String,
}

pub fn message_type(v: &Value) -> &str {
    v.get("t").and_then(|x| x.as_str()).unwrap_or("")
}

/// Split a JSON payload into frag messages when it exceeds `max`.
pub fn fragment_json(plain: &[u8], max: usize) -> Result<Vec<Vec<u8>>, String> {
    if plain.len() <= max {
        return Ok(vec![plain.to_vec()]);
    }
    let fid = rand_hex(4);
    let total = (plain.len() + max - 1) / max;
    let mut out = Vec::with_capacity(total);
    for i in 0..total {
        let lo = i * max;
        let hi = std::cmp::min(lo + max, plain.len());
        let f = Frag {
            t: "frag".into(),
            fid: fid.clone(),
            idx: i,
            total,
            data: b64(&plain[lo..hi]),
        };
        out.push(serde_json::to_vec(&f).map_err(|e| e.to_string())?);
    }
    Ok(out)
}

pub struct Reassembler {
    parts: std::collections::HashMap<String, (Vec<Option<Vec<u8>>>, usize)>,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self { parts: std::collections::HashMap::new() }
    }
}

impl Reassembler {
    pub fn add(&mut self, v: &Value) -> Result<Option<Vec<u8>>, String> {
        let fid = v.get("fid").and_then(|x| x.as_str()).ok_or("frag: missing fid")?.to_string();
        let idx = v.get("idx").and_then(|x| x.as_u64()).ok_or("frag: missing idx")? as usize;
        let total = v.get("total").and_then(|x| x.as_u64()).ok_or("frag: missing total")? as usize;
        let data = unb64(v.get("data").and_then(|x| x.as_str()).ok_or("frag: missing data")?)?;
        if total == 0 || total > 100000 || idx >= total {
            return Err("frag: bad index/total".into());
        }
        let entry = self
            .parts
            .entry(fid.clone())
            .or_insert_with(|| (vec![None; total], total));
        if entry.1 != total {
            return Err("frag: total mismatch".into());
        }
        entry.0[idx] = Some(data);
        if entry.0.iter().any(|x| x.is_none()) {
            return Ok(None);
        }
        let (parts, _) = self.parts.remove(&fid).unwrap();
        let mut out = Vec::new();
        for p in parts {
            out.extend_from_slice(&p.unwrap());
        }
        Ok(Some(out))
    }
}

/// DNS name codec (base32hex, lowercase, no padding), max 50-char labels.
pub fn encode_dns_name(payload: &[u8], suffix: &str, label_len: usize) -> String {
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    // base32hex without padding
    let mut enc = base32hex_encode(payload);
    if enc.is_empty() {
        enc = "x".into();
    }
    let ll = if label_len == 0 || label_len > 63 { 50 } else { label_len };
    let mut labels = Vec::new();
    while enc.len() > ll {
        labels.push(enc[..ll].to_string());
        enc = enc[ll..].to_string();
    }
    labels.push(enc);
    let _ = STANDARD_NO_PAD;
    let mut name = labels.join(".");
    let s = suffix.trim_end_matches('.');
    if !s.is_empty() {
        name.push('.');
        name.push_str(s);
    }
    name
}

pub fn decode_dns_name(name: &str, suffix: &str) -> Result<Vec<u8>, String> {
    let mut n = name.trim_end_matches('.').to_lowercase();
    let s = suffix.trim_end_matches('.').to_lowercase();
    if !s.is_empty() {
        if n == s {
            return Ok(Vec::new());
        }
        let tail = format!(".{}", s);
        if !n.ends_with(&tail) {
            return Err("dns suffix mismatch".into());
        }
        n.truncate(n.len() - tail.len());
    }
    let joined: String = n.split('.').collect();
    if joined.is_empty() || joined == "x" {
        return Ok(Vec::new());
    }
    base32hex_decode(&joined)
}

const B32HEX: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";

fn base32hex_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for &b in data {
        buffer = (buffer << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            out.push(B32HEX[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(B32HEX[idx] as char);
    }
    out
}

fn base32hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for c in s.bytes() {
        let v = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'v' => c - b'a' + 10,
            b'A'..=b'V' => c - b'A' + 10,
            _ => return Err(format!("bad base32hex char {:?}", c as char)),
        };
        buffer = (buffer << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

/// Batch codec used by UDP/DNS/DoH.
pub fn decode_batch(buf: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if buf.len() < 2 {
        return Err("short batch".into());
    }
    let n = ((buf[0] as usize) << 8) | buf[1] as usize;
    let mut off = 2;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        if off + 2 > buf.len() {
            return Err("truncated batch".into());
        }
        let l = ((buf[off] as usize) << 8) | buf[off + 1] as usize;
        off += 2;
        if off + l > buf.len() {
            return Err("truncated batch item".into());
        }
        out.push(buf[off..off + l].to_vec());
        off += l;
    }
    Ok(out)
}

/// Parse DNS TXT chunks from a response and concatenate them.
pub fn parse_dns_txt(msg: &[u8]) -> Result<Vec<u8>, String> {
    if msg.len() < 12 {
        return Err("short dns response".into());
    }
    let qd = (((msg[4] as usize) << 8) | msg[5] as usize) as usize;
    let an = (((msg[6] as usize) << 8) | msg[7] as usize) as usize;
    let mut off = 12usize;
    fn skip_name(msg: &[u8], mut o: usize) -> Result<usize, String> {
        loop {
            if o >= msg.len() {
                return Err("truncated name".into());
            }
            let l = msg[o] as usize;
            if l == 0 {
                return Ok(o + 1);
            }
            if l & 0xC0 == 0xC0 {
                return Ok(o + 2);
            }
            o += 1 + l;
        }
    }
    for _ in 0..qd {
        off = skip_name(msg, off)?;
        off += 4;
    }
    let mut out = Vec::new();
    for _ in 0..an {
        off = skip_name(msg, off)?;
        if off + 10 > msg.len() {
            return Err("truncated rr".into());
        }
        let rtype = ((msg[off] as usize) << 8) | msg[off + 1] as usize;
        let rdlen = ((msg[off + 8] as usize) << 8) | msg[off + 9] as usize;
        off += 10;
        if off + rdlen > msg.len() {
            return Err("truncated rdata".into());
        }
        if rtype == 16 {
            let rd = &msg[off..off + rdlen];
            let mut p = 0;
            while p < rd.len() {
                let l = rd[p] as usize;
                p += 1;
                if p + l > rd.len() {
                    break;
                }
                out.extend_from_slice(&rd[p..p + l]);
                p += l;
            }
        }
        off += rdlen;
    }
    Ok(out)
}

/// Encode a DNS query for `name` (type TXT, class IN).
/// Build a query whose questions jointly carry `payload`.  A single QNAME is
/// limited to 253 octets, so the base32 payload is split into 200-character
/// chunks (each comfortable below the limit) and each chunk becomes one
/// question.  The receiver concatenates the decoded questions.
pub fn build_dns_query_multi(payload: &[u8], suffix: &str, label_len: usize, id: u16) -> Vec<u8> {
    let mut enc = base32hex_encode(payload);
    if enc.is_empty() {
        enc = "x".into();
    }
    let ll = if label_len == 0 || label_len > 50 { 50 } else { label_len };
    let mut names: Vec<String> = Vec::new();
    let chars: Vec<char> = enc.chars().collect();
    let mut idx = 0usize;
    while idx < chars.len() {
        let take = std::cmp::min(200, chars.len() - idx);
        let part: String = chars[idx..idx + take].iter().collect();
        idx += take;
        let mut name = Vec::new();
        let bytes = part.as_bytes();
        let mut p = 0usize;
        while bytes.len() - p > ll {
            name.push(bytes[p..p + ll].to_vec());
            p += ll;
        }
        if p < bytes.len() {
            name.push(bytes[p..].to_vec());
        }
        let mut s = name
            .iter()
            .map(|l| String::from_utf8_lossy(l).to_string())
            .collect::<Vec<_>>()
            .join(".");
        let sfx = suffix.trim_end_matches('.');
        if !sfx.is_empty() {
            s.push('.');
            s.push_str(sfx);
        }
        names.push(s);
    }
    if names.is_empty() {
        names.push(suffix.trim_end_matches('.').to_string());
    }
    let mut q = Vec::new();
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]);
    q.extend_from_slice(&(names.len() as u16).to_be_bytes());
    q.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    for name in names {
        for label in name.trim_end_matches('.').split('.') {
            if label.is_empty() {
                continue;
            }
            let b = label.as_bytes();
            let l = std::cmp::min(b.len(), 63);
            q.push(l as u8);
            q.extend_from_slice(&b[..l]);
        }
        q.push(0);
        q.extend_from_slice(&[0x00, 0x10, 0x00, 0x01]); // TXT IN
    }
    q
}

pub fn build_dns_query(name: &str, id: u16) -> Vec<u8> {
    let mut q = Vec::new();
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // RD
    q.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        let b = label.as_bytes();
        let l = std::cmp::min(b.len(), 63);
        q.push(l as u8);
        q.extend_from_slice(&b[..l]);
    }
    q.push(0);
    q.extend_from_slice(&[0x00, 0x10, 0x00, 0x01]); // TXT IN
    q
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query_names(q: &[u8]) -> Vec<String> {
        assert!(q.len() > 12);
        let qd = ((q[4] as usize) << 8) | q[5] as usize;
        let mut off = 12usize;
        let mut out = Vec::new();
        for _ in 0..qd {
            let mut labels = Vec::new();
            loop {
                let l = q[off] as usize;
                if l == 0 {
                    off += 1;
                    break;
                }
                labels.push(String::from_utf8(q[off + 1..off + 1 + l].to_vec()).unwrap());
                off += 1 + l;
            }
            off += 4; // qtype + qclass
            out.push(labels.join("."));
        }
        out
    }

    #[test]
    fn dns_multi_question_roundtrip_600_bytes() {
        let payload: Vec<u8> = (0..600u32).map(|i| (i * 7 % 251) as u8).collect();
        let q = build_dns_query_multi(&payload, "test.example.com", 50, 0x1234);
        let names = query_names(&q);
        assert!(names.len() >= 2, "expected multiple questions, got {}", names.len());
        let mut joined = Vec::new();
        for n in &names {
            assert!(n.len() <= 253, "question too long: {}", n.len());
            assert!(n.ends_with("test.example.com"));
            joined.extend(decode_dns_name(n, "test.example.com").unwrap());
        }
        assert_eq!(joined, payload);
    }

    #[test]
    fn dns_multi_question_handles_small_payload_and_empty() {
        for payload in [vec![], b"hi".to_vec(), vec![0u8; 3]] {
            let q = build_dns_query_multi(&payload, "t.example.com", 50, 1);
            let names = query_names(&q);
            assert!(names.len() >= 1);
            let mut joined = Vec::new();
            for n in &names {
                joined.extend(decode_dns_name(n, "t.example.com").unwrap());
            }
            assert_eq!(joined, payload);
        }
    }
}
