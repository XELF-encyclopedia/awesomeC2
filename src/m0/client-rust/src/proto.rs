//! Wire codec for the M0 slice.
//!
//! Frame = 4-byte big-endian length + UTF-8 JSON object. Maximum payload is
//! 1 MiB; anything larger closes the connection. See docs/PROTOCOL.md.

use std::io::{self, Read, Write};

pub const MAX_FRAME: usize = 1024 * 1024;

pub fn write_frame<W: Write>(w: &mut W, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "frame too large"));
    }
    let mut hdr = [0u8; 4];
    hdr.copy_from_slice(&(payload.len() as u32).to_be_bytes());
    w.write_all(&hdr)?;
    w.write_all(payload)?;
    w.flush()
}

pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut hdr = [0u8; 4];
    r.read_exact(&mut hdr)?;
    let n = u32::from_be_bytes(hdr) as usize;
    if n > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Tiny JSON subset (objects with scalar fields only). Enough for M0 frames and
// keeps the client dependency-free so it builds with --offline.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum JVal {
    Str(String),
    Num(i64),
    Bool(bool),
    Null,
}

impl JVal {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            JVal::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            JVal::Num(n) => Some(*n),
            _ => None,
        }
    }
}

pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Build a flat JSON object preserving key order.
pub fn object(fields: &[(&str, JVal)]) -> String {
    let mut s = String::from("{");
    for (i, (k, v)) in fields.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push('"');
        s.push_str(&escape(k));
        s.push_str("\":");
        match v {
            JVal::Str(x) => {
                s.push('"');
                s.push_str(&escape(x));
                s.push('"');
            }
            JVal::Num(n) => s.push_str(&n.to_string()),
            JVal::Bool(b) => s.push_str(if *b { "true" } else { "false" }),
            JVal::Null => s.push_str("null"),
        }
    }
    s.push('}');
    s
}

pub struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    pub fn new(s: &'a str) -> Self {
        Parser { b: s.as_bytes(), i: 0 }
    }

    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn eat(&mut self, expect: u8) -> Result<(), String> {
        self.ws();
        if self.i < self.b.len() && self.b[self.i] == expect {
            self.i += 1;
            Ok(())
        } else {
            Err(format!("expected '{}' at byte {}", expect as char, self.i))
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.eat(b'"')?;
        let mut out = String::new();
        while self.i < self.b.len() {
            let c = self.b[self.i];
            self.i += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    if self.i >= self.b.len() {
                        return Err("truncated escape".into());
                    }
                    let e = self.b[self.i];
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'u' => {
                            if self.i + 4 > self.b.len() {
                                return Err("truncated \\u".into());
                            }
                            let hex = std::str::from_utf8(&self.b[self.i..self.i + 4])
                                .map_err(|_| "bad \\u".to_string())?;
                            let cp = u32::from_str_radix(hex, 16)
                                .map_err(|_| "bad \\u".to_string())?;
                            self.i += 4;
                            out.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
                        }
                        _ => return Err("bad escape".into()),
                    }
                }
                c if c < 0x80 => out.push(c as char),
                _ => {
                    // Re-decode the UTF-8 sequence starting at self.i-1.
                    let start = self.i - 1;
                    let mut end = start + 1;
                    while end < self.b.len() && (self.b[end] & 0xC0) == 0x80 {
                        end += 1;
                    }
                    let s = std::str::from_utf8(&self.b[start..end])
                        .map_err(|_| "bad utf8".to_string())?;
                    out.push_str(s);
                    self.i = end;
                }
            }
        }
        Err("unterminated string".into())
    }

    fn scalar(&mut self) -> Result<JVal, String> {
        self.ws();
        if self.i >= self.b.len() {
            return Err("eof".into());
        }
        match self.b[self.i] {
            b'"' => Ok(JVal::Str(self.string()?)),
            b't' => {
                self.lit("true")?;
                Ok(JVal::Bool(true))
            }
            b'f' => {
                self.lit("false")?;
                Ok(JVal::Bool(false))
            }
            b'n' => {
                self.lit("null")?;
                Ok(JVal::Null)
            }
            _ => {
                let start = self.i;
                if self.b[self.i] == b'-' {
                    self.i += 1;
                }
                while self.i < self.b.len() && self.b[self.i].is_ascii_digit() {
                    self.i += 1;
                }
                let s = std::str::from_utf8(&self.b[start..self.i])
                    .map_err(|_| "bad number".to_string())?;
                s.parse::<i64>().map(JVal::Num).map_err(|_| "bad number".to_string())
            }
        }
    }

    fn lit(&mut self, s: &str) -> Result<(), String> {
        if self.b[self.i..].starts_with(s.as_bytes()) {
            self.i += s.len();
            Ok(())
        } else {
            Err(format!("expected {s}"))
        }
    }

    /// Parse a flat object of scalar fields. Unknown/nested values are rejected
    /// (M0 protocol has none).
    pub fn object(&mut self) -> Result<Vec<(String, JVal)>, String> {
        self.eat(b'{')?;
        let mut out = Vec::new();
        self.ws();
        if self.i < self.b.len() && self.b[self.i] == b'}' {
            self.i += 1;
            return Ok(out);
        }
        loop {
            let k = self.string()?;
            self.eat(b':')?;
            let v = self.scalar()?;
            out.push((k, v));
            self.ws();
            if self.i >= self.b.len() {
                return Err("unterminated object".into());
            }
            match self.b[self.i] {
                b',' => {
                    self.i += 1;
                }
                b'}' => {
                    self.i += 1;
                    return Ok(out);
                }
                _ => return Err("expected , or }".into()),
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Msg {
    pub fields: Vec<(String, JVal)>,
}

impl Msg {
    pub fn parse(s: &str) -> Result<Msg, String> {
        let mut p = Parser::new(s);
        let fields = p.object()?;
        Ok(Msg { fields })
    }
    pub fn get(&self, k: &str) -> Option<&JVal> {
        self.fields.iter().find(|(kk, _)| kk == k).map(|(_, v)| v)
    }
    pub fn s(&self, k: &str) -> &str {
        self.get(k).and_then(|v| v.as_str()).unwrap_or("")
    }
    pub fn n(&self, k: &str) -> i64 {
        self.get(k).and_then(|v| v.as_i64()).unwrap_or(0)
    }
    pub fn kind(&self) -> &str {
        self.s("t")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frame_roundtrip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"{\"t\":\"hello\"}").unwrap();
        let mut c = Cursor::new(buf);
        assert_eq!(read_frame(&mut c).unwrap(), b"{\"t\":\"hello\"}");
        assert!(read_frame(&mut c).is_err());
    }

    #[test]
    fn parse_object() {
        let m = Msg::parse(r#"{"t":"task","task_id":"abc","n":42,"ok":true,"x":null}"#).unwrap();
        assert_eq!(m.kind(), "task");
        assert_eq!(m.s("task_id"), "abc");
        assert_eq!(m.n("n"), 42);
        assert_eq!(m.get("ok"), Some(&JVal::Bool(true)));
        assert_eq!(m.get("x"), Some(&JVal::Null));
    }

    #[test]
    fn escape_roundtrip() {
        let raw = "a\"b\\c\nd";
        let built = object(&[("k", JVal::Str(raw.to_string()))]);
        let m = Msg::parse(&built).unwrap();
        assert_eq!(m.s("k"), raw);
    }
}
