use crate::config::TransportCfg;
use crate::wire;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

static PROVIDER: OnceLock<()> = OnceLock::new();

fn init_crypto() {
    PROVIDER.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[derive(Debug)]
struct LabVerifier {
    pin: Option<String>,
    insecure: bool,
}

impl LabVerifier {
    fn check(&self, cert: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        if let Some(pin) = &self.pin {
            let got = hex::encode(Sha256::digest(cert.as_ref()));
            if !got.eq_ignore_ascii_case(pin.trim()) {
                return Err(rustls::Error::General("certificate pin mismatch".into()));
            }
        }
        if !self.insecure && self.pin.is_none() {
            return Err(rustls::Error::General("no pin and not insecure".into()));
        }
        Ok(())
    }
}

impl ServerCertVerifier for LabVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.check(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn tls_config(cfg: &TransportCfg) -> Result<Arc<ClientConfig>, String> {
    init_crypto();
    if cfg.tls_insecure || !cfg.pin_sha256.is_empty() {
        let verifier = Arc::new(LabVerifier {
            pin: if cfg.pin_sha256.is_empty() { None } else { Some(cfg.pin_sha256.clone()) },
            insecure: cfg.tls_insecure,
        });
        let c = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        return Ok(Arc::new(c));
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let c = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(c))
}

fn server_name(cfg: &TransportCfg) -> String {
    if !cfg.sni.is_empty() {
        return cfg.sni.clone();
    }
    if cfg.host.parse::<std::net::IpAddr>().is_ok() {
        // Use a DNS name for SNI; lab servers accept either.
        return "localhost".to_string();
    }
    cfg.host.clone()
}

/// Rw is either a plain TCP stream or a rustls session over TCP.
pub enum Rw {
    Tcp(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Rw {
    fn stream_ref(&self) -> &TcpStream {
        match self {
            Rw::Tcp(s) => s,
            Rw::Tls(s) => &s.sock,
        }
    }
    pub fn set_timeout(&self, d: Option<Duration>) {
        let _ = self.stream_ref().set_read_timeout(d);
        let _ = self.stream_ref().set_write_timeout(d);
    }
}

impl Read for Rw {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Rw::Tcp(s) => s.read(buf),
            Rw::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Rw {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Rw::Tcp(s) => s.write(buf),
            Rw::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Rw::Tcp(s) => s.flush(),
            Rw::Tls(s) => s.flush(),
        }
    }
}

fn connect_tcp(cfg: &TransportCfg) -> Result<TcpStream, String> {
    let addr = format!("{}:{}", cfg.host, cfg.port);
    let s = TcpStream::connect(&addr).map_err(|e| format!("connect {}: {}", addr, e))?;
    let _ = s.set_nodelay(true);
    s.set_read_timeout(Some(Duration::from_secs(cfg.timeout_secs.max(5))))
        .map_err(|e| e.to_string())?;
    s.set_write_timeout(Some(Duration::from_secs(15))).map_err(|e| e.to_string())?;
    Ok(s)
}

fn wrap_tls(sock: TcpStream, cfg: &TransportCfg) -> Result<Rw, String> {
    let cc = tls_config(cfg)?;
    let name = server_name(cfg);
    let sn = ServerName::try_from(name.clone()).map_err(|e| format!("server name {}: {}", name, e))?;
    let conn = ClientConnection::new(cc, sn).map_err(|e| e.to_string())?;
    let mut stream = StreamOwned::new(conn, sock);
    // Force the handshake so errors surface here.
    stream.flush().map_err(|e| format!("tls handshake: {}", e))?;
    Ok(Rw::Tls(Box::new(stream)))
}

pub struct StreamLink {
    rw: Rw,
    pub transport: &'static str,
}

impl StreamLink {
    fn open(cfg: &TransportCfg, tls: bool, transport: &'static str) -> Result<Self, String> {
        let sock = connect_tcp(cfg)?;
        let rw = if tls { wrap_tls(sock, cfg)? } else { Rw::Tcp(sock) };
        Ok(StreamLink { rw, transport })
    }
}

pub struct WsLink {
    rw: Rw,
    pending: Vec<u8>,
    pub transport: &'static str,
}

impl WsLink {
    fn open(cfg: &TransportCfg, tls: bool, transport: &'static str) -> Result<Self, String> {
        let sock = connect_tcp(cfg)?;
        let mut rw = if tls { wrap_tls(sock, cfg)? } else { Rw::Tcp(sock) };
        let path = if cfg.path.is_empty() { "/ws" } else { &cfg.path };
        let host = if cfg.port == 80 || cfg.port == 443 {
            cfg.host.clone()
        } else {
            format!("{}:{}", cfg.host, cfg.port)
        };
        ws_handshake(&mut rw, &host, path)?;
        Ok(WsLink { rw, pending: Vec::new(), transport })
    }

    /// WS carries the same length-prefixed stream framing as raw TCP.
    fn send_framed(&mut self, env: &[u8]) -> io::Result<()> {
        let mut buf = Vec::with_capacity(env.len() + 4);
        buf.extend_from_slice(&(env.len() as u32).to_be_bytes());
        buf.extend_from_slice(env);
        ws_write(&mut self.rw, &buf)
    }

    fn recv_framed(&mut self) -> io::Result<Vec<u8>> {
        loop {
            if self.pending.len() >= 4 {
                let n = u32::from_be_bytes([
                    self.pending[0],
                    self.pending[1],
                    self.pending[2],
                    self.pending[3],
                ]) as usize;
                if n == 0 || n > wire::MAX_FRAME {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "bad ws frame length"));
                }
                if self.pending.len() >= 4 + n {
                    let out = self.pending[4..4 + n].to_vec();
                    self.pending.drain(..4 + n);
                    return Ok(out);
                }
            }
            let msg = ws_read(&mut self.rw)?;
            if msg.is_empty() {
                continue;
            }
            self.pending.extend_from_slice(&msg);
        }
    }
}

fn read_until_headers(rw: &mut Rw) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    let mut b = [0u8; 1];
    loop {
        let n = rw.read(&mut b).map_err(|e| format!("ws handshake read: {}", e))?;
        if n == 0 {
            return Err("ws handshake eof".into());
        }
        buf.push(b[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            return Ok(buf);
        }
        if buf.len() > 16384 {
            return Err("ws handshake header too large".into());
        }
    }
}

fn ws_handshake(rw: &mut Rw, host: &str, path: &str) -> Result<(), String> {
    let key = wire::b64(&{
        let mut k = [0u8; 16];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut k);
        k
    });
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\n\r\n",
        path, host, key
    );
    rw.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    rw.flush().map_err(|e| e.to_string())?;
    let hdr = read_until_headers(rw)?;
    let text = String::from_utf8_lossy(&hdr);
    if !text.starts_with("HTTP/1.1 101") {
        return Err(format!("ws upgrade rejected: {}", text.lines().next().unwrap_or("")));
    }
    Ok(())
}

fn ws_write(rw: &mut Rw, payload: &[u8]) -> io::Result<()> {
    let mut hdr = Vec::with_capacity(14);
    hdr.push(0x82u8); // FIN + binary
    let mask = {
        let mut m = [0u8; 4];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut m);
        m
    };
    match payload.len() {
        n if n < 126 => hdr.push(0x80 | n as u8),
        n if n <= 0xFFFF => {
            hdr.push(0x80 | 126);
            hdr.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            hdr.push(0x80 | 127);
            hdr.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    hdr.extend_from_slice(&mask);
    let mut body = Vec::with_capacity(payload.len());
    for (i, b) in payload.iter().enumerate() {
        body.push(b ^ mask[i % 4]);
    }
    rw.write_all(&hdr)?;
    rw.write_all(&body)?;
    rw.flush()
}

fn ws_read(rw: &mut Rw) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let mut h = [0u8; 2];
        rw.read_exact(&mut h)?;
        let fin = h[0] & 0x80 != 0;
        let opcode = h[0] & 0x0f;
        let masked = h[1] & 0x80 != 0;
        let mut n = (h[1] & 0x7f) as u64;
        if n == 126 {
            let mut e = [0u8; 2];
            rw.read_exact(&mut e)?;
            n = u16::from_be_bytes(e) as u64;
        } else if n == 127 {
            let mut e = [0u8; 8];
            rw.read_exact(&mut e)?;
            n = u64::from_be_bytes(e);
        }
        if n > wire::MAX_FRAME as u64 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "ws message too large"));
        }
        let mut mask = [0u8; 4];
        if masked {
            rw.read_exact(&mut mask)?;
        }
        let mut payload = vec![0u8; n as usize];
        rw.read_exact(&mut payload)?;
        if masked {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
        }
        match opcode {
            0x8 => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "ws close")),
            0x9 => {
                // pong
                let mut pong = vec![0x8au8, 0x80];
                let m = [0u8; 4];
                pong.extend_from_slice(&m);
                pong.extend_from_slice(&payload);
                rw.write_all(&pong)?;
                rw.flush()?;
                continue;
            }
            0xa => continue,
            _ => {
                out.extend_from_slice(&payload);
                if fin {
                    return Ok(out);
                }
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DatagramKind {
    Udp,
    Dns,
    Doh,
}

pub struct DatagramLink {
    sock: UdpSocket,
    kind: DatagramKind,
    cfg: TransportCfg,
    pub sid: String,
    queue: std::collections::VecDeque<Vec<u8>>,
}

impl DatagramLink {
    fn open(cfg: &TransportCfg, kind: DatagramKind) -> Result<Self, String> {
        let (bind, target) = if kind == DatagramKind::Doh {
            // DoH uses TLS/TCP; a local dummy socket keeps the struct shape simple.
            ("127.0.0.1:0".to_string(), String::new())
        } else {
            ("0.0.0.0:0".to_string(), format!("{}:{}", cfg.host, cfg.port))
        };
        let sock = UdpSocket::bind(&bind).map_err(|e| format!("udp bind {}: {}", bind, e))?;
        if kind != DatagramKind::Doh {
            sock.connect(&target).map_err(|e| format!("udp connect {}: {}", target, e))?;
            sock.set_read_timeout(Some(Duration::from_secs(cfg.timeout_secs.max(5))))
                .map_err(|e| e.to_string())?;
            sock.set_write_timeout(Some(Duration::from_secs(10))).map_err(|e| e.to_string())?;
        }
        Ok(DatagramLink { sock, kind, cfg: cfg.clone(), sid: String::new(), queue: Default::default() })
    }

    fn blob(&self, env: &[u8]) -> Vec<u8> {
        let sid = self.sid.as_bytes();
        let mut out = Vec::with_capacity(2 + sid.len() + env.len());
        out.extend_from_slice(&[2u8, sid.len() as u8]);
        out.extend_from_slice(sid);
        out.extend_from_slice(env);
        out
    }

    fn poll_blob(&self) -> Vec<u8> {
        let sid = self.sid.as_bytes();
        let mut out = Vec::with_capacity(2 + sid.len());
        out.extend_from_slice(&[2u8, sid.len() as u8]);
        out.extend_from_slice(sid);
        out
    }

    fn send_blob(&mut self, blob: &[u8]) -> io::Result<()> {
        match self.kind {
            DatagramKind::Udp => {
                self.sock.send(blob)?;
                Ok(())
            }
            DatagramKind::Dns => {
                let name = wire::encode_dns_name(blob, &self.cfg.suffix, 50);
                let q = wire::build_dns_query(&name, rand_id());
                self.sock.send(&q)?;
                let mut buf = vec![0u8; 65535];
                let n = self.sock.recv(&mut buf)?;
                buf.truncate(n);
                let body = wire::parse_dns_txt(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                self.enqueue_batch(&body)
            }
            DatagramKind::Doh => {
                let body = http_post(
                    &self.cfg.host,
                    self.cfg.port,
                    if self.cfg.path.is_empty() { "/doh" } else { &self.cfg.path },
                    blob,
                    &self.cfg,
                )?;
                self.enqueue_batch(&body)
            }
        }
    }

    fn enqueue_batch(&mut self, buf: &[u8]) -> io::Result<()> {
        let items = wire::decode_batch(buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        for it in items {
            // Server items are [version][sidLen][sid][envelope].
            if it.len() >= 2 && it[0] == 2 {
                let sid_len = it[1] as usize;
                if it.len() >= 2 + sid_len {
                    self.queue.push_back(it[2 + sid_len..].to_vec());
                    continue;
                }
            }
            self.queue.push_back(it);
        }
        Ok(())
    }
}

fn rand_id() -> u16 {
    use rand::Rng;
    rand::thread_rng().gen()
}

/// Link abstracts stream and datagram transports with the same envelope API.
pub enum Link {
    Stream(StreamLink),
    Ws(WsLink),
    Datagram(DatagramLink),
}

impl Link {
    pub fn open(cfg: &TransportCfg) -> Result<Link, String> {
        match cfg.kind.as_str() {
            "tls" => Ok(Link::Stream(StreamLink::open(cfg, true, "tls")?)),
            "tcp" => Ok(Link::Stream(StreamLink::open(cfg, false, "tcp")?)),
            "wss" => Ok(Link::Ws(WsLink::open(cfg, true, "wss")?)),
            "ws" => Ok(Link::Ws(WsLink::open(cfg, false, "ws")?)),
            "udp" => Ok(Link::Datagram(DatagramLink::open(cfg, DatagramKind::Udp)?)),
            "dns" => Ok(Link::Datagram(DatagramLink::open(cfg, DatagramKind::Dns)?)),
            "doh" => Ok(Link::Datagram(DatagramLink::open(cfg, DatagramKind::Doh)?)),
            other => Err(format!("unknown transport {:?}", other)),
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Link::Stream(s) => s.transport,
            Link::Ws(w) => w.transport,
            Link::Datagram(d) => match d.kind {
                DatagramKind::Udp => "udp",
                DatagramKind::Dns => "dns",
                DatagramKind::Doh => "doh",
            },
        }
    }

    pub fn is_datagram(&self) -> bool {
        matches!(self, Link::Datagram(_))
    }

    pub fn set_sid(&mut self, sid: &str) {
        if let Link::Datagram(d) = self {
            d.sid = sid.to_string();
        }
    }

    pub fn max_datagram(&self) -> usize {
        match self {
            Link::Datagram(d) => match d.kind {
                DatagramKind::Dns => 90,
                DatagramKind::Doh => 2000,
                DatagramKind::Udp => 900,
            },
            _ => wire::MAX_FRAME,
        }
    }

    pub fn set_read_timeout(&mut self, dur: Option<Duration>) {
        match self {
            Link::Stream(s) => s.rw.set_timeout(dur),
            Link::Ws(w) => w.rw.set_timeout(dur),
            Link::Datagram(d) => {
                let _ = d.sock.set_read_timeout(dur);
            }
        }
    }

    pub fn send_env(&mut self, env: &[u8]) -> io::Result<()> {
        match self {
            Link::Stream(s) => wire::write_frame(&mut s.rw, env),
            Link::Ws(w) => w.send_framed(env),
            Link::Datagram(d) => {
                let blob = d.blob(env);
                if d.kind == DatagramKind::Doh || d.kind == DatagramKind::Dns {
                    d.send_blob(&blob)
                } else {
                    d.sock.send(&blob).map(|_| ())
                }
            }
        }
    }

    pub fn recv_env(&mut self) -> io::Result<Vec<u8>> {
        match self {
            Link::Stream(s) => wire::read_frame(&mut s.rw),
            Link::Ws(w) => w.recv_framed(),
            Link::Datagram(d) => {
                if let Some(x) = d.queue.pop_front() {
                    return Ok(x);
                }
                // Poll once; also consume any unsolicited datagram first.
                if d.kind == DatagramKind::Udp {
                    let mut buf = vec![0u8; 65535];
                    match d.sock.recv(&mut buf) {
                        Ok(n) => {
                            buf.truncate(n);
                            d.enqueue_batch(&buf)?;
                        }
                        Err(e)
                            if e.kind() == io::ErrorKind::WouldBlock
                                || e.kind() == io::ErrorKind::TimedOut => {}
                        Err(e) => return Err(e),
                    }
                    if let Some(x) = d.queue.pop_front() {
                        return Ok(x);
                    }
                }
                let blob = d.poll_blob();
                d.send_blob(&blob)?;
                d.queue.pop_front().ok_or_else(|| io::Error::new(io::ErrorKind::WouldBlock, "no data"))
            }
        }
    }
}

/// Minimal HTTP/1.1 POST over TLS, returning the response body.
pub fn http_post(host: &str, port: u16, path: &str, body: &[u8], cfg: &TransportCfg) -> io::Result<Vec<u8>> {
    let mut c = cfg.clone();
    c.host = host.to_string();
    c.port = port;
    let sock = connect_tcp(&c).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let mut rw = wrap_tls(sock, &c).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        if path.is_empty() { "/doh" } else { path },
        host,
        body.len()
    );
    rw.write_all(req.as_bytes())?;
    rw.write_all(body)?;
    rw.flush()?;
    let mut raw = Vec::new();
    rw.read_to_end(&mut raw)?;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "http: no header end"))?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let mut body = raw[split + 4..].to_vec();
    let mut chunked = false;
    let mut content_len = None;
    for line in head.lines() {
        let l = line.to_ascii_lowercase();
        if l.starts_with("transfer-encoding:") && l.contains("chunked") {
            chunked = true;
        }
        if let Some(v) = l.strip_prefix("content-length:") {
            content_len = v.trim().parse::<usize>().ok();
        }
    }
    if !head.starts_with("HTTP/1.1 200") && !head.starts_with("HTTP/1.0 200") {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("http status: {}", head.lines().next().unwrap_or("")),
        ));
    }
    if chunked {
        body = dechunk(&body);
    } else if let Some(n) = content_len {
        if body.len() > n {
            body.truncate(n);
        }
    }
    Ok(body)
}

fn dechunk(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let mut j = i;
        while j < data.len() && data[j] != b'\r' {
            j += 1;
        }
        let size_str = String::from_utf8_lossy(&data[i..j]);
        let size = match usize::from_str_radix(size_str.trim(), 16) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        let start = j + 2;
        if start + size > data.len() {
            out.extend_from_slice(&data[start..]);
            break;
        }
        out.extend_from_slice(&data[start..start + size]);
        i = start + size + 2;
    }
    out
}

/// Minimal HTTP/1.1 GET, used by the update module.
pub fn http_get(url: &str, cfg: &TransportCfg) -> io::Result<Vec<u8>> {
    let (host, port, path, tls) = parse_url(url)?;
    let mut c = cfg.clone();
    c.host = host.clone();
    c.port = port;
    let sock = connect_tcp(&c).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let mut rw = if tls {
        wrap_tls(sock, &c).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
    } else {
        Rw::Tcp(sock)
    };
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: c2v2-updater\r\nConnection: close\r\n\r\n",
        path, host
    );
    rw.write_all(req.as_bytes())?;
    rw.flush()?;
    let mut raw = Vec::new();
    rw.read_to_end(&mut raw)?;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "http: no header end"))?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    if !head.starts_with("HTTP/1.1 200") && !head.starts_with("HTTP/1.0 200") {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("http status: {}", head.lines().next().unwrap_or("")),
        ));
    }
    let mut body = raw[split + 4..].to_vec();
    let mut chunked = false;
    for line in head.lines() {
        let l = line.to_ascii_lowercase();
        if l.starts_with("transfer-encoding:") && l.contains("chunked") {
            chunked = true;
        }
        if let Some(v) = l.strip_prefix("content-length:") {
            if let Ok(n) = v.trim().parse::<usize>() {
                if body.len() > n {
                    body.truncate(n);
                }
            }
        }
    }
    if chunked {
        body = dechunk(&body);
    }
    Ok(body)
}

fn parse_url(url: &str) -> io::Result<(String, u16, String, bool)> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "url: missing scheme"))?;
    let tls = scheme.eq_ignore_ascii_case("https");
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(if tls { 443 } else { 80 })),
        None => (hostport.to_string(), if tls { 443 } else { 80 }),
    };
    Ok((host, port, path.to_string(), tls))
}
