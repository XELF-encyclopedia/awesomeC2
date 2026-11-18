use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

pub const CIPHER_AES: u8 = 1;
pub const CIPHER_CHACHA: u8 = 2;
pub const DIR_C2S: u8 = 1;
pub const DIR_S2C: u8 = 2;

pub struct Keys {
    pub sid: String,
    pub cipher: u8,
    pub c2s: [u8; 32],
    pub s2c: [u8; 32],
}

impl Keys {
    pub fn zeroize(&mut self) {
        self.c2s = [0u8; 32];
        self.s2c = [0u8; 32];
        self.sid.clear();
    }
}

pub fn new_secret() -> StaticSecret {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    StaticSecret::from(b)
}

pub fn public_bytes(s: &StaticSecret) -> [u8; 32] {
    PublicKey::from(s).to_bytes()
}

pub fn shared_secret(s: &StaticSecret, peer: &[u8]) -> Result<[u8; 32], String> {
    if peer.len() != 32 {
        return Err("peer public key must be 32 bytes".into());
    }
    let mut p = [0u8; 32];
    p.copy_from_slice(peer);
    Ok(s.diffie_hellman(&PublicKey::from(p)).to_bytes())
}

pub fn derive_keys(
    shared: &[u8; 32],
    psk: &[u8],
    nonce_c: &[u8],
    nonce_s: &[u8],
    cipher: u8,
) -> Keys {
    let mut salt_input = Vec::with_capacity(nonce_c.len() + nonce_s.len());
    salt_input.extend_from_slice(nonce_c);
    salt_input.extend_from_slice(nonce_s);
    let salt = Sha256::digest(&salt_input);
    let mut ikm = Vec::with_capacity(32 + psk.len());
    ikm.extend_from_slice(shared);
    ikm.extend_from_slice(psk);

    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    hk.expand(b"c2v2/c2s/v2", &mut c2s).expect("hkdf");
    hk.expand(b"c2v2/s2c/v2", &mut s2c).expect("hkdf");

    let mut sid_input = Vec::with_capacity(64 + nonce_c.len() + nonce_s.len());
    sid_input.extend_from_slice(shared);
    sid_input.extend_from_slice(nonce_c);
    sid_input.extend_from_slice(nonce_s);
    let sid_hash = Sha256::digest(&sid_input);
    let sid = hex::encode(&sid_hash[..8]);

    Keys { sid, cipher, c2s, s2c }
}

fn aead_encrypt(cipher: u8, key: &[u8], nonce: &[u8], aad: &[u8], plain: &[u8]) -> Result<Vec<u8>, String> {
    let payload = Payload { msg: plain, aad };
    match cipher {
        CIPHER_CHACHA => {
            let c = ChaCha20Poly1305::new_from_slice(key).map_err(|e| e.to_string())?;
            c.encrypt(chacha20poly1305::Nonce::from_slice(nonce), payload)
                .map_err(|e| format!("chacha encrypt: {}", e))
        }
        _ => {
            let c = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
            c.encrypt(aes_gcm::Nonce::from_slice(nonce), payload)
                .map_err(|e| format!("aes encrypt: {}", e))
        }
    }
}

fn aead_decrypt(cipher: u8, key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, String> {
    let payload = Payload { msg: ct, aad };
    match cipher {
        CIPHER_CHACHA => {
            let c = ChaCha20Poly1305::new_from_slice(key).map_err(|e| e.to_string())?;
            c.decrypt(chacha20poly1305::Nonce::from_slice(nonce), payload)
                .map_err(|_| "chacha auth failed".to_string())
        }
        _ => {
            let c = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
            c.decrypt(aes_gcm::Nonce::from_slice(nonce), payload)
                .map_err(|_| "aes auth failed".to_string())
        }
    }
}

pub fn seal(k: &Keys, dir: u8, plain: &[u8]) -> Result<Vec<u8>, String> {
    let key: &[u8] = if dir == DIR_C2S { &k.c2s } else { &k.s2c };
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let mut aad = Vec::with_capacity(5);
    aad.extend_from_slice(b"C2V2");
    aad.push(dir);
    let ct = aead_encrypt(k.cipher, key, &nonce, &aad, plain)?;
    let mut out = Vec::with_capacity(4 + 12 + ct.len());
    out.extend_from_slice(&[2u8, 1u8, k.cipher, dir]);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open(k: &Keys, want_dir: u8, env: &[u8]) -> Result<Vec<u8>, String> {
    if env.len() < 4 {
        return Err("envelope too short".into());
    }
    if env[0] != 2 || env[1] != 1 {
        return Err("not a sealed v2 envelope".into());
    }
    if env[2] != k.cipher {
        return Err("cipher mismatch".into());
    }
    let dir = env[3];
    if dir != want_dir {
        return Err("direction mismatch".into());
    }
    if env.len() < 4 + 12 + 16 {
        return Err("sealed envelope too short".into());
    }
    let nonce = &env[4..16];
    let ct = &env[16..];
    let key: &[u8] = if dir == DIR_C2S { &k.c2s } else { &k.s2c };
    let mut aad = Vec::with_capacity(5);
    aad.extend_from_slice(b"C2V2");
    aad.push(dir);
    aead_decrypt(k.cipher, key, nonce, &aad, ct)
}

pub fn plain_envelope(json: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(json.len() + 2);
    out.extend_from_slice(&[2u8, 0u8]);
    out.extend_from_slice(json);
    out
}

pub fn parse_plain(env: &[u8]) -> Result<&[u8], String> {
    if env.len() < 2 || env[0] != 2 || env[1] != 0 {
        return Err("not a plain v2 envelope".into());
    }
    Ok(&env[2..])
}

pub fn hmac_hex(key: &[u8], parts: &[&str]) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            mac.update(b"|");
        }
        mac.update(p.as_bytes());
    }
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify_hmac(key: &[u8], sig: &str, parts: &[&str]) -> bool {
    let want = hmac_hex(key, parts);
    // constant-time compare
    if want.len() != sig.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in want.bytes().zip(sig.bytes()) {
        diff |= a ^ b;
    }
    diff == 0
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
