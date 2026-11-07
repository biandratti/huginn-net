//! TLS key derivation for the client write direction.
//!
//! - TLS 1.3: `HKDF-Expand-Label` (RFC 8446 section 7.1) turns a client traffic secret into the
//!   record key and IV (section 7.3).
//! - TLS 1.2: the PRF `P_hash` (RFC 5246 section 5) expands the master secret into the key block,
//!   from which the client write key and IV are sliced (section 6.3).

use super::record::{AeadAlg, CipherSuite};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha384};
use zeroize::Zeroizing;

/// Hash function of a cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {
    Sha256,
    Sha384,
}

impl HashAlg {
    pub fn output_len(self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
        }
    }
}

/// Key derivation failed: wrong secret length for the suite's hash, or an impossible length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyScheduleError;

/// Client write key and IV for one direction.
pub struct TrafficKeys {
    pub key: Zeroizing<Vec<u8>>,
    pub iv: Zeroizing<Vec<u8>>,
}

/// `HKDF-Expand-Label(secret, label, context, length)` with the `"tls13 "` prefix.
pub fn hkdf_expand_label(
    alg: HashAlg,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
) -> Result<Zeroizing<Vec<u8>>, KeyScheduleError> {
    const PREFIX: &[u8] = b"tls13 ";
    let out_len = u16::try_from(len).map_err(|_| KeyScheduleError)?;
    let label_len =
        u8::try_from(PREFIX.len().saturating_add(label.len())).map_err(|_| KeyScheduleError)?;
    let context_len = u8::try_from(context.len()).map_err(|_| KeyScheduleError)?;

    let mut info = Vec::with_capacity(
        4usize
            .saturating_add(usize::from(label_len))
            .saturating_add(context.len()),
    );
    info.extend_from_slice(&out_len.to_be_bytes());
    info.push(label_len);
    info.extend_from_slice(PREFIX);
    info.extend_from_slice(label);
    info.push(context_len);
    info.extend_from_slice(context);

    let mut okm = Zeroizing::new(vec![0u8; len]);
    let expanded = match alg {
        HashAlg::Sha256 => Hkdf::<Sha256>::from_prk(secret)
            .map_err(|_| KeyScheduleError)?
            .expand(&info, okm.as_mut_slice()),
        HashAlg::Sha384 => Hkdf::<Sha384>::from_prk(secret)
            .map_err(|_| KeyScheduleError)?
            .expand(&info, okm.as_mut_slice()),
    };
    expanded.map_err(|_| KeyScheduleError)?;
    Ok(okm)
}

/// TLS 1.3 record key and IV from a client traffic secret (RFC 8446 section 7.3).
pub fn tls13_traffic_keys(
    secret: &[u8],
    suite: CipherSuite,
) -> Result<TrafficKeys, KeyScheduleError> {
    if secret.len() != suite.hash.output_len() {
        return Err(KeyScheduleError);
    }
    Ok(TrafficKeys {
        key: hkdf_expand_label(suite.hash, secret, b"key", b"", suite.aead.key_len())?,
        iv: hkdf_expand_label(suite.hash, secret, b"iv", b"", 12)?,
    })
}

/// TLS 1.2 `PRF(secret, label, seed)` = `P_<hash>(secret, label || seed)` (RFC 5246 section 5).
pub fn tls12_prf(
    alg: HashAlg,
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    out_len: usize,
) -> Result<Zeroizing<Vec<u8>>, KeyScheduleError> {
    let mut label_seed = Vec::with_capacity(label.len().saturating_add(seed.len()));
    label_seed.extend_from_slice(label);
    label_seed.extend_from_slice(seed);
    match alg {
        HashAlg::Sha256 => p_hash::<Hmac<Sha256>>(secret, &label_seed, out_len),
        HashAlg::Sha384 => p_hash::<Hmac<Sha384>>(secret, &label_seed, out_len),
    }
}

fn p_hash<M: Mac + KeyInit + Clone>(
    secret: &[u8],
    seed: &[u8],
    out_len: usize,
) -> Result<Zeroizing<Vec<u8>>, KeyScheduleError> {
    let keyed = <M as KeyInit>::new_from_slice(secret).map_err(|_| KeyScheduleError)?;
    let mut out = Zeroizing::new(Vec::with_capacity(out_len));
    // A(1) = HMAC(secret, seed); A(i) = HMAC(secret, A(i-1)).
    let mut a = Zeroizing::new({
        let mut m = keyed.clone();
        m.update(seed);
        m.finalize().into_bytes().to_vec()
    });
    while out.len() < out_len {
        let mut m = keyed.clone();
        m.update(&a);
        m.update(seed);
        let block = m.finalize().into_bytes();
        let take = out_len.saturating_sub(out.len()).min(block.len());
        out.extend_from_slice(&block[..take]);

        let mut next = keyed.clone();
        next.update(&a);
        a = Zeroizing::new(next.finalize().into_bytes().to_vec());
    }
    Ok(out)
}

/// TLS 1.2 client write key and IV for an AEAD suite (RFC 5246 section 6.3; RFC 5288 for GCM,
/// RFC 7905 for ChaCha20-Poly1305). AEAD suites have no MAC keys, so the key block is
/// `client_write_key | server_write_key | client_write_IV | server_write_IV`.
pub fn tls12_client_keys(
    master: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    suite: CipherSuite,
) -> Result<TrafficKeys, KeyScheduleError> {
    let key_len = suite.aead.key_len();
    let iv_len: usize = match suite.aead {
        AeadAlg::Aes128Gcm | AeadAlg::Aes256Gcm => 4,
        AeadAlg::ChaCha20Poly1305 => 12,
    };
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(server_random);
    seed[32..].copy_from_slice(client_random);
    let block_len = key_len
        .saturating_mul(2)
        .saturating_add(iv_len.saturating_mul(2));
    let block = tls12_prf(suite.hash, master, b"key expansion", &seed, block_len)?;

    let iv_start = key_len.saturating_mul(2);
    let key = block.get(..key_len).ok_or(KeyScheduleError)?;
    let iv = block
        .get(iv_start..iv_start.saturating_add(iv_len))
        .ok_or(KeyScheduleError)?;
    Ok(TrafficKeys { key: Zeroizing::new(key.to_vec()), iv: Zeroizing::new(iv.to_vec()) })
}
