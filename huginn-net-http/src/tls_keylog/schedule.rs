//! TLS key derivation for the client write direction.
//!
//! - TLS 1.3: `HKDF-Expand-Label` (RFC 8446 §7.1) turns a client traffic secret into the
//!   record key and IV (§7.3).
//! - TLS 1.2: the PRF `P_hash` (RFC 5246 §5) expands the master secret into the key block,
//!   from which the client write key and IV are sliced (§6.3).

use super::record::{AeadAlg, CipherSuite};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha384};
use zeroize::Zeroizing;

/// Hash function of a cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HashAlg {
    Sha256,
    Sha384,
}

impl HashAlg {
    pub(crate) fn output_len(self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
        }
    }
}

/// Key derivation failed: wrong secret length for the suite's hash, or an impossible length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeyScheduleError;

/// Client write key and IV for one direction.
pub(crate) struct TrafficKeys {
    pub(crate) key: Zeroizing<Vec<u8>>,
    pub(crate) iv: Zeroizing<Vec<u8>>,
}

/// `HKDF-Expand-Label(secret, label, context, length)` with the `"tls13 "` prefix.
pub(crate) fn hkdf_expand_label(
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

/// TLS 1.3 record key and IV from a client traffic secret (RFC 8446 §7.3).
pub(crate) fn tls13_traffic_keys(
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

/// TLS 1.2 `PRF(secret, label, seed)` = `P_<hash>(secret, label || seed)` (RFC 5246 §5).
pub(crate) fn tls12_prf(
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

/// TLS 1.2 client write key and IV for an AEAD suite (RFC 5246 §6.3; RFC 5288 for GCM,
/// RFC 7905 for ChaCha20-Poly1305). AEAD suites have no MAC keys, so the key block is
/// `client_write_key | server_write_key | client_write_IV | server_write_IV`.
pub(crate) fn tls12_client_keys(
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn hex(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..clean.len())
            .step_by(2)
            .map(|i| match u8::from_str_radix(&clean[i..i.saturating_add(2)], 16) {
                Ok(b) => b,
                Err(e) => panic!("bad hex in test vector: {e}"),
            })
            .collect()
    }

    fn suite(id: u16) -> CipherSuite {
        match CipherSuite::from_id(id) {
            Some(s) => s,
            None => panic!("suite {id:#06x} must be supported"),
        }
    }

    // RFC 8448 §3 "Simple 1-RTT Handshake": client handshake traffic secret and the derived
    // client handshake write key/IV ("{server} derive read traffic keys for handshake data").
    pub(crate) const RFC8448_C_HS_SECRET: &str = "b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21";
    // RFC 8448 §3: client application traffic secret 0 ("tls13 c ap traffic").
    pub(crate) const RFC8448_C_AP_SECRET: &str = "9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce 65 52 87 5a fa 0b 06 df 00 87 f7 92 eb b7 c1 75 04 a5";

    #[test]
    fn rfc8448_client_handshake_keys() {
        let keys = match tls13_traffic_keys(&hex(RFC8448_C_HS_SECRET), suite(0x1301)) {
            Ok(k) => k,
            Err(_) => panic!("derivation must succeed"),
        };
        assert_eq!(keys.key.as_slice(), hex("db fa a6 93 d1 76 2c 5b 66 6a f5 d9 50 25 8d 01"));
        assert_eq!(keys.iv.as_slice(), hex("5b d3 c7 1b 83 6e 0b 76 bb 73 26 5f"));
    }

    #[test]
    fn rfc8448_client_application_keys() {
        let keys = match tls13_traffic_keys(&hex(RFC8448_C_AP_SECRET), suite(0x1301)) {
            Ok(k) => k,
            Err(_) => panic!("derivation must succeed"),
        };
        assert_eq!(keys.key.as_slice(), hex("17 42 2d da 59 6e d5 d9 ac d8 90 e3 c6 3f 50 51"));
        assert_eq!(keys.iv.as_slice(), hex("5b 78 92 3d ee 08 57 90 33 e5 23 d9"));
    }

    #[test]
    fn tls13_rejects_secret_length_not_matching_hash() {
        // A 32-byte secret with a SHA-384 suite is a key log / suite mismatch.
        assert!(tls13_traffic_keys(&hex(RFC8448_C_AP_SECRET), suite(0x1302)).is_err());
    }

    // TLS 1.2 PRF vectors computed with Python's stdlib `hmac` (independent implementation):
    // secret = bytes(0..48), label = "key expansion", seed = bytes(0..64).
    #[test]
    fn tls12_prf_sha256_and_sha384() {
        let secret: Vec<u8> = (0u8..48).collect();
        let seed: Vec<u8> = (0u8..64).collect();
        let out = match tls12_prf(HashAlg::Sha256, &secret, b"key expansion", &seed, 88) {
            Ok(o) => o,
            Err(_) => panic!("prf must succeed"),
        };
        assert_eq!(
            out.as_slice(),
            hex(
                "4ac38c4d46e5ff44538c63cd6644009fd1aa1b19a81b76452615cb3f94ce61ea9f2477bd23b09dfa\
                 855a5d720e91e4b20588e7d3c8a7ea09ee756866999714e82ec648155182727f19c882dbc6845bd4\
                 b682147c403e2560"
            )
        );
        let out = match tls12_prf(HashAlg::Sha384, &secret, b"key expansion", &seed, 72) {
            Ok(o) => o,
            Err(_) => panic!("prf must succeed"),
        };
        assert_eq!(
            out.as_slice(),
            hex(
                "724152abe2fd4f3af374fb9420892f7f596f6d7ca573a31a50fb435dfd0c431ed62e5d92aa135958\
                 dbf9035cf97c343bcdf6f744378ff8bd58030551645fe8cabcfa300b6c3ba5e6"
            )
        );
    }

    #[test]
    fn tls12_key_block_slicing() {
        let master: Vec<u8> = (0u8..48).collect();
        let mut server_random = [0u8; 32];
        let mut client_random = [0u8; 32];
        for (i, b) in server_random.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap_or(0);
        }
        for (i, b) in client_random.iter_mut().enumerate() {
            *b = u8::try_from(i.saturating_add(32)).unwrap_or(0);
        }
        // Same seed as the PRF vector above: server_random || client_random = bytes(0..64).
        let keys = match tls12_client_keys(&master, &client_random, &server_random, suite(0xC02F)) {
            Ok(k) => k,
            Err(_) => panic!("derivation must succeed"),
        };
        assert_eq!(keys.key.as_slice(), hex("4ac38c4d46e5ff44538c63cd6644009f"));
        // client IV follows both 16-byte keys: bytes 32..36 of the block.
        assert_eq!(keys.iv.as_slice(), hex("9f2477bd"));
    }
}
