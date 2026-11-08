//! TLS record framing and AEAD record decryption (client direction only).

use super::schedule::{HashAlg, TrafficKeys};
use crate::output::TlsVersion;
use aes_gcm::aead::{Aead, KeyInit, Nonce, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use zeroize::Zeroizing;

/// TLS record content types.
pub const CT_CHANGE_CIPHER_SPEC: u8 = 20;
pub const CT_ALERT: u8 = 21;
pub const CT_HANDSHAKE: u8 = 22;
pub const CT_APPLICATION_DATA: u8 = 23;

/// Largest record payload accepted: 2^14 plaintext + 256 bytes of expansion (RFC 8446 section 5.2).
pub const MAX_RECORD_PAYLOAD: usize = 16384 + 256;
const TAG_LEN: usize = 16;
const TLS12_GCM_EXPLICIT_NONCE: usize = 8;

/// AEAD algorithm of a supported suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlg {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl AeadAlg {
    pub fn key_len(self) -> usize {
        match self {
            AeadAlg::Aes128Gcm => 16,
            AeadAlg::Aes256Gcm | AeadAlg::ChaCha20Poly1305 => 32,
        }
    }
}

/// A cipher suite huginn can decrypt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CipherSuite {
    pub id: u16,
    pub version: TlsVersion,
    pub aead: AeadAlg,
    pub hash: HashAlg,
}

impl CipherSuite {
    /// Maps an IANA cipher suite value to a supported suite, `None` if unsupported.
    pub fn from_id(id: u16) -> Option<Self> {
        let (version, aead, hash) = match id {
            0x1301 => (TlsVersion::Tls13, AeadAlg::Aes128Gcm, HashAlg::Sha256),
            0x1302 => (TlsVersion::Tls13, AeadAlg::Aes256Gcm, HashAlg::Sha384),
            0x1303 => (TlsVersion::Tls13, AeadAlg::ChaCha20Poly1305, HashAlg::Sha256),
            0xC02B | 0xC02F | 0x009C | 0x009E => {
                (TlsVersion::Tls12, AeadAlg::Aes128Gcm, HashAlg::Sha256)
            }
            0xC02C | 0xC030 | 0x009D | 0x009F => {
                (TlsVersion::Tls12, AeadAlg::Aes256Gcm, HashAlg::Sha384)
            }
            0xCCA8..=0xCCAA => (TlsVersion::Tls12, AeadAlg::ChaCha20Poly1305, HashAlg::Sha256),
            _ => return None,
        };
        Some(Self { id, version, aead, hash })
    }

    /// Length of the IV from the key schedule: the 4 byte implicit part for TLS 1.2 AES-GCM
    /// (RFC 5288), the full 12 byte nonce mask otherwise.
    pub fn iv_len(self) -> usize {
        match (self.version, self.aead) {
            (TlsVersion::Tls12, AeadAlg::Aes128Gcm | AeadAlg::Aes256Gcm) => 4,
            _ => 12,
        }
    }
}

/// Record-layer failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordError {
    /// Framing is invalid (oversized length, too short for the AEAD, all-zero inner plaintext).
    Malformed,
    /// AEAD authentication failed (wrong key, wrong sequence number or tampered record).
    Auth,
}

/// One TLS record as it appeared on the wire.
#[derive(Debug, Clone)]
pub struct RawRecord {
    pub content_type: u8,
    pub version: u16,
    pub header: [u8; 5],
    pub payload: Vec<u8>,
}

/// Splits complete records off the front of `buf`.
///
/// Returns the records and the number of bytes they used; a trailing partial record is left
/// for the next call.
///
/// # Errors
/// [`RecordError::Malformed`] when a record header declares a payload longer than
/// [`MAX_RECORD_PAYLOAD`].
pub fn split_records(buf: &[u8]) -> Result<(Vec<RawRecord>, usize), RecordError> {
    let mut records = Vec::new();
    let mut pos = 0usize;
    while let Some(span) = next_record(buf, pos)? {
        records.push(span.to_owned());
        pos = span.end;
    }
    Ok((records, pos))
}

/// A complete record borrowed from a stream buffer.
pub(crate) struct RecordSpan<'a> {
    pub(crate) header: [u8; 5],
    pub(crate) payload: &'a [u8],
    /// Offset just past the record in the buffer.
    pub(crate) end: usize,
}

impl RecordSpan<'_> {
    pub(crate) fn content_type(&self) -> u8 {
        self.header[0]
    }

    pub(crate) fn to_owned(&self) -> RawRecord {
        RawRecord {
            content_type: self.header[0],
            version: u16::from_be_bytes([self.header[1], self.header[2]]),
            header: self.header,
            payload: self.payload.to_vec(),
        }
    }
}

/// The complete record starting at `pos`, without copying it. `Ok(None)` when only a
/// partial record (or nothing) is left.
pub(crate) fn next_record(buf: &[u8], pos: usize) -> Result<Option<RecordSpan<'_>>, RecordError> {
    let Some(header) = buf.get(pos..pos.saturating_add(5)) else {
        return Ok(None);
    };
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if length > MAX_RECORD_PAYLOAD {
        return Err(RecordError::Malformed);
    }
    let start = pos.saturating_add(5);
    let end = start.saturating_add(length);
    let Some(payload) = buf.get(start..end) else {
        return Ok(None);
    };
    let mut hdr = [0u8; 5];
    hdr.copy_from_slice(header);
    Ok(Some(RecordSpan { header: hdr, payload, end }))
}

enum Cipher {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

/// Decrypts consecutive client records with one traffic key. The sequence number advances
/// only on successful authentication.
pub struct RecordDecryptor {
    version: TlsVersion,
    cipher: Cipher,
    iv: Zeroizing<Vec<u8>>,
    seq: u64,
}

impl RecordDecryptor {
    pub fn new(suite: CipherSuite, keys: &TrafficKeys) -> Result<Self, RecordError> {
        let cipher = match suite.aead {
            AeadAlg::Aes128Gcm => Cipher::Aes128(Box::new(
                Aes128Gcm::new_from_slice(&keys.key).map_err(|_| RecordError::Malformed)?,
            )),
            AeadAlg::Aes256Gcm => Cipher::Aes256(Box::new(
                Aes256Gcm::new_from_slice(&keys.key).map_err(|_| RecordError::Malformed)?,
            )),
            AeadAlg::ChaCha20Poly1305 => Cipher::ChaCha(Box::new(
                ChaCha20Poly1305::new_from_slice(&keys.key).map_err(|_| RecordError::Malformed)?,
            )),
        };
        if keys.iv.len() != suite.iv_len() {
            return Err(RecordError::Malformed);
        }
        Ok(Self { version: suite.version, cipher, iv: keys.iv.clone(), seq: 0 })
    }

    /// Starts the sequence number at `seq`.
    pub fn with_seq(mut self, seq: u64) -> Self {
        self.seq = seq;
        self
    }

    /// Decrypts one record and returns `(content type, plaintext)`.
    ///
    /// For TLS 1.3 the content type is the inner type found after the padding; for TLS 1.2 it
    /// is the record header type.
    pub fn open(&mut self, record: &RawRecord) -> Result<(u8, Zeroizing<Vec<u8>>), RecordError> {
        let seq_bytes = self.seq.to_be_bytes();
        let result = match self.version {
            TlsVersion::Tls13 => {
                let nonce = self.xor_nonce(&seq_bytes)?;
                let mut plain = self.decrypt(&nonce, &record.payload, &record.header)?;
                let Some(type_pos) = plain.iter().rposition(|&b| b != 0) else {
                    return Err(RecordError::Malformed);
                };
                let inner_type = plain[type_pos];
                plain.truncate(type_pos);
                (inner_type, plain)
            }
            TlsVersion::Tls12 => {
                let (nonce, ciphertext) = match self.cipher {
                    Cipher::ChaCha(_) => (self.xor_nonce(&seq_bytes)?, record.payload.as_slice()),
                    Cipher::Aes128(_) | Cipher::Aes256(_) => {
                        let Some(explicit) = record.payload.get(..TLS12_GCM_EXPLICIT_NONCE) else {
                            return Err(RecordError::Malformed);
                        };
                        let mut nonce = [0u8; 12];
                        nonce[..4].copy_from_slice(&self.iv);
                        nonce[4..].copy_from_slice(explicit);
                        (nonce, &record.payload[TLS12_GCM_EXPLICIT_NONCE..])
                    }
                };
                let plain_len = ciphertext
                    .len()
                    .checked_sub(TAG_LEN)
                    .ok_or(RecordError::Malformed)?;
                let plain_len = u16::try_from(plain_len).map_err(|_| RecordError::Malformed)?;
                let mut aad = [0u8; 13];
                aad[..8].copy_from_slice(&seq_bytes);
                aad[8] = record.content_type;
                aad[9..11].copy_from_slice(&record.version.to_be_bytes());
                aad[11..].copy_from_slice(&plain_len.to_be_bytes());
                (record.content_type, self.decrypt(&nonce, ciphertext, &aad)?)
            }
        };
        self.seq = self.seq.checked_add(1).ok_or(RecordError::Malformed)?;
        Ok(result)
    }

    fn xor_nonce(&self, seq_bytes: &[u8; 8]) -> Result<[u8; 12], RecordError> {
        let mut nonce = [0u8; 12];
        if self.iv.len() != 12 {
            return Err(RecordError::Malformed);
        }
        nonce.copy_from_slice(&self.iv);
        for (n, s) in nonce[4..].iter_mut().zip(seq_bytes) {
            *n ^= s;
        }
        Ok(nonce)
    }

    fn decrypt(
        &self,
        nonce: &[u8; 12],
        msg: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        if msg.len() < TAG_LEN {
            return Err(RecordError::Malformed);
        }
        let payload = Payload { msg, aad };
        let plain = match &self.cipher {
            Cipher::Aes128(c) => c.decrypt(&Nonce::<Aes128Gcm>::from(*nonce), payload),
            Cipher::Aes256(c) => c.decrypt(&Nonce::<Aes256Gcm>::from(*nonce), payload),
            Cipher::ChaCha(c) => c.decrypt(&Nonce::<ChaCha20Poly1305>::from(*nonce), payload),
        };
        plain.map(Zeroizing::new).map_err(|_| RecordError::Auth)
    }
}
