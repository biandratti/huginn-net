//! TLS record framing and AEAD record decryption (client direction only).

use super::schedule::{HashAlg, TrafficKeys};
use crate::output::TlsVersion;
use aes_gcm::aead::{Aead, KeyInit, Nonce, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use zeroize::Zeroizing;

/// TLS record content types.
pub(crate) const CT_CHANGE_CIPHER_SPEC: u8 = 20;
pub(crate) const CT_ALERT: u8 = 21;
pub(crate) const CT_HANDSHAKE: u8 = 22;
pub(crate) const CT_APPLICATION_DATA: u8 = 23;

/// Largest record payload accepted: 2^14 plaintext + 256 bytes of expansion (RFC 8446 §5.2).
pub(crate) const MAX_RECORD_PAYLOAD: usize = 16384 + 256;
const TAG_LEN: usize = 16;
const TLS12_GCM_EXPLICIT_NONCE: usize = 8;

/// AEAD algorithm of a supported suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AeadAlg {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl AeadAlg {
    pub(crate) fn key_len(self) -> usize {
        match self {
            AeadAlg::Aes128Gcm => 16,
            AeadAlg::Aes256Gcm | AeadAlg::ChaCha20Poly1305 => 32,
        }
    }
}

/// A cipher suite huginn can decrypt (research R3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CipherSuite {
    pub(crate) id: u16,
    pub(crate) version: TlsVersion,
    pub(crate) aead: AeadAlg,
    pub(crate) hash: HashAlg,
}

impl CipherSuite {
    /// Maps an IANA cipher suite value to a supported suite, `None` if unsupported.
    pub(crate) fn from_id(id: u16) -> Option<Self> {
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
}

/// Record-layer failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordError {
    /// Framing is invalid (oversized length, too short for the AEAD, all-zero inner plaintext).
    Malformed,
    /// AEAD authentication failed (wrong key, wrong sequence number or tampered record).
    Auth,
}

/// One TLS record as it appeared on the wire.
#[derive(Debug, Clone)]
pub(crate) struct RawRecord {
    pub(crate) content_type: u8,
    pub(crate) version: u16,
    pub(crate) header: [u8; 5],
    pub(crate) payload: Vec<u8>,
}

/// Splits complete records off the front of `buf`.
///
/// Returns the records and the number of bytes they used; a trailing partial record is left
/// for the next call.
///
/// # Errors
/// [`RecordError::Malformed`] when a record header declares a payload longer than
/// [`MAX_RECORD_PAYLOAD`].
pub(crate) fn split_records(buf: &[u8]) -> Result<(Vec<RawRecord>, usize), RecordError> {
    let mut records = Vec::new();
    let mut pos = 0usize;
    while let Some(header) = buf.get(pos..pos.saturating_add(5)) {
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if length > MAX_RECORD_PAYLOAD {
            return Err(RecordError::Malformed);
        }
        let start = pos.saturating_add(5);
        let end = start.saturating_add(length);
        let Some(payload) = buf.get(start..end) else {
            break;
        };
        let mut hdr = [0u8; 5];
        hdr.copy_from_slice(header);
        records.push(RawRecord {
            content_type: header[0],
            version: u16::from_be_bytes([header[1], header[2]]),
            header: hdr,
            payload: payload.to_vec(),
        });
        pos = end;
    }
    Ok((records, pos))
}

enum Cipher {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

/// Decrypts consecutive client records with one traffic key. The sequence number advances
/// only on successful authentication.
pub(crate) struct RecordDecryptor {
    version: TlsVersion,
    cipher: Cipher,
    iv: Zeroizing<Vec<u8>>,
    seq: u64,
}

impl RecordDecryptor {
    pub(crate) fn new(suite: CipherSuite, keys: &TrafficKeys) -> Result<Self, RecordError> {
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
        let iv_ok = match (suite.version, suite.aead) {
            (TlsVersion::Tls12, AeadAlg::Aes128Gcm | AeadAlg::Aes256Gcm) => keys.iv.len() == 4,
            _ => keys.iv.len() == 12,
        };
        if !iv_ok {
            return Err(RecordError::Malformed);
        }
        Ok(Self { version: suite.version, cipher, iv: keys.iv.clone(), seq: 0 })
    }

    /// Starts the sequence number at `seq`.
    #[cfg(test)]
    pub(crate) fn with_seq(mut self, seq: u64) -> Self {
        self.seq = seq;
        self
    }

    /// Decrypts one record and returns `(content type, plaintext)`.
    ///
    /// For TLS 1.3 the content type is the inner type found after the padding; for TLS 1.2 it
    /// is the record header type.
    pub(crate) fn open(
        &mut self,
        record: &RawRecord,
    ) -> Result<(u8, Zeroizing<Vec<u8>>), RecordError> {
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

#[cfg(test)]
mod tests {
    use super::super::schedule::tests::{RFC8448_C_AP_SECRET, RFC8448_C_HS_SECRET, hex};
    use super::super::schedule::tls13_traffic_keys;
    use super::*;

    fn rfc8448_decryptor(secret: &str) -> RecordDecryptor {
        let Some(suite) = CipherSuite::from_id(0x1301) else {
            panic!("0x1301 must be supported");
        };
        let keys = match tls13_traffic_keys(&hex(secret), suite) {
            Ok(k) => k,
            Err(_) => panic!("derivation must succeed"),
        };
        match RecordDecryptor::new(suite, &keys) {
            Ok(d) => d,
            Err(e) => panic!("decryptor must build: {e:?}"),
        }
    }

    fn single_record(bytes: &[u8]) -> RawRecord {
        match split_records(bytes) {
            Ok((mut records, used)) if records.len() == 1 && used == bytes.len() => {
                records.remove(0)
            }
            other => panic!("expected exactly one complete record, got {other:?}"),
        }
    }

    // RFC 8448 §3: "{client} send handshake record" (the client Finished), 58 octets.
    const RFC8448_CLIENT_FINISHED_RECORD: &str = "17 03 03 00 35 75 ec 4d c2 38 cc e6 0b 29 80 44 a7 1e 21 9c 56 cc 77 b0 51 7f e9 b9 3c 7a 4b fc 44 d8 7f 38 f8 03 38 ac 98 fc 46 de b3 84 bd 1c ae ac ab 68 67 d7 26 c4 05 46";
    // RFC 8448 §3: "{client} send application_data record", 72 octets.
    const RFC8448_CLIENT_APP_RECORD: &str = "17 03 03 00 43 a2 3f 70 54 b6 2c 94 d0 af fa fe 82 28 ba 55 cb ef ac ea 42 f9 14 aa 66 bc ab 3f 2b 98 19 a8 a5 b4 6b 39 5b d5 4a 9a 20 44 1e 2b 62 97 4e 1f 5a 62 92 a2 97 70 14 bd 1e 3d ea e6 3a ee bb 21 69 49 15 e4";

    #[test]
    fn rfc8448_client_finished_record() {
        let mut dec = rfc8448_decryptor(RFC8448_C_HS_SECRET);
        let record = single_record(&hex(RFC8448_CLIENT_FINISHED_RECORD));
        let (ct, plain) = match dec.open(&record) {
            Ok(r) => r,
            Err(e) => panic!("must decrypt: {e:?}"),
        };
        assert_eq!(ct, CT_HANDSHAKE);
        assert_eq!(
            plain.as_slice(),
            hex(
                "14 00 00 20 a8 ec 43 6d 67 76 34 ae 52 5a c1 fc eb e1 1a 03 9e c1 76 94 fa c6 e9 85 27 b6 42 f2 ed d5 ce 61"
            )
        );
    }

    #[test]
    fn rfc8448_client_application_record() {
        let mut dec = rfc8448_decryptor(RFC8448_C_AP_SECRET);
        let record = single_record(&hex(RFC8448_CLIENT_APP_RECORD));
        let (ct, plain) = match dec.open(&record) {
            Ok(r) => r,
            Err(e) => panic!("must decrypt: {e:?}"),
        };
        assert_eq!(ct, CT_APPLICATION_DATA);
        let expected: Vec<u8> = (0u8..50).collect();
        assert_eq!(plain.as_slice(), expected.as_slice());
    }

    #[test]
    fn flipped_bit_fails_authentication_and_keeps_seq() {
        let mut dec = rfc8448_decryptor(RFC8448_C_AP_SECRET);
        let mut bytes = hex(RFC8448_CLIENT_APP_RECORD);
        bytes[10] ^= 0x01;
        assert_eq!(dec.open(&single_record(&bytes)).err(), Some(RecordError::Auth));
        // seq did not advance: the untampered record still decrypts at seq 0.
        assert!(
            dec.open(&single_record(&hex(RFC8448_CLIENT_APP_RECORD)))
                .is_ok()
        );
    }

    #[test]
    fn wrong_sequence_number_fails_authentication() {
        let mut dec = rfc8448_decryptor(RFC8448_C_AP_SECRET).with_seq(1);
        assert_eq!(
            dec.open(&single_record(&hex(RFC8448_CLIENT_APP_RECORD)))
                .err(),
            Some(RecordError::Auth)
        );
    }

    #[test]
    fn split_records_keeps_partial_tail_and_rejects_oversized() {
        let full = hex(RFC8448_CLIENT_APP_RECORD);
        let mut buf = full.clone();
        buf.extend_from_slice(&full[..10]);
        match split_records(&buf) {
            Ok((records, used)) => {
                assert_eq!(records.len(), 1);
                assert_eq!(used, full.len());
            }
            Err(e) => panic!("must split: {e:?}"),
        }
        assert_eq!(
            split_records(&[0x17, 0x03, 0x03, 0xFF, 0xFF]).err(),
            Some(RecordError::Malformed)
        );
    }

    #[test]
    fn suite_table() {
        for id in [
            0x1301u16, 0x1302, 0x1303, 0xC02B, 0xC02F, 0x009C, 0x009E, 0xC02C, 0xC030, 0x009D,
            0x009F, 0xCCA8, 0xCCA9, 0xCCAA,
        ] {
            assert!(CipherSuite::from_id(id).is_some(), "{id:#06x} must be supported");
        }
        for id in [0x002Fu16, 0x0035, 0xC013, 0x00FF] {
            assert!(CipherSuite::from_id(id).is_none(), "{id:#06x} must be unsupported");
        }
    }
}
