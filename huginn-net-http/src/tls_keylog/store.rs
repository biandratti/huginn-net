//! In-memory store of TLS session secrets parsed from NSS key log lines.
//!
//! Format: `<LABEL> <client_random_hex64> <secret_hex>` (one entry per line), as written by
//! browsers with `SSLKEYLOGFILE`, OpenSSL, BoringSSL, rustls and Go. Secrets never leave this
//! module except as zeroizing copies handed to the session that needs them.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{PoisonError, RwLock};
use zeroize::Zeroizing;

/// Longest accepted key log line, in bytes (without the line terminator).
pub(crate) const MAX_LINE_LEN: usize = 512;

/// Why a key log line was rejected. Variants carry no line content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeylogLineError {
    /// The line is longer than 512 bytes.
    #[error("key log line too long")]
    TooLong,
    /// The line does not have exactly three space-separated fields.
    #[error("key log line has the wrong number of fields")]
    WrongFieldCount,
    /// The label is not a known key log label.
    #[error("unknown key log label")]
    UnknownLabel,
    /// The client random or secret is not valid hex.
    #[error("invalid hex in key log line")]
    BadHex,
    /// The client random is not 32 bytes.
    #[error("client random must be 32 bytes")]
    BadClientRandomLength,
    /// The secret length is not valid for its label.
    #[error("secret length not valid for its label")]
    BadSecretLength,
    /// The line is not valid UTF-8.
    #[error("key log line is not valid UTF-8")]
    NotUtf8,
}

/// Secrets known for one TLS connection, keyed by its client random.
#[derive(Clone, Default)]
pub(crate) struct KeyEntry {
    /// TLS 1.2 master secret (`CLIENT_RANDOM`).
    pub(crate) tls12_master: Option<Zeroizing<[u8; 48]>>,
    /// TLS 1.3 `CLIENT_HANDSHAKE_TRAFFIC_SECRET`.
    pub(crate) tls13_client_hs: Option<Zeroizing<Vec<u8>>>,
    /// TLS 1.3 `CLIENT_TRAFFIC_SECRET_0`.
    pub(crate) tls13_client_app0: Option<Zeroizing<Vec<u8>>>,
}

impl fmt::Debug for KeyEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyEntry")
            .field("tls12_master", &self.tls12_master.as_ref().map(|_| "[redacted]"))
            .field("tls13_client_hs", &self.tls13_client_hs.as_ref().map(|_| "[redacted]"))
            .field("tls13_client_app0", &self.tls13_client_app0.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

#[derive(Default)]
struct StoreInner {
    map: HashMap<[u8; 32], KeyEntry>,
    order: VecDeque<[u8; 32]>,
}

/// Bounded, thread-safe store of TLS session secrets from a key log.
///
/// Fill it with [`KeyLogStore::insert_line`], or let the analyzer read a key log file
/// (see `KeylogSource`). Secrets cannot be read back through the public API, and `Debug`
/// prints only the number of entries. When more than `max_entries` connections are stored,
/// the oldest entry is evicted.
pub struct KeyLogStore {
    inner: RwLock<StoreInner>,
    max_entries: usize,
    accepted: AtomicU64,
    rejected: AtomicU64,
}

enum Label {
    ClientRandom,
    ClientHandshake,
    ClientTraffic0,
    Ignored,
}

impl KeyLogStore {
    /// Creates an empty store holding at most `max_entries` connections (minimum 1).
    #[must_use]
    pub fn new(max_entries: usize) -> Self {
        Self {
            inner: RwLock::new(StoreInner::default()),
            max_entries: max_entries.max(1),
            accepted: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
        }
    }

    /// Parses one NSS key log line and stores its secret.
    ///
    /// Blank lines, `#` comments and known labels huginn does not need (server secrets,
    /// exporter secrets, early traffic secrets) are accepted and ignored.
    ///
    /// # Errors
    /// Returns [`KeylogLineError`] when the line is malformed or has an unknown label. The
    /// error never contains the line itself.
    pub fn insert_line(&self, line: &str) -> Result<(), KeylogLineError> {
        let result = self.parse_and_insert(line);
        match &result {
            Ok(true) => {
                self.accepted.fetch_add(1, Ordering::Relaxed);
            }
            Ok(false) => {}
            Err(_) => {
                self.rejected.fetch_add(1, Ordering::Relaxed);
            }
        }
        result.map(|_| ())
    }

    /// Like [`Self::insert_line`] for raw bytes (used when following a file).
    pub(crate) fn insert_line_bytes(&self, line: &[u8]) -> Result<(), KeylogLineError> {
        match std::str::from_utf8(line) {
            Ok(text) => self.insert_line(text),
            Err(_) => {
                self.rejected.fetch_add(1, Ordering::Relaxed);
                Err(KeylogLineError::NotUtf8)
            }
        }
    }

    /// Counts one rejected line that never reached the parser (e.g. an over-long line
    /// discarded while following a file).
    pub(crate) fn count_rejected(&self) {
        self.rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// Number of connections with at least one stored secret.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .map
            .len()
    }

    /// `true` when no secrets are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub(crate) fn lines_accepted(&self) -> u64 {
        self.accepted.load(Ordering::Relaxed)
    }

    pub(crate) fn lines_rejected(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }

    /// Returns a copy of the secrets for `client_random`, if any.
    pub(crate) fn get(&self, client_random: &[u8; 32]) -> Option<KeyEntry> {
        self.inner
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .map
            .get(client_random)
            .cloned()
    }

    /// Forgets the secrets for `client_random` (the connection reached a terminal state).
    pub(crate) fn remove(&self, client_random: &[u8; 32]) {
        let mut inner = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        inner.map.remove(client_random);
        if inner.order.len() > self.max_entries.saturating_mul(2) {
            let StoreInner { map, order } = &mut *inner;
            order.retain(|k| map.contains_key(k));
        }
    }

    /// `Ok(true)` when a secret was stored or a known label ignored, `Ok(false)` for
    /// comments and blank lines.
    fn parse_and_insert(&self, line: &str) -> Result<bool, KeylogLineError> {
        if line.len() > MAX_LINE_LEN {
            return Err(KeylogLineError::TooLong);
        }
        let line = line.trim_end_matches(['\r', '\n']);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return Ok(false);
        }

        let mut fields = trimmed.split_ascii_whitespace();
        let (Some(label), Some(random_hex), Some(secret_hex), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(KeylogLineError::WrongFieldCount);
        };

        let label = match label {
            "CLIENT_RANDOM" => Label::ClientRandom,
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET" => Label::ClientHandshake,
            "CLIENT_TRAFFIC_SECRET_0" => Label::ClientTraffic0,
            "SERVER_HANDSHAKE_TRAFFIC_SECRET"
            | "SERVER_TRAFFIC_SECRET_0"
            | "EXPORTER_SECRET"
            | "EARLY_EXPORTER_SECRET"
            | "CLIENT_EARLY_TRAFFIC_SECRET" => Label::Ignored,
            _ => return Err(KeylogLineError::UnknownLabel),
        };

        let random = decode_hex(random_hex)?;
        let random: [u8; 32] = random
            .as_slice()
            .try_into()
            .map_err(|_| KeylogLineError::BadClientRandomLength)?;
        let secret = Zeroizing::new(decode_hex(secret_hex)?);

        let mut entry_update = KeyEntry::default();
        match label {
            Label::Ignored => return Ok(true),
            Label::ClientRandom => {
                let master: [u8; 48] = secret
                    .as_slice()
                    .try_into()
                    .map_err(|_| KeylogLineError::BadSecretLength)?;
                entry_update.tls12_master = Some(Zeroizing::new(master));
            }
            Label::ClientHandshake | Label::ClientTraffic0 => {
                if secret.len() != 32 && secret.len() != 48 {
                    return Err(KeylogLineError::BadSecretLength);
                }
                if matches!(label, Label::ClientHandshake) {
                    entry_update.tls13_client_hs = Some(secret);
                } else {
                    entry_update.tls13_client_app0 = Some(secret);
                }
            }
        }

        self.merge(random, entry_update);
        Ok(true)
    }

    fn merge(&self, random: [u8; 32], update: KeyEntry) {
        let mut inner = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        if !inner.map.contains_key(&random) {
            while inner.map.len() >= self.max_entries {
                let Some(oldest) = inner.order.pop_front() else {
                    break;
                };
                inner.map.remove(&oldest);
            }
            inner.order.push_back(random);
        }
        let entry = inner.map.entry(random).or_default();
        if update.tls12_master.is_some() {
            entry.tls12_master = update.tls12_master;
        }
        if update.tls13_client_hs.is_some() {
            entry.tls13_client_hs = update.tls13_client_hs;
        }
        if update.tls13_client_app0.is_some() {
            entry.tls13_client_app0 = update.tls13_client_app0;
        }
    }
}

impl fmt::Debug for KeyLogStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyLogStore")
            .field("entries", &self.len())
            .finish()
    }
}

fn decode_hex(text: &str) -> Result<Vec<u8>, KeylogLineError> {
    let bytes = text.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(KeylogLineError::BadHex);
    }
    bytes
        .chunks_exact(2)
        .map(|pair| match (hex_value(pair[0]), hex_value(pair[1])) {
            (Some(hi), Some(lo)) => Ok((hi << 4) | lo),
            _ => Err(KeylogLineError::BadHex),
        })
        .collect()
}

fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => c.checked_sub(b'0'),
        b'a'..=b'f' => c.checked_sub(b'a').and_then(|v| v.checked_add(10)),
        b'A'..=b'F' => c.checked_sub(b'A').and_then(|v| v.checked_add(10)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RANDOM: &str = "0102030405060708091011121314151617181920212223242526272829303132";

    fn random_bytes() -> [u8; 32] {
        match decode_hex(RANDOM) {
            Ok(v) => match v.as_slice().try_into() {
                Ok(a) => a,
                Err(_) => panic!("test random must be 32 bytes"),
            },
            Err(e) => panic!("test random must be hex: {e}"),
        }
    }

    #[test]
    fn accepts_the_three_used_labels_and_merges_them() {
        let store = KeyLogStore::new(10);
        let s32 = "aa".repeat(32);
        let s48 = "BB".repeat(48);
        assert_eq!(store.insert_line(&format!("CLIENT_RANDOM {RANDOM} {s48}")), Ok(()));
        assert_eq!(
            store.insert_line(&format!("CLIENT_HANDSHAKE_TRAFFIC_SECRET {RANDOM} {s32}\r\n")),
            Ok(())
        );
        assert_eq!(store.insert_line(&format!("CLIENT_TRAFFIC_SECRET_0 {RANDOM} {s48}")), Ok(()));
        assert_eq!(store.len(), 1);
        let Some(entry) = store.get(&random_bytes()) else {
            panic!("entry must exist");
        };
        assert!(entry.tls12_master.is_some());
        assert_eq!(entry.tls13_client_hs.as_ref().map(|s| s.len()), Some(32));
        assert_eq!(entry.tls13_client_app0.as_ref().map(|s| s.len()), Some(48));
        assert_eq!(store.lines_accepted(), 3);
    }

    #[test]
    fn ignores_comments_blank_lines_and_unused_labels() {
        let store = KeyLogStore::new(10);
        let s32 = "aa".repeat(32);
        for line in [
            "",
            "   ",
            "# SSL/TLS secrets log file, generated by OpenSSL",
            &format!("SERVER_HANDSHAKE_TRAFFIC_SECRET {RANDOM} {s32}"),
            &format!("SERVER_TRAFFIC_SECRET_0 {RANDOM} {s32}"),
            &format!("EXPORTER_SECRET {RANDOM} {s32}"),
            &format!("EARLY_EXPORTER_SECRET {RANDOM} {s32}"),
            &format!("CLIENT_EARLY_TRAFFIC_SECRET {RANDOM} {s32}"),
        ] {
            assert_eq!(store.insert_line(line), Ok(()), "line must be accepted: {line:?}");
        }
        assert!(store.is_empty());
        assert_eq!(store.lines_rejected(), 0);
    }

    #[test]
    fn rejects_malformed_lines() {
        let store = KeyLogStore::new(10);
        let s32 = "aa".repeat(32);
        let cases = [
            (format!("BOGUS_LABEL {RANDOM} {s32}"), KeylogLineError::UnknownLabel),
            (format!("CLIENT_RANDOM {RANDOM} abc"), KeylogLineError::BadHex),
            (format!("CLIENT_RANDOM {RANDOM} zz{}", "aa".repeat(47)), KeylogLineError::BadHex),
            (format!("CLIENT_RANDOM {RANDOM} {s32}"), KeylogLineError::BadSecretLength),
            (
                format!("CLIENT_TRAFFIC_SECRET_0 {RANDOM} {}", "aa".repeat(40)),
                KeylogLineError::BadSecretLength,
            ),
            (format!("CLIENT_RANDOM aabb {s32}"), KeylogLineError::BadClientRandomLength),
            (format!("CLIENT_RANDOM {RANDOM}"), KeylogLineError::WrongFieldCount),
            (format!("CLIENT_RANDOM {RANDOM} {s32} extra"), KeylogLineError::WrongFieldCount),
            (format!("CLIENT_RANDOM {RANDOM} {}", "a".repeat(600)), KeylogLineError::TooLong),
        ];
        for (line, expected) in &cases {
            assert_eq!(store.insert_line(line).as_ref(), Err(expected));
        }
        assert_eq!(
            store.insert_line_bytes(b"CLIENT_RANDOM \xff\xfe"),
            Err(KeylogLineError::NotUtf8)
        );
        assert!(store.is_empty());
        assert_eq!(
            store.lines_rejected(),
            u64::try_from(cases.len()).unwrap_or(0).saturating_add(1)
        );
    }

    #[test]
    fn evicts_oldest_entry_when_full() {
        let store = KeyLogStore::new(2);
        let s48 = "cc".repeat(48);
        for i in 0u8..3 {
            let random = format!("{i:02x}{}", "00".repeat(31));
            assert_eq!(store.insert_line(&format!("CLIENT_RANDOM {random} {s48}")), Ok(()));
        }
        assert_eq!(store.len(), 2);
        let mut first = [0u8; 32];
        assert!(store.get(&first).is_none(), "oldest entry must be evicted");
        first[0] = 2;
        assert!(store.get(&first).is_some());
    }

    #[test]
    fn debug_output_contains_no_secret_material() {
        let store = KeyLogStore::new(4);
        let secret = "de".repeat(48);
        assert_eq!(store.insert_line(&format!("CLIENT_RANDOM {RANDOM} {secret}")), Ok(()));
        let store_dbg = format!("{store:?}");
        assert_eq!(store_dbg, "KeyLogStore { entries: 1 }");
        let entry_dbg = match store.get(&random_bytes()) {
            Some(e) => format!("{e:?}"),
            None => panic!("entry must exist"),
        };
        assert!(!entry_dbg.to_lowercase().contains("dede"));
    }
}
