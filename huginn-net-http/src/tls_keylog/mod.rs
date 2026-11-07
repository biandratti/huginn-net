//! TLS key log decryption for Akamai HTTP/2 fingerprinting (`akamai-keylog` feature).
//!
//! A passive observer gets the session secrets of HTTP/2-over-TLS connections from a TLS key
//! log (NSS `SSLKEYLOGFILE` format) written by the operator's TLS terminator or clients,
//! decrypts the start of each client stream, and emits one [`crate::AkamaiOutput`] per
//! connection. Decrypted bytes are only fed to the Akamai fingerprint and are never exposed.

mod follow;
pub(crate) mod handshake;
pub(crate) mod reassembly;
pub(crate) mod record;
pub(crate) mod schedule;
pub(crate) mod session;
pub(crate) mod store;
mod tracker;

pub use store::{KeyLogStore, KeylogLineError};
pub use tracker::KeylogTracker;

use crate::error::HuginnNetHttpError;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Where the key log comes from.
#[derive(Debug, Clone)]
pub enum KeylogSource {
    /// Read the file once when the analyzer is configured (capture-file analysis).
    File(PathBuf),
    /// Read the file, then keep following lines appended to it (live analysis).
    Follow(PathBuf),
    /// A store the caller fills with [`KeyLogStore::insert_line`] (tests, embedding).
    Store(Arc<KeyLogStore>),
}

/// Key log decryption settings. Build with [`KeylogConfig::new`] and the setters.
#[derive(Debug, Clone)]
pub struct KeylogConfig {
    pub(crate) source: KeylogSource,
    pub(crate) pending_timeout: Duration,
    pub(crate) max_client_buffer: usize,
    pub(crate) max_server_buffer: usize,
    pub(crate) max_entries: usize,
    pub(crate) follow_interval: Duration,
}

impl KeylogConfig {
    /// Defaults: wait up to 2 s for a late secret, buffer up to 64 KiB of client and 16 KiB
    /// of server bytes per connection, keep up to 100 000 key log entries, poll a followed
    /// file every 100 ms.
    #[must_use]
    pub fn new(source: KeylogSource) -> Self {
        Self {
            source,
            pending_timeout: Duration::from_secs(2),
            max_client_buffer: 64 * 1024,
            max_server_buffer: 16 * 1024,
            max_entries: 100_000,
            follow_interval: Duration::from_millis(100),
        }
    }

    /// How long a connection waits for its secret (or a missing segment). Must be > 0.
    #[must_use]
    pub fn pending_timeout(mut self, timeout: Duration) -> Self {
        self.pending_timeout = timeout;
        self
    }

    /// Client bytes buffered per connection. Must be ≥ 16 KiB.
    #[must_use]
    pub fn max_client_buffer(mut self, bytes: usize) -> Self {
        self.max_client_buffer = bytes;
        self
    }

    /// Server bytes buffered per connection (only the ServerHello is needed). Must be ≥ 4 KiB.
    #[must_use]
    pub fn max_server_buffer(mut self, bytes: usize) -> Self {
        self.max_server_buffer = bytes;
        self
    }

    /// Maximum connections kept in the key log store (oldest evicted first). Must be ≥ 1.
    #[must_use]
    pub fn max_entries(mut self, entries: usize) -> Self {
        self.max_entries = entries;
        self
    }

    /// Polling period for [`KeylogSource::Follow`].
    #[must_use]
    pub fn follow_interval(mut self, interval: Duration) -> Self {
        self.follow_interval = interval;
        self
    }

    pub(crate) fn validate(&self) -> Result<(), HuginnNetHttpError> {
        let invalid = |msg: &str| Err(HuginnNetHttpError::Misconfiguration(msg.to_string()));
        if self.pending_timeout.is_zero() {
            return invalid("keylog pending_timeout must be > 0");
        }
        if self.max_client_buffer < 16 * 1024 {
            return invalid("keylog max_client_buffer must be >= 16 KiB");
        }
        if self.max_server_buffer < 4 * 1024 {
            return invalid("keylog max_server_buffer must be >= 4 KiB");
        }
        if self.max_entries < 1 {
            return invalid("keylog max_entries must be >= 1");
        }
        if self.follow_interval.is_zero() {
            return invalid("keylog follow_interval must be > 0");
        }
        Ok(())
    }
}

/// Snapshot of key log decryption counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct KeylogStats {
    /// Connections decrypted and fingerprinted.
    pub decrypted: u64,
    /// Connections dropped because no secret arrived in time.
    pub no_secret: u64,
    /// Connections with an unsupported TLS version or cipher suite.
    pub unsupported: u64,
    /// Connections whose records failed authentication (wrong or mismatched secret).
    pub auth_failed: u64,
    /// Connections dropped for missing data or buffer limits.
    pub reassembly: u64,
    /// Decrypted connections that were not HTTP/2.
    pub not_http2: u64,
    /// Connections with malformed TLS or HTTP/2 data.
    pub malformed: u64,
    /// Key log lines accepted.
    pub keylog_lines_accepted: u64,
    /// Key log lines rejected.
    pub keylog_lines_rejected: u64,
}

#[derive(Debug, Default)]
pub(crate) struct KeylogCounters {
    pub(crate) decrypted: AtomicU64,
    pub(crate) no_secret: AtomicU64,
    pub(crate) unsupported: AtomicU64,
    pub(crate) auth_failed: AtomicU64,
    pub(crate) reassembly: AtomicU64,
    pub(crate) not_http2: AtomicU64,
    pub(crate) malformed: AtomicU64,
}

impl KeylogCounters {
    pub(crate) fn record(&self, outcome: Option<session::Abandon>) {
        use session::Abandon;
        let counter = match outcome {
            None => &self.decrypted,
            Some(Abandon::NoSecret) => &self.no_secret,
            Some(Abandon::Unsupported) => &self.unsupported,
            Some(Abandon::AuthFailed) => &self.auth_failed,
            Some(Abandon::Reassembly) => &self.reassembly,
            Some(Abandon::NotHttp2) => &self.not_http2,
            Some(Abandon::Malformed) => &self.malformed,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn snapshot(&self, store: &KeyLogStore) -> KeylogStats {
        let load = |c: &AtomicU64| c.load(Ordering::Relaxed);
        KeylogStats {
            decrypted: load(&self.decrypted),
            no_secret: load(&self.no_secret),
            unsupported: load(&self.unsupported),
            auth_failed: load(&self.auth_failed),
            reassembly: load(&self.reassembly),
            not_http2: load(&self.not_http2),
            malformed: load(&self.malformed),
            keylog_lines_accepted: store.lines_accepted(),
            keylog_lines_rejected: store.lines_rejected(),
        }
    }
}
