//! Per-connection Akamai HTTP/2 fingerprint result emitted by the analysis pipeline.

use super::common::IpPort;
use crate::akamai::AkamaiFingerprint;
use std::fmt;

/// TLS protocol version of a connection whose HTTP/2 bytes were decrypted with a key log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub enum TlsVersion {
    /// TLS 1.2
    #[cfg_attr(feature = "json", serde(rename = "tls1.2"))]
    Tls12,
    /// TLS 1.3
    #[cfg_attr(feature = "json", serde(rename = "tls1.3"))]
    Tls13,
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TlsVersion::Tls12 => "tls1.2",
            TlsVersion::Tls13 => "tls1.3",
        })
    }
}

/// How the client's HTTP/2 bytes were made readable.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[cfg_attr(feature = "json", serde(tag = "kind", rename_all = "snake_case"))]
#[non_exhaustive]
pub enum AkamaiTransport {
    /// Cleartext HTTP/2 ("h2c"), prior knowledge or `Upgrade: h2c`.
    Cleartext,
    /// HTTP/2 over TLS, decrypted with secrets from a TLS key log.
    TlsDecrypted {
        /// Negotiated TLS version.
        version: TlsVersion,
        /// Negotiated cipher suite (IANA value, e.g. `0x1301`).
        cipher_suite: u16,
    },
}

impl fmt::Display for AkamaiTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AkamaiTransport::Cleartext => f.write_str("cleartext"),
            AkamaiTransport::TlsDecrypted { version, cipher_suite } => {
                write!(f, "{version} decrypted (0x{cipher_suite:04x})")
            }
        }
    }
}

/// One Akamai HTTP/2 client fingerprint observed on a connection.
///
/// Emitted at most once per connection, in [`crate::HttpAnalysisResult::http_akamai`].
/// The type is `#[non_exhaustive]` so that a match outcome can be added later without a
/// breaking change.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[non_exhaustive]
pub struct AkamaiOutput {
    /// Client endpoint.
    pub source: IpPort,
    /// Server endpoint.
    pub destination: IpPort,
    /// How the HTTP/2 bytes were obtained.
    pub transport: AkamaiTransport,
    /// The fingerprint, identical to the standalone extractor's output for the same bytes.
    pub fingerprint: AkamaiFingerprint,
}

impl AkamaiOutput {
    /// Builds an output value. Used by the pipeline; exposed for tests and downstream tooling.
    #[must_use]
    pub fn new(
        source: IpPort,
        destination: IpPort,
        transport: AkamaiTransport,
        fingerprint: AkamaiFingerprint,
    ) -> Self {
        Self { source, destination, transport, fingerprint }
    }
}

impl fmt::Display for AkamaiOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[HTTP Akamai Request] {}:{} → {}:{}\n\
              Transport: {}\n\
              Sig:       {}\n",
            self.source.ip,
            self.source.port,
            self.destination.ip,
            self.destination.port,
            self.transport,
            self.fingerprint.fingerprint
        )
    }
}
