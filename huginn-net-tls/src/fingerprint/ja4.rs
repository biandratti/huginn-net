use std::fmt;

/// JA4 Fingerprint - sorted/unsorted (original)
#[derive(Debug, Clone, PartialEq)]
pub enum Ja4Fingerprint {
    Sorted(String),
    Unsorted(String),
    /// JA4 with ephemeral extensions excluded
    StableV1(String),
}

impl fmt::Display for Ja4Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ja4Fingerprint::Sorted(s) => write!(f, "{s}"),
            Ja4Fingerprint::Unsorted(s) => write!(f, "{s}"),
            Ja4Fingerprint::StableV1(s) => write!(f, "{s}"),
        }
    }
}

impl Ja4Fingerprint {
    pub fn variant_name(&self) -> &'static str {
        match self {
            Ja4Fingerprint::Sorted(_) => "ja4",
            Ja4Fingerprint::Unsorted(_) => "ja4_o",
            Ja4Fingerprint::StableV1(_) => "ja4_s1",
        }
    }

    pub fn value(&self) -> &str {
        match self {
            Ja4Fingerprint::Sorted(s) => s,
            Ja4Fingerprint::Unsorted(s) => s,
            Ja4Fingerprint::StableV1(s) => s,
        }
    }
}

/// JA4 Raw Fingerprint (full version) - sorted/unsorted (original)
#[derive(Debug, Clone, PartialEq)]
pub enum Ja4RawFingerprint {
    Sorted(String),
    Unsorted(String),
    /// JA4 raw with ephemeral extensions excluded
    StableV1(String),
}

impl fmt::Display for Ja4RawFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ja4RawFingerprint::Sorted(s) => write!(f, "{s}"),
            Ja4RawFingerprint::Unsorted(s) => write!(f, "{s}"),
            Ja4RawFingerprint::StableV1(s) => write!(f, "{s}"),
        }
    }
}

impl Ja4RawFingerprint {
    pub fn variant_name(&self) -> &'static str {
        match self {
            Ja4RawFingerprint::Sorted(_) => "ja4_r",
            Ja4RawFingerprint::Unsorted(_) => "ja4_ro",
            Ja4RawFingerprint::StableV1(_) => "ja4_rs1",
        }
    }

    pub fn value(&self) -> &str {
        match self {
            Ja4RawFingerprint::Sorted(s) => s,
            Ja4RawFingerprint::Unsorted(s) => s,
            Ja4RawFingerprint::StableV1(s) => s,
        }
    }
}

/// JA4 Payload structure following official FoxIO specification
/// Uses elegant sorted/unsorted enums like the original rustica_tls implementation
#[derive(Debug, Clone, PartialEq)]
pub struct Ja4Payload {
    /// JA4_a: TLS version + SNI + cipher count + extension count + ALPN
    pub ja4_a: String,
    /// JA4_b: Cipher suites (sorted or original order)
    pub ja4_b: String,
    /// JA4_c: Extensions + signature algorithms (sorted or original order)
    pub ja4_c: String,
    /// JA4 fingerprint (hashed, sorted/unsorted)
    pub full: Ja4Fingerprint,
    /// JA4 raw fingerprint (full, sorted/unsorted)
    pub raw: Ja4RawFingerprint,
}

/// Controls the order and filtering mode for JA4 computation
pub(super) enum Ja4Mode {
    Sorted,
    Unsorted,
    #[cfg(feature = "stable-v1")]
    StableV1,
}

impl Ja4Mode {
    pub(super) fn is_original_order(&self) -> bool {
        matches!(self, Ja4Mode::Unsorted)
    }

    #[cfg(feature = "stable-v1")]
    pub(super) fn is_exclude_ephemeral(&self) -> bool {
        matches!(self, Ja4Mode::StableV1)
    }

    pub(super) fn into_fingerprints(
        self,
        hashed: String,
        raw: String,
    ) -> (Ja4Fingerprint, Ja4RawFingerprint) {
        match self {
            Ja4Mode::Sorted => (Ja4Fingerprint::Sorted(hashed), Ja4RawFingerprint::Sorted(raw)),
            Ja4Mode::Unsorted => {
                (Ja4Fingerprint::Unsorted(hashed), Ja4RawFingerprint::Unsorted(raw))
            }
            #[cfg(feature = "stable-v1")]
            Ja4Mode::StableV1 => {
                (Ja4Fingerprint::StableV1(hashed), Ja4RawFingerprint::StableV1(raw))
            }
        }
    }
}
