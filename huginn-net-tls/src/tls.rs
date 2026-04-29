use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::fmt::{self};

/// TLS version for fingerprinting
/// Includes legacy SSL versions for complete JA4 specification compatibility.
/// Note: SSL 2.0 is not supported by tls-parser (too legacy/vulnerable)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsVersion {
    V1_3,
    V1_2,
    V1_1,
    V1_0,
    Ssl3_0,
    Ssl2_0,
    Unknown(u16),
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsVersion::V1_3 => write!(f, "13"),
            TlsVersion::V1_2 => write!(f, "12"),
            TlsVersion::V1_1 => write!(f, "11"),
            TlsVersion::V1_0 => write!(f, "10"),
            TlsVersion::Ssl3_0 => write!(f, "s3"),
            TlsVersion::Ssl2_0 => write!(f, "s2"),
            TlsVersion::Unknown(_) => write!(f, "00"),
        }
    }
}

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

/// See <https://datatracker.ietf.org/doc/html/draft-davidben-tls-grease-01#page-5>
pub const TLS_GREASE_VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// Check if a value is a GREASE value according to RFC 8701
fn is_grease_value(value: u16) -> bool {
    TLS_GREASE_VALUES.contains(&value)
}

/// Filter out GREASE values from a list of u16 values
fn filter_grease_values(values: &[u16]) -> Vec<u16> {
    values
        .iter()
        .filter(|&&v| !is_grease_value(v))
        .copied()
        .collect()
}

/// TLS Session Ticket extension (RFC 9149): ephemeral, varies per-connection
pub const TLS_EXT_SESSION_TICKET: u16 = 0x0023;
/// Pre-Shared Key extension (RFC 8446): ephemeral, varies per-connection
pub const TLS_EXT_PRE_SHARED_KEY: u16 = 0x0029;
/// Padding extension (RFC 7685): ephemeral, varies per-connection
pub const TLS_EXT_PADDING: u16 = 0x0015;

/// Ephemeral TLS extensions that may vary per-connection and break JA4 stability
pub const EPHEMERAL_TLS_EXTENSIONS: [u16; 3] =
    [TLS_EXT_SESSION_TICKET, TLS_EXT_PRE_SHARED_KEY, TLS_EXT_PADDING];

#[cfg(feature = "stable_v1")]
fn filter_ephemeral_extensions(values: &[u16]) -> Cow<'_, [u16]> {
    if values
        .iter()
        .any(|v| matches!(v, &TLS_EXT_SESSION_TICKET | &TLS_EXT_PRE_SHARED_KEY | &TLS_EXT_PADDING))
    {
        Cow::Owned(
            values
                .iter()
                .copied()
                .filter(|v| {
                    !matches!(
                        v,
                        &TLS_EXT_SESSION_TICKET | &TLS_EXT_PRE_SHARED_KEY | &TLS_EXT_PADDING
                    )
                })
                .collect(),
        )
    } else {
        Cow::Borrowed(values)
    }
}

enum Ja4Mode {
    Sorted,
    Unsorted,
    #[cfg(feature = "stable_v1")]
    StableV1,
}

impl Ja4Mode {
    fn is_original_order(&self) -> bool {
        matches!(self, Ja4Mode::Unsorted)
    }

    #[cfg(feature = "stable_v1")]
    fn is_exclude_ephemeral(&self) -> bool {
        matches!(self, Ja4Mode::StableV1)
    }

    fn into_fingerprints(self, hashed: String, raw: String) -> (Ja4Fingerprint, Ja4RawFingerprint) {
        match self {
            Ja4Mode::Sorted => (Ja4Fingerprint::Sorted(hashed), Ja4RawFingerprint::Sorted(raw)),
            Ja4Mode::Unsorted => {
                (Ja4Fingerprint::Unsorted(hashed), Ja4RawFingerprint::Unsorted(raw))
            }
            #[cfg(feature = "stable_v1")]
            Ja4Mode::StableV1 => {
                (Ja4Fingerprint::StableV1(hashed), Ja4RawFingerprint::StableV1(raw))
            }
        }
    }
}

/// TLS ClientHello Signature
#[derive(Debug, Clone, PartialEq)]
pub struct Signature {
    /// TLS version (used in JA4_a)
    pub version: TlsVersion,
    /// Cipher suites (used in JA4_b)
    pub cipher_suites: Vec<u16>,
    /// Extensions (used in JA4_c)
    pub extensions: Vec<u16>,
    /// Elliptic curves (parsed for completeness, not used in JA4)
    pub elliptic_curves: Vec<u16>,
    /// Elliptic curve point formats (parsed for completeness, not used in JA4)
    pub elliptic_curve_point_formats: Vec<u8>,
    /// Signature algorithms (used in JA4_c)
    pub signature_algorithms: Vec<u16>,
    /// Server Name Indication (used in JA4_a)
    pub sni: Option<String>,
    /// Application-Layer Protocol Negotiation (used in JA4_a)
    pub alpn: Option<String>,
}

/// Extract first and last characters from ALPN string, replacing non-ASCII with '9'
pub fn first_last_alpn(s: &str) -> (char, char) {
    let replace_nonascii_with_9 = |c: char| {
        if c.is_ascii() {
            c
        } else {
            '9'
        }
    };
    let mut chars = s.chars();
    let first = chars.next().map(replace_nonascii_with_9).unwrap_or('0');
    let last = chars
        .next_back()
        .map(replace_nonascii_with_9)
        .unwrap_or('0');
    (first, if s.len() == 1 { '0' } else { last })
}

/// Generate 12-character hash (first 12 chars of SHA256)
pub fn hash12(input: &str) -> String {
    // 12 hex chars = 6 bytes
    use std::fmt::Write;
    Sha256::digest(input.as_bytes())[..6]
        .iter()
        .fold(String::with_capacity(12), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

impl Signature {
    /// Generate JA4 fingerprint according to official FoxIO specification
    pub fn generate_ja4(&self) -> Ja4Payload {
        self.compute_ja4(Ja4Mode::Sorted)
    }

    /// Generate JA4 fingerprint with original order
    pub fn generate_ja4_original(&self) -> Ja4Payload {
        self.compute_ja4(Ja4Mode::Unsorted)
    }

    /// Generate JA4 fingerprint with ephemeral extensions excluded (sorted)
    #[cfg(feature = "stable_v1")]
    pub fn generate_ja4_stable_v1(&self) -> Ja4Payload {
        self.compute_ja4(Ja4Mode::StableV1)
    }

    /// Core JA4 computation. Returns Ja4Payload(ja4_a, ja4_b_raw, ja4_c_raw, ja4_hashed, ja4_raw_full)
    fn compute_ja4(&self, mode: Ja4Mode) -> Ja4Payload {
        let original_order = mode.is_original_order();

        #[cfg(feature = "stable_v1")]
        let extensions_after_exclude: Cow<[u16]> = if mode.is_exclude_ephemeral() {
            filter_ephemeral_extensions(&self.extensions)
        } else {
            Cow::Borrowed(&self.extensions)
        };
        #[cfg(not(feature = "stable_v1"))]
        let extensions_after_exclude: Cow<[u16]> = Cow::Borrowed(&self.extensions);

        // Filter out GREASE values from cipher suites for JA4_b and JA4_c processing
        let filtered_ciphers = filter_grease_values(&self.cipher_suites);
        let filtered_extensions = filter_grease_values(&extensions_after_exclude);
        let filtered_sig_algs = filter_grease_values(&self.signature_algorithms);

        // Protocol marker (always 't' for TLS, 'q' for QUIC)
        let protocol = "t";

        // TLS version
        let tls_version_str = format!("{}", self.version);

        // SNI indicator: 'd' if SNI present, 'i' if not
        let sni_indicator = if self.sni.is_some() { "d" } else { "i" };

        // Cipher count in 2-digit decimal (max 99) - use ORIGINAL count before filtering
        let cipher_count = format!("{:02}", self.cipher_suites.len().min(99));

        // Extension count in 2-digit decimal (max 99) - after exclusions, before GREASE filtering
        let extension_count = format!("{:02}", extensions_after_exclude.len().min(99));

        // ALPN first and last characters
        let (alpn_first, alpn_last) = match &self.alpn {
            Some(alpn) => first_last_alpn(alpn),
            None => ('0', '0'),
        };

        // JA4_a format: protocol + version + sni + cipher_count + extension_count + alpn_first + alpn_last
        let ja4_a = format!(
            "{protocol}{tls_version_str}{sni_indicator}{cipher_count}{extension_count}{alpn_first}{alpn_last}"
        );

        // JA4_b: Cipher suites (sorted or original order, comma-separated, 4-digit hex) - GREASE filtered
        let mut ciphers_for_b = filtered_ciphers;
        if !original_order {
            ciphers_for_b.sort_unstable();
        }
        let ja4_b_raw = ciphers_for_b
            .iter()
            .map(|c| format!("{c:04x}"))
            .collect::<Vec<String>>()
            .join(",");

        // JA4_c: Extensions (sorted or original order, comma-separated, 4-digit hex) + "_" + signature algorithms
        let mut extensions_for_c = filtered_extensions;

        // For sorted version: Remove SNI (0x0000) and ALPN (0x0010) from extensions AND sort
        // For original version: Keep SNI/ALPN and preserve original order
        if !original_order {
            extensions_for_c.retain(|&ext| ext != 0x0000 && ext != 0x0010);
            extensions_for_c.sort_unstable();
        }

        let extensions_str = extensions_for_c
            .iter()
            .map(|e| format!("{e:04x}"))
            .collect::<Vec<String>>()
            .join(",");

        // Signature algorithms are NOT sorted according to the official spec
        // But GREASE values are filtered
        let sig_algs_str = filtered_sig_algs
            .iter()
            .map(|s| format!("{s:04x}"))
            .collect::<Vec<String>>()
            .join(",");

        // According to the specification, "if there are no signature algorithms in the
        // Hello packet, then the string ends without an underscore".
        let ja4_c_raw = if sig_algs_str.is_empty() {
            extensions_str
        } else if extensions_str.is_empty() {
            sig_algs_str
        } else {
            format!("{extensions_str}_{sig_algs_str}")
        };

        // JA4 raw: ja4_a + "_" + ja4_b_raw + "_" + ja4_c_raw
        let ja4_raw_full = format!("{ja4_a}_{ja4_b_raw}_{ja4_c_raw}");

        // Generate hashes for JA4_b and JA4_c (first 12 characters of SHA256)
        let ja4_b_hash = hash12(&ja4_b_raw);
        let ja4_c_hash = hash12(&ja4_c_raw);

        // JA4 hashed: ja4_a + "_" + ja4_b_hash + "_" + ja4_c_hash
        let ja4_hashed = format!("{ja4_a}_{ja4_b_hash}_{ja4_c_hash}");

        let (ja4_fingerprint, ja4_raw_fingerprint) =
            mode.into_fingerprints(ja4_hashed, ja4_raw_full);
        Ja4Payload {
            ja4_a,
            ja4_b: ja4_b_raw,
            ja4_c: ja4_c_raw,
            full: ja4_fingerprint,
            raw: ja4_raw_fingerprint,
        }
    }
}
