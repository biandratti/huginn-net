#[cfg(feature = "stable-v1")]
use super::grease::filter_ephemeral_extensions;
use super::grease::filter_grease_values;
use super::ja4::{Ja4Mode, Ja4Payload};
use super::version::TlsVersion;
use sha2::{Digest, Sha256};
#[cfg(feature = "stable-v1")]
use std::borrow::Cow;
use std::fmt::Write as _;

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
    let replace_nonascii_with_9 = |c: char| if c.is_ascii() { c } else { '9' };
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
    Sha256::digest(input.as_bytes())[..6]
        .iter()
        .fold(String::with_capacity(12), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

impl Signature {
    /// Generate JA4 fingerprint according to official FoxIO specification
    #[inline]
    pub fn generate_ja4(&self) -> Ja4Payload {
        self.compute_ja4(Ja4Mode::Sorted)
    }

    /// Generate JA4 fingerprint with original order
    #[inline]
    pub fn generate_ja4_original(&self) -> Ja4Payload {
        self.compute_ja4(Ja4Mode::Unsorted)
    }

    /// Generate JA4 fingerprint with ephemeral extensions excluded (sorted)
    #[cfg(feature = "stable-v1")]
    #[cfg_attr(docsrs, doc(cfg(feature = "stable-v1")))]
    #[inline]
    pub fn generate_ja4_stable_v1(&self) -> Ja4Payload {
        self.compute_ja4(Ja4Mode::StableV1)
    }

    /// Core JA4 computation
    fn compute_ja4(&self, mode: Ja4Mode) -> Ja4Payload {
        let original_order = mode.is_original_order();

        #[cfg(feature = "stable-v1")]
        let extensions_after_exclude: Cow<[u16]> = if mode.is_exclude_ephemeral() {
            filter_ephemeral_extensions(&self.extensions)
        } else {
            Cow::Borrowed(&self.extensions)
        };
        #[cfg(not(feature = "stable-v1"))]
        let extensions_after_exclude: std::borrow::Cow<[u16]> =
            std::borrow::Cow::Borrowed(&self.extensions);

        let filtered_ciphers = filter_grease_values(&self.cipher_suites);
        let filtered_extensions = filter_grease_values(&extensions_after_exclude);
        let filtered_sig_algs = filter_grease_values(&self.signature_algorithms);

        let protocol = "t";
        let tls_version_str = format!("{}", self.version);
        let sni_indicator = if self.sni.is_some() { "d" } else { "i" };
        let cipher_count = format!("{:02}", self.cipher_suites.len().min(99));
        let extension_count = format!("{:02}", extensions_after_exclude.len().min(99));

        let (alpn_first, alpn_last) = match &self.alpn {
            Some(alpn) => first_last_alpn(alpn),
            None => ('0', '0'),
        };

        let ja4_a = format!(
            "{protocol}{tls_version_str}{sni_indicator}{cipher_count}{extension_count}{alpn_first}{alpn_last}"
        );

        let mut ciphers_for_b = filtered_ciphers;
        if !original_order {
            ciphers_for_b.sort_unstable();
        }
        let mut ja4_b_raw = String::with_capacity(ciphers_for_b.len().saturating_mul(5));
        for (i, &c) in ciphers_for_b.iter().enumerate() {
            if i > 0 {
                ja4_b_raw.push(',');
            }
            let _ = write!(ja4_b_raw, "{c:04x}");
        }

        let mut extensions_for_c = filtered_extensions;
        if !original_order {
            extensions_for_c.retain(|&ext| ext != 0x0000 && ext != 0x0010);
            extensions_for_c.sort_unstable();
        }

        let mut extensions_str = String::with_capacity(extensions_for_c.len().saturating_mul(5));
        for (i, &e) in extensions_for_c.iter().enumerate() {
            if i > 0 {
                extensions_str.push(',');
            }
            let _ = write!(extensions_str, "{e:04x}");
        }

        let mut sig_algs_str = String::with_capacity(filtered_sig_algs.len().saturating_mul(5));
        for (i, &s) in filtered_sig_algs.iter().enumerate() {
            if i > 0 {
                sig_algs_str.push(',');
            }
            let _ = write!(sig_algs_str, "{s:04x}");
        }

        let ja4_c_raw = if sig_algs_str.is_empty() {
            extensions_str
        } else if extensions_str.is_empty() {
            sig_algs_str
        } else {
            format!("{extensions_str}_{sig_algs_str}")
        };

        let ja4_raw_full = format!("{ja4_a}_{ja4_b_raw}_{ja4_c_raw}");
        let ja4_b_hash = hash12(&ja4_b_raw);
        let ja4_c_hash = hash12(&ja4_c_raw);
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
