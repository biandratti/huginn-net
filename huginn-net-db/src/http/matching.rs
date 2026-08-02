//! Glue between [`huginn_net_http::observable`] and the database matcher
//! infrastructure.
//!
//! Provides:
//! - The [`HttpDistance`] bridge trait. Each method delegates to a pure free
//!   function ([`crate::http::headers_match`], etc., re-exported from the
//!   private `crate::http::distances` module); the trait exists to preserve
//!   the public API (external callers use
//!   `<X as HttpDistance>::headers_match`) and to give observation types a
//!   uniform interface. New internal code should call the free functions
//!   directly, mirroring TCP.
//! - The [`crate::db_matching_trait::ObservedFingerprint`] impls for
//!   [`HttpRequestObservation`] and [`HttpResponseObservation`].
//! - The [`crate::db_matching_trait::DatabaseSignature`] impls comparing
//!   `http::Signature` against either observation type.
//!
//! For backward compatibility this module is re-exposed at the crate root as
//! `huginn_net_db::observable_http_signals_matching` via a `#[path]` shim in
//! `lib.rs`.

use crate::database::HttpIndexKey;
use crate::db_matching_trait::{DatabaseSignature, NoFuzziness, ObservedFingerprint, SignatureFit};
use crate::http::{
    self, absent_headers_match, expsw_matches, headers_match, http_version_matches, Header, Version,
};
use huginn_net_http::observable::{HttpRequestObservation, HttpResponseObservation};

impl ObservedFingerprint for HttpRequestObservation {
    type Key = HttpIndexKey;

    fn generate_index_key(&self) -> Self::Key {
        HttpIndexKey { http_version_key: self.version }
    }
}

impl ObservedFingerprint for HttpResponseObservation {
    type Key = HttpIndexKey;

    fn generate_index_key(&self) -> Self::Key {
        HttpIndexKey { http_version_key: self.version }
    }
}

/// Bridge between an observation type and the pure gate helpers in
/// [`crate::http`].
///
/// Each method is a thin wrapper around the corresponding free function in
/// `crate::http::distances`. The trait exists to give observations
/// (`HttpRequestObservation`, `HttpResponseObservation`) a uniform interface
/// and to preserve the public API; new code should prefer the free functions
/// directly, mirroring how [`crate::tcp::ttl_fit`] etc. are used.
pub trait HttpDistance {
    fn get_version(&self) -> Version;
    fn get_horder(&self) -> &[Header];
    fn get_habsent(&self) -> &[Header];
    fn get_expsw(&self) -> &str;

    fn version_matches(&self, other: &http::Signature) -> bool {
        http_version_matches(self.get_version(), other.version)
    }

    /// Check that every header the signature expects appears in the observed
    /// list, in order. Delegates to [`crate::http::headers_match`].
    fn headers_match(observed: &[Header], signature: &[Header]) -> bool {
        headers_match(observed, signature)
    }

    fn horder_matches(&self, other: &http::Signature) -> bool {
        headers_match(self.get_horder(), &other.horder)
    }

    /// The signature's forbidden headers are checked against the headers
    /// actually seen, so this reads `horder`, not the observation's own
    /// `habsent`. See [`crate::http::absent_headers_match`].
    fn absent_headers_match(&self, other: &http::Signature) -> bool {
        absent_headers_match(self.get_horder(), &other.habsent)
    }

    /// Whether the traffic's software string backs up what the signature
    /// declares. Not part of the distance; see [`crate::http::expsw_matches`].
    fn expsw_matches(&self, other: &http::Signature) -> bool {
        expsw_matches(self.get_expsw(), &other.expsw)
    }
}

impl HttpDistance for HttpRequestObservation {
    fn get_version(&self) -> Version {
        self.version
    }
    fn get_horder(&self) -> &[Header] {
        &self.horder
    }
    fn get_habsent(&self) -> &[Header] {
        &self.habsent
    }
    fn get_expsw(&self) -> &str {
        &self.expsw
    }
}

impl HttpDistance for HttpResponseObservation {
    fn get_version(&self) -> Version {
        self.version
    }
    fn get_horder(&self) -> &[Header] {
        &self.horder
    }
    fn get_habsent(&self) -> &[Header] {
        &self.habsent
    }
    fn get_expsw(&self) -> &str {
        &self.expsw
    }
}

trait HttpSignatureHelper {
    fn http_fit<T: HttpDistance>(&self, observed: &T) -> Option<SignatureFit<NoFuzziness>>;

    fn generate_http_index_keys(&self) -> Vec<HttpIndexKey>;
}

impl HttpSignatureHelper for http::Signature {
    /// Every HTTP field is a gate. p0f has no fuzzy tier for HTTP — it keeps a
    /// generic fallback and nothing else (`fp_http.c:162-282`) — so a fit is
    /// always exact, and there is nothing to measure for tie-breaks: two
    /// signatures that both fit are separated by their order in the database.
    ///
    /// `expsw` is deliberately absent: p0f checks it only after a signature has
    /// been chosen, and a mismatch flags the host as dishonest instead of
    /// making the signature fit any worse.
    fn http_fit<T: HttpDistance>(&self, observed: &T) -> Option<SignatureFit<NoFuzziness>> {
        let gates = http_version_matches(observed.get_version(), self.version)
            && headers_match(observed.get_horder(), &self.horder)
            && absent_headers_match(observed.get_horder(), &self.habsent);

        gates.then(SignatureFit::exact)
    }

    fn generate_http_index_keys(&self) -> Vec<HttpIndexKey> {
        let mut keys = Vec::new();
        if self.version == Version::Any {
            keys.push(HttpIndexKey { http_version_key: Version::V10 });
            keys.push(HttpIndexKey { http_version_key: Version::V11 });
        } else {
            keys.push(HttpIndexKey { http_version_key: self.version });
        }
        keys
    }
}

impl DatabaseSignature<HttpRequestObservation> for http::Signature {
    type Fuzziness = NoFuzziness;

    fn fit(&self, observed: &HttpRequestObservation) -> Option<SignatureFit<NoFuzziness>> {
        self.http_fit(observed)
    }
    fn generate_index_keys_for_db_entry(&self) -> Vec<HttpIndexKey> {
        self.generate_http_index_keys()
    }
}

impl DatabaseSignature<HttpResponseObservation> for http::Signature {
    type Fuzziness = NoFuzziness;

    fn fit(&self, observed: &HttpResponseObservation) -> Option<SignatureFit<NoFuzziness>> {
        self.http_fit(observed)
    }
    fn generate_index_keys_for_db_entry(&self) -> Vec<HttpIndexKey> {
        self.generate_http_index_keys()
    }
}
