//! Glue between [`huginn_net_http::observable`] and the database matcher
//! infrastructure.
//!
//! Provides:
//! - The [`HttpDistance`] bridge trait. Each method delegates to a pure free
//!   function in [`super::distances`]; the trait exists to preserve the
//!   public API (external callers use `<X as HttpDistance>::distance_header`)
//!   and to give observation types a uniform interface. New internal code
//!   should call the free functions directly, mirroring TCP.
//! - The [`crate::db_matching_trait::ObservedFingerprint`] impls for
//!   [`HttpRequestObservation`] and [`HttpResponseObservation`].
//! - The [`crate::db_matching_trait::DatabaseSignature`] impls scoring
//!   `http::Signature` against either observation type.
//!
//! For backward compatibility this module is re-exposed at the crate root as
//! `huginn_net_db::observable_http_signals_matching` via a `#[path]` shim in
//! `lib.rs`.

use crate::database::HttpIndexKey;
use crate::db_matching_trait::{DatabaseSignature, MatchQuality, ObservedFingerprint};
use crate::http::{self, distance_expsw, distance_header, distance_http_version, Header, Version};
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

/// Bridge between an observation type and the pure distance helpers in
/// [`crate::http`].
///
/// Each method is a thin wrapper around the corresponding free function in
/// `crate::http::distances`. The trait exists to give observations
/// (`HttpRequestObservation`, `HttpResponseObservation`) a uniform interface
/// and to preserve the public API; new code should prefer the free functions
/// directly, mirroring how [`crate::tcp::distance_ttl`] etc. are used.
pub trait HttpDistance {
    fn get_version(&self) -> Version;
    fn get_horder(&self) -> &[Header];
    fn get_habsent(&self) -> &[Header];
    fn get_expsw(&self) -> &str;

    fn distance_ip_version(&self, other: &http::Signature) -> Option<u32> {
        distance_http_version(self.get_version(), other.version)
    }

    /// Compare two header vectors respecting order and allowing optional
    /// header skips. Delegates to [`crate::http::distance_header`].
    fn distance_header(observed: &[Header], signature: &[Header]) -> Option<u32> {
        distance_header(observed, signature)
    }

    fn distance_horder(&self, other: &http::Signature) -> Option<u32> {
        distance_header(self.get_horder(), &other.horder)
    }

    fn distance_habsent(&self, other: &http::Signature) -> Option<u32> {
        distance_header(self.get_habsent(), &other.habsent)
    }

    fn distance_expsw(&self, other: &http::Signature) -> Option<u32> {
        distance_expsw(self.get_expsw(), &other.expsw)
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
    fn calculate_http_distance<T: HttpDistance>(&self, observed: &T) -> Option<u32>;

    fn generate_http_index_keys(&self) -> Vec<HttpIndexKey>;

    /// Returns the quality score based on the distance.
    ///
    /// The score is a value between 0.0 and 1.0, where 1.0 is a perfect match.
    ///
    /// The score is calculated based on the distance of the observed signal to the database signature.
    /// The distance is a value between 0 and 12, where 0 is a perfect match and 12 is the maximum possible distance.
    fn get_quality_score_by_distance(&self, distance: u32) -> f32 {
        http::HttpMatchQuality::distance_to_score(distance)
    }
}

impl HttpSignatureHelper for http::Signature {
    fn calculate_http_distance<T: HttpDistance>(&self, observed: &T) -> Option<u32> {
        let distance = distance_http_version(observed.get_version(), self.version)?
            .saturating_add(distance_header(observed.get_horder(), &self.horder)?)
            .saturating_add(distance_header(observed.get_habsent(), &self.habsent)?)
            .saturating_add(distance_expsw(observed.get_expsw(), &self.expsw)?);
        Some(distance)
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
    fn calculate_distance(&self, observed: &HttpRequestObservation) -> Option<u32> {
        self.calculate_http_distance(observed)
    }
    fn get_quality_score(&self, distance: u32) -> f32 {
        self.get_quality_score_by_distance(distance)
    }
    fn generate_index_keys_for_db_entry(&self) -> Vec<HttpIndexKey> {
        self.generate_http_index_keys()
    }
}

impl DatabaseSignature<HttpResponseObservation> for http::Signature {
    fn calculate_distance(&self, observed: &HttpResponseObservation) -> Option<u32> {
        self.calculate_http_distance(observed)
    }
    fn get_quality_score(&self, distance: u32) -> f32 {
        self.get_quality_score_by_distance(distance)
    }
    fn generate_index_keys_for_db_entry(&self) -> Vec<HttpIndexKey> {
        self.generate_http_index_keys()
    }
}
