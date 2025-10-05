use crate::db::HttpIndexKey;
use crate::db_matching_trait::{DatabaseSignature, MatchQuality};
use crate::http::{self, Header, HttpMatchQuality, Version};
use crate::observable_signals::{HttpRequestObservation, HttpResponseObservation};

pub trait HttpDistance {
    fn get_version(&self) -> Version;
    fn get_horder(&self) -> &[Header];
    fn get_habsent(&self) -> &[Header];
    fn get_expsw(&self) -> &str;

    fn distance_ip_version(&self, other: &http::Signature) -> Option<u32> {
        if other.version == Version::Any || self.get_version() == other.version {
            Some(HttpMatchQuality::High.as_score())
        } else {
            None
        }
    }

    // Compare two header vectors respecting order and allowing optional header skips
    //
    // This function implements a sophisticated two-pointer algorithm to compare HTTP headers
    // from observed traffic against database signatures while preserving order and handling
    // optional headers that may be missing from the observed traffic.
    //
    // Algorithm Overview:
    // 1. Use two pointers to traverse both lists simultaneously
    // 2. When headers match perfectly (name + value), advance both pointers
    // 3. When names match but values differ, count as error only if header is required
    // 4. When names differ, skip optional signature headers or count required ones as errors
    // 5. Handle remaining headers at the end of either list
    //
    // Parameters:
    // - observed: Headers from actual HTTP traffic (never marked as optional)
    // - signature: Headers from database signature (may have optional headers marked with ?)
    //
    // Returns:
    // - Some(score) based on error count converted to quality score
    // - None if too many errors (unmatchable)
    fn distance_header(observed: &[Header], signature: &[Header]) -> Option<u32> {
        let mut obs_idx = 0usize; // Index pointer for observed headers
        let mut sig_idx = 0usize; // Index pointer for signature headers
        let mut errors: u32 = 0; // Running count of matching errors

        while obs_idx < observed.len() && sig_idx < signature.len() {
            let obs_header = &observed[obs_idx];
            let sig_header = &signature[sig_idx];

            if obs_header.name == sig_header.name && obs_header.value == sig_header.value {
                obs_idx = obs_idx.saturating_add(1);
                sig_idx = sig_idx.saturating_add(1);
            } else if obs_header.name == sig_header.name {
                if !sig_header.optional {
                    errors = errors.saturating_add(1);
                }
                obs_idx = obs_idx.saturating_add(1);
                sig_idx = sig_idx.saturating_add(1);
            } else if sig_header.optional {
                sig_idx = sig_idx.saturating_add(1);
            } else {
                errors = errors.saturating_add(1);
                sig_idx = sig_idx.saturating_add(1);
            }
        }

        while obs_idx < observed.len() {
            errors = errors.saturating_add(1);
            obs_idx = obs_idx.saturating_add(1);
        }

        while sig_idx < signature.len() {
            if !signature[sig_idx].optional {
                errors = errors.saturating_add(1);
            }
            sig_idx = sig_idx.saturating_add(1);
        }

        match errors {
            0..=2 => Some(HttpMatchQuality::High.as_score()), // 0-2 errors: High quality match
            3..=5 => Some(HttpMatchQuality::Medium.as_score()), // 3-5 errors: Medium quality match
            6..=8 => Some(HttpMatchQuality::Low.as_score()),  // 6-8 errors: Low quality match
            9..=11 => Some(HttpMatchQuality::Bad.as_score()), // 9-11 errors: Bad quality match
            _ => None, // 12+ errors: Too many differences, not a viable match
        }
    }

    fn distance_horder(&self, other: &http::Signature) -> Option<u32> {
        Self::distance_header(self.get_horder(), &other.horder)
    }

    fn distance_habsent(&self, other: &http::Signature) -> Option<u32> {
        Self::distance_header(self.get_habsent(), &other.habsent)
    }

    fn distance_expsw(&self, other: &http::Signature) -> Option<u32> {
        if other.expsw.as_str().contains(self.get_expsw()) {
            Some(HttpMatchQuality::High.as_score())
        } else {
            Some(HttpMatchQuality::Bad.as_score())
        }
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
        let signature: &http::Signature = self;
        let distance = observed
            .distance_ip_version(signature)?
            .saturating_add(observed.distance_horder(signature)?)
            .saturating_add(observed.distance_habsent(signature)?)
            .saturating_add(observed.distance_expsw(signature)?);
        Some(distance)
    }
    fn generate_http_index_keys(&self) -> Vec<HttpIndexKey> {
        let mut keys = Vec::new();
        if self.version == Version::Any {
            keys.push(HttpIndexKey {
                http_version_key: Version::V10,
            });
            keys.push(HttpIndexKey {
                http_version_key: Version::V11,
            });
        } else {
            keys.push(HttpIndexKey {
                http_version_key: self.version,
            });
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
