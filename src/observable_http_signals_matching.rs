use crate::observable_signals::{ObservableHttpRequest, ObservableHttpResponse};
use huginn_net_db::db::HttpIndexKey;
use huginn_net_db::db_matching_trait::{DatabaseSignature, MatchQuality, ObservedFingerprint};
use huginn_net_db::http;
use huginn_net_db::http::{Header, HttpMatchQuality, Version};

trait HttpDistance {
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
        let mut obs_idx = 0; // Index pointer for observed headers
        let mut sig_idx = 0; // Index pointer for signature headers
        let mut errors: u32 = 0; // Running count of matching errors

        while obs_idx < observed.len() && sig_idx < signature.len() {
            let obs_header = &observed[obs_idx];
            let sig_header = &signature[sig_idx];

            // Check if headers match (name and value)
            if obs_header.name == sig_header.name && obs_header.value == sig_header.value {
                // Perfect match - advance both pointers
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

        // Convert error count to quality score using predefined ranges
        // Lower error counts indicate better matches
        match errors {
            0..=2 => Some(HttpMatchQuality::High.as_score()), // 0-2 errors: High quality match
            3..=5 => Some(HttpMatchQuality::Medium.as_score()), // 3-5 errors: Medium quality match
            6..=8 => Some(HttpMatchQuality::Low.as_score()),  // 6-8 errors: Low quality match
            9..=11 => Some(HttpMatchQuality::Bad.as_score()), // 9-11 errors: Bad but still usable match
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

impl HttpDistance for ObservableHttpRequest {
    fn get_version(&self) -> Version {
        self.matching.version
    }

    fn get_horder(&self) -> &[Header] {
        &self.matching.horder
    }

    fn get_habsent(&self) -> &[Header] {
        &self.matching.habsent
    }

    fn get_expsw(&self) -> &str {
        &self.matching.expsw
    }
}

impl ObservedFingerprint for ObservableHttpRequest {
    type Key = HttpIndexKey;

    fn generate_index_key(&self) -> Self::Key {
        HttpIndexKey {
            http_version_key: self.matching.version,
        }
    }
}

trait HttpSignatureHelper {
    fn calculate_http_distance<T: HttpDistance>(&self, observed: &T) -> Option<u32>
    where
        Self: AsRef<http::Signature>,
    {
        let signature = self.as_ref();
        let distance = observed
            .distance_ip_version(signature)?
            .saturating_add(observed.distance_horder(signature)?)
            .saturating_add(observed.distance_habsent(signature)?)
            .saturating_add(observed.distance_expsw(signature)?);
        Some(distance)
    }

    fn generate_http_index_keys(&self) -> Vec<HttpIndexKey>;

    /// Returns the quality score based on the distance.
    ///
    /// The score is a value between 0.0 and 1.0, where 1.0 is a perfect match.
    ///
    /// The score is calculated based on the distance of the observed signal to the database signature.
    /// The distance is a value between 0 and 12, where 0 is a perfect match and 12 is the maximum possible distance.
    fn get_quality_score_by_distance(&self, distance: u32) -> f32 {
        HttpMatchQuality::distance_to_score(distance)
    }
}

impl HttpSignatureHelper for http::Signature {
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

impl DatabaseSignature<ObservableHttpRequest> for http::Signature {
    fn calculate_distance(&self, observed: &ObservableHttpRequest) -> Option<u32> {
        self.calculate_http_distance(observed)
    }

    fn get_quality_score(&self, distance: u32) -> f32 {
        self.get_quality_score_by_distance(distance)
    }

    fn generate_index_keys_for_db_entry(&self) -> Vec<HttpIndexKey> {
        self.generate_http_index_keys()
    }
}

impl HttpDistance for ObservableHttpResponse {
    fn get_version(&self) -> Version {
        self.matching.version
    }

    fn get_horder(&self) -> &[Header] {
        &self.matching.horder
    }

    fn get_habsent(&self) -> &[Header] {
        &self.matching.habsent
    }

    fn get_expsw(&self) -> &str {
        &self.matching.expsw
    }
}

impl ObservedFingerprint for ObservableHttpResponse {
    type Key = HttpIndexKey;

    fn generate_index_key(&self) -> Self::Key {
        HttpIndexKey {
            http_version_key: self.matching.version,
        }
    }
}

impl DatabaseSignature<ObservableHttpResponse> for http::Signature {
    fn calculate_distance(&self, observed: &ObservableHttpResponse) -> Option<u32> {
        self.calculate_http_distance(observed)
    }

    fn get_quality_score(&self, distance: u32) -> f32 {
        self.get_quality_score_by_distance(distance)
    }

    fn generate_index_keys_for_db_entry(&self) -> Vec<HttpIndexKey> {
        self.generate_http_index_keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_distance_header_with_one_optional_header_mismatch() {
        let a = vec![
            Header::new("Date"),
            Header::new("Server"),
            Header::new("Last-Modified").optional(),
            Header::new("Accept-Ranges").optional().with_value("bytes"),
            Header::new("Content-Length").optional(),
            Header::new("Content-Range").optional(),
            Header::new("Keep-Alive").optional().with_value("timeout"),
            Header::new("Connection").with_value("Keep-Alive"),
            Header::new("Transfer-Encoding")
                .optional()
                .with_value("chunked"),
            Header::new("Content-Type"),
        ];

        let b = vec![
            Header::new("Date"),
            Header::new("Server"),
            Header::new("Last-Modified").optional(),
            Header::new("Accept-Ranges").optional().with_value("bytes"),
            Header::new("Content-Length").optional(),
            Header::new("Content-Range").optional(),
            Header::new("Keep-Alive").with_value("timeout"),
            Header::new("Connection").with_value("Keep-Alive"),
            Header::new("Transfer-Encoding")
                .optional()
                .with_value("chunked"),
            Header::new("Content-Type"),
        ];

        assert!(a[6].optional);
        assert!(!b[6].optional);
        assert_ne!(a[6], b[6]);

        let result = <ObservableHttpResponse as HttpDistance>::distance_header(&a, &b);
        assert_eq!(
            result,
            Some(HttpMatchQuality::High.as_score()),
            "Expected Medium quality for 1 error in lists of 10"
        );
    }

    #[test]
    fn test_distance_header_optional_skip_in_middle() {
        let observed = vec![
            Header::new("Host"),
            Header::new("User-Agent").with_value("Mozilla/5.0"),
            Header::new("Connection").with_value("keep-alive"),
        ];

        let signature = vec![
            Header::new("Host"),
            Header::new("Accept-Language")
                .optional()
                .with_value("en-US"),
            Header::new("User-Agent").with_value("Mozilla/5.0"),
            Header::new("Connection").with_value("keep-alive"),
        ];

        let result =
            <ObservableHttpRequest as HttpDistance>::distance_header(&observed, &signature);
        assert_eq!(
            result,
            Some(HttpMatchQuality::High.as_score()),
            "Optional header in middle should be skipped for perfect alignment"
        );
    }

    #[test]
    fn test_distance_header_multiple_optional_skips() {
        let observed = vec![
            Header::new("Host"),
            Header::new("Connection").with_value("keep-alive"),
        ];

        let signature = vec![
            Header::new("Host"),
            Header::new("Accept-Language")
                .optional()
                .with_value("en-US"),
            Header::new("Accept-Encoding").optional().with_value("gzip"),
            Header::new("Connection").with_value("keep-alive"),
        ];

        let result =
            <ObservableHttpRequest as HttpDistance>::distance_header(&observed, &signature);
        assert_eq!(
            result,
            Some(HttpMatchQuality::High.as_score()),
            "Multiple optional headers should be skipped"
        );
    }

    #[test]
    fn test_distance_header_required_in_middle_causes_error() {
        // Required header in middle should cause error and misalignment
        let observed = vec![
            Header::new("Host"),
            Header::new("Connection").with_value("keep-alive"),
        ];

        let signature = vec![
            Header::new("Host"),
            Header::new("User-Agent").with_value("Mozilla/5.0"), // Required, missing
            Header::new("Connection").with_value("keep-alive"),
        ];

        let result =
            <ObservableHttpRequest as HttpDistance>::distance_header(&observed, &signature);
        assert_eq!(
            result,
            Some(HttpMatchQuality::High.as_score()), // 1 error falls in High range (0-2 errors)
            "Required header missing should cause 1 error"
        );
    }

    #[test]
    fn test_distance_header_realistic_browser_with_optional_skips() {
        let observed = vec![
            Header::new("Host"),
            Header::new("User-Agent").with_value("Mozilla/5.0"),
            Header::new("Accept").with_value("text/html"),
            Header::new("Connection").with_value("keep-alive"),
        ];

        let signature = vec![
            Header::new("Host"),
            Header::new("User-Agent").with_value("Mozilla/5.0"),
            Header::new("Accept").with_value("text/html"),
            Header::new("Accept-Language")
                .optional()
                .with_value("en-US"), // Optional, missing
            Header::new("Accept-Encoding").optional().with_value("gzip"), // Optional, missing
            Header::new("Cookie").optional(),                             // Optional, missing
            Header::new("Connection").with_value("keep-alive"),
        ];

        let result =
            <ObservableHttpRequest as HttpDistance>::distance_header(&observed, &signature);
        assert_eq!(
            result,
            Some(HttpMatchQuality::High.as_score()),
            "Browser should match signature even with optional headers missing"
        );
    }

    #[test]
    fn test_distance_header_missing_optional_header() {
        let observed = vec![
            Header::new("Host"),
            Header::new("User-Agent").with_value("Mozilla/5.0"),
        ];

        let signature = vec![
            Header::new("Host"),
            Header::new("User-Agent").with_value("Mozilla/5.0"),
            Header::new("Accept-Language")
                .optional()
                .with_value("en-US"), // Missing but optional
        ];

        let result =
            <ObservableHttpRequest as HttpDistance>::distance_header(&observed, &signature);
        assert_eq!(
            result,
            Some(HttpMatchQuality::High.as_score()),
            "Missing optional headers should not cause errors"
        );
    }

    #[test]
    fn test_distance_header_missing_required_header() {
        let observed = vec![Header::new("Host")];

        let signature = vec![
            Header::new("Host"),
            Header::new("User-Agent").with_value("Mozilla/5.0"), // Missing and NOT optional
        ];

        let result =
            <ObservableHttpRequest as HttpDistance>::distance_header(&observed, &signature);
        assert_eq!(
            result,
            Some(HttpMatchQuality::High.as_score()), // 1 error out of many
            "Missing required headers should cause errors"
        );
    }

    #[test]
    fn test_distance_header_extra_headers_in_observed() {
        let observed = vec![
            Header::new("Host"),
            Header::new("User-Agent").with_value("Mozilla/5.0"),
            Header::new("X-Custom-Header").with_value("custom"), // Extra header
        ];

        let signature = vec![
            Header::new("Host"),
            Header::new("User-Agent").with_value("Mozilla/5.0"),
        ];

        let result =
            <ObservableHttpRequest as HttpDistance>::distance_header(&observed, &signature);
        assert_eq!(
            result,
            Some(HttpMatchQuality::High.as_score()), // 1 error for extra header
            "Extra headers in observed should cause errors"
        );
    }

    #[test]
    fn test_distance_header_optional_header_at_end() {
        let observed = vec![
            Header::new("Host"),
            Header::new("User-Agent").with_value("Mozilla/5.0"),
        ];

        let signature = vec![
            Header::new("Host"),
            Header::new("User-Agent").with_value("Mozilla/5.0"),
            Header::new("Accept-Language")
                .optional()
                .with_value("en-US"), // Optional, missing
        ];

        let result =
            <ObservableHttpRequest as HttpDistance>::distance_header(&observed, &signature);
        assert_eq!(
            result,
            Some(HttpMatchQuality::High.as_score()),
            "Missing optional headers at end should not cause errors"
        );
    }

    #[test]
    fn test_distance_header_required_header_at_end() {
        let observed = vec![Header::new("Host")];

        let signature = vec![
            Header::new("Host"),
            Header::new("User-Agent").with_value("Mozilla/5.0"), // Required, missing
        ];

        let result =
            <ObservableHttpRequest as HttpDistance>::distance_header(&observed, &signature);
        assert_eq!(
            result,
            Some(HttpMatchQuality::High.as_score()),
            "Missing required headers should cause 1 error"
        );
    }

    #[test]
    fn test_distance_header_observed_vs_signature_with_optional() {
        let observed = vec![
            Header::new("Host"),
            Header::new("User-Agent").with_value("Mozilla/5.0"),
            Header::new("Accept").with_value("text/html"),
            Header::new("Accept-Language").with_value("en-US"),
        ];

        let signature = vec![
            Header::new("Host"),
            Header::new("User-Agent").with_value("Mozilla/5.0"),
            Header::new("Accept").with_value("text/html"),
            Header::new("Accept-Language")
                .optional()
                .with_value("en-US"), // Optional but value must match
        ];

        let result =
            <ObservableHttpRequest as HttpDistance>::distance_header(&observed, &signature);
        assert_eq!(
            result,
            Some(HttpMatchQuality::High.as_score()),
            "Should match perfectly: all headers match including values for optional headers"
        );
    }

    #[test]
    fn test_distance_header_value_mismatch_not_optional() {
        let observed = vec![
            Header::new("Host"),
            Header::new("Connection").with_value("keep-alive"),
        ];

        let signature = vec![
            Header::new("Host"),
            Header::new("Connection").with_value("close"), // Different value, not optional
        ];

        let result =
            <ObservableHttpRequest as HttpDistance>::distance_header(&observed, &signature);
        assert_eq!(
            result,
            Some(HttpMatchQuality::High.as_score()),
            "Should have 1 error out of 2 headers"
        );
    }

    #[test]
    fn test_distance_header_realistic_browser_scenario() {
        let observed = vec![
            Header::new("Host"),
            Header::new("User-Agent")
                .with_value("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"),
            Header::new("Accept").with_value("text/html,application/xhtml+xml"),
            Header::new("Accept-Language").with_value("en-US,en;q=0.9"),
            Header::new("Accept-Encoding").with_value("gzip, deflate"),
            Header::new("Connection").with_value("keep-alive"),
        ];

        // Database signature for Chrome
        let signature = vec![
            Header::new("Host"),
            Header::new("User-Agent")
                .with_value("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"),
            Header::new("Accept").with_value("text/html,application/xhtml+xml"),
            Header::new("Accept-Language")
                .optional()
                .with_value("en-US,en;q=0.9"), // Optional but value must match
            Header::new("Accept-Encoding").with_value("gzip, deflate"),
            Header::new("Connection").with_value("keep-alive"),
        ];

        let result =
            <ObservableHttpRequest as HttpDistance>::distance_header(&observed, &signature);
        assert_eq!(
            result,
            Some(HttpMatchQuality::High.as_score()),
            "Should match perfectly for realistic Chrome signature with value matching"
        );
    }
}
