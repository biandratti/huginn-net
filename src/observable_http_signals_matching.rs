use crate::db::HttpIndexKey;
use crate::db_matching_trait::{DatabaseSignature, MatchQuality, ObservedFingerprint};
use crate::http;
use crate::http::{Header, HttpMatchQuality, Version};
use crate::observable_signals::{ObservableHttpRequest, ObservableHttpResponse};

// Helper function to compare observed headers with signature headers
// 1. If the header name is different, return false
// 2. If the header is optional, return true
// 3. If the header is not optional, return true if the value is the same
fn headers_match(observed: &Header, signature: &Header) -> bool {
    if observed.name != signature.name {
        return false;
    }
    if signature.optional {
        return true;
    }
    observed.value == signature.value
}

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

    // Compare two header vectors and return the number of matching headers.
    // The quality is based on the number of matching headers.
    fn distance_header(observed: &[Header], signature: &[Header]) -> Option<u32> {
        let len_a = observed.len();
        let len_b = signature.len();
        let min_len = len_a.min(len_b);
        let max_len = len_a.max(len_b);

        let mut actual_matches = 0;
        for i in 0..min_len {
            if headers_match(&observed[i], &signature[i]) {
                actual_matches += 1;
            }
        }

        // Calculate errors based on the difference between the length of the longer list
        // and the number of actual matches in the common part.
        let errors = max_len - actual_matches;

        match errors {
            0..=2 => Some(HttpMatchQuality::High.as_score()),
            3..=5 => Some(HttpMatchQuality::Medium.as_score()),
            6..=8 => Some(HttpMatchQuality::Low.as_score()),
            9..=11 => Some(HttpMatchQuality::Bad.as_score()),
            _ => None,
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

impl ObservedFingerprint for ObservableHttpRequest {
    type Key = HttpIndexKey;

    fn generate_index_key(&self) -> Self::Key {
        HttpIndexKey {
            http_version_key: self.version,
        }
    }
}

trait HttpSignatureHelper {
    fn calculate_http_distance<T: HttpDistance>(&self, observed: &T) -> Option<u32>
    where
        Self: AsRef<http::Signature>,
    {
        let signature = self.as_ref();
        let distance = observed.distance_ip_version(signature)?
            + observed.distance_horder(signature)?
            + observed.distance_habsent(signature)?
            + observed.distance_expsw(signature)?;
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

impl AsRef<http::Signature> for http::Signature {
    fn as_ref(&self) -> &http::Signature {
        self
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

impl ObservedFingerprint for ObservableHttpResponse {
    type Key = HttpIndexKey;

    fn generate_index_key(&self) -> Self::Key {
        HttpIndexKey {
            http_version_key: self.version,
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
}
