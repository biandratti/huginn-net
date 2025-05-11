use crate::db::HttpP0fIndexKey;
use crate::fingerprint_traits::{DatabaseSignature, ObservedFingerprint};

#[derive(Clone, Debug, PartialEq)]
pub struct Signature {
    /// HTTP version
    pub version: Version,
    /// ordered list of headers that should appear in matching traffic.
    pub horder: Vec<Header>,
    /// list of headers that must *not* appear in matching traffic.
    pub habsent: Vec<Header>,
    /// expected substring in 'User-Agent' or 'Server'.
    pub expsw: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMatchQuality {
    High,
    Medium,
    Low,
    Bad,
}

impl HttpMatchQuality {
    pub fn as_score(self) -> u32 {
        match self {
            HttpMatchQuality::High => 0,
            HttpMatchQuality::Medium => 5,
            HttpMatchQuality::Low => 10,
            HttpMatchQuality::Bad => 20,
        }
    }
}

impl ObservedFingerprint for Signature {
    type Key = HttpP0fIndexKey;

    fn generate_index_key(&self) -> Self::Key {
        HttpP0fIndexKey {
            http_version: self.version,
            expsw_key: self.expsw.clone(),
        }
    }
}

impl DatabaseSignature<Signature> for Signature {
    fn calculate_distance(&self, observed: &Signature) -> Option<u32> {
        let distance = observed.distance_ip_version(self)?
            + observed.distance_horder(self)?
            + observed.distance_habsent(self)?
            + observed.distance_expsw(self)?;
        Some(distance)
    }

    fn generate_index_keys_for_db_entry(&self) -> Vec<HttpP0fIndexKey> {
        let mut keys = Vec::new();
        if self.version == Version::Any {
            keys.push(HttpP0fIndexKey {
                http_version: Version::V10,
                expsw_key: self.expsw.clone(),
            });
            keys.push(HttpP0fIndexKey {
                http_version: Version::V11,
                expsw_key: self.expsw.clone(),
            });
        } else {
            keys.push(HttpP0fIndexKey {
                http_version: self.version,
                expsw_key: self.expsw.clone(),
            });
        }
        keys
    }
}

impl Signature {
    pub fn distance_ip_version(&self, other: &Self) -> Option<u32> {
        if other.version == Version::Any || self.version == other.version {
            Some(HttpMatchQuality::High.as_score())
        } else {
            None
        }
    }

    // Compare two header vectors and return the number of matching headers.
    // The quality is based on the number of matching headers.
    fn distance_header(a: &[Header], b: &[Header]) -> Option<u32> {
        let len_a = a.len();
        let len_b = b.len();
        let min_len = len_a.min(len_b);
        let max_len = len_a.max(len_b);

        let mut actual_matches = 0;
        for i in 0..min_len {
            //The match is based on the header name and value.
            // If the header is optional, it is not considered a match.
            if a[i] == b[i] {
                actual_matches += 1;
            }
        }

        // Calculate errors based on the difference between the length of the longer list
        // and the number of actual matches in the common part.
        let errors = max_len - actual_matches;

        match errors {
            0 => Some(HttpMatchQuality::High.as_score()),
            1 => Some(HttpMatchQuality::Medium.as_score()),
            2 => Some(HttpMatchQuality::Low.as_score()),
            3 => Some(HttpMatchQuality::Bad.as_score()),
            _ => None,
        }
    }

    fn distance_horder(&self, other: &Self) -> Option<u32> {
        Self::distance_header(&self.horder, &other.horder)
    }

    fn distance_habsent(&self, other: &Self) -> Option<u32> {
        Self::distance_header(&self.habsent, &other.habsent)
    }

    fn distance_expsw(&self, other: &Self) -> Option<u32> {
        if self.expsw == other.expsw {
            Some(HttpMatchQuality::High.as_score())
        } else {
            Some(HttpMatchQuality::Low.as_score())
        }
    }
}

/// Version of the HTTP protocol used in a request or response.
/// Used in signatures to distinguish behavior between HTTP/1.0 and HTTP/1.1.
/// The `Any` variant is used in database signatures to match any HTTP version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Version {
    /// HTTP/1.0
    V10,
    /// HTTP/1.1
    V11,
    /// Matches any HTTP version (used in database signatures).
    Any,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Header {
    pub optional: bool,
    pub name: String,
    pub value: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum HttpDiagnosis {
    Dishonest,
    Anonymous,
    Generic,
    None,
}

#[cfg(test)]
pub fn header<S: AsRef<str>>(name: S) -> Header {
    Header::new(name)
}

impl Header {
    pub fn new<S: AsRef<str>>(name: S) -> Self {
        Header {
            optional: false,
            name: name.as_ref().to_owned(),
            value: None,
        }
    }

    pub fn with_value<S: AsRef<str>>(mut self, value: S) -> Self {
        self.value = Some(value.as_ref().to_owned());
        self
    }

    pub fn with_optional_value<S: AsRef<str>>(mut self, value: Option<S>) -> Self {
        self.value = value.map(|v| v.as_ref().to_owned());
        self
    }

    pub fn optional(mut self) -> Self {
        self.optional = true;
        self
    }
}

pub fn request_optional_headers() -> Vec<&'static str> {
    vec![
        "Cookie",
        "Referer",
        "Origin",
        "Range",
        "If-Modified-Since",
        "If-None-Match",
        "Via",
        "X-Forwarded-For",
        "Authorization",
        "Proxy-Authorization",
        "Cache-Control",
    ]
}

pub fn response_optional_headers() -> Vec<&'static str> {
    vec![
        "Set-Cookie",
        "Last-Modified",
        "ETag",
        "Content-Length",
        "Content-Disposition",
        "Cache-Control",
        "Expires",
        "Pragma",
        "Location",
        "Refresh",
        "Content-Range",
        "Vary",
    ]
}

pub fn request_skip_value_headers() -> Vec<&'static str> {
    vec!["Host", "User-Agent"]
}

pub fn response_skip_value_headers() -> Vec<&'static str> {
    vec!["Date", "Content-Type", "Server"]
}

pub fn request_common_headers() -> Vec<&'static str> {
    vec![
        "Host",
        "User-Agent",
        "Connection",
        "Accept",
        "Accept-Encoding",
        "Accept-Language",
        "Accept-Charset",
        "Keep-Alive",
    ]
}

pub fn response_common_headers() -> Vec<&'static str> {
    vec![
        "Content-Type",
        "Connection",
        "Keep-Alive",
        "Accept-Ranges",
        "Date",
    ]
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
            Header::new("Keep-Alive").optional().with_value("timeout"), // optional: true
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
            Header::new("Keep-Alive").with_value("timeout"), // optional: false
            Header::new("Connection").with_value("Keep-Alive"),
            Header::new("Transfer-Encoding")
                .optional()
                .with_value("chunked"),
            Header::new("Content-Type"),
        ];

        assert!(a[6].optional);
        assert!(!b[6].optional);
        assert_ne!(a[6], b[6]);

        let result = Signature::distance_header(&a, &b);
        assert_eq!(
            result,
            Some(HttpMatchQuality::Medium.as_score()),
            "Expected Medium quality for 1 error in lists of 10"
        );
    }
}
