use crate::db::Label;
use tracing::debug;

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
        let min_len = a.len().min(b.len());
        let mut matches = 0;

        for i in 0..min_len {
            if a[i] == b[i] {
                matches += 1;
            }
        }

        match matches {
            n if n == min_len && a.len() == b.len() => Some(HttpMatchQuality::High.as_score()),
            4 => Some(HttpMatchQuality::Medium.as_score()),
            3 => Some(HttpMatchQuality::Low.as_score()),
            2 => Some(HttpMatchQuality::Bad.as_score()),
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

    pub fn get_distance(&self, other: &Self) -> Option<u32> {
        let distance = self.distance_ip_version(other)?
            + self.distance_horder(other)?
            + self.distance_habsent(other)?
            + self.distance_expsw(other)?;

        Some(distance)
    }

    pub fn find_closest_signature<'a>(
        &self,
        signature: &Signature,
        db: &'a Vec<(Label, Vec<Signature>)>,
    ) -> Option<(&'a Label, &'a Signature, u32)> {
        let mut best_label = None;
        let mut best_sig = None;
        let mut min_distance = u32::MAX;
        for (label, sigs) in db {
            for db_sig in sigs {
                if let Some(distance) = signature.get_distance(db_sig) {
                    debug!("db_sig: {:?}, distance: {:?}", db_sig.to_string(), distance);
                    if distance < min_distance {
                        min_distance = distance;
                        best_label = Some(label);
                        best_sig = Some(db_sig);
                    }
                }
            }
        }

        if let (Some(label), Some(sig)) = (best_label, best_sig) {
            Some((label, sig, min_distance))
        } else {
            None
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Version {
    V10,
    V11,
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
    fn test_distance_header_user_case_mismatch() {
        // Scenario provided by the user
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
            Header::new("Keep-Alive").with_value("timeout"), // optional: false (default behavior of .with_value())
            Header::new("Connection").with_value("Keep-Alive"),
            Header::new("Transfer-Encoding")
                .optional()
                .with_value("chunked"),
            Header::new("Content-Type"),
        ];

        // Verify the specific difference that causes a mismatch at index 6
        assert!(a[6].optional);
        assert!(!b[6].optional); // Header::new("...").with_value("...") results in optional: false
        assert_ne!(a[6], b[6]);

        // With 9 matches out of 10, and lengths being equal, this should be None
        // as it doesn't hit `n == min_len` (9 != 10) for High quality, nor 2, 3, or 4.
        let result = Signature::distance_header(&a, &b);
        assert_eq!(
            result, None,
            "Expected None for 9 matches out of 10 (equal length)"
        );
    }

    #[test]
    fn test_distance_header_perfect_match() {
        let a = vec![
            Header::new("Date"),
            Header::new("Server"),
            Header::new("Last-Modified").optional(),
            Header::new("Accept-Ranges").optional().with_value("bytes"),
        ];

        let b = vec![
            Header::new("Date"),
            Header::new("Server"),
            Header::new("Last-Modified").optional(),
            Header::new("Accept-Ranges").optional().with_value("bytes"),
        ];
        // All headers match, lengths are equal.
        // min_len = 4, matches = 4.
        // `n == min_len && a.len() == b.len()` is true.
        let result = Signature::distance_header(&a, &b);
        assert_eq!(result, Some(HttpMatchQuality::High.as_score()));
    }

    #[test]
    fn test_distance_header_medium_match_due_to_length_diff() {
        let a = vec![
            Header::new("Date"),
            Header::new("Server"),
            Header::new("Last-Modified").optional(),
            Header::new("Accept-Ranges").optional().with_value("bytes"),
            Header::new("Extra-Header-A"), // Extra header in 'a'
        ];

        let b = vec![
            Header::new("Date"),
            Header::new("Server"),
            Header::new("Last-Modified").optional(),
            Header::new("Accept-Ranges").optional().with_value("bytes"),
        ];
        // min_len = 4, matches = 4. a.len() != b.len().
        // `n == min_len && a.len() == b.len()` is false.
        // Hits `4 => Some(HttpMatchQuality::Medium.as_score())`.
        let result = Signature::distance_header(&a, &b);
        assert_eq!(result, Some(HttpMatchQuality::Medium.as_score()));

        let result_swapped = Signature::distance_header(&b, &a);
        assert_eq!(result_swapped, Some(HttpMatchQuality::Medium.as_score()));
    }

    #[test]
    fn test_distance_header_low_match() {
        let a = vec![
            Header::new("Date"),
            Header::new("Server"),
            Header::new("Last-Modified").optional(),
            Header::new("Different-Header-A"), // This one won't match
        ];

        let b = vec![
            Header::new("Date"),
            Header::new("Server"),
            Header::new("Last-Modified").optional(),
            Header::new("Accept-Ranges").optional().with_value("bytes"), // This one won't match
        ];
        // min_len = 4, matches = 3.
        // Hits `3 => Some(HttpMatchQuality::Low.as_score())`.
        let result = Signature::distance_header(&a, &b);
        assert_eq!(result, Some(HttpMatchQuality::Low.as_score()));
    }

    #[test]
    fn test_distance_header_bad_match() {
        let a = vec![
            Header::new("Date"),
            Header::new("Server"),
            Header::new("Different-Header-A"),
            Header::new("Different-Header-B"),
        ];

        let b = vec![
            Header::new("Date"),
            Header::new("Server"),
            Header::new("Last-Modified").optional(),
            Header::new("Accept-Ranges").optional().with_value("bytes"),
        ];
        // min_len = 4, matches = 2.
        // Hits `2 => Some(HttpMatchQuality::Bad.as_score())`.
        let result = Signature::distance_header(&a, &b);
        assert_eq!(result, Some(HttpMatchQuality::Bad.as_score()));
    }

    #[test]
    fn test_distance_header_very_few_matches() {
        let a = vec![
            Header::new("Date"), // Match
            Header::new("Different-Header-A"),
            Header::new("Different-Header-B"),
            Header::new("Different-Header-C"),
        ];

        let b = vec![
            Header::new("Date"), // Match
            Header::new("Server"),
            Header::new("Last-Modified").optional(),
            Header::new("Accept-Ranges").optional().with_value("bytes"),
        ];
        // min_len = 4, matches = 1.
        // Hits `_ => None`.
        let result = Signature::distance_header(&a, &b);
        assert_eq!(result, None);
    }

    #[test]
    fn test_distance_header_no_matches() {
        let a = vec![Header::new("Header1"), Header::new("Header2")];

        let b = vec![Header::new("Header3"), Header::new("Header4")];
        // min_len = 2, matches = 0.
        // Hits `_ => None`.
        let result = Signature::distance_header(&a, &b);
        assert_eq!(result, None);
    }

    #[test]
    fn test_distance_header_empty_slices() {
        let a: Vec<Header> = vec![];
        let b: Vec<Header> = vec![];
        // min_len = 0, matches = 0.
        // `n == min_len && a.len() == b.len()` is true.
        let result = Signature::distance_header(&a, &b);
        assert_eq!(result, Some(HttpMatchQuality::High.as_score()));
    }

    #[test]
    fn test_distance_header_one_empty_one_not() {
        let a: Vec<Header> = vec![Header::new("Test")];
        let b: Vec<Header> = vec![];
        // min_len = 0, matches = 0.
        // `n == min_len && a.len() == b.len()` -> `0 == 0 && 1 == 0` is false.
        // Hits `_ => None`.
        let result = Signature::distance_header(&a, &b);
        assert_eq!(result, None);

        let result_swapped = Signature::distance_header(&b, &a);
        assert_eq!(result_swapped, None);
    }
}
