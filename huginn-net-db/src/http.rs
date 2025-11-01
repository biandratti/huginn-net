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
            HttpMatchQuality::Medium => 1,
            HttpMatchQuality::Low => 2,
            HttpMatchQuality::Bad => 3,
        }
    }
}

impl crate::db_matching_trait::MatchQuality for HttpMatchQuality {
    // HTTP has 4 components, each can contribute max 3 points (Bad)
    const MAX_DISTANCE: u32 = 12;

    fn distance_to_score(distance: u32) -> f32 {
        match distance {
            0 => 1.0,
            1 => 0.95,
            2 => 0.90,
            3 => 0.80,
            4..=5 => 0.70,
            6..=7 => 0.60,
            8..=9 => 0.40,
            10..=11 => 0.20,
            d if d <= Self::MAX_DISTANCE => 0.10,
            _ => 0.05,
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
    /// HTTP/2
    V20,
    /// HTTP/3
    V30,
    /// Matches any HTTP version (used in database signatures).
    Any,
}

impl Version {
    pub fn parse(version_str: &str) -> Option<Self> {
        match version_str {
            "HTTP/1.0" => Some(Version::V10),
            "HTTP/1.1" => Some(Version::V11),
            "HTTP/2" | "HTTP/2.0" => Some(Version::V20),
            "HTTP/3" | "HTTP/3.0" => Some(Version::V30),
            _ => None,
        }
    }
}

impl std::str::FromStr for Version {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(())
    }
}

impl Version {
    pub fn as_str(&self) -> &'static str {
        match self {
            Version::V10 => "HTTP/1.0",
            Version::V11 => "HTTP/1.1",
            Version::V20 => "HTTP/2",
            Version::V30 => "HTTP/3",
            Version::Any => "Any",
        }
    }
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

impl Header {
    pub fn new<S: AsRef<str>>(name: S) -> Self {
        Header { optional: false, name: name.as_ref().to_owned(), value: None }
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
    vec!["Content-Type", "Connection", "Keep-Alive", "Accept-Ranges", "Date"]
}
