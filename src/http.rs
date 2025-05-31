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
