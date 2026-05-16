pub mod common;
pub mod languages;
pub mod observable;

pub use common::{
    get_diagnostic, HeaderSource, HttpCookie, HttpHeader, HttpParser, HttpProcessor,
    ParsingMetadata,
};
pub use languages::get_highest_quality_language;
pub use observable::*;

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

impl std::str::FromStr for Version {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(())
    }
}

impl core::fmt::Display for Version {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Version::V10 => "0",
            Version::V11 => "1",
            Version::V20 => "2",
            Version::V30 => "3",
            Version::Any => "*",
        })
    }
}

/// A header name (and optional value) used in p0f-style HTTP signatures.
///
/// Headers may be marked optional (`?`) to signal "match if present, ignore
/// if absent".
#[derive(Clone, Debug, PartialEq)]
pub struct Header {
    pub optional: bool,
    pub name: String,
    pub value: Option<String>,
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

impl core::fmt::Display for Header {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.optional {
            f.write_str("?")?;
        }
        f.write_str(&self.name)?;
        if let Some(ref value) = self.value {
            write!(f, "=[{value}]")?;
        }
        Ok(())
    }
}

/// HTTP diagnostic flags derived from comparing User-Agent claims with the
/// matched OS signature.
#[derive(Clone, Debug, PartialEq)]
pub enum HttpDiagnosis {
    Dishonest,
    Anonymous,
    Generic,
    None,
}

impl core::fmt::Display for HttpDiagnosis {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            HttpDiagnosis::Dishonest => "dishonest",
            HttpDiagnosis::Anonymous => "anonymous",
            HttpDiagnosis::Generic => "generic",
            HttpDiagnosis::None => "none",
        })
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
