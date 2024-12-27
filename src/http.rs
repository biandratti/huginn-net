use std::collections::HashMap;

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

impl Signature {
    pub fn matches(&self, db_signature: &Self) -> bool {
        self.version.matches_version(&db_signature.version)
            && self.horder == db_signature.horder
            && self.habsent == db_signature.habsent
            && self.expsw == db_signature.expsw
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Version {
    V10,
    V11,
    Any,
}

impl Version {
    pub fn matches_version(&self, other: &Version) -> bool {
        matches!(
            (self, other),
            (Version::V10, Version::V10) | (Version::V11, Version::V11) | (_, Version::Any)
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Header {
    pub optional: bool,
    pub name: String,
    pub value: Option<String>,
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

    pub fn optional(mut self) -> Self {
        self.optional = true;
        self
    }
}

#[derive(Debug, Clone)]
pub struct HeaderRegistry {
    headers: HashMap<String, (u32, HeaderCategory)>,
    id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HeaderCategory {
    Mandatory,
    Optional,
    SkipValue,
    Common,
}

impl HeaderRegistry {
    pub fn new() -> Self {
        Self {
            headers: HashMap::new(),
            id: 0,
        }
    }

    pub fn init() -> Self {
        let mut registry = HeaderRegistry::new();

        for &header in &Self::expected_headers() {
            registry.register_header(header, HeaderCategory::Mandatory);
        }
        for &header in &Self::request_optional_headers() {
            registry.register_header(header, HeaderCategory::Optional);
        }
        for &header in &Self::response_optional_headers() {
            registry.register_header(header, HeaderCategory::Optional);
        }
        for &header in &Self::request_skip_value_headers() {
            registry.register_header(header, HeaderCategory::SkipValue);
        }
        for &header in &Self::response_skip_value_headers() {
            registry.register_header(header, HeaderCategory::SkipValue);
        }
        for &header in &Self::request_common_headers() {
            registry.register_header(header, HeaderCategory::Common);
        }
        for &header in &Self::response_common_headers() {
            registry.register_header(header, HeaderCategory::Common);
        }

        registry
    }

    /// Register a header and return the id registered
    pub fn register_header<S: AsRef<str>>(&mut self, name: S, category: HeaderCategory) -> u32 {
        let name = name.as_ref();

        if let Some(&(id, _)) = self.headers.get(name) {
            return id;
        }

        // Assign a new ID and insert into the registry
        let id = self.id;
        self.id += 1;

        self.headers.insert(name.to_owned(), (id, category));

        id
    }

    pub fn expected_headers() -> [&'static str; 6] {
        [
            "User-Agent",
            "Server",
            "Accept-Language",
            "Via",
            "X-Forwarded-For",
            "Date",
        ]
    }

    pub fn request_optional_headers() -> [&'static str; 11] {
        [
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

    pub fn response_optional_headers() -> [&'static str; 12] {
        [
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

    pub fn request_skip_value_headers() -> [&'static str; 2] {
        ["Host", "User-Agent"]
    }

    pub fn response_skip_value_headers() -> [&'static str; 3] {
        ["Date", "Content-Type", "Server"]
    }

    pub fn request_common_headers() -> [&'static str; 8] {
        [
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

    pub fn response_common_headers() -> [&'static str; 5] {
        [
            "Content-Type",
            "Connection",
            "Keep-Alive",
            "Accept-Ranges",
            "Date",
        ]
    }
}
