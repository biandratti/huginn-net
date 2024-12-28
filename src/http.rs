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

    pub fn with_optional_value<S: AsRef<str>>(mut self, value: Option<S>) -> Self {
        self.value = value.map(|v| v.as_ref().to_owned());
        self
    }

    pub fn optional(mut self) -> Self {
        self.optional = true;
        self
    }
}

pub struct HeaderRegistry {
    pub headers: HashMap<String, (u32, HeaderCategory, HeaderGroup)>,
    id: u32,
}

pub enum HeaderCategory {
    Mandatory,
    Optional,
    SkipValue,
    Common,
}

pub enum HeaderGroup {
    All,
    Request,
    Response,
}

impl HeaderRegistry {
    fn new() -> Self {
        Self {
            headers: HashMap::new(),
            id: 0,
        }
    }

    // TODO: evaluate static
    pub fn init() -> Self {
        let mut registry = HeaderRegistry::new();

        for &header in &Self::expected_headers() {
            registry.register_header(header, HeaderCategory::Mandatory, HeaderGroup::All);
        }
        for &header in &Self::request_optional_headers() {
            registry.register_header(header, HeaderCategory::Optional, HeaderGroup::Request);
        }
        for &header in &Self::response_optional_headers() {
            registry.register_header(header, HeaderCategory::Optional, HeaderGroup::Response);
        }
        for &header in &Self::request_skip_value_headers() {
            registry.register_header(header, HeaderCategory::SkipValue, HeaderGroup::Request);
        }
        for &header in &Self::response_skip_value_headers() {
            registry.register_header(header, HeaderCategory::SkipValue, HeaderGroup::Response);
        }
        for &header in &Self::request_common_headers() {
            registry.register_header(header, HeaderCategory::Common, HeaderGroup::Request);
        }
        for &header in &Self::response_common_headers() {
            registry.register_header(header, HeaderCategory::Common, HeaderGroup::Response);
        }

        registry
    }

    /// Register a header and return the id registered
    fn register_header<S: AsRef<str>>(
        &mut self,
        name: S,
        category: HeaderCategory,
        group: HeaderGroup,
    ) -> u32 {
        let name = name.as_ref();

        if let Some(&(id, _, _)) = self.headers.get(name) {
            return id;
        }

        // Assign a new ID and insert into the registry
        let id = self.id;
        self.id += 1;

        self.headers.insert(name.to_owned(), (id, category, group));

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

    fn request_optional_headers() -> [&'static str; 11] {
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

    fn response_optional_headers() -> [&'static str; 12] {
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

    fn request_skip_value_headers() -> [&'static str; 2] {
        ["Host", "User-Agent"]
    }

    fn response_skip_value_headers() -> [&'static str; 3] {
        ["Date", "Content-Type", "Server"]
    }

    fn request_common_headers() -> [&'static str; 8] {
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

    fn response_common_headers() -> [&'static str; 5] {
        [
            "Content-Type",
            "Connection",
            "Keep-Alive",
            "Accept-Ranges",
            "Date",
        ]
    }
}
