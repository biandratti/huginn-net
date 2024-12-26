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
    headers: HashMap<String, (u32, Header)>,
    next_id: u32,
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
            next_id: 0,
        }
    }

    /// Register a header and return the id registered
    pub fn register_header<S: AsRef<str>>(&mut self, name: S, category: HeaderCategory) -> u32 {
        let name = name.as_ref();

        // Return existing ID if already registered
        if let Some(&(id, _)) = self.headers.get(name) {
            return id;
        }

        // Create a new Header
        let mut header = Header::new(name);
        if category == HeaderCategory::Optional {
            header.optional = true;
        }

        // Assign a new ID and insert into the registry
        let id = self.next_id;
        self.next_id += 1;

        self.headers.insert(name.to_owned(), (id, header));

        id
    }

    // Get header by name
    fn get_header<S: AsRef<str>>(&self, name: S) -> Option<&Header> {
        self.headers.get(name.as_ref()).map(|(_, header)| header)
    }

    // Get header ID by name
    fn get_header_id<S: AsRef<str>>(&self, name: S) -> Option<u32> {
        self.headers.get(name.as_ref()).map(|(id, _)| *id)
    }
}
