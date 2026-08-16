use core::fmt;
use huginn_net_http::display::HttpDisplayFormat;
use huginn_net_http::http::{Header, Version};
use std::fmt::Formatter;

#[derive(Clone, Debug, PartialEq)]
pub struct Signature {
    /// HTTP version
    pub version: super::Version,
    /// ordered list of headers that should appear in matching traffic.
    pub horder: Vec<super::Header>,
    /// list of headers that must *not* appear in matching traffic.
    pub habsent: Vec<super::Header>,
    /// expected substring in 'User-Agent' or 'Server'.
    pub expsw: String,
}

impl HttpDisplayFormat for Signature {
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

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.format_http_display(f)
    }
}
