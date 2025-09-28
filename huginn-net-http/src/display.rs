use crate::http_common::HttpHeader;
use crate::observable::{ObservableHttpRequest, ObservableHttpResponse};
use core::fmt;
use huginn_net_db::display::http::HttpDisplayFormat;
use huginn_net_db::http::{Header, Version};
use std::fmt::Formatter;

impl HttpDisplayFormat for ObservableHttpRequest {
    fn get_version(&self) -> Version {
        self.matching.version
    }
    fn get_horder(&self) -> &[Header] {
        &self.matching.horder
    }
    fn get_habsent(&self) -> &[Header] {
        &self.matching.habsent
    }
    fn get_expsw(&self) -> &str {
        &self.matching.expsw
    }
}

impl HttpDisplayFormat for ObservableHttpResponse {
    fn get_version(&self) -> Version {
        self.matching.version
    }
    fn get_horder(&self) -> &[Header] {
        &self.matching.horder
    }
    fn get_habsent(&self) -> &[Header] {
        &self.matching.habsent
    }
    fn get_expsw(&self) -> &str {
        &self.matching.expsw
    }
}

impl fmt::Display for ObservableHttpRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.format_http_display(f)
    }
}

impl fmt::Display for ObservableHttpResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.format_http_display(f)
    }
}

impl fmt::Display for HttpHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Some(ref value) = self.value {
            write!(f, "{}={}", self.name, value)
        } else {
            write!(f, "{}", self.name)
        }
    }
}
