use crate::http::{Header, Version};
use crate::http_common::HttpHeader;
use crate::observable::{
    HttpRequestObservation, HttpResponseObservation, ObservableHttpRequest, ObservableHttpResponse,
};
use core::fmt;
use std::fmt::Formatter;

/// Trait used to render HTTP signatures in the canonical p0f text form
/// `version:horder:habsent:expsw`.
///
/// `huginn-net-db` implements this trait for its own `http::Signature` and
/// reuses the same shape, so observations and DB signatures print identically.
pub trait HttpDisplayFormat {
    fn get_version(&self) -> Version;
    fn get_horder(&self) -> &[Header];
    fn get_habsent(&self) -> &[Header];
    fn get_expsw(&self) -> &str;

    fn format_http_display(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.get_version())?;

        for (i, h) in self.get_horder().iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            write!(f, "{h}")?;
        }

        f.write_str(":")?;

        for (i, h) in self.get_habsent().iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            write!(f, "{h}")?;
        }

        write!(f, ":{}", self.get_expsw())
    }
}

impl HttpDisplayFormat for HttpRequestObservation {
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

impl HttpDisplayFormat for HttpResponseObservation {
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

impl fmt::Display for HttpRequestObservation {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.format_http_display(f)
    }
}

impl fmt::Display for HttpResponseObservation {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.format_http_display(f)
    }
}

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
