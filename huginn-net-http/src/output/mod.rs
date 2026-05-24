pub mod common;
#[cfg(feature = "p0f-request")]
pub mod request;
#[cfg(feature = "p0f-response")]
pub mod response;

#[cfg(feature = "json")]
pub(crate) fn serialize_display<T: std::fmt::Display, S: serde::Serializer>(
    val: &T,
    s: S,
) -> Result<S::Ok, S::Error> {
    s.serialize_str(&val.to_string())
}

pub use common::*;
#[cfg(feature = "p0f-request")]
pub use request::*;
#[cfg(feature = "p0f-response")]
pub use response::*;

/// Result of analyzing HTTP packets, mirrors the database-agnostic shape of
/// `HuginnNetHttp::analyze_*`.
///
/// Field availability depends on the enabled HTTP features:
/// - [`Self::http_request`] requires the `p0f-request` feature.
/// - [`Self::http_response`] requires the `p0f-response` feature.
///
/// Use [`Self::empty`] to construct a fallback value that is valid under any
/// feature combination.
#[derive(Debug)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct HttpAnalysisResult {
    /// Information derived from HTTP request packets.
    #[cfg(feature = "p0f-request")]
    pub http_request: Option<HttpRequestOutput>,
    /// Information derived from HTTP response packets.
    #[cfg(feature = "p0f-response")]
    pub http_response: Option<HttpResponseOutput>,
}

impl HttpAnalysisResult {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            #[cfg(feature = "p0f-request")]
            http_request: None,
            #[cfg(feature = "p0f-response")]
            http_response: None,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        #[cfg(feature = "p0f-request")]
        if self.http_request.is_some() {
            return false;
        }
        #[cfg(feature = "p0f-response")]
        if self.http_response.is_some() {
            return false;
        }
        true
    }
}
