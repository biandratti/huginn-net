#[cfg(any(feature = "p0f-request", feature = "p0f-response"))]
use crate::http::HttpDiagnosis;
#[cfg(feature = "p0f-request")]
use crate::observable::ObservableHttpRequest;
#[cfg(feature = "p0f-response")]
use crate::observable::ObservableHttpResponse;
#[cfg(any(feature = "p0f-request", feature = "p0f-response"))]
use std::fmt;
#[cfg(any(feature = "p0f-request", feature = "p0f-response"))]
use std::fmt::Formatter;

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
}

#[derive(Debug, Clone, PartialEq)]
pub struct IpPort {
    pub ip: std::net::IpAddr,
    pub port: u16,
}

impl IpPort {
    pub fn new(ip: std::net::IpAddr, port: u16) -> Self {
        Self { ip, port }
    }
}

/// Whether a matched browser/web server label was a *specified* (concrete)
/// or *generic* (catch-all) entry in the underlying database.
///
/// Defined locally so `huginn-net-http` does not depend on `huginn-net-db`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OsKind {
    Specified,
    Generic,
}

/// Quality classification for an HTTP match.
///
/// - `Matched(score)` a signature was matched with the given quality score
///   (higher is better, typically in `[0.0, 1.0]`).
/// - `NotMatched` the matcher was active but no signature was a viable fit.
/// - `Disabled` matching was disabled (no matcher plugged in).
#[derive(Clone, Debug)]
pub enum MatchQuality {
    Matched(f32),
    NotMatched,
    Disabled,
}

#[cfg(feature = "p0f-request")]
#[derive(Debug)]
pub struct BrowserQualityMatched {
    pub browser: Option<Browser>,
    pub quality: MatchQuality,
}

/// Represents a browser identified from an HTTP request signature.
#[derive(Debug, Clone)]
pub struct Browser {
    pub name: String,
    pub family: Option<String>,
    pub variant: Option<String>,
    pub kind: OsKind,
}

#[cfg(feature = "p0f-response")]
#[derive(Debug)]
pub struct WebServerQualityMatched {
    pub web_server: Option<WebServer>,
    pub quality: MatchQuality,
}

/// Represents a web server identified from an HTTP response signature.
#[derive(Debug, Clone)]
pub struct WebServer {
    pub name: String,
    pub family: Option<String>,
    pub variant: Option<String>,
    pub kind: OsKind,
}

/// Holds information derived from analyzing HTTP request headers.
#[cfg(feature = "p0f-request")]
#[derive(Debug)]
pub struct HttpRequestOutput {
    /// The source IP address and port of the client making the request.
    pub source: IpPort,
    /// The destination IP address and port of the server receiving the request.
    pub destination: IpPort,
    /// The preferred language indicated in the `Accept-Language` header, if present.
    pub lang: Option<String>,
    /// Diagnostic information about potential HTTP specification violations or common practices.
    pub diagnosis: HttpDiagnosis,
    /// The browser with the highest quality that matches the HTTP request.
    pub browser_matched: BrowserQualityMatched,
    /// The raw signature representing the HTTP headers and their order.
    pub sig: ObservableHttpRequest,
}

#[cfg(feature = "p0f-request")]
impl fmt::Display for HttpRequestOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[HTTP Request] {}:{} → {}:{}\n\
              Browser: {}\n\
              Lang:    {}\n\
              Params:  {}\n\
              Sig:     {}\n",
            self.source.ip,
            self.source.port,
            self.destination.ip,
            self.destination.port,
            self.browser_matched
                .browser
                .as_ref()
                .map_or("???".to_string(), |browser| {
                    format!(
                        "{}:{}",
                        browser.family.as_deref().unwrap_or("???"),
                        browser.variant.as_deref().unwrap_or("???")
                    )
                }),
            self.lang.as_deref().unwrap_or("???"),
            self.diagnosis,
            self.sig,
        )
    }
}

/// Holds information derived from analyzing HTTP response headers.
#[cfg(feature = "p0f-response")]
#[derive(Debug)]
pub struct HttpResponseOutput {
    /// The source IP address and port of the server sending the response.
    pub source: IpPort,
    /// The destination IP address and port of the client receiving the response.
    pub destination: IpPort,
    /// Diagnostic information about potential HTTP specification violations or common practices.
    pub diagnosis: HttpDiagnosis,
    /// The label identifying the likely server application (e.g., Apache, Nginx) and the quality.
    pub web_server_matched: WebServerQualityMatched,
    /// The raw signature representing the HTTP headers and their order.
    pub sig: ObservableHttpResponse,
}

#[cfg(feature = "p0f-response")]
impl fmt::Display for HttpResponseOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[HTTP Response] {}:{} → {}:{}\n\
              Server:  {}\n\
              Params:  {}\n\
              Sig:     {}\n",
            self.source.ip,
            self.source.port,
            self.destination.ip,
            self.destination.port,
            self.web_server_matched
                .web_server
                .as_ref()
                .map_or("???".to_string(), |web_server| {
                    if !web_server.name.is_empty() {
                        web_server.name.clone()
                    } else {
                        format!(
                            "{}:{}",
                            web_server.family.as_deref().unwrap_or("???"),
                            web_server.variant.as_deref().unwrap_or("???")
                        )
                    }
                }),
            self.diagnosis,
            self.sig,
        )
    }
}
