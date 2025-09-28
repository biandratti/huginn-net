use huginn_net_db::{Label, MatchQualityType, Type};
use std::fmt;
use std::fmt::Formatter;

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
use crate::observable::{ObservableHttpRequest, ObservableHttpResponse};
use huginn_net_db::http::HttpDiagnosis;

pub struct BrowserQualityMatched {
    pub browser: Option<Browser>,
    pub quality: MatchQualityType,
}

/// Represents a browser.
///
/// This struct contains the name, family, variant, and kind of browser.
/// Examples:
/// - name: "", family: "chrome", variant: "11.x to 26.x", kind: Type::Specified
/// - name: "", family: "firefox", variant: "3.x", kind: Type::Specified
pub struct Browser {
    pub name: String,
    pub family: Option<String>,
    pub variant: Option<String>,
    pub kind: Type,
}

impl From<&Label> for Browser {
    fn from(label: &Label) -> Self {
        Browser {
            name: label.name.clone(),
            family: label.class.clone(),
            variant: label.flavor.clone(),
            kind: label.ty.clone(),
        }
    }
}

/// Holds information derived from analyzing HTTP request headers.
///
/// This structure contains details about the client, the detected application
/// (if any), the preferred language, diagnostic parameters related to HTTP behavior,
/// and the raw HTTP signature.
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

impl fmt::Display for HttpRequestOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            ".-[ {}/{} -> {}/{} (http request) ]-\n\
            |\n\
            | client   = {}/{}\n\
            | app      = {}\n\
            | lang     = {}\n\
            | params   = {}\n\
            | raw_sig  = {}\n\
            `----\n",
            self.source.ip,
            self.source.port,
            self.destination.ip,
            self.destination.port,
            self.source.ip,
            self.source.port,
            self.browser_matched
                .browser
                .as_ref()
                .map_or("???".to_string(), |browser| {
                    format!(
                        "{}/{}/{}",
                        browser.name,
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

pub struct WebServerQualityMatched {
    pub web_server: Option<WebServer>,
    pub quality: MatchQualityType,
}

/// Represents a web server.
///
/// This struct contains the name, family, variant, and kind of browser.
/// Examples:
/// - name: "", family: "apache", variant: "2.x", kind: Type::Specified
/// - name: "", family: "nginx", variant: "1.x", kind: Type::Specified
pub struct WebServer {
    pub name: String,
    pub family: Option<String>,
    pub variant: Option<String>,
    pub kind: Type,
}

impl From<&Label> for WebServer {
    fn from(label: &Label) -> Self {
        WebServer {
            name: label.name.clone(),
            family: label.class.clone(),
            variant: label.flavor.clone(),
            kind: label.ty.clone(),
        }
    }
}

/// Holds information derived from analyzing HTTP response headers.
///
/// This structure contains details about the server, the detected application
/// (if any), diagnostic parameters related to HTTP behavior, and the raw HTTP signature.
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

impl fmt::Display for HttpResponseOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            ".-[ {}/{} -> {}/{} (http response) ]-\n\
            |\n\
            | server   = {}/{}\n\
            | app      = {}\n\
            | params   = {}\n\
            | raw_sig  = {}\n\
            `----\n",
            self.source.ip,
            self.source.port,
            self.destination.ip,
            self.destination.port,
            self.destination.ip,
            self.destination.port,
            self.web_server_matched
                .web_server
                .as_ref()
                .map_or("???".to_string(), |web_server| {
                    format!(
                        "{}/{}/{}",
                        web_server.name,
                        web_server.family.as_deref().unwrap_or("???"),
                        web_server.variant.as_deref().unwrap_or("???")
                    )
                }),
            self.diagnosis,
            self.sig,
        )
    }
}
