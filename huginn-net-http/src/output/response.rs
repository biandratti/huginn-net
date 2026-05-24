use super::common::{IpPort, MatchQuality, WebServer};
use crate::http::HttpDiagnosis;
use crate::observable::ObservableHttpResponse;
use std::fmt;
use std::fmt::Formatter;

#[derive(Debug)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct WebServerQualityMatched {
    pub web_server: Option<WebServer>,
    pub quality: MatchQuality,
}

/// Holds information derived from analyzing HTTP response headers.
#[derive(Debug)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct HttpResponseOutput {
    /// The source IP address and port of the server sending the response.
    pub source: IpPort,
    /// The destination IP address and port of the client receiving the response.
    pub destination: IpPort,
    /// Diagnostic information about potential HTTP specification violations or common practices.
    #[cfg_attr(feature = "json", serde(serialize_with = "super::serialize_display"))]
    pub diagnosis: HttpDiagnosis,
    /// The label identifying the likely server application (e.g., Apache, Nginx) and the quality.
    pub web_server_matched: WebServerQualityMatched,
    /// The raw signature representing the HTTP headers and their order.
    #[cfg_attr(feature = "json", serde(serialize_with = "super::serialize_display"))]
    pub sig: ObservableHttpResponse,
}

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
