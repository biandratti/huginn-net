use super::common::{Browser, IpPort, MatchQuality};
use crate::http::HttpParams;
use crate::observable::ObservableHttpRequest;
use std::fmt;
use std::fmt::Formatter;

#[derive(Debug)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct BrowserQualityMatched {
    pub browser: Option<Browser>,
    pub quality: MatchQuality,
}

/// Holds information derived from analyzing HTTP request headers.
#[derive(Debug)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct HttpRequestOutput {
    /// The source IP address and port of the client making the request.
    pub source: IpPort,
    /// The destination IP address and port of the server receiving the request.
    pub destination: IpPort,
    /// The preferred language indicated in the `Accept-Language` header, if present.
    pub lang: Option<String>,
    /// Notes about the matched signature: whether the host is lying about its
    /// software, whether it identified itself at all, and whether the match
    /// was a generic catch-all.
    #[cfg_attr(feature = "json", serde(serialize_with = "super::serialize_display"))]
    pub params: HttpParams,
    /// The browser with the highest quality that matches the HTTP request.
    pub browser_matched: BrowserQualityMatched,
    /// The raw signature representing the HTTP headers and their order.
    #[cfg_attr(feature = "json", serde(serialize_with = "super::serialize_display"))]
    pub sig: ObservableHttpRequest,
}

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
            self.params,
            self.sig,
        )
    }
}
