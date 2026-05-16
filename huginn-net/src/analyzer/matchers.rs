use super::HuginnNet;
use huginn_net_http::http::HttpDiagnosis;
use huginn_net_http::observable::{ObservableHttpRequest, ObservableHttpResponse};
use huginn_net_http::output::{
    BrowserQualityMatched, MatchQuality as HttpMatchQuality, WebServerQualityMatched,
};
use huginn_net_tcp::observable::ObservableTcp;
use huginn_net_tcp::output::{
    MTUQualityMatched, MatchQuality as TcpMatchQuality, OSQualityMatched,
};

#[cfg(feature = "db")]
use crate::quality_match;
#[cfg(feature = "db")]
use crate::simple_quality_match;
#[cfg(feature = "db")]
use huginn_net_http::output::{Browser, WebServer};
#[cfg(feature = "db")]
use huginn_net_tcp::output::OperativeSystem;

use crate::AnalysisConfig;

/// Combined HTTP request matching outcome. Internal helper used by
/// [`HuginnNet::match_http_request`] so that the cfg-gated branches stay
/// confined to a single function.
pub(super) struct HttpRequestMatchResult {
    pub(super) browser_quality: BrowserQualityMatched,
    pub(super) http_diagnosis: HttpDiagnosis,
}

/// Compute the connection-tracker and HTTP flow cache sizes based on which
/// protocols the user enabled. Disabled protocols don't reserve memory.
pub(super) fn cache_sizes(config: &AnalysisConfig, max_connections: usize) -> (usize, usize) {
    let connection_tracker_size = if config.tcp_enabled {
        max_connections
    } else {
        0
    };
    let http_flows_size = if config.http_enabled {
        max_connections
    } else {
        0
    };
    (connection_tracker_size, http_flows_size)
}

impl<'a> HuginnNet<'a> {
    pub(super) fn match_mtu(&self, mtu: &u16) -> MTUQualityMatched {
        #[cfg(feature = "db")]
        {
            simple_quality_match!(
                enabled: self.config.matcher_enabled,
                matcher: self.tcp_matcher,
                method: matching_by_mtu(mtu),
                success: (link, _) => MTUQualityMatched {
                    link: Some(link.clone()),
                    quality: TcpMatchQuality::Matched(1.0),
                },
                failure: MTUQualityMatched {
                    link: None,
                    quality: TcpMatchQuality::NotMatched,
                },
                disabled: MTUQualityMatched {
                    link: None,
                    quality: TcpMatchQuality::Disabled,
                }
            )
        }
        #[cfg(not(feature = "db"))]
        {
            let _ = mtu;
            MTUQualityMatched { link: None, quality: TcpMatchQuality::Disabled }
        }
    }

    pub(super) fn match_tcp_request(&self, observable_tcp: &ObservableTcp) -> OSQualityMatched {
        #[cfg(feature = "db")]
        {
            simple_quality_match!(
                enabled: self.config.matcher_enabled,
                matcher: self.tcp_matcher,
                method: matching_by_tcp_request(observable_tcp),
                success: (label, _signature, quality) => OSQualityMatched {
                    os: Some(OperativeSystem::from(label)),
                    quality: TcpMatchQuality::Matched(quality),
                },
                failure: OSQualityMatched {
                    os: None,
                    quality: TcpMatchQuality::NotMatched,
                },
                disabled: OSQualityMatched {
                    os: None,
                    quality: TcpMatchQuality::Disabled,
                }
            )
        }
        #[cfg(not(feature = "db"))]
        {
            let _ = observable_tcp;
            OSQualityMatched { os: None, quality: TcpMatchQuality::Disabled }
        }
    }

    pub(super) fn match_tcp_response(&self, observable_tcp: &ObservableTcp) -> OSQualityMatched {
        #[cfg(feature = "db")]
        {
            simple_quality_match!(
                enabled: self.config.matcher_enabled,
                matcher: self.tcp_matcher,
                method: matching_by_tcp_response(observable_tcp),
                success: (label, _signature, quality) => OSQualityMatched {
                    os: Some(OperativeSystem::from(label)),
                    quality: TcpMatchQuality::Matched(quality),
                },
                failure: OSQualityMatched {
                    os: None,
                    quality: TcpMatchQuality::NotMatched,
                },
                disabled: OSQualityMatched {
                    os: None,
                    quality: TcpMatchQuality::Disabled,
                }
            )
        }
        #[cfg(not(feature = "db"))]
        {
            let _ = observable_tcp;
            OSQualityMatched { os: None, quality: TcpMatchQuality::Disabled }
        }
    }

    pub(super) fn match_http_request(
        &self,
        observable_http_request: &ObservableHttpRequest,
    ) -> HttpRequestMatchResult {
        #[cfg(feature = "db")]
        {
            let (signature_matcher, ua_matcher, browser_quality) = quality_match!(
                enabled: self.config.matcher_enabled,
                matcher: self.http_matcher,
                call: matcher => {
                    let sig_match = matcher.matching_by_http_request(&observable_http_request.matching);
                    let ua_match = observable_http_request.user_agent.clone()
                        .and_then(|ua| matcher.matching_by_user_agent(&ua));
                    Some((sig_match, ua_match))
                },
                matched: (signature_matcher, ua_matcher) => {
                    let browser_quality = signature_matcher
                        .map(|(label, _signature, quality)| BrowserQualityMatched {
                            browser: Some(Browser::from(label)),
                            quality: HttpMatchQuality::Matched(quality),
                        })
                        .unwrap_or(BrowserQualityMatched {
                            browser: None,
                            quality: HttpMatchQuality::NotMatched,
                        });
                    (signature_matcher, ua_matcher, browser_quality)
                },
                not_matched: {
                    let browser_quality = BrowserQualityMatched {
                        browser: None,
                        quality: HttpMatchQuality::NotMatched,
                    };
                    (None, None, browser_quality)
                },
                disabled: {
                    let browser_quality = BrowserQualityMatched {
                        browser: None,
                        quality: HttpMatchQuality::Disabled,
                    };
                    (None, None, browser_quality)
                }
            );

            // TODO(v2-followup): the third argument should be the OS name from
            // the TCP fingerprint match (network-observed OS), not the HTTP
            // signature label name (which is a *browser* name like "Firefox"
            // when the matcher is HTTP). Revisit in a dedicated PR by wiring
            // the TCP `OSQualityMatched` produced for `syn`/`syn_ack` of the
            // same packet into this diagnostic.
            let http_diagnosis = huginn_net_http::http_common::get_diagnostic(
                observable_http_request.user_agent.clone(),
                ua_matcher.and_then(|(_, family)| family),
                signature_matcher.map(|(label, _signature, _quality)| label.name.as_str()),
            );

            HttpRequestMatchResult { browser_quality, http_diagnosis }
        }
        #[cfg(not(feature = "db"))]
        {
            // Without the `db` feature we can still report UA/network agreement
            // based on the User-Agent string alone (UA → declared OS family).
            let http_diagnosis = huginn_net_http::http_common::get_diagnostic(
                observable_http_request.user_agent.clone(),
                None,
                None,
            );
            HttpRequestMatchResult {
                browser_quality: BrowserQualityMatched {
                    browser: None,
                    quality: HttpMatchQuality::Disabled,
                },
                http_diagnosis,
            }
        }
    }

    pub(super) fn match_http_response(
        &self,
        observable_http_response: &ObservableHttpResponse,
    ) -> WebServerQualityMatched {
        #[cfg(feature = "db")]
        {
            simple_quality_match!(
                enabled: self.config.matcher_enabled,
                matcher: self.http_matcher,
                method: matching_by_http_response(&observable_http_response.matching),
                success: (label, _signature, quality) => WebServerQualityMatched {
                    web_server: Some(WebServer::from(label)),
                    quality: HttpMatchQuality::Matched(quality),
                },
                failure: WebServerQualityMatched {
                    web_server: None,
                    quality: HttpMatchQuality::NotMatched,
                },
                disabled: WebServerQualityMatched {
                    web_server: None,
                    quality: HttpMatchQuality::Disabled,
                }
            )
        }
        #[cfg(not(feature = "db"))]
        {
            let _ = observable_http_response;
            WebServerQualityMatched { web_server: None, quality: HttpMatchQuality::Disabled }
        }
    }
}
