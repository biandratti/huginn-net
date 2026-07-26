use super::HuginnNet;
#[cfg(any(feature = "http-p0f-request", feature = "http-p0f-response"))]
use huginn_net_http::http::{build_params, HttpParams, MatchedSignatureNotes};
#[cfg(feature = "http-p0f-request")]
use huginn_net_http::observable::ObservableHttpRequest;
#[cfg(feature = "http-p0f-response")]
use huginn_net_http::observable::ObservableHttpResponse;
#[cfg(feature = "http-p0f-request")]
use huginn_net_http::output::BrowserQualityMatched;
#[cfg(any(feature = "http-p0f-request", feature = "http-p0f-response"))]
use huginn_net_http::output::MatchQuality as HttpMatchQuality;
#[cfg(feature = "http-p0f-response")]
use huginn_net_http::output::WebServerQualityMatched;
#[cfg(any(feature = "tcp-syn", feature = "tcp-syn-ack"))]
use huginn_net_tcp::observable::ObservableTcp;
#[cfg(feature = "tcp-mtu")]
use huginn_net_tcp::output::MTUQualityMatched;
#[cfg(any(feature = "tcp-syn", feature = "tcp-syn-ack", feature = "tcp-mtu"))]
use huginn_net_tcp::output::MatchQuality as TcpMatchQuality;
#[cfg(any(feature = "tcp-syn", feature = "tcp-syn-ack"))]
use huginn_net_tcp::output::OSQualityMatched;

#[cfg(all(
    feature = "db",
    any(
        feature = "tcp-syn",
        feature = "tcp-syn-ack",
        feature = "tcp-mtu",
        feature = "http-p0f-request",
        feature = "http-p0f-response"
    )
))]
use crate::quality_match;
#[cfg(all(
    feature = "db",
    any(
        feature = "tcp-syn",
        feature = "tcp-syn-ack",
        feature = "tcp-mtu",
        feature = "http-p0f-response"
    )
))]
use crate::simple_quality_match;
#[cfg(all(feature = "db", feature = "http-p0f-request"))]
use huginn_net_http::output::Browser;
#[cfg(all(feature = "db", feature = "http-p0f-response"))]
use huginn_net_http::output::WebServer;
#[cfg(all(feature = "db", any(feature = "tcp-syn", feature = "tcp-syn-ack")))]
use huginn_net_tcp::output::OperativeSystem;

use crate::AnalysisConfig;

/// Combined HTTP request matching outcome. Internal helper used by
/// [`HuginnNet::match_http_request`] so that the cfg-gated branches stay
/// confined to a single function.
#[cfg(feature = "http-p0f-request")]
pub(super) struct HttpRequestMatchResult {
    pub(super) browser_quality: BrowserQualityMatched,
    pub(super) params: HttpParams,
}

/// Same, for responses.
#[cfg(feature = "http-p0f-response")]
pub(super) struct HttpResponseMatchResult {
    pub(super) web_server_quality: WebServerQualityMatched,
    pub(super) params: HttpParams,
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
    #[cfg(feature = "tcp-mtu")]
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

    #[cfg(feature = "tcp-syn")]
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

    #[cfg(feature = "tcp-syn-ack")]
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

    #[cfg(feature = "http-p0f-request")]
    pub(super) fn match_http_request(
        &self,
        observable_http_request: &ObservableHttpRequest,
    ) -> HttpRequestMatchResult {
        #[cfg(feature = "db")]
        {
            let observed = &observable_http_request.matching;
            let (browser_quality, notes) = quality_match!(
                enabled: self.config.matcher_enabled,
                matcher: self.http_matcher,
                call: matcher => Some(matcher.matching_by_http_request(observed)),
                matched: signature_matcher => {
                    signature_matcher
                        .map(|(label, signature, quality)| {
                            let notes = MatchedSignatureNotes {
                                dishonest: !huginn_net_db::http::expsw_matches(
                                    &observed.expsw,
                                    &signature.expsw,
                                ),
                                generic: label.ty == huginn_net_db::database::Type::Generic,
                            };
                            (
                                BrowserQualityMatched {
                                    browser: Some(Browser::from(label)),
                                    quality: HttpMatchQuality::Matched(quality),
                                },
                                Some(notes),
                            )
                        })
                        .unwrap_or((
                            BrowserQualityMatched {
                                browser: None,
                                quality: HttpMatchQuality::NotMatched,
                            },
                            None,
                        ))
                },
                not_matched: (
                    BrowserQualityMatched {
                        browser: None,
                        quality: HttpMatchQuality::NotMatched,
                    },
                    None
                ),
                disabled: (
                    BrowserQualityMatched {
                        browser: None,
                        quality: HttpMatchQuality::Disabled,
                    },
                    None
                )
            );

            HttpRequestMatchResult { params: build_params(&observed.expsw, notes), browser_quality }
        }
        #[cfg(not(feature = "db"))]
        {
            // Without the `db` feature nothing matched, so the only note we can
            // still make is whether the client identified itself at all.
            HttpRequestMatchResult {
                params: build_params(&observable_http_request.matching.expsw, None),
                browser_quality: BrowserQualityMatched {
                    browser: None,
                    quality: HttpMatchQuality::Disabled,
                },
            }
        }
    }

    #[cfg(feature = "http-p0f-response")]
    pub(super) fn match_http_response(
        &self,
        observable_http_response: &ObservableHttpResponse,
    ) -> HttpResponseMatchResult {
        #[cfg(feature = "db")]
        {
            let observed = &observable_http_response.matching;
            let (web_server_quality, notes) = quality_match!(
                enabled: self.config.matcher_enabled,
                matcher: self.http_matcher,
                call: matcher => Some(matcher.matching_by_http_response(observed)),
                matched: signature_matcher => {
                    signature_matcher
                        .map(|(label, signature, quality)| {
                            let notes = MatchedSignatureNotes {
                                dishonest: !huginn_net_db::http::expsw_matches(
                                    &observed.expsw,
                                    &signature.expsw,
                                ),
                                generic: label.ty == huginn_net_db::database::Type::Generic,
                            };
                            (
                                WebServerQualityMatched {
                                    web_server: Some(WebServer::from(label)),
                                    quality: HttpMatchQuality::Matched(quality),
                                },
                                Some(notes),
                            )
                        })
                        .unwrap_or((
                            WebServerQualityMatched {
                                web_server: None,
                                quality: HttpMatchQuality::NotMatched,
                            },
                            None,
                        ))
                },
                not_matched: (
                    WebServerQualityMatched {
                        web_server: None,
                        quality: HttpMatchQuality::NotMatched,
                    },
                    None
                ),
                disabled: (
                    WebServerQualityMatched {
                        web_server: None,
                        quality: HttpMatchQuality::Disabled,
                    },
                    None
                )
            );

            HttpResponseMatchResult {
                params: build_params(&observed.expsw, notes),
                web_server_quality,
            }
        }
        #[cfg(not(feature = "db"))]
        {
            HttpResponseMatchResult {
                params: build_params(&observable_http_response.matching.expsw, None),
                web_server_quality: WebServerQualityMatched {
                    web_server: None,
                    quality: HttpMatchQuality::Disabled,
                },
            }
        }
    }
}
