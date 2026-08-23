use super::HuginnNet;
#[cfg(all(
    feature = "db",
    any(feature = "http-p0f-request", feature = "http-p0f-response")
))]
use huginn_net_http::http::MatchedSignatureNotes;
#[cfg(any(feature = "http-p0f-request", feature = "http-p0f-response"))]
use huginn_net_http::http::{build_params, HttpParams};
#[cfg(feature = "http-p0f-request")]
use huginn_net_http::http::{check_ua_os_agreement, ObservedOsInput, UaOsAgreement};
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
#[cfg(all(
    feature = "db",
    any(feature = "tcp-syn", feature = "tcp-syn-ack", feature = "tcp-mtu")
))]
use huginn_net_tcp::matcher_api::TcpMatcher;
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
use crate::{quality_match, simple_quality_match};
#[cfg(all(
    feature = "db",
    any(feature = "http-p0f-request", feature = "http-p0f-response")
))]
use huginn_net_http::matcher_api::HttpMatcher;
#[cfg(all(
    feature = "db",
    any(feature = "http-p0f-request", feature = "http-p0f-response")
))]
use huginn_net_http::output::OsKind;

use crate::AnalysisConfig;

/// Combined HTTP request matching outcome. Internal helper used by
/// [`HuginnNet::match_http_request`] so that the cfg-gated branches stay
/// confined to a single function.
#[cfg(feature = "http-p0f-request")]
pub(super) struct HttpRequestMatchResult {
    pub(super) browser_quality: BrowserQualityMatched,
    pub(super) params: HttpParams,
    pub(super) ua_os: UaOsAgreement,
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
                method: match_mtu(*mtu),
                success: found => MTUQualityMatched {
                    link: Some(found.link),
                    quality: TcpMatchQuality::exact(1.0),
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
            let obs = &observable_tcp.matching;
            simple_quality_match!(
                enabled: self.config.matcher_enabled,
                matcher: self.tcp_matcher,
                method: match_tcp_request(obs),
                success: found => OSQualityMatched {
                    os: Some(found.os),
                    quality: TcpMatchQuality::Matched {
                        quality: found.quality,
                        fuzzy: found.fuzzy,
                    },
                    dist: found.dist,
                    random_ttl: found.random_ttl,
                    excess_dist: found.excess_dist,
                    tos: obs.tos,
                },
                failure: OSQualityMatched::without_match(TcpMatchQuality::NotMatched, obs),
                disabled: OSQualityMatched::without_match(TcpMatchQuality::Disabled, obs)
            )
        }
        #[cfg(not(feature = "db"))]
        {
            OSQualityMatched::without_match(TcpMatchQuality::Disabled, &observable_tcp.matching)
        }
    }

    #[cfg(feature = "tcp-syn-ack")]
    pub(super) fn match_tcp_response(&self, observable_tcp: &ObservableTcp) -> OSQualityMatched {
        #[cfg(feature = "db")]
        {
            let obs = &observable_tcp.matching;
            simple_quality_match!(
                enabled: self.config.matcher_enabled,
                matcher: self.tcp_matcher,
                method: match_tcp_response(obs),
                success: found => OSQualityMatched {
                    os: Some(found.os),
                    quality: TcpMatchQuality::Matched {
                        quality: found.quality,
                        fuzzy: found.fuzzy,
                    },
                    dist: found.dist,
                    random_ttl: found.random_ttl,
                    excess_dist: found.excess_dist,
                    tos: obs.tos,
                },
                failure: OSQualityMatched::without_match(TcpMatchQuality::NotMatched, obs),
                disabled: OSQualityMatched::without_match(TcpMatchQuality::Disabled, obs)
            )
        }
        #[cfg(not(feature = "db"))]
        {
            OSQualityMatched::without_match(TcpMatchQuality::Disabled, &observable_tcp.matching)
        }
    }

    #[cfg(feature = "http-p0f-request")]
    pub(super) fn match_http_request(
        &self,
        observable_http_request: &ObservableHttpRequest,
        os_observed: ObservedOsInput<'_>,
    ) -> HttpRequestMatchResult {
        #[cfg(feature = "db")]
        {
            let observed = &observable_http_request.matching;
            let (browser_quality, notes, req_match) = simple_quality_match!(
                enabled: self.config.matcher_enabled,
                matcher: self.http_matcher,
                method: match_http_request(observed),
                success: found => {
                    let notes = MatchedSignatureNotes {
                        dishonest: found.dishonest,
                        generic: found.browser.kind == OsKind::Generic,
                    };
                    (
                        BrowserQualityMatched {
                            browser: Some(found.browser.clone()),
                            quality: HttpMatchQuality::Matched(found.quality),
                        },
                        Some(notes),
                        Some(found),
                    )
                },
                failure: (
                    BrowserQualityMatched {
                        browser: None,
                        quality: HttpMatchQuality::NotMatched,
                    },
                    None,
                    None
                ),
                disabled: (
                    BrowserQualityMatched {
                        browser: None,
                        quality: HttpMatchQuality::Disabled,
                    },
                    None,
                    None
                )
            );

            let matcher: Option<&dyn HttpMatcher> =
                self.http_matcher.as_ref().map(|m| m as &dyn HttpMatcher);
            HttpRequestMatchResult {
                params: build_params(&observed.expsw, notes),
                browser_quality,
                ua_os: check_ua_os_agreement(
                    observable_http_request.user_agent.as_deref(),
                    req_match.as_ref(),
                    matcher,
                    os_observed,
                ),
            }
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
                ua_os: check_ua_os_agreement(
                    observable_http_request.user_agent.as_deref(),
                    None,
                    None,
                    os_observed,
                ),
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
            let (web_server_quality, notes) = simple_quality_match!(
                enabled: self.config.matcher_enabled,
                matcher: self.http_matcher,
                method: match_http_response(observed),
                success: found => {
                    let notes = MatchedSignatureNotes {
                        dishonest: found.dishonest,
                        generic: found.web_server.kind == OsKind::Generic,
                    };
                    (
                        WebServerQualityMatched {
                            web_server: Some(found.web_server),
                            quality: HttpMatchQuality::Matched(found.quality),
                        },
                        Some(notes),
                    )
                },
                failure: (
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
