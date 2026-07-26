pub mod flow;
pub mod parallel;

pub use flow::{FlowKey, HttpProcessors, ObservableHttpPackage, TcpFlow};
pub use parallel::{DispatchResult, PoolStats, SharedHttpMatcher, WorkerPool, WorkerStats};

use self::flow as http_process;
use crate::error::HuginnNetHttpError;
#[cfg(any(feature = "p0f-request", feature = "p0f-response"))]
use crate::http::{build_params, MatchedSignatureNotes};
use crate::matcher_api::HttpMatcher;
#[cfg(feature = "p0f-request")]
use crate::output::{BrowserQualityMatched, HttpRequestOutput};
use crate::output::{HttpAnalysisResult, IpPort};
#[cfg(feature = "p0f-response")]
use crate::output::{HttpResponseOutput, WebServerQualityMatched};
#[cfg(any(feature = "p0f-request", feature = "p0f-response"))]
use crate::output::{MatchQuality, OsKind};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::net::IpAddr;
use ttl_cache::TtlCache;

pub struct ObservablePackage {
    pub source: IpPort,
    pub destination: IpPort,
    pub http_result: HttpAnalysisResult,
}

/// Processes an IPv4 packet for HTTP content.
#[inline]
pub fn process_ipv4_packet(
    ipv4: &Ipv4Packet,
    http_flows: &mut TtlCache<http_process::FlowKey, http_process::TcpFlow>,
    http_processors: &http_process::HttpProcessors,
    matcher: Option<&dyn HttpMatcher>,
) -> Result<HttpAnalysisResult, HuginnNetHttpError> {
    let observable_package =
        create_observable_package_ipv4(ipv4, http_flows, http_processors, matcher)?;
    Ok(observable_package.http_result)
}

fn create_observable_package_ipv4(
    ipv4: &Ipv4Packet,
    http_flows: &mut TtlCache<http_process::FlowKey, http_process::TcpFlow>,
    http_processors: &http_process::HttpProcessors,
    matcher: Option<&dyn HttpMatcher>,
) -> Result<ObservablePackage, HuginnNetHttpError> {
    let tcp = TcpPacket::new(ipv4.payload())
        .ok_or_else(|| HuginnNetHttpError::Parse("Invalid TCP packet".to_string()))?;

    let source = IpPort { ip: IpAddr::V4(ipv4.get_source()), port: tcp.get_source() };
    let destination =
        IpPort { ip: IpAddr::V4(ipv4.get_destination()), port: tcp.get_destination() };

    let http_package = http_process::process_http_ipv4(ipv4, http_flows, http_processors)?;

    let http_result = build_http_result(http_package, source.clone(), destination.clone(), matcher);

    Ok(ObservablePackage { source, destination, http_result })
}

/// Processes an IPv6 packet for HTTP content.
#[inline]
pub fn process_ipv6_packet(
    ipv6: &Ipv6Packet,
    http_flows: &mut TtlCache<http_process::FlowKey, http_process::TcpFlow>,
    http_processors: &http_process::HttpProcessors,
    matcher: Option<&dyn HttpMatcher>,
) -> Result<HttpAnalysisResult, HuginnNetHttpError> {
    let observable_package =
        create_observable_package_ipv6(ipv6, http_flows, http_processors, matcher)?;
    Ok(observable_package.http_result)
}

fn create_observable_package_ipv6(
    ipv6: &Ipv6Packet,
    http_flows: &mut TtlCache<http_process::FlowKey, http_process::TcpFlow>,
    http_processors: &http_process::HttpProcessors,
    matcher: Option<&dyn HttpMatcher>,
) -> Result<ObservablePackage, HuginnNetHttpError> {
    let tcp = TcpPacket::new(ipv6.payload())
        .ok_or_else(|| HuginnNetHttpError::Parse("Invalid TCP packet".to_string()))?;

    let source = IpPort { ip: IpAddr::V6(ipv6.get_source()), port: tcp.get_source() };
    let destination =
        IpPort { ip: IpAddr::V6(ipv6.get_destination()), port: tcp.get_destination() };

    let http_package = http_process::process_http_ipv6(ipv6, http_flows, http_processors)?;

    let http_result = build_http_result(http_package, source.clone(), destination.clone(), matcher);

    Ok(ObservablePackage { source, destination, http_result })
}

#[cfg_attr(
    not(any(feature = "p0f-request", feature = "p0f-response")),
    allow(unused_mut)
)]
fn build_http_result(
    http_package: http_process::ObservableHttpPackage,
    source: IpPort,
    destination: IpPort,
    matcher: Option<&dyn HttpMatcher>,
) -> HttpAnalysisResult {
    #[cfg(not(any(feature = "p0f-request", feature = "p0f-response")))]
    let _ = (&http_package, &source, &destination, &matcher);

    let mut http_result = HttpAnalysisResult::empty();

    #[cfg(feature = "p0f-request")]
    if let Some(http_request) = http_package.http_request {
        let (browser_quality, notes) = match matcher {
            Some(m) => match m.match_http_request(&http_request.matching) {
                Some(req_match) => {
                    let notes = MatchedSignatureNotes {
                        dishonest: req_match.dishonest,
                        generic: req_match.browser.kind == OsKind::Generic,
                    };
                    (
                        BrowserQualityMatched {
                            browser: Some(req_match.browser),
                            quality: MatchQuality::Matched(req_match.quality),
                        },
                        Some(notes),
                    )
                }
                None => (
                    BrowserQualityMatched { browser: None, quality: MatchQuality::NotMatched },
                    None,
                ),
            },
            None => {
                (BrowserQualityMatched { browser: None, quality: MatchQuality::Disabled }, None)
            }
        };

        let request_output = HttpRequestOutput {
            source: source.clone(),
            destination: destination.clone(),
            lang: http_request.lang.clone(),
            params: build_params(&http_request.matching.expsw, notes),
            browser_matched: browser_quality,
            sig: http_request,
        };
        http_result.http_request = Some(request_output);
    }

    #[cfg(feature = "p0f-response")]
    if let Some(http_response) = http_package.http_response {
        let (web_server_quality, notes) = match matcher {
            Some(m) => match m.match_http_response(&http_response.matching) {
                Some(resp_match) => {
                    let notes = MatchedSignatureNotes {
                        dishonest: resp_match.dishonest,
                        generic: resp_match.web_server.kind == OsKind::Generic,
                    };
                    (
                        WebServerQualityMatched {
                            web_server: Some(resp_match.web_server),
                            quality: MatchQuality::Matched(resp_match.quality),
                        },
                        Some(notes),
                    )
                }
                None => (
                    WebServerQualityMatched { web_server: None, quality: MatchQuality::NotMatched },
                    None,
                ),
            },
            None => (
                WebServerQualityMatched { web_server: None, quality: MatchQuality::Disabled },
                None,
            ),
        };

        let response_output = HttpResponseOutput {
            source,
            destination,
            params: build_params(&http_response.matching.expsw, notes),
            web_server_matched: web_server_quality,
            sig: http_response,
        };
        http_result.http_response = Some(response_output);
    }

    http_result
}
