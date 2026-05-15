use crate::error::HuginnNetHttpError;
use crate::http::HttpDiagnosis;
use crate::http_process;
use crate::matcher_api::HttpMatcher;
use crate::output::{
    BrowserQualityMatched, HttpAnalysisResult, HttpRequestOutput, HttpResponseOutput, IpPort,
    MatchQuality, OsKind, WebServerQualityMatched,
};
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

fn build_http_result(
    http_package: http_process::ObservableHttpPackage,
    source: IpPort,
    destination: IpPort,
    matcher: Option<&dyn HttpMatcher>,
) -> HttpAnalysisResult {
    let mut http_result = HttpAnalysisResult { http_request: None, http_response: None };

    if let Some(http_request) = http_package.http_request {
        let req_match = matcher.and_then(|m| m.match_http_request(&http_request.matching));

        let browser_quality = match (matcher, req_match.as_ref()) {
            (Some(_), Some(rm)) => BrowserQualityMatched {
                browser: Some(rm.browser.clone()),
                quality: MatchQuality::Matched(rm.quality),
            },
            (Some(_), None) => {
                BrowserQualityMatched { browser: None, quality: MatchQuality::NotMatched }
            }
            (None, _) => BrowserQualityMatched { browser: None, quality: MatchQuality::Disabled },
        };

        let matched_for_diag = req_match
            .as_ref()
            .map(|rm| (matches!(rm.browser.kind, OsKind::Generic), rm.expsw.as_str()));

        let diagnosis = crate::http_common::get_diagnostic(
            http_request.user_agent.as_deref(),
            matched_for_diag,
        );

        let request_output = HttpRequestOutput {
            source: source.clone(),
            destination: destination.clone(),
            lang: http_request.lang.clone(),
            diagnosis,
            browser_matched: browser_quality,
            sig: http_request,
        };
        http_result.http_request = Some(request_output);
    }

    if let Some(http_response) = http_package.http_response {
        let web_server_quality = match matcher {
            Some(m) => match m.match_http_response(&http_response.matching) {
                Some(resp_match) => WebServerQualityMatched {
                    web_server: Some(resp_match.web_server),
                    quality: MatchQuality::Matched(resp_match.quality),
                },
                None => {
                    WebServerQualityMatched { web_server: None, quality: MatchQuality::NotMatched }
                }
            },
            None => WebServerQualityMatched { web_server: None, quality: MatchQuality::Disabled },
        };

        let response_output = HttpResponseOutput {
            source,
            destination,
            diagnosis: HttpDiagnosis::None,
            web_server_matched: web_server_quality,
            sig: http_response,
        };
        http_result.http_response = Some(response_output);
    }

    http_result
}
