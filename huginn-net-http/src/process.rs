use crate::error::HuginnNetHttpError;
use crate::output::{
    Browser, BrowserQualityMatched, HttpRequestOutput, HttpResponseOutput, IpPort, WebServer,
    WebServerQualityMatched,
};
use crate::{http_process, HttpAnalysisResult, SignatureMatcher};
use huginn_net_db::http::HttpDiagnosis;
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
    matcher: Option<&SignatureMatcher>,
) -> Result<HttpAnalysisResult, HuginnNetHttpError> {
    let observable_package =
        create_observable_package_ipv4(ipv4, http_flows, http_processors, matcher)?;
    Ok(observable_package.http_result)
}

fn create_observable_package_ipv4(
    ipv4: &Ipv4Packet,
    http_flows: &mut TtlCache<http_process::FlowKey, http_process::TcpFlow>,
    http_processors: &http_process::HttpProcessors,
    matcher: Option<&SignatureMatcher>,
) -> Result<ObservablePackage, HuginnNetHttpError> {
    let tcp = TcpPacket::new(ipv4.payload())
        .ok_or_else(|| HuginnNetHttpError::Parse("Invalid TCP packet".to_string()))?;

    let source = IpPort { ip: IpAddr::V4(ipv4.get_source()), port: tcp.get_source() };
    let destination =
        IpPort { ip: IpAddr::V4(ipv4.get_destination()), port: tcp.get_destination() };

    let http_package = http_process::process_http_ipv4(ipv4, http_flows, http_processors)?;

    let mut http_result = HttpAnalysisResult { http_request: None, http_response: None };

    if let Some(http_request) = http_package.http_request {
        let browser_quality = if let Some(matcher) = matcher {
            if let Some((label, _signature, quality)) =
                matcher.matching_by_http_request(&http_request)
            {
                BrowserQualityMatched {
                    browser: Some(Browser::from(label)),
                    quality: huginn_net_db::utils::MatchQualityType::Matched(quality),
                }
            } else {
                BrowserQualityMatched {
                    browser: None,
                    quality: huginn_net_db::utils::MatchQualityType::NotMatched,
                }
            }
        } else {
            BrowserQualityMatched {
                browser: None,
                quality: huginn_net_db::utils::MatchQualityType::Disabled,
            }
        };

        let user_agent = http_request.user_agent.clone();
        let (signature_matcher, ua_matcher) = if let Some(matcher) = matcher {
            let sig_match = matcher.matching_by_http_request(&http_request);
            let ua_match = user_agent
                .as_ref()
                .and_then(|ua| matcher.matching_by_user_agent(ua.clone()));
            (sig_match, ua_match)
        } else {
            (None, None)
        };

        let diagnosis = crate::http_common::get_diagnostic(
            user_agent,
            ua_matcher,
            signature_matcher.map(|(label, _signature, _quality)| label),
        );

        let request_output = HttpRequestOutput {
            source: IpPort::new(IpAddr::V4(ipv4.get_source()), tcp.get_source()),
            destination: IpPort::new(IpAddr::V4(ipv4.get_destination()), tcp.get_destination()),
            lang: http_request.lang.clone(),
            diagnosis,
            browser_matched: browser_quality,
            sig: http_request,
        };
        http_result.http_request = Some(request_output);
    }

    if let Some(http_response) = http_package.http_response {
        let web_server_quality = if let Some(matcher) = matcher {
            if let Some((label, _signature, quality)) =
                matcher.matching_by_http_response(&http_response)
            {
                WebServerQualityMatched {
                    web_server: Some(WebServer::from(label)),
                    quality: huginn_net_db::utils::MatchQualityType::Matched(quality),
                }
            } else {
                WebServerQualityMatched {
                    web_server: None,
                    quality: huginn_net_db::utils::MatchQualityType::NotMatched,
                }
            }
        } else {
            WebServerQualityMatched {
                web_server: None,
                quality: huginn_net_db::utils::MatchQualityType::Disabled,
            }
        };

        let response_output = HttpResponseOutput {
            source: IpPort::new(IpAddr::V4(ipv4.get_source()), tcp.get_source()),
            destination: IpPort::new(IpAddr::V4(ipv4.get_destination()), tcp.get_destination()),
            diagnosis: HttpDiagnosis::None, // Default diagnosis for responses
            web_server_matched: web_server_quality,
            sig: http_response,
        };
        http_result.http_response = Some(response_output);
    }

    Ok(ObservablePackage { source, destination, http_result })
}

/// Processes an IPv6 packet for HTTP content.
pub fn process_ipv6_packet(
    ipv6: &Ipv6Packet,
    http_flows: &mut TtlCache<http_process::FlowKey, http_process::TcpFlow>,
    http_processors: &http_process::HttpProcessors,
    matcher: Option<&SignatureMatcher>,
) -> Result<HttpAnalysisResult, HuginnNetHttpError> {
    let observable_package =
        create_observable_package_ipv6(ipv6, http_flows, http_processors, matcher)?;
    Ok(observable_package.http_result)
}

fn create_observable_package_ipv6(
    ipv6: &Ipv6Packet,
    http_flows: &mut TtlCache<http_process::FlowKey, http_process::TcpFlow>,
    http_processors: &http_process::HttpProcessors,
    matcher: Option<&SignatureMatcher>,
) -> Result<ObservablePackage, HuginnNetHttpError> {
    // Extract TCP info for source/destination ports
    let tcp = TcpPacket::new(ipv6.payload())
        .ok_or_else(|| HuginnNetHttpError::Parse("Invalid TCP packet".to_string()))?;

    let source = IpPort { ip: IpAddr::V6(ipv6.get_source()), port: tcp.get_source() };
    let destination =
        IpPort { ip: IpAddr::V6(ipv6.get_destination()), port: tcp.get_destination() };

    let http_package = http_process::process_http_ipv6(ipv6, http_flows, http_processors)?;

    let mut http_result = HttpAnalysisResult { http_request: None, http_response: None };

    // Process HTTP request
    if let Some(http_request) = http_package.http_request {
        let browser_quality = if let Some(matcher) = matcher {
            if let Some((label, _signature, quality)) =
                matcher.matching_by_http_request(&http_request)
            {
                BrowserQualityMatched {
                    browser: Some(Browser::from(label)),
                    quality: huginn_net_db::utils::MatchQualityType::Matched(quality),
                }
            } else {
                BrowserQualityMatched {
                    browser: None,
                    quality: huginn_net_db::utils::MatchQualityType::NotMatched,
                }
            }
        } else {
            BrowserQualityMatched {
                browser: None,
                quality: huginn_net_db::utils::MatchQualityType::Disabled,
            }
        };

        let user_agent = http_request.user_agent.clone();
        let (signature_matcher, ua_matcher) = if let Some(matcher) = matcher {
            let sig_match = matcher.matching_by_http_request(&http_request);
            let ua_match = user_agent
                .as_ref()
                .and_then(|ua| matcher.matching_by_user_agent(ua.clone()));
            (sig_match, ua_match)
        } else {
            (None, None)
        };

        let diagnosis = crate::http_common::get_diagnostic(
            user_agent,
            ua_matcher,
            signature_matcher.map(|(label, _signature, _quality)| label),
        );

        let request_output = HttpRequestOutput {
            source: IpPort::new(IpAddr::V6(ipv6.get_source()), tcp.get_source()),
            destination: IpPort::new(IpAddr::V6(ipv6.get_destination()), tcp.get_destination()),
            lang: http_request.lang.clone(),
            diagnosis,
            browser_matched: browser_quality,
            sig: http_request,
        };
        http_result.http_request = Some(request_output);
    }

    // Process HTTP response
    if let Some(http_response) = http_package.http_response {
        let web_server_quality = if let Some(matcher) = matcher {
            if let Some((label, _signature, quality)) =
                matcher.matching_by_http_response(&http_response)
            {
                WebServerQualityMatched {
                    web_server: Some(WebServer::from(label)),
                    quality: huginn_net_db::utils::MatchQualityType::Matched(quality),
                }
            } else {
                WebServerQualityMatched {
                    web_server: None,
                    quality: huginn_net_db::utils::MatchQualityType::NotMatched,
                }
            }
        } else {
            WebServerQualityMatched {
                web_server: None,
                quality: huginn_net_db::utils::MatchQualityType::Disabled,
            }
        };

        let response_output = HttpResponseOutput {
            source: IpPort::new(IpAddr::V6(ipv6.get_source()), tcp.get_source()),
            destination: IpPort::new(IpAddr::V6(ipv6.get_destination()), tcp.get_destination()),
            diagnosis: HttpDiagnosis::None, // Default diagnosis for responses
            web_server_matched: web_server_quality,
            sig: http_response,
        };
        http_result.http_response = Some(response_output);
    }

    Ok(ObservablePackage { source, destination, http_result })
}
