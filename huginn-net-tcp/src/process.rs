use crate::error::HuginnNetTcpError;
use crate::matcher_api::TcpMatcher;
use crate::output::{
    IpPort, MTUOutput, MTUQualityMatched, MatchQuality, OSQualityMatched, SynAckTCPOutput,
    SynTCPOutput, UptimeOutput,
};
use crate::{tcp_process, ConnectionKey, TcpAnalysisResult, TcpTimestamp, UptimeRole};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::net::IpAddr;
use ttl_cache::TtlCache;

pub struct ObservablePackage {
    pub source: IpPort,
    pub destination: IpPort,
    pub tcp_result: TcpAnalysisResult,
}

/// Processes an IPv4 packet for TCP content.
pub fn process_ipv4_packet(
    ipv4: &Ipv4Packet,
    connection_tracker: &mut TtlCache<ConnectionKey, TcpTimestamp>,
    matcher: Option<&dyn TcpMatcher>,
) -> Result<TcpAnalysisResult, HuginnNetTcpError> {
    create_observable_package_ipv4(ipv4, connection_tracker, matcher).map(|pkg| pkg.tcp_result)
}

fn create_observable_package_ipv4(
    ipv4: &Ipv4Packet,
    connection_tracker: &mut TtlCache<ConnectionKey, TcpTimestamp>,
    matcher: Option<&dyn TcpMatcher>,
) -> Result<ObservablePackage, HuginnNetTcpError> {
    let tcp = TcpPacket::new(ipv4.payload())
        .ok_or_else(|| HuginnNetTcpError::Parse("Invalid TCP packet".to_string()))?;

    let source = IpPort { ip: IpAddr::V4(ipv4.get_source()), port: tcp.get_source() };
    let destination =
        IpPort { ip: IpAddr::V4(ipv4.get_destination()), port: tcp.get_destination() };

    let tcp_package = tcp_process::process_tcp_ipv4(ipv4, connection_tracker)?;

    let mut tcp_result = TcpAnalysisResult {
        syn: None,
        syn_ack: None,
        mtu: None,
        client_uptime: None,
        server_uptime: None,
    };

    if let Some(tcp_request) = tcp_package.tcp_request {
        let os_quality =
            classify_tcp_match(matcher, |m| m.match_tcp_request(&tcp_request.matching));

        let syn_output = SynTCPOutput {
            source: IpPort::new(IpAddr::V4(ipv4.get_source()), tcp.get_source()),
            destination: IpPort::new(IpAddr::V4(ipv4.get_destination()), tcp.get_destination()),
            os_matched: os_quality,
            sig: tcp_request,
        };
        tcp_result.syn = Some(syn_output);
    }

    if let Some(tcp_response) = tcp_package.tcp_response {
        let os_quality =
            classify_tcp_match(matcher, |m| m.match_tcp_response(&tcp_response.matching));

        let syn_ack_output = SynAckTCPOutput {
            source: IpPort::new(IpAddr::V4(ipv4.get_source()), tcp.get_source()),
            destination: IpPort::new(IpAddr::V4(ipv4.get_destination()), tcp.get_destination()),
            os_matched: os_quality,
            sig: tcp_response,
        };
        tcp_result.syn_ack = Some(syn_ack_output);
    }

    if let Some(mtu) = tcp_package.mtu {
        let link_quality = classify_mtu_match(matcher, mtu.value);

        let mtu_output = MTUOutput {
            source: IpPort::new(IpAddr::V4(ipv4.get_source()), tcp.get_source()),
            destination: IpPort::new(IpAddr::V4(ipv4.get_destination()), tcp.get_destination()),
            link: link_quality,
            mtu: mtu.value,
        };
        tcp_result.mtu = Some(mtu_output);
    }

    if let Some(uptime) = tcp_package.client_uptime {
        let uptime_output = UptimeOutput {
            source: IpPort::new(IpAddr::V4(ipv4.get_source()), tcp.get_source()),
            destination: IpPort::new(IpAddr::V4(ipv4.get_destination()), tcp.get_destination()),
            role: UptimeRole::Client,
            days: uptime.days,
            hours: uptime.hours,
            min: uptime.min,
            up_mod_days: uptime.up_mod_days,
            freq: uptime.freq,
        };
        tcp_result.client_uptime = Some(uptime_output);
    }

    if let Some(uptime) = tcp_package.server_uptime {
        let uptime_output = UptimeOutput {
            source: IpPort::new(IpAddr::V4(ipv4.get_source()), tcp.get_source()),
            destination: IpPort::new(IpAddr::V4(ipv4.get_destination()), tcp.get_destination()),
            role: UptimeRole::Server,
            days: uptime.days,
            hours: uptime.hours,
            min: uptime.min,
            up_mod_days: uptime.up_mod_days,
            freq: uptime.freq,
        };
        tcp_result.server_uptime = Some(uptime_output);
    }

    Ok(ObservablePackage { source, destination, tcp_result })
}

/// Processes an IPv6 packet for TCP content.
pub fn process_ipv6_packet(
    ipv6: &Ipv6Packet,
    connection_tracker: &mut TtlCache<ConnectionKey, TcpTimestamp>,
    matcher: Option<&dyn TcpMatcher>,
) -> Result<TcpAnalysisResult, HuginnNetTcpError> {
    create_observable_package_ipv6(ipv6, connection_tracker, matcher).map(|pkg| pkg.tcp_result)
}

fn create_observable_package_ipv6(
    ipv6: &Ipv6Packet,
    connection_tracker: &mut TtlCache<ConnectionKey, TcpTimestamp>,
    matcher: Option<&dyn TcpMatcher>,
) -> Result<ObservablePackage, HuginnNetTcpError> {
    let tcp = TcpPacket::new(ipv6.payload())
        .ok_or_else(|| HuginnNetTcpError::Parse("Invalid TCP packet".to_string()))?;

    let source = IpPort { ip: IpAddr::V6(ipv6.get_source()), port: tcp.get_source() };
    let destination =
        IpPort { ip: IpAddr::V6(ipv6.get_destination()), port: tcp.get_destination() };

    let tcp_package = tcp_process::process_tcp_ipv6(ipv6, connection_tracker)?;

    let mut tcp_result = TcpAnalysisResult {
        syn: None,
        syn_ack: None,
        mtu: None,
        client_uptime: None,
        server_uptime: None,
    };

    if let Some(tcp_request) = tcp_package.tcp_request {
        let os_quality =
            classify_tcp_match(matcher, |m| m.match_tcp_request(&tcp_request.matching));

        let syn_output = SynTCPOutput {
            source: IpPort::new(IpAddr::V6(ipv6.get_source()), tcp.get_source()),
            destination: IpPort::new(IpAddr::V6(ipv6.get_destination()), tcp.get_destination()),
            os_matched: os_quality,
            sig: tcp_request,
        };
        tcp_result.syn = Some(syn_output);
    }

    if let Some(tcp_response) = tcp_package.tcp_response {
        let os_quality =
            classify_tcp_match(matcher, |m| m.match_tcp_response(&tcp_response.matching));

        let syn_ack_output = SynAckTCPOutput {
            source: IpPort::new(IpAddr::V6(ipv6.get_source()), tcp.get_source()),
            destination: IpPort::new(IpAddr::V6(ipv6.get_destination()), tcp.get_destination()),
            os_matched: os_quality,
            sig: tcp_response,
        };
        tcp_result.syn_ack = Some(syn_ack_output);
    }

    if let Some(mtu) = tcp_package.mtu {
        let link_quality = classify_mtu_match(matcher, mtu.value);

        let mtu_output = MTUOutput {
            source: IpPort::new(IpAddr::V6(ipv6.get_source()), tcp.get_source()),
            destination: IpPort::new(IpAddr::V6(ipv6.get_destination()), tcp.get_destination()),
            link: link_quality,
            mtu: mtu.value,
        };
        tcp_result.mtu = Some(mtu_output);
    }

    if let Some(uptime) = tcp_package.client_uptime {
        let uptime_output = UptimeOutput {
            source: IpPort::new(IpAddr::V6(ipv6.get_source()), tcp.get_source()),
            destination: IpPort::new(IpAddr::V6(ipv6.get_destination()), tcp.get_destination()),
            role: UptimeRole::Client,
            days: uptime.days,
            hours: uptime.hours,
            min: uptime.min,
            up_mod_days: uptime.up_mod_days,
            freq: uptime.freq,
        };
        tcp_result.client_uptime = Some(uptime_output);
    }

    if let Some(uptime) = tcp_package.server_uptime {
        let uptime_output = UptimeOutput {
            source: IpPort::new(IpAddr::V6(ipv6.get_source()), tcp.get_source()),
            destination: IpPort::new(IpAddr::V6(ipv6.get_destination()), tcp.get_destination()),
            role: UptimeRole::Server,
            days: uptime.days,
            hours: uptime.hours,
            min: uptime.min,
            up_mod_days: uptime.up_mod_days,
            freq: uptime.freq,
        };
        tcp_result.server_uptime = Some(uptime_output);
    }

    Ok(ObservablePackage { source, destination, tcp_result })
}

fn classify_tcp_match<F>(matcher: Option<&dyn TcpMatcher>, call: F) -> OSQualityMatched
where
    F: FnOnce(&dyn TcpMatcher) -> Option<crate::matcher_api::TcpMatch>,
{
    match matcher {
        Some(m) => match call(m) {
            Some(found) => OSQualityMatched {
                os: Some(found.os),
                quality: MatchQuality::Matched(found.quality),
            },
            None => OSQualityMatched { os: None, quality: MatchQuality::NotMatched },
        },
        None => OSQualityMatched { os: None, quality: MatchQuality::Disabled },
    }
}

fn classify_mtu_match(matcher: Option<&dyn TcpMatcher>, mtu: u16) -> MTUQualityMatched {
    match matcher {
        Some(m) => match m.match_mtu(mtu) {
            Some(found) => {
                MTUQualityMatched { link: Some(found.link), quality: MatchQuality::Matched(1.0) }
            }
            None => MTUQualityMatched { link: None, quality: MatchQuality::NotMatched },
        },
        None => MTUQualityMatched { link: None, quality: MatchQuality::Disabled },
    }
}
