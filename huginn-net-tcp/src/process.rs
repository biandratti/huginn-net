use crate::error::HuginnNetTcpError;
use crate::output::{
    IpPort, MTUOutput, MTUQualityMatched, OSQualityMatched, SynAckTCPOutput, SynTCPOutput,
    UptimeOutput,
};
#[cfg(not(feature = "db"))]
use crate::types::MatchQualityType;
use crate::{tcp_process, ConnectionKey, TcpAnalysisResult, TcpTimestamp, UptimeRole};
#[cfg(feature = "db")]
use huginn_net_db::MatchQualityType;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::net::IpAddr;
use ttl_cache::TtlCache;

#[cfg(feature = "db")]
use crate::observable::ObservableTcp;
#[cfg(feature = "db")]
use crate::output::OperativeSystem;
#[cfg(feature = "db")]
use crate::SignatureMatcher;

// ---------------------------------------------------------------------------
// OS quality helpers — compile only when the db feature is active
// ---------------------------------------------------------------------------

#[cfg(feature = "db")]
fn os_quality_from_request(
    tcp_request: &ObservableTcp,
    matcher: Option<&SignatureMatcher>,
) -> OSQualityMatched {
    if let Some(matcher) = matcher {
        if let Some((label, _signature, quality)) = matcher.matching_by_tcp_request(tcp_request) {
            OSQualityMatched {
                os: Some(OperativeSystem::from(label)),
                quality: MatchQualityType::Matched(quality),
            }
        } else {
            OSQualityMatched { os: None, quality: MatchQualityType::NotMatched }
        }
    } else {
        OSQualityMatched { os: None, quality: MatchQualityType::Disabled }
    }
}

#[cfg(feature = "db")]
fn os_quality_from_response(
    tcp_response: &ObservableTcp,
    matcher: Option<&SignatureMatcher>,
) -> OSQualityMatched {
    if let Some(matcher) = matcher {
        if let Some((label, _signature, quality)) = matcher.matching_by_tcp_response(tcp_response) {
            OSQualityMatched {
                os: Some(OperativeSystem::from(label)),
                quality: MatchQualityType::Matched(quality),
            }
        } else {
            OSQualityMatched { os: None, quality: MatchQualityType::NotMatched }
        }
    } else {
        OSQualityMatched { os: None, quality: MatchQualityType::Disabled }
    }
}

#[cfg(feature = "db")]
fn mtu_quality(mtu_value: &u16, matcher: Option<&SignatureMatcher>) -> MTUQualityMatched {
    if let Some(matcher) = matcher {
        if let Some((link, _)) = matcher.matching_by_mtu(mtu_value) {
            MTUQualityMatched { link: Some(link.clone()), quality: MatchQualityType::Matched(1.0) }
        } else {
            MTUQualityMatched { link: None, quality: MatchQualityType::NotMatched }
        }
    } else {
        MTUQualityMatched { link: None, quality: MatchQualityType::Disabled }
    }
}

#[cfg(not(feature = "db"))]
fn os_quality_disabled() -> OSQualityMatched {
    OSQualityMatched { quality: MatchQualityType::Disabled }
}

#[cfg(not(feature = "db"))]
fn mtu_quality_disabled() -> MTUQualityMatched {
    MTUQualityMatched { link: None, quality: MatchQualityType::Disabled }
}

// ---------------------------------------------------------------------------
// IPv4
// ---------------------------------------------------------------------------

/// Processes an IPv4 packet for TCP content.
pub fn process_ipv4_packet(
    ipv4: &Ipv4Packet,
    connection_tracker: &mut TtlCache<ConnectionKey, TcpTimestamp>,
    #[cfg(feature = "db")] matcher: Option<&SignatureMatcher>,
) -> Result<TcpAnalysisResult, HuginnNetTcpError> {
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
        #[cfg(feature = "db")]
        let os_quality = os_quality_from_request(&tcp_request, matcher);
        #[cfg(not(feature = "db"))]
        let os_quality = os_quality_disabled();

        tcp_result.syn = Some(SynTCPOutput {
            source: IpPort::new(IpAddr::V4(ipv4.get_source()), tcp.get_source()),
            destination: IpPort::new(IpAddr::V4(ipv4.get_destination()), tcp.get_destination()),
            os_matched: os_quality,
            sig: tcp_request,
        });
    }

    if let Some(tcp_response) = tcp_package.tcp_response {
        #[cfg(feature = "db")]
        let os_quality = os_quality_from_response(&tcp_response, matcher);
        #[cfg(not(feature = "db"))]
        let os_quality = os_quality_disabled();

        tcp_result.syn_ack = Some(SynAckTCPOutput {
            source: IpPort::new(IpAddr::V4(ipv4.get_source()), tcp.get_source()),
            destination: IpPort::new(IpAddr::V4(ipv4.get_destination()), tcp.get_destination()),
            os_matched: os_quality,
            sig: tcp_response,
        });
    }

    if let Some(mtu) = tcp_package.mtu {
        #[cfg(feature = "db")]
        let link_quality = mtu_quality(&mtu.value, matcher);
        #[cfg(not(feature = "db"))]
        let link_quality = mtu_quality_disabled();

        tcp_result.mtu = Some(MTUOutput {
            source: IpPort::new(IpAddr::V4(ipv4.get_source()), tcp.get_source()),
            destination: IpPort::new(IpAddr::V4(ipv4.get_destination()), tcp.get_destination()),
            link: link_quality,
            mtu: mtu.value,
        });
    }

    if let Some(uptime) = tcp_package.client_uptime {
        tcp_result.client_uptime = Some(UptimeOutput {
            source: IpPort::new(IpAddr::V4(ipv4.get_source()), tcp.get_source()),
            destination: IpPort::new(IpAddr::V4(ipv4.get_destination()), tcp.get_destination()),
            role: UptimeRole::Client,
            days: uptime.days,
            hours: uptime.hours,
            min: uptime.min,
            up_mod_days: uptime.up_mod_days,
            freq: uptime.freq,
        });
    }

    if let Some(uptime) = tcp_package.server_uptime {
        tcp_result.server_uptime = Some(UptimeOutput {
            source: IpPort::new(IpAddr::V4(ipv4.get_source()), tcp.get_source()),
            destination: IpPort::new(IpAddr::V4(ipv4.get_destination()), tcp.get_destination()),
            role: UptimeRole::Server,
            days: uptime.days,
            hours: uptime.hours,
            min: uptime.min,
            up_mod_days: uptime.up_mod_days,
            freq: uptime.freq,
        });
    }

    let _ = (source, destination);
    Ok(tcp_result)
}

// ---------------------------------------------------------------------------
// IPv6
// ---------------------------------------------------------------------------

/// Processes an IPv6 packet for TCP content.
pub fn process_ipv6_packet(
    ipv6: &Ipv6Packet,
    connection_tracker: &mut TtlCache<ConnectionKey, TcpTimestamp>,
    #[cfg(feature = "db")] matcher: Option<&SignatureMatcher>,
) -> Result<TcpAnalysisResult, HuginnNetTcpError> {
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
        #[cfg(feature = "db")]
        let os_quality = os_quality_from_request(&tcp_request, matcher);
        #[cfg(not(feature = "db"))]
        let os_quality = os_quality_disabled();

        tcp_result.syn = Some(SynTCPOutput {
            source: IpPort::new(IpAddr::V6(ipv6.get_source()), tcp.get_source()),
            destination: IpPort::new(IpAddr::V6(ipv6.get_destination()), tcp.get_destination()),
            os_matched: os_quality,
            sig: tcp_request,
        });
    }

    if let Some(tcp_response) = tcp_package.tcp_response {
        #[cfg(feature = "db")]
        let os_quality = os_quality_from_response(&tcp_response, matcher);
        #[cfg(not(feature = "db"))]
        let os_quality = os_quality_disabled();

        tcp_result.syn_ack = Some(SynAckTCPOutput {
            source: IpPort::new(IpAddr::V6(ipv6.get_source()), tcp.get_source()),
            destination: IpPort::new(IpAddr::V6(ipv6.get_destination()), tcp.get_destination()),
            os_matched: os_quality,
            sig: tcp_response,
        });
    }

    if let Some(mtu) = tcp_package.mtu {
        #[cfg(feature = "db")]
        let link_quality = mtu_quality(&mtu.value, matcher);
        #[cfg(not(feature = "db"))]
        let link_quality = mtu_quality_disabled();

        tcp_result.mtu = Some(MTUOutput {
            source: IpPort::new(IpAddr::V6(ipv6.get_source()), tcp.get_source()),
            destination: IpPort::new(IpAddr::V6(ipv6.get_destination()), tcp.get_destination()),
            link: link_quality,
            mtu: mtu.value,
        });
    }

    if let Some(uptime) = tcp_package.client_uptime {
        tcp_result.client_uptime = Some(UptimeOutput {
            source: IpPort::new(IpAddr::V6(ipv6.get_source()), tcp.get_source()),
            destination: IpPort::new(IpAddr::V6(ipv6.get_destination()), tcp.get_destination()),
            role: UptimeRole::Client,
            days: uptime.days,
            hours: uptime.hours,
            min: uptime.min,
            up_mod_days: uptime.up_mod_days,
            freq: uptime.freq,
        });
    }

    if let Some(uptime) = tcp_package.server_uptime {
        tcp_result.server_uptime = Some(UptimeOutput {
            source: IpPort::new(IpAddr::V6(ipv6.get_source()), tcp.get_source()),
            destination: IpPort::new(IpAddr::V6(ipv6.get_destination()), tcp.get_destination()),
            role: UptimeRole::Server,
            days: uptime.days,
            hours: uptime.hours,
            min: uptime.min,
            up_mod_days: uptime.up_mod_days,
            freq: uptime.freq,
        });
    }

    let _ = (source, destination);
    Ok(tcp_result)
}
