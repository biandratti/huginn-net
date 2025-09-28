use crate::error::HuginnNetError;
use crate::output::{
    IpPort, MTUOutput, MTUQualityMatched, OSQualityMatched, OperativeSystem, SynAckTCPOutput,
    SynTCPOutput, UptimeOutput,
};
use crate::{tcp_process, Connection, SignatureMatcher, SynData, TcpAnalysisResult};
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
    connection_tracker: &mut TtlCache<Connection, SynData>,
    matcher: Option<&SignatureMatcher>,
) -> Result<TcpAnalysisResult, HuginnNetError> {
    let observable_package = create_observable_package_ipv4(ipv4, connection_tracker, matcher)?;
    Ok(observable_package.tcp_result)
}

fn create_observable_package_ipv4(
    ipv4: &Ipv4Packet,
    connection_tracker: &mut TtlCache<Connection, SynData>,
    matcher: Option<&SignatureMatcher>,
) -> Result<ObservablePackage, HuginnNetError> {
    let tcp = TcpPacket::new(ipv4.payload())
        .ok_or_else(|| HuginnNetError::Parse("Invalid TCP packet".to_string()))?;

    let source = IpPort {
        ip: IpAddr::V4(ipv4.get_source()),
        port: tcp.get_source(),
    };
    let destination = IpPort {
        ip: IpAddr::V4(ipv4.get_destination()),
        port: tcp.get_destination(),
    };

    let tcp_package = tcp_process::process_tcp_ipv4(ipv4, connection_tracker)?;

    let mut tcp_result = TcpAnalysisResult {
        syn: None,
        syn_ack: None,
        mtu: None,
        uptime: None,
    };

    if let Some(tcp_request) = tcp_package.tcp_request {
        let os_quality = if let Some(matcher) = matcher {
            if let Some((label, _signature, quality)) =
                matcher.matching_by_tcp_request(&tcp_request)
            {
                OSQualityMatched {
                    os: Some(OperativeSystem::from(label)),
                    quality: crate::db::MatchQualityType::Matched(quality),
                }
            } else {
                OSQualityMatched {
                    os: None,
                    quality: crate::db::MatchQualityType::NotMatched,
                }
            }
        } else {
            OSQualityMatched {
                os: None,
                quality: crate::db::MatchQualityType::Disabled,
            }
        };

        let syn_output = SynTCPOutput {
            source: IpPort::new(std::net::IpAddr::V4(ipv4.get_source()), tcp.get_source()),
            destination: IpPort::new(
                std::net::IpAddr::V4(ipv4.get_destination()),
                tcp.get_destination(),
            ),
            os_matched: os_quality,
            sig: tcp_request,
        };
        tcp_result.syn = Some(syn_output);
    }

    if let Some(tcp_response) = tcp_package.tcp_response {
        let os_quality = if let Some(matcher) = matcher {
            if let Some((label, _signature, quality)) =
                matcher.matching_by_tcp_response(&tcp_response)
            {
                OSQualityMatched {
                    os: Some(OperativeSystem::from(label)),
                    quality: crate::db::MatchQualityType::Matched(quality),
                }
            } else {
                OSQualityMatched {
                    os: None,
                    quality: crate::db::MatchQualityType::NotMatched,
                }
            }
        } else {
            OSQualityMatched {
                os: None,
                quality: crate::db::MatchQualityType::Disabled,
            }
        };

        let syn_ack_output = SynAckTCPOutput {
            source: IpPort::new(std::net::IpAddr::V4(ipv4.get_source()), tcp.get_source()),
            destination: IpPort::new(
                std::net::IpAddr::V4(ipv4.get_destination()),
                tcp.get_destination(),
            ),
            os_matched: os_quality,
            sig: tcp_response,
        };
        tcp_result.syn_ack = Some(syn_ack_output);
    }

    if let Some(mtu) = tcp_package.mtu {
        let link_quality = if let Some(matcher) = matcher {
            if let Some((link, _)) = matcher.matching_by_mtu(&mtu.value) {
                MTUQualityMatched {
                    link: Some(link.clone()),
                    quality: crate::db::MatchQualityType::Matched(1.0),
                }
            } else {
                MTUQualityMatched {
                    link: None,
                    quality: crate::db::MatchQualityType::NotMatched,
                }
            }
        } else {
            MTUQualityMatched {
                link: None,
                quality: crate::db::MatchQualityType::Disabled,
            }
        };

        let mtu_output = MTUOutput {
            source: IpPort::new(std::net::IpAddr::V4(ipv4.get_source()), tcp.get_source()),
            destination: IpPort::new(
                std::net::IpAddr::V4(ipv4.get_destination()),
                tcp.get_destination(),
            ),
            link: link_quality,
            mtu: mtu.value,
        };
        tcp_result.mtu = Some(mtu_output);
    }

    if let Some(uptime) = tcp_package.uptime {
        let uptime_output = UptimeOutput {
            source: IpPort::new(std::net::IpAddr::V4(ipv4.get_source()), tcp.get_source()),
            destination: IpPort::new(
                std::net::IpAddr::V4(ipv4.get_destination()),
                tcp.get_destination(),
            ),
            days: uptime.days,
            hours: uptime.hours,
            min: uptime.min,
            up_mod_days: uptime.up_mod_days,
            freq: uptime.freq,
        };
        tcp_result.uptime = Some(uptime_output);
    }

    Ok(ObservablePackage {
        source,
        destination,
        tcp_result,
    })
}

/// Processes an IPv6 packet for TCP content.
pub fn process_ipv6_packet(
    ipv6: &Ipv6Packet,
    connection_tracker: &mut TtlCache<Connection, SynData>,
    matcher: Option<&SignatureMatcher>,
) -> Result<TcpAnalysisResult, HuginnNetError> {
    let observable_package = create_observable_package_ipv6(ipv6, connection_tracker, matcher)?;
    Ok(observable_package.tcp_result)
}

fn create_observable_package_ipv6(
    ipv6: &Ipv6Packet,
    connection_tracker: &mut TtlCache<Connection, SynData>,
    matcher: Option<&SignatureMatcher>,
) -> Result<ObservablePackage, HuginnNetError> {
    // Extract TCP info for source/destination ports
    let tcp = TcpPacket::new(ipv6.payload())
        .ok_or_else(|| HuginnNetError::Parse("Invalid TCP packet".to_string()))?;

    let source = IpPort {
        ip: IpAddr::V6(ipv6.get_source()),
        port: tcp.get_source(),
    };
    let destination = IpPort {
        ip: IpAddr::V6(ipv6.get_destination()),
        port: tcp.get_destination(),
    };

    let tcp_package = tcp_process::process_tcp_ipv6(ipv6, connection_tracker)?;

    let mut tcp_result = TcpAnalysisResult {
        syn: None,
        syn_ack: None,
        mtu: None,
        uptime: None,
    };

    // Process TCP request (SYN)
    if let Some(tcp_request) = tcp_package.tcp_request {
        let os_quality = if let Some(matcher) = matcher {
            if let Some((label, _signature, quality)) =
                matcher.matching_by_tcp_request(&tcp_request)
            {
                OSQualityMatched {
                    os: Some(OperativeSystem::from(label)),
                    quality: crate::db::MatchQualityType::Matched(quality),
                }
            } else {
                OSQualityMatched {
                    os: None,
                    quality: crate::db::MatchQualityType::NotMatched,
                }
            }
        } else {
            OSQualityMatched {
                os: None,
                quality: crate::db::MatchQualityType::Disabled,
            }
        };

        let syn_output = SynTCPOutput {
            source: IpPort::new(std::net::IpAddr::V6(ipv6.get_source()), tcp.get_source()),
            destination: IpPort::new(
                std::net::IpAddr::V6(ipv6.get_destination()),
                tcp.get_destination(),
            ),
            os_matched: os_quality,
            sig: tcp_request,
        };
        tcp_result.syn = Some(syn_output);
    }

    // Process TCP response (SYN-ACK)
    if let Some(tcp_response) = tcp_package.tcp_response {
        let os_quality = if let Some(matcher) = matcher {
            if let Some((label, _signature, quality)) =
                matcher.matching_by_tcp_response(&tcp_response)
            {
                OSQualityMatched {
                    os: Some(OperativeSystem::from(label)),
                    quality: crate::db::MatchQualityType::Matched(quality),
                }
            } else {
                OSQualityMatched {
                    os: None,
                    quality: crate::db::MatchQualityType::NotMatched,
                }
            }
        } else {
            OSQualityMatched {
                os: None,
                quality: crate::db::MatchQualityType::Disabled,
            }
        };

        let syn_ack_output = SynAckTCPOutput {
            source: IpPort::new(std::net::IpAddr::V6(ipv6.get_source()), tcp.get_source()),
            destination: IpPort::new(
                std::net::IpAddr::V6(ipv6.get_destination()),
                tcp.get_destination(),
            ),
            os_matched: os_quality,
            sig: tcp_response,
        };
        tcp_result.syn_ack = Some(syn_ack_output);
    }

    // Process MTU
    if let Some(mtu) = tcp_package.mtu {
        let link_quality = if let Some(matcher) = matcher {
            if let Some((link, _)) = matcher.matching_by_mtu(&mtu.value) {
                MTUQualityMatched {
                    link: Some(link.clone()),
                    quality: crate::db::MatchQualityType::Matched(1.0),
                }
            } else {
                MTUQualityMatched {
                    link: None,
                    quality: crate::db::MatchQualityType::NotMatched,
                }
            }
        } else {
            MTUQualityMatched {
                link: None,
                quality: crate::db::MatchQualityType::Disabled,
            }
        };

        let mtu_output = MTUOutput {
            source: IpPort::new(std::net::IpAddr::V6(ipv6.get_source()), tcp.get_source()),
            destination: IpPort::new(
                std::net::IpAddr::V6(ipv6.get_destination()),
                tcp.get_destination(),
            ),
            link: link_quality,
            mtu: mtu.value,
        };
        tcp_result.mtu = Some(mtu_output);
    }

    if let Some(uptime) = tcp_package.uptime {
        let uptime_output = UptimeOutput {
            source: IpPort::new(std::net::IpAddr::V6(ipv6.get_source()), tcp.get_source()),
            destination: IpPort::new(
                std::net::IpAddr::V6(ipv6.get_destination()),
                tcp.get_destination(),
            ),
            days: uptime.days,
            hours: uptime.hours,
            min: uptime.min,
            up_mod_days: uptime.up_mod_days,
            freq: uptime.freq,
        };
        tcp_result.uptime = Some(uptime_output);
    }

    Ok(ObservablePackage {
        source,
        destination,
        tcp_result,
    })
}
