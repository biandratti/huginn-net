pub mod flow;
pub mod parallel;

use self::flow as tcp_process;
use crate::error::HuginnNetTcpError;
use crate::matcher_api::TcpMatcher;
use crate::output::{IpPort, TcpAnalysisResult};
#[cfg(any(feature = "syn", feature = "syn-ack", feature = "mtu"))]
use crate::output::MatchQuality;
#[cfg(any(feature = "syn", feature = "syn-ack"))]
use crate::output::OSQualityMatched;
#[cfg(feature = "mtu")]
use crate::output::{MTUOutput, MTUQualityMatched};
#[cfg(feature = "syn")]
use crate::output::SynTCPOutput;
#[cfg(feature = "syn-ack")]
use crate::output::SynAckTCPOutput;
#[cfg(feature = "uptime")]
use crate::output::{UptimeOutput, UptimeRole};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::net::IpAddr;

pub use parallel::{DispatchResult, PoolStats, WorkerPool, WorkerStats};

/// Per-flow connection state used by uptime tracking.
///
/// When the `uptime` feature is enabled, this wraps a `TtlCache` of TCP
/// timestamp samples keyed by connection direction. When the feature is
/// disabled, it is a zero-sized stub and all operations on it are no-ops, so
/// builds without uptime tracking drop the `ttl_cache` dependency entirely
/// without changing public function signatures.
pub struct ConnectionTracker {
    #[cfg(feature = "uptime")]
    pub(crate) inner:
        ttl_cache::TtlCache<crate::uptime::ConnectionKey, crate::uptime::TcpTimestamp>,
}

impl ConnectionTracker {
    /// Creates a new connection tracker.
    ///
    /// `max_connections` is the upper bound on tracked flows. When the
    /// `uptime` feature is disabled the argument is ignored.
    pub fn new(_max_connections: usize) -> Self {
        Self {
            #[cfg(feature = "uptime")]
            inner: ttl_cache::TtlCache::new(_max_connections),
        }
    }
}

pub struct ObservablePackage {
    pub source: IpPort,
    pub destination: IpPort,
    pub tcp_result: TcpAnalysisResult,
}

/// Processes an IPv4 packet for TCP content.
#[inline]
pub fn process_ipv4_packet(
    ipv4: &Ipv4Packet,
    connection_tracker: &mut ConnectionTracker,
    matcher: Option<&dyn TcpMatcher>,
) -> Result<TcpAnalysisResult, HuginnNetTcpError> {
    create_observable_package_ipv4(ipv4, connection_tracker, matcher).map(|pkg| pkg.tcp_result)
}

#[cfg_attr(
    not(any(feature = "syn", feature = "syn-ack")),
    allow(unused_variables)
)]
#[cfg_attr(
    not(any(feature = "syn", feature = "syn-ack", feature = "mtu", feature = "uptime")),
    allow(unused_mut)
)]
fn create_observable_package_ipv4(
    ipv4: &Ipv4Packet,
    connection_tracker: &mut ConnectionTracker,
    matcher: Option<&dyn TcpMatcher>,
) -> Result<ObservablePackage, HuginnNetTcpError> {
    let tcp = TcpPacket::new(ipv4.payload())
        .ok_or_else(|| HuginnNetTcpError::Parse("Invalid TCP packet".to_string()))?;

    let source = IpPort { ip: IpAddr::V4(ipv4.get_source()), port: tcp.get_source() };
    let destination =
        IpPort { ip: IpAddr::V4(ipv4.get_destination()), port: tcp.get_destination() };

    let tcp_package = tcp_process::process_tcp_ipv4(ipv4, connection_tracker)?;

    let mut tcp_result = TcpAnalysisResult {
        #[cfg(feature = "syn")]
        syn: None,
        #[cfg(feature = "syn-ack")]
        syn_ack: None,
        #[cfg(feature = "mtu")]
        mtu: None,
        #[cfg(feature = "uptime")]
        client_uptime: None,
        #[cfg(feature = "uptime")]
        server_uptime: None,
    };

    #[cfg(feature = "syn")]
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

    #[cfg(feature = "syn-ack")]
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

    #[cfg(feature = "mtu")]
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

    #[cfg(feature = "uptime")]
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

    #[cfg(feature = "uptime")]
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
#[inline]
pub fn process_ipv6_packet(
    ipv6: &Ipv6Packet,
    connection_tracker: &mut ConnectionTracker,
    matcher: Option<&dyn TcpMatcher>,
) -> Result<TcpAnalysisResult, HuginnNetTcpError> {
    create_observable_package_ipv6(ipv6, connection_tracker, matcher).map(|pkg| pkg.tcp_result)
}

#[cfg_attr(
    not(any(feature = "syn", feature = "syn-ack")),
    allow(unused_variables)
)]
#[cfg_attr(
    not(any(feature = "syn", feature = "syn-ack", feature = "mtu", feature = "uptime")),
    allow(unused_mut)
)]
fn create_observable_package_ipv6(
    ipv6: &Ipv6Packet,
    connection_tracker: &mut ConnectionTracker,
    matcher: Option<&dyn TcpMatcher>,
) -> Result<ObservablePackage, HuginnNetTcpError> {
    let tcp = TcpPacket::new(ipv6.payload())
        .ok_or_else(|| HuginnNetTcpError::Parse("Invalid TCP packet".to_string()))?;

    let source = IpPort { ip: IpAddr::V6(ipv6.get_source()), port: tcp.get_source() };
    let destination =
        IpPort { ip: IpAddr::V6(ipv6.get_destination()), port: tcp.get_destination() };

    let tcp_package = tcp_process::process_tcp_ipv6(ipv6, connection_tracker)?;

    let mut tcp_result = TcpAnalysisResult {
        #[cfg(feature = "syn")]
        syn: None,
        #[cfg(feature = "syn-ack")]
        syn_ack: None,
        #[cfg(feature = "mtu")]
        mtu: None,
        #[cfg(feature = "uptime")]
        client_uptime: None,
        #[cfg(feature = "uptime")]
        server_uptime: None,
    };

    #[cfg(feature = "syn")]
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

    #[cfg(feature = "syn-ack")]
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

    #[cfg(feature = "mtu")]
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

    #[cfg(feature = "uptime")]
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

    #[cfg(feature = "uptime")]
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

#[cfg(feature = "mtu")]
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
