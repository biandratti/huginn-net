use crate::error::HuginnNetTcpError;
#[cfg(feature = "mtu")]
use crate::mtu;
#[cfg(feature = "mtu")]
use crate::mtu::ObservableMtu;
use crate::process::ConnectionTracker;
use crate::tcp;
#[cfg(any(feature = "syn", feature = "syn-ack"))]
use crate::tcp::observable::{ObservableTcp, TcpObservation};
#[cfg(any(feature = "syn", feature = "syn-ack"))]
use crate::tcp::PayloadSize;
use crate::tcp::{IpOptions, IpVersion, Quirk, QuirkSet, TcpOption, Ttl};
#[cfg(feature = "uptime")]
use crate::uptime::{check_ts_tcp, Connection, ObservableUptime};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::{
    ipv4::{Ipv4Flags, Ipv4Packet},
    ipv6::Ipv6Packet,
    tcp::{TcpFlags, TcpOptionNumbers::*, TcpOptionPacket, TcpPacket},
    Packet, PacketSize,
};
use std::convert::TryInto;
use std::net::IpAddr;

/// Congestion encountered
const IP_TOS_CE: u8 = 0x01;
/// ECN supported
const IP_TOS_ECT: u8 = 0x02;
/// Must be zero
const IP4_MBZ: u8 = 0b0100;

// Internal representation of a TCP package
pub struct ObservableTCPPackage {
    #[cfg(feature = "syn")]
    pub tcp_request: Option<ObservableTcp>,
    #[cfg(feature = "syn-ack")]
    pub tcp_response: Option<ObservableTcp>,
    #[cfg(feature = "mtu")]
    pub mtu: Option<ObservableMtu>,
    #[cfg(feature = "uptime")]
    pub client_uptime: Option<ObservableUptime>,
    #[cfg(feature = "uptime")]
    pub server_uptime: Option<ObservableUptime>,
}

impl ObservableTCPPackage {
    #[inline]
    pub fn empty() -> Self {
        Self {
            #[cfg(feature = "syn")]
            tcp_request: None,
            #[cfg(feature = "syn-ack")]
            tcp_response: None,
            #[cfg(feature = "mtu")]
            mtu: None,
            #[cfg(feature = "uptime")]
            client_uptime: None,
            #[cfg(feature = "uptime")]
            server_uptime: None,
        }
    }
}

pub fn from_client(tcp_flags: u8) -> bool {
    use TcpFlags::*;
    tcp_flags & SYN != 0 && tcp_flags & ACK == 0
}

pub fn from_server(tcp_flags: u8) -> bool {
    use TcpFlags::*;
    tcp_flags & SYN != 0 && tcp_flags & ACK != 0
}

/// Determines if a packet is from the client side of a connection.
///
/// This function uses a two-phase approach:
/// 1. During TCP handshake: Uses SYN/SYN+ACK flags for definitive identification
/// 2. After handshake: Uses port heuristics (ephemeral vs well-known ports)
///
/// # Returns
/// `true` if the packet is from the client, `false` if from the server
///
/// # Port Heuristic
/// - Ephemeral ports (>1024) typically indicate client-side
/// - Well-known ports (≤1024) typically indicate server-side
/// - A packet from high port to low port is likely from client
pub fn is_packet_from_client(tcp_flags: u8, src_port: u16, dst_port: u16) -> bool {
    if from_client(tcp_flags) {
        // SYN packet (no ACK) is definitely from client
        true
    } else if from_server(tcp_flags) {
        // SYN+ACK packet is definitely from server
        false
    } else {
        src_port > 1024 && dst_port <= 1024
    }
}

pub fn is_valid(tcp_flags: u8, tcp_type: u8) -> bool {
    use TcpFlags::*;

    !(((tcp_flags & SYN) == SYN && (tcp_flags & (FIN | RST)) != 0)
        || (tcp_flags & (FIN | RST)) == (FIN | RST)
        || tcp_type == 0)
}

/// SYN and SYN+ACK only.
pub fn is_fingerprintable(tcp_type: u8) -> bool {
    use TcpFlags::*;

    tcp_type == SYN || tcp_type == (SYN | ACK)
}

#[inline]
pub fn process_tcp_ipv4(
    packet: &Ipv4Packet,
    connection_tracker: &mut ConnectionTracker,
) -> Result<ObservableTCPPackage, HuginnNetTcpError> {
    if packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return Err(HuginnNetTcpError::UnsupportedProtocol("IPv4".to_string()));
    }

    if packet.get_fragment_offset() > 0
        || (packet.get_flags() & Ipv4Flags::MoreFragments) == Ipv4Flags::MoreFragments
    {
        return Err(HuginnNetTcpError::UnexpectedPackage("IPv4".to_string()));
    }

    let version = IpVersion::V4;
    let ttl_observed: u8 = packet.get_ttl();
    let ttl: Ttl = tcp::ttl::calculate_ttl(ttl_observed);
    let tos: u8 = packet.get_dscp();
    let olen: u8 = IpOptions::calculate_ipv4_length(packet);
    let mut quirks = QuirkSet::EMPTY;

    if (packet.get_ecn() & (IP_TOS_CE | IP_TOS_ECT)) != 0 {
        quirks.insert(Quirk::Ecn);
    }

    if (packet.get_flags() & IP4_MBZ) != 0 {
        quirks.insert(Quirk::MustBeZero);
    }

    if (packet.get_flags() & Ipv4Flags::DontFragment) != 0 {
        quirks.insert(Quirk::Df);

        if packet.get_identification() != 0 {
            quirks.insert(Quirk::NonZeroID);
        }
    } else if packet.get_identification() == 0 {
        quirks.insert(Quirk::ZeroID);
    }

    let source_ip: IpAddr = IpAddr::V4(packet.get_source());
    let destination_ip = IpAddr::V4(packet.get_destination());

    let tcp_payload = packet.payload(); // Get a reference to the payload without moving `packet`

    let ip_package_header_length: u8 = packet.get_header_length();

    TcpPacket::new(tcp_payload)
        .ok_or_else(|| HuginnNetTcpError::UnexpectedPackage("TCP packet too short".to_string()))
        .and_then(|tcp_packet| {
            visit_tcp(
                connection_tracker,
                &tcp_packet,
                version,
                ttl,
                tos,
                ip_package_header_length,
                // IHL counts 32-bit words.
                u16::from(ip_package_header_length).saturating_mul(4),
                olen,
                quirks,
                source_ip,
                destination_ip,
            )
        })
}

#[inline]
pub fn process_tcp_ipv6(
    packet: &Ipv6Packet,
    connection_tracker: &mut ConnectionTracker,
) -> Result<ObservableTCPPackage, HuginnNetTcpError> {
    if packet.get_next_header() != IpNextHeaderProtocols::Tcp {
        return Err(HuginnNetTcpError::UnsupportedProtocol("IPv6".to_string()));
    }
    let version = IpVersion::V6;
    let ttl_observed: u8 = packet.get_hop_limit();
    let ttl: Ttl = tcp::ttl::calculate_ttl(ttl_observed);
    let tos: u8 = packet.get_traffic_class() >> 2;
    let olen: u8 = IpOptions::calculate_ipv6_length(packet);
    let mut quirks = QuirkSet::EMPTY;

    if packet.get_flow_label() != 0 {
        quirks.insert(Quirk::FlowID);
    }
    if (packet.get_traffic_class() & (IP_TOS_CE | IP_TOS_ECT)) != 0 {
        quirks.insert(Quirk::Ecn);
    }

    let source_ip: IpAddr = IpAddr::V6(packet.get_source());
    let destination_ip = IpAddr::V6(packet.get_destination());

    let ip_package_header_length: u8 = 40; //IPv6 header is always 40 bytes

    TcpPacket::new(packet.payload())
        .ok_or_else(|| HuginnNetTcpError::UnexpectedPackage("TCP packet too short".to_string()))
        .and_then(|tcp_packet| {
            visit_tcp(
                connection_tracker,
                &tcp_packet,
                version,
                ttl,
                tos,
                ip_package_header_length,
                u16::from(ip_package_header_length),
                olen,
                quirks,
                source_ip,
                destination_ip,
            )
        })
}

/// Builds the observation shared by SYN and SYN+ACK fingerprint paths.
#[cfg(any(feature = "syn", feature = "syn-ack"))]
#[allow(clippy::too_many_arguments)]
fn tcp_observation(
    version: IpVersion,
    ittl: Ttl,
    tos: u8,
    olen: u8,
    mss: Option<u16>,
    wsize: u16,
    ip_header_bytes: u16,
    tcp: &TcpPacket,
    wscale: Option<u8>,
    olayout: Vec<TcpOption>,
    quirks: QuirkSet,
    peer_mss: Option<u16>,
) -> TcpObservation {
    let tot_hdr =
        ip_header_bytes.saturating_add(u16::from(tcp.get_data_offset()).saturating_mul(4));

    TcpObservation {
        version,
        ittl,
        olen,
        mss,
        wsize,
        tot_hdr,
        wscale,
        olayout,
        quirks,
        pclass: if tcp.payload().is_empty() {
            PayloadSize::Zero
        } else {
            PayloadSize::NonZero
        },
        peer_mss,
        tos,
    }
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(
    any(
        not(feature = "mtu"),
        not(feature = "uptime"),
        not(any(feature = "syn", feature = "syn-ack")),
    ),
    allow(unused_variables)
)]
#[cfg_attr(
    not(any(feature = "syn", feature = "syn-ack")),
    allow(unused_assignments)
)]
fn visit_tcp(
    connection_tracker: &mut ConnectionTracker,
    tcp: &TcpPacket,
    version: IpVersion,
    ittl: Ttl,
    tos: u8,
    ip_package_header_length: u8,
    ip_header_bytes: u16,
    olen: u8,
    mut quirks: QuirkSet,
    source_ip: IpAddr,
    destination_ip: IpAddr,
) -> Result<ObservableTCPPackage, HuginnNetTcpError> {
    use TcpFlags::*;
    let flags: u8 = tcp.get_flags();
    let from_client: bool = from_client(flags);

    let tcp_type: u8 = flags & (SYN | ACK | FIN | RST);
    if !is_valid(flags, tcp_type) {
        return Err(HuginnNetTcpError::InvalidTcpFlags(flags));
    }

    #[cfg(not(all(
        feature = "syn",
        feature = "syn-ack",
        feature = "mtu",
        feature = "uptime"
    )))]
    {
        // `syn-ack` alone still needs to see the SYN: the peer MSS lives there.
        // It does not emit a client OS match when `syn` is off, only flow state.
        let needs_request_side = cfg!(feature = "syn")
            || cfg!(feature = "mtu")
            || cfg!(feature = "uptime")
            || cfg!(feature = "syn-ack");
        let needs_response_side = cfg!(feature = "syn-ack") || cfg!(feature = "uptime");
        if (from_client && !needs_request_side) || (!from_client && !needs_response_side) {
            return Ok(ObservableTCPPackage::empty());
        }
    }

    if (flags & (ECE | CWR)) != 0 {
        quirks.insert(Quirk::Ecn);
    }
    if tcp.get_sequence() == 0 {
        quirks.insert(Quirk::SeqNumZero);
    }
    if flags & ACK == ACK {
        if tcp.get_acknowledgement() == 0 {
            quirks.insert(Quirk::AckNumZero);
        }
    } else if tcp.get_acknowledgement() != 0 && flags & RST == 0 {
        quirks.insert(Quirk::AckNumNonZero);
    }

    if flags & URG == URG {
        quirks.insert(Quirk::Urg);
    } else if tcp.get_urgent_ptr() != 0 {
        quirks.insert(Quirk::NonZeroURG);
    }

    if flags & PSH == PSH {
        quirks.insert(Quirk::Push);
    }

    let mut buf = tcp.get_options_raw();
    let mut mss = None;
    let mut wscale = None;
    let mut olayout: Vec<TcpOption> = Vec::with_capacity(8);
    #[cfg(feature = "uptime")]
    let mut client_uptime: Option<ObservableUptime> = None;
    #[cfg(feature = "uptime")]
    let mut server_uptime: Option<ObservableUptime> = None;

    while let Some(opt) = TcpOptionPacket::new(buf) {
        buf = &buf[opt.packet_size().min(buf.len())..];

        let data: &[u8] = opt.payload();

        match opt.get_number() {
            EOL => {
                olayout.push(TcpOption::Eol(buf.len() as u8));

                if buf.iter().any(|&b| b != 0) {
                    quirks.insert(Quirk::TrailinigNonZero);
                }

                break;
            }
            NOP => {
                olayout.push(TcpOption::Nop);
            }
            MSS => {
                olayout.push(TcpOption::Mss);
                if data.len() >= 2 {
                    let mss_value: u16 = u16::from_be_bytes([data[0], data[1]]);
                    mss = Some(mss_value);
                }
            }
            WSCALE => {
                olayout.push(TcpOption::Ws);

                if !data.is_empty() {
                    wscale = Some(data[0]);

                    if data[0] > 14 {
                        quirks.insert(Quirk::ExcessiveWindowScaling);
                    }
                }
            }
            SACK_PERMITTED => {
                olayout.push(TcpOption::Sok);
            }
            SACK => {
                olayout.push(TcpOption::Sack);
            }
            TIMESTAMPS => {
                olayout.push(TcpOption::TS);

                if data.len() >= 4 {
                    let ts_val_bytes: [u8; 4] = data[..4].try_into().map_err(|_| {
                        HuginnNetTcpError::Parse(
                            "Failed to convert slice to array for timestamp value".to_string(),
                        )
                    })?;
                    if u32::from_be_bytes(ts_val_bytes) == 0 {
                        quirks.insert(Quirk::OwnTimestampZero);
                    }
                }

                if data.len() >= 8 && tcp_type == SYN {
                    let ts_peer_bytes: [u8; 4] = data[4..8].try_into().map_err(|_| {
                        HuginnNetTcpError::Parse(
                            "Failed to convert slice to array for peer timestamp value".to_string(),
                        )
                    })?;
                    if u32::from_be_bytes(ts_peer_bytes) != 0 {
                        quirks.insert(Quirk::PeerTimestampNonZero);
                    }
                }

                #[cfg(feature = "uptime")]
                if data.len() >= 8 {
                    let ts_val_bytes: [u8; 4] = data[..4].try_into().map_err(|_| {
                        HuginnNetTcpError::Parse(
                            "Failed to convert slice to array for timestamp value".to_string(),
                        )
                    })?;
                    let ts_val: u32 = u32::from_be_bytes(ts_val_bytes);
                    let connection: Connection = Connection {
                        src_ip: source_ip,
                        src_port: tcp.get_source(),
                        dst_ip: destination_ip,
                        dst_port: tcp.get_destination(),
                    };

                    let is_from_client =
                        is_packet_from_client(flags, tcp.get_source(), tcp.get_destination());

                    let (cli_uptime, srv_uptime) = check_ts_tcp(
                        &mut connection_tracker.inner,
                        &connection,
                        is_from_client,
                        ts_val,
                    );
                    client_uptime = cli_uptime;
                    server_uptime = srv_uptime;
                }
            }
            _ => {
                olayout.push(TcpOption::Unknown(opt.get_number().0));
            }
        }
    }

    #[cfg(feature = "mtu")]
    let mtu: Option<ObservableMtu> = match (mss, &version) {
        (Some(mss_value), IpVersion::V4) => {
            mtu::extract_from_ipv4(tcp, ip_package_header_length, mss_value)
        }
        (Some(mss_value), IpVersion::V6) => {
            mtu::extract_from_ipv6(tcp, ip_package_header_length, mss_value)
        }
        _ => None,
    };

    #[cfg(feature = "syn-ack")]
    if tcp_type == SYN {
        // Always record the client's MSS when responses are fingerprinted, even
        // if the `syn` feature is off and no client OS signal is emitted.
        connection_tracker.flows.note_syn(
            crate::process::flow_state::FlowKey::from_syn(
                source_ip,
                tcp.get_source(),
                destination_ip,
                tcp.get_destination(),
            ),
            mss,
        );
    }

    #[cfg(any(feature = "syn", feature = "syn-ack"))]
    #[cfg_attr(
        not(all(feature = "syn", feature = "syn-ack")),
        allow(unused_variables)
    )]
    let (tcp_request, tcp_response): (Option<ObservableTcp>, Option<ObservableTcp>) =
        if !is_fingerprintable(tcp_type) {
            (None, None)
        } else if tcp_type == SYN {
            #[cfg(feature = "syn")]
            {
                (
                    Some(ObservableTcp {
                        matching: tcp_observation(
                            version,
                            ittl,
                            tos,
                            olen,
                            mss,
                            tcp.get_window(),
                            ip_header_bytes,
                            tcp,
                            wscale,
                            olayout,
                            quirks,
                            None,
                        ),
                    }),
                    None,
                )
            }
            #[cfg(not(feature = "syn"))]
            {
                // `syn-ack` only: the SYN was recorded above for peer MSS; nothing to emit.
                drop((olayout, quirks, wscale));
                (None, None)
            }
        } else {
            #[cfg(feature = "syn-ack")]
            {
                use crate::process::flow_state::{FlowKey, SynAckDisposition};

                let key = FlowKey::from_syn_ack(
                    source_ip,
                    tcp.get_source(),
                    destination_ip,
                    tcp.get_destination(),
                );
                match connection_tracker.flows.begin_syn_ack(key) {
                    SynAckDisposition::Duplicate => (None, None),
                    SynAckDisposition::First { peer_mss } => (
                        None,
                        Some(ObservableTcp {
                            matching: tcp_observation(
                                version,
                                ittl,
                                tos,
                                olen,
                                mss,
                                tcp.get_window(),
                                ip_header_bytes,
                                tcp,
                                wscale,
                                olayout,
                                quirks,
                                peer_mss,
                            ),
                        }),
                    ),
                }
            }
            #[cfg(not(feature = "syn-ack"))]
            {
                (None, None)
            }
        };

    Ok(ObservableTCPPackage {
        #[cfg(feature = "syn")]
        tcp_request,
        #[cfg(feature = "syn-ack")]
        tcp_response,
        #[cfg(feature = "mtu")]
        mtu: if from_client { mtu } else { None },
        #[cfg(feature = "uptime")]
        client_uptime,
        #[cfg(feature = "uptime")]
        server_uptime,
    })
}
