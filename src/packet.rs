use crate::mtu;
use crate::tcp::{IpVersion, PayloadSize, Quirk, Signature, TcpOption, Ttl, WindowSize};
use crate::uptime::{Uptime};
use failure::{bail, err_msg, Error};
use pnet::packet::{
    ethernet::{EtherType, EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::{Ipv4Flags, Ipv4Packet},
    ipv6::Ipv6Packet,
    tcp::{TcpFlags, TcpOptionNumbers::*, TcpOptionPacket, TcpPacket},
    vlan::VlanPacket,
    Packet, PacketSize,
};
use std::convert::TryInto;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct IpPort {
    pub ip: IpAddr,
    pub port: u16,
}

pub struct SignatureDetails {
    pub signature: Signature,
    pub mtu: Option<u16>,
    pub uptime: Option<Uptime>,
    pub client: IpPort,
    pub server: IpPort,
    pub is_client: bool,
}
impl SignatureDetails {
    pub fn extract(packet: &[u8]) -> Result<Self, Error> {
        EthernetPacket::new(packet)
            .ok_or_else(|| err_msg("ethernet packet too short"))
            .and_then(|packet| visit_ethernet(packet.get_ethertype(), packet.payload()))
    }
}

fn visit_ethernet(ethertype: EtherType, payload: &[u8]) -> Result<SignatureDetails, Error> {
    match ethertype {
        EtherTypes::Vlan => VlanPacket::new(payload)
            .ok_or_else(|| err_msg("vlan packet too short"))
            .and_then(visit_vlan),

        EtherTypes::Ipv4 => Ipv4Packet::new(payload)
            .ok_or_else(|| err_msg("ipv4 packet too short"))
            .and_then(visit_ipv4),

        EtherTypes::Ipv6 => Ipv6Packet::new(payload)
            .ok_or_else(|| err_msg("ipv6 packet too short"))
            .and_then(visit_ipv6),

        ty => bail!("unsupport ethernet type: {}", ty),
    }
}

fn visit_vlan(packet: VlanPacket) -> Result<SignatureDetails, Error> {
    visit_ethernet(packet.get_ethertype(), packet.payload())
}

/// Congestion encountered
const IP_TOS_CE: u8 = 0x01;
/// ECN supported
const IP_TOS_ECT: u8 = 0x02;
/// Must be zero
const IP4_MBZ: u8 = 0b0100;

fn is_client(tcp_flags: u8) -> bool {
    tcp_flags & TcpFlags::SYN != 0 && tcp_flags & TcpFlags::ACK == 0
}

fn visit_ipv4(packet: Ipv4Packet) -> Result<SignatureDetails, Error> {
    if packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        bail!(
            "unsuppport IPv4 packet with non-TCP payload: {}",
            packet.get_next_level_protocol()
        );
    }

    if packet.get_fragment_offset() > 0
        || (packet.get_flags() & Ipv4Flags::MoreFragments) == Ipv4Flags::MoreFragments
    {
        bail!("unsupport IPv4 fragment");
    }

    let version = IpVersion::V4;
    let ttl_value: u8 = packet.get_ttl();
    let ttl = Ttl::Distance(ttl_value, guess_dist(ttl_value)); //TODO: WIP..
    let olen: u8 = packet.get_options_raw().len() as u8;
    let mut quirks = vec![];

    if (packet.get_ecn() & (IP_TOS_CE | IP_TOS_ECT)) != 0 {
        quirks.push(Quirk::Ecn);
    }

    if (packet.get_flags() & IP4_MBZ) != 0 {
        quirks.push(Quirk::MustBeZero);
    }

    if (packet.get_flags() & Ipv4Flags::DontFragment) != 0 {
        quirks.push(Quirk::Df);

        if packet.get_identification() != 0 {
            quirks.push(Quirk::NonZeroID);
        }
    } else if packet.get_identification() == 0 {
        quirks.push(Quirk::ZeroID);
    }

    let client_ip: IpAddr = IpAddr::V4(packet.get_source());
    let server_ip = IpAddr::V4(packet.get_destination());

    let tcp_payload = packet.payload(); // Get a reference to the payload without moving `packet`

    let ip_package_header_length: u8 = packet.get_header_length();

    TcpPacket::new(tcp_payload)
        .ok_or_else(|| err_msg("TCP packet too short"))
        .and_then(|tcp_packet| {
            visit_tcp(
                &tcp_packet,
                version,
                ttl,
                ip_package_header_length,
                olen,
                quirks,
                client_ip,
                server_ip,
            )
        })
}

fn visit_ipv6(packet: Ipv6Packet) -> Result<SignatureDetails, Error> {
    if packet.get_next_header() != IpNextHeaderProtocols::Tcp {
        bail!(
            "unsuppport IPv6 packet with non-TCP payload: {}",
            packet.get_next_header()
        );
    }

    let version = IpVersion::V6;
    let ttl_value: u8 = packet.get_hop_limit();
    let ttl = Ttl::Distance(ttl_value, guess_dist(ttl_value)); // TODO: WIP
    let olen = 0; // TODO handle extensions
    let mut quirks = vec![];

    if packet.get_flow_label() != 0 {
        quirks.push(Quirk::FlowID);
    }
    if (packet.get_traffic_class() & (IP_TOS_CE | IP_TOS_ECT)) != 0 {
        quirks.push(Quirk::Ecn);
    }

    let client_ip: IpAddr = IpAddr::V6(packet.get_source());
    let server_ip = IpAddr::V6(packet.get_destination());

    let ip_package_header_length: u8 = 40; //IPv6 header is always 40 bytes

    TcpPacket::new(packet.payload())
        .ok_or_else(|| err_msg("TCP packet too short"))
        .and_then(|tcp_packet| {
            visit_tcp(
                &tcp_packet,
                version,
                ttl,
                ip_package_header_length,
                olen,
                quirks,
                client_ip,
                server_ip,
            )
        })
}

fn guess_dist(ttl: u8) -> u8 {
    if ttl <= 32 {
        32 - ttl
    } else if ttl <= 64 {
        64 - ttl
    } else if ttl <= 128 {
        128 - ttl
    } else {
        255 - ttl
    }
}

//TODO: move to uptime
#[derive(Debug)]
struct SynData {
    ts1: u32,
    recv_ms: u64,
}
fn get_unix_time_ms() -> u64 {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH)
        .expect("Time went backwards"); // Maneja posibles errores, si el sistema tiene un problema con el tiempo

    // Convertir a milisegundos
    duration.as_millis() as u64
}

//TODO: WIP: observable tcp params
#[allow(clippy::too_many_arguments)]
fn visit_tcp(
    tcp: &TcpPacket,
    version: IpVersion,
    ittl: Ttl,
    ip_package_header_length: u8,
    olen: u8,
    mut quirks: Vec<Quirk>,
    client_ip: IpAddr,
    server_ip: IpAddr,
) -> Result<SignatureDetails, Error> {
    use TcpFlags::*;

    let flags: u8 = tcp.get_flags();
    let is_client = is_client(flags);
    let tcp_type: u8 = flags & (SYN | ACK | FIN | RST);

    if ((flags & SYN) == SYN && (flags & (FIN | RST)) != 0)
        || (flags & (FIN | RST)) == (FIN | RST)
        || tcp_type == 0
    {
        bail!("invalid TCP flags: {}", flags);
    }

    if (flags & (ECE | CWR)) != 0 {
        //TODO:    if (flags & (ECE | CWR | NS)) != 0 {
        quirks.push(Quirk::Ecn);
    }
    if tcp.get_sequence() == 0 {
        quirks.push(Quirk::SeqNumZero);
    }
    if flags & ACK == ACK {
        if tcp.get_acknowledgement() == 0 {
            quirks.push(Quirk::AckNumZero);
        }
    } else if tcp.get_acknowledgement() != 0 && flags & RST == 0 {
        quirks.push(Quirk::AckNumNonZero);
    }

    if flags & URG == URG {
        quirks.push(Quirk::Urg);
    } else if tcp.get_urgent_ptr() != 0 {
        quirks.push(Quirk::NonZeroURG);
    }

    if flags & PSH == PSH {
        quirks.push(Quirk::Push);
    }

    let mut buf = tcp.get_options_raw();
    let mut mss = None;
    let mut wscale = None;
    let mut olayout = vec![];
    let mut uptime: Option<Uptime> = None;
    let mut last_syn: Option<SynData> = None;
    let mut last_synack: Option<SynData> = None;

    while let Some(opt) = TcpOptionPacket::new(buf) {
        buf = &buf[opt.packet_size().min(buf.len())..];

        //println!("Buffer before parsing MSS: {:?}", buf);

        let data: &[u8] = opt.payload();

        match opt.get_number() {
            EOL => {
                olayout.push(TcpOption::Eol(buf.len() as u8));

                if buf.iter().any(|&b| b != 0) {
                    quirks.push(Quirk::TrailinigNonZero);
                }
            }
            NOP => {
                olayout.push(TcpOption::Nop);
            }
            MSS => {
                olayout.push(TcpOption::Mss);
                if data.len() >= 2 {
                    let mss_value: u16 = ((data[0] as u16) << 8) | (data[1] as u16);
                    //quirks.push(Quirk::mss);
                    mss = Some(mss_value);
                }

                /*if data.len() != 4 {
                    quirks.push(Quirk::OptBad);
                }*/
            }
            WSCALE => {
                olayout.push(TcpOption::Ws);

                wscale = Some(data[0]);

                if data[0] > 14 {
                    quirks.push(Quirk::ExcessiveWindowScaling);
                }
                /*if data.len() != 3 {
                    quirks.push(Quirk::OptBad);
                }*/
            }
            SACK_PERMITTED => {
                olayout.push(TcpOption::Sok);

                /*if data.len() != 2 {
                    quirks.push(Quirk::OptBad);
                }*/
            }
            SACK => {
                olayout.push(TcpOption::Sack);

                /*match data.len() {
                    10 | 18 | 26 | 34 => {}
                    _ => quirks.push(Quirk::OptBad),
                }*/
            }
            TIMESTAMPS => {
                olayout.push(TcpOption::TS);

                if data.len() >= 4 && u32::from_ne_bytes(data[..4].try_into()?) == 0 {
                    quirks.push(Quirk::OwnTimestampZero);
                }

                if data.len() >= 8
                    && tcp_type == SYN
                    && u32::from_ne_bytes(data[4..8].try_into()?) != 0
                {
                    quirks.push(Quirk::PeerTimestampNonZero);
                }

                if data.len() >= 8 {

                    let ts1 = u32::from_ne_bytes(data[0..4].try_into()?);
                    let ts2 = u32::from_ne_bytes(data[4..8].try_into()?);

                    // Guardamos el timestamp del SYN recibido
                    if tcp_type == SYN {
                        last_syn = Some(SynData { ts1, recv_ms: get_unix_time_ms() });
                    } else if tcp_type == ACK {
                        last_synack = Some(SynData { ts1, recv_ms: get_unix_time_ms() });
                    }

                    //println!("get diff?");
                    // Cálculo de la diferencia de timestamps y la frecuencia de los mismos
                    if let Some(last_syn_data) = &last_syn {
                        let ms_diff = get_unix_time_ms() - last_syn_data.recv_ms;
                        let ts_diff = ts1 - last_syn_data.ts1;

                        println!("previus condition, {}, {}", ms_diff, ts_diff );
                        if ms_diff >= 25 && ms_diff <= 600000 && ts_diff >= 5 {
                            println!("in condition");
                            let ffreq = ts_diff as f64 * 1000.0 / ms_diff as f64;

                            // Rango de frecuencias para ajustar el uptime
                            if ffreq >= 0.01 && ffreq <= 10.0 {
                                let freq = ffreq.round() as u32;
                                uptime = Some(Uptime {
                                    days: (ts1 / freq / 60 / 60 / 24),
                                    hours: (ts1 / freq / 60 / 60) % 24,
                                    min: (ts1 / freq / 60) % 60,
                                    up_mod_days: u32::MAX / (freq * 60 * 60 * 24),
                                    freq,
                                });
                            }
                        }
                    }
                }

                /*if data.len() != 10 {
                    quirks.push(Quirk::OptBad);
                }*/
            }
            _ => {
                olayout.push(TcpOption::Unknown(opt.get_number().0));
            }
        }
    }

    let mtu: Option<u16> = match (mss, &version) {
        (Some(mss_value), IpVersion::V4) => {
            mtu::extract_from_ipv4(tcp, ip_package_header_length, mss_value)
        }
        (Some(mss_value), IpVersion::V6) => {
            mtu::extract_from_ipv6(tcp, ip_package_header_length, mss_value)
        }
        _ => None,
    };

    let client_port = tcp.get_source();
    let server_port = tcp.get_destination();

    let wsize: WindowSize = match (tcp.get_window(), mss) {
        (wsize, Some(mss_value)) if wsize % mss_value == 0 => {
            WindowSize::Mss((wsize / mss_value) as u8)
        }
        (wsize, _) if mtu.is_some() && wsize % mtu.unwrap() == 0 => {
            WindowSize::Mtu((wsize / mtu.unwrap()) as u8)
        }
        (wsize, _) => WindowSize::Value(wsize),
    };

    Ok(SignatureDetails {
        signature: Signature {
            version,
            ittl,
            olen,
            mss,
            wsize,
            wscale,
            olayout,
            quirks,
            pclass: if tcp.payload().is_empty() {
                PayloadSize::Zero
            } else {
                PayloadSize::NonZero
            },
        },
        mtu,
        uptime,
        client: IpPort {
            ip: client_ip,
            port: client_port,
        },
        server: IpPort {
            ip: server_ip,
            port: server_port,
        },
        is_client,
    })
}
