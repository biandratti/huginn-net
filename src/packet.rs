use std::convert::TryInto;

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

use crate::tcp::{IpVersion, PayloadSize, Quirk, Signature, TcpOption, Ttl, WindowSize};

impl Signature {
    pub fn extract(packet: &[u8]) -> Result<Self, Error> {
        EthernetPacket::new(packet)
            .ok_or_else(|| err_msg("ethernet packet too short"))
            .and_then(|packet| visit_ethernet(packet.get_ethertype(), packet.payload()))
    }
}

fn visit_ethernet(ethertype: EtherType, payload: &[u8]) -> Result<Signature, Error> {
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

fn visit_vlan(packet: VlanPacket) -> Result<Signature, Error> {
    visit_ethernet(packet.get_ethertype(), packet.payload())
}

/// Congestion encountered
const IP_TOS_CE: u8 = 0x01;
/// ECN supported
const IP_TOS_ECT: u8 = 0x02;
/// Must be zero
const IP4_MBZ: u8 = 0b0100;

fn visit_ipv4(packet: Ipv4Packet) -> Result<Signature, Error> {
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
    let ttl = Ttl::Distance(ttl_value, guess_dist(ttl_value));
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

    TcpPacket::new(packet.payload())
        .ok_or_else(|| err_msg("TCP packet too short"))
        .and_then(|packet| visit_tcp(packet, version, ttl, olen, quirks))
}

fn visit_ipv6(packet: Ipv6Packet) -> Result<Signature, Error> {
    if packet.get_next_header() != IpNextHeaderProtocols::Tcp {
        bail!(
            "unsuppport IPv6 packet with non-TCP payload: {}",
            packet.get_next_header()
        );
    }

    let version = IpVersion::V6;
    let ttl_value: u8 = packet.get_hop_limit();
    let ttl = Ttl::Distance(ttl_value, guess_dist(ttl_value));
    let olen = 0; // TODO handle extensions
    let mut quirks = vec![];

    if packet.get_flow_label() != 0 {
        quirks.push(Quirk::FlowID);
    }
    if (packet.get_traffic_class() & (IP_TOS_CE | IP_TOS_ECT)) != 0 {
        quirks.push(Quirk::Ecn);
    }

    TcpPacket::new(packet.payload())
        .ok_or_else(|| err_msg("TCP packet too short"))
        .and_then(|packet| visit_tcp(packet, version, ttl, olen, quirks))
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

fn visit_tcp(
    tcp: TcpPacket,
    version: IpVersion,
    ittl: Ttl,
    olen: u8,
    mut quirks: Vec<Quirk>,
) -> Result<Signature, Error> {
    use TcpFlags::*;

    let flags: u8 = tcp.get_flags();
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

                /*if data.len() != 10 {
                    quirks.push(Quirk::OptBad);
                }*/
            }
            _ => {
                olayout.push(TcpOption::Unknown(opt.get_number().0));
            }
        }
    }

    Ok(Signature {
        version,
        ittl,
        olen,
        mss,
        wsize: match (tcp.get_window(), mss) {
            (wsize, Some(mss_value)) if wsize % mss_value == 0 => {
                WindowSize::Mss((wsize / mss_value) as u8)
            }
            (wsize, _) if wsize % 1500 == 0 => {
                WindowSize::Mtu((wsize / 1500) as u8) // TODO: [WIP] Assuming 1500 as a typical MTU
            }
            (wsize, _) => WindowSize::Value(wsize),
        },
        wscale,
        olayout,
        quirks,
        pclass: if tcp.payload().is_empty() {
            PayloadSize::Zero
        } else {
            PayloadSize::NonZero
        },
    })
}
