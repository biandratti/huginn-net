/// Packet parsing utilities for different network packet formats
///
/// This module provides unified parsing for various network packet formats
/// from both live network capture and PCAP files:
/// - Ethernet frames (most common in network interfaces)
/// - Raw IP packets (tunnels, loopback interfaces)
/// - NULL datalink packets (specialized capture tools)
/// - Future packet formats can be added here
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use tracing::debug;

/// Represents the result of IP packet parsing
#[derive(Debug)]
pub enum IpPacket<'a> {
    Ipv4(Ipv4Packet<'a>),
    Ipv6(Ipv6Packet<'a>),
    None,
}

/// Datalink format types supported
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DatalinkFormat {
    /// Standard Ethernet frame (14-byte header)
    Ethernet,
    /// Raw IP packet (no datalink header)
    RawIp,
    /// NULL datalink with 4-byte header (0x1e 0x00 ...)
    Null,
}

/// Parse a network packet using multiple format strategies
///
/// Tries different parsing strategies in order of likelihood:
/// 1. Ethernet (most common in network interfaces and PCAPs)
/// 2. Raw IP (tunnels, loopback interfaces, some PCAPs)
/// 3. NULL datalink (specialized capture tools)
///
/// Works with packets from both live network capture and PCAP files.
///
/// # Arguments
/// * `packet` - Raw packet bytes from network interface or PCAP file
///
/// # Returns
/// * `IpPacket` - The parsed IP packet or None if no valid format found
pub fn parse_packet(packet: &[u8]) -> IpPacket<'_> {
    // Strategy 1: Try Ethernet first (most common)
    if let Some(parsed) = try_ethernet_format(packet) {
        return parsed;
    }

    // Strategy 2: Try Raw IP (no Ethernet header)
    if let Some(parsed) = try_raw_ip_format(packet) {
        return parsed;
    }

    // Strategy 3: Try NULL datalink (skip 4-byte header)
    if let Some(parsed) = try_null_datalink_format(packet) {
        return parsed;
    }

    IpPacket::None
}

/// Try parsing as Ethernet frame
fn try_ethernet_format(packet: &[u8]) -> Option<IpPacket<'_>> {
    // Ethernet header is 14 bytes: [6B dst][6B src][2B ethertype]
    if packet.len() < 14 {
        return None;
    }

    let ethernet = EthernetPacket::new(packet)?;
    let ip_data = &packet[14..]; // Skip 14-byte Ethernet header

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            if let Some(ipv4) = Ipv4Packet::new(ip_data) {
                debug!("Parsed Ethernet IPv4 packet");
                return Some(IpPacket::Ipv4(ipv4));
            }
        }
        EtherTypes::Ipv6 => {
            if let Some(ipv6) = Ipv6Packet::new(ip_data) {
                debug!("Parsed Ethernet IPv6 packet");
                return Some(IpPacket::Ipv6(ipv6));
            }
        }
        _ => {}
    }

    None
}

/// Try parsing as Raw IP (no datalink header)
fn try_raw_ip_format(packet: &[u8]) -> Option<IpPacket<'_>> {
    if packet.len() < 20 {
        return None;
    }

    // Check IP version in first 4 bits
    let version = (packet[0] & 0xF0) >> 4;
    match version {
        4 => {
            if let Some(ipv4) = Ipv4Packet::new(packet) {
                debug!("Parsed Raw IPv4 packet");
                return Some(IpPacket::Ipv4(ipv4));
            }
        }
        6 => {
            if let Some(ipv6) = Ipv6Packet::new(packet) {
                debug!("Parsed Raw IPv6 packet");
                return Some(IpPacket::Ipv6(ipv6));
            }
        }
        _ => {}
    }

    None
}

/// Try parsing as NULL datalink format (4-byte header)
fn try_null_datalink_format(packet: &[u8]) -> Option<IpPacket<'_>> {
    // Check for NULL datalink signature and minimum size
    if packet.len() < 24 || packet[0] != 0x1e || packet[1] != 0x00 {
        return None;
    }

    let ip_data = &packet[4..]; // Skip 4-byte NULL header
    let version = (ip_data[0] & 0xF0) >> 4;

    match version {
        4 => {
            if let Some(ipv4) = Ipv4Packet::new(ip_data) {
                debug!("Parsed NULL datalink IPv4 packet");
                return Some(IpPacket::Ipv4(ipv4));
            }
        }
        6 => {
            if let Some(ipv6) = Ipv6Packet::new(ip_data) {
                debug!("Parsed NULL datalink IPv6 packet");
                return Some(IpPacket::Ipv6(ipv6));
            }
        }
        _ => {}
    }

    None
}

/// Detect the datalink format of a packet without full parsing
///
/// Useful for statistics or format validation
pub fn detect_datalink_format(packet: &[u8]) -> Option<DatalinkFormat> {
    // Check NULL datalink first (most specific signature)
    if packet.len() >= 24 && packet[0] == 0x1e && packet[1] == 0x00 {
        let ip_data = &packet[4..];
        let version = (ip_data[0] & 0xF0) >> 4;
        if version == 4 || version == 6 {
            return Some(DatalinkFormat::Null);
        }
    }

    // Check Raw IP (check if it starts with valid IP version)
    if packet.len() >= 20 {
        let version = (packet[0] & 0xF0) >> 4;
        if version == 4 || version == 6 {
            // Additional validation for IPv4
            if version == 4 {
                let ihl = (packet[0] & 0x0F).saturating_mul(4);
                if ihl >= 20 && packet.len() >= usize::from(ihl) {
                    return Some(DatalinkFormat::RawIp);
                }
            }
            // Additional validation for IPv6
            else if version == 6 && packet.len() >= 40 {
                return Some(DatalinkFormat::RawIp);
            }
        }
    }

    // Check Ethernet (least specific - needs valid EtherType)
    if packet.len() >= 14 {
        if let Some(ethernet) = EthernetPacket::new(packet) {
            let ethertype = ethernet.get_ethertype();
            // Only consider it Ethernet if it has a valid IP EtherType
            if ethertype == EtherTypes::Ipv4 || ethertype == EtherTypes::Ipv6 {
                let ip_data = &packet[14..];
                if !ip_data.is_empty() {
                    let version = (ip_data[0] & 0xF0) >> 4;
                    if (ethertype == EtherTypes::Ipv4 && version == 4)
                        || (ethertype == EtherTypes::Ipv6 && version == 6)
                    {
                        return Some(DatalinkFormat::Ethernet);
                    }
                }
            }
        }
    }

    None
}
