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
    /// IPv4 packet data (slice of original packet)
    Ipv4(&'a [u8]),
    /// IPv6 packet data (slice of original packet)
    Ipv6(&'a [u8]),
    /// No valid IP packet found
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
pub fn parse_packet(packet: &[u8]) -> IpPacket {
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
fn try_ethernet_format(packet: &[u8]) -> Option<IpPacket> {
    // Ethernet header is 14 bytes: [6B dst][6B src][2B ethertype]
    if packet.len() < 14 {
        return None;
    }

    let ethernet = EthernetPacket::new(packet)?;
    let ip_data = &packet[14..]; // Skip 14-byte Ethernet header

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            if Ipv4Packet::new(ip_data).is_some() {
                debug!("Parsed Ethernet IPv4 packet");
                return Some(IpPacket::Ipv4(ip_data));
            }
        }
        EtherTypes::Ipv6 => {
            if Ipv6Packet::new(ip_data).is_some() {
                debug!("Parsed Ethernet IPv6 packet");
                return Some(IpPacket::Ipv6(ip_data));
            }
        }
        _ => {}
    }

    None
}

/// Try parsing as Raw IP (no datalink header)
fn try_raw_ip_format(packet: &[u8]) -> Option<IpPacket> {
    if packet.len() < 20 {
        return None;
    }

    // Check IP version in first 4 bits
    let version = (packet[0] & 0xF0) >> 4;
    match version {
        4 => {
            if Ipv4Packet::new(packet).is_some() {
                debug!("Parsed Raw IPv4 packet");
                return Some(IpPacket::Ipv4(packet));
            }
        }
        6 => {
            if Ipv6Packet::new(packet).is_some() {
                debug!("Parsed Raw IPv6 packet");
                return Some(IpPacket::Ipv6(packet));
            }
        }
        _ => {}
    }

    None
}

/// Try parsing as NULL datalink format (4-byte header)
fn try_null_datalink_format(packet: &[u8]) -> Option<IpPacket> {
    // Check for NULL datalink signature and minimum size
    if packet.len() < 24 || packet[0] != 0x1e || packet[1] != 0x00 {
        return None;
    }

    let ip_data = &packet[4..]; // Skip 4-byte NULL header
    let version = (ip_data[0] & 0xF0) >> 4;

    match version {
        4 => {
            if Ipv4Packet::new(ip_data).is_some() {
                debug!("Parsed NULL datalink IPv4 packet");
                return Some(IpPacket::Ipv4(ip_data));
            }
        }
        6 => {
            if Ipv6Packet::new(ip_data).is_some() {
                debug!("Parsed NULL datalink IPv6 packet");
                return Some(IpPacket::Ipv6(ip_data));
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
    // Check Ethernet
    if EthernetPacket::new(packet).is_some() {
        return Some(DatalinkFormat::Ethernet);
    }

    // Check NULL datalink
    if packet.len() >= 24 && packet[0] == 0x1e && packet[1] == 0x00 {
        let ip_data = &packet[4..];
        let version = (ip_data[0] & 0xF0) >> 4;
        if version == 4 || version == 6 {
            return Some(DatalinkFormat::Null);
        }
    }

    // Check Raw IP
    if packet.len() >= 20 {
        let version = (packet[0] & 0xF0) >> 4;
        if version == 4 || version == 6 {
            return Some(DatalinkFormat::RawIp);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_null_datalink() {
        let null_packet = vec![0x1e, 0x00, 0x00, 0x00, 0x60, 0x02]; // NULL + IPv6 start
        let format = detect_datalink_format(&null_packet);
        assert_eq!(format, Some(DatalinkFormat::Null));
    }

    #[test]
    fn test_detect_raw_ipv4() {
        let raw_ipv4 = vec![0x45, 0x00, 0x00, 0x1c]; // IPv4 header start
        let format = detect_datalink_format(&raw_ipv4);
        assert_eq!(format, Some(DatalinkFormat::RawIp));
    }

    #[test]
    fn test_detect_raw_ipv6() {
        let raw_ipv6 = vec![0x60, 0x00, 0x00, 0x00]; // IPv6 header start
        let format = detect_datalink_format(&raw_ipv6);
        assert_eq!(format, Some(DatalinkFormat::RawIp));
    }
}
