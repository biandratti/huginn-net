use super::config::FilterConfig;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::debug;

/// Apply raw filter check on raw packet bytes
///
/// Extracts only IPs and ports without creating full packet structures.
/// This is much faster than parsing the entire packet first.
///
/// # Returns
///
/// - `true`: Packet should be processed (passed filter or no filter)
/// - `false`: Packet should be dropped (failed filter)
pub fn apply(packet: &[u8], filter: &FilterConfig) -> bool {
    if let Some((src_ip, dst_ip, src_port, dst_port)) = extract_quick_info(packet) {
        filter.should_process(&src_ip, &dst_ip, src_port, dst_port)
    } else {
        debug!("Could not extract quick info from packet");
        true
    }
}

/// Extract IPs and ports without full parsing
///
/// Tries multiple datalink formats (Ethernet, Raw IP, NULL) to find IP header.
/// Only extracts the minimum fields needed for filtering.
fn extract_quick_info(packet: &[u8]) -> Option<(IpAddr, IpAddr, u16, u16)> {
    if let Some(info) = try_ethernet(packet) {
        return Some(info);
    }
    if let Some(info) = try_raw_ip(packet) {
        return Some(info);
    }
    if let Some(info) = try_null_datalink(packet) {
        return Some(info);
    }
    None
}

fn try_ethernet(packet: &[u8]) -> Option<(IpAddr, IpAddr, u16, u16)> {
    if packet.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([packet[12], packet[13]]);
    match ethertype {
        0x0800 => extract_ipv4_info(&packet[14..]),
        0x86DD => extract_ipv6_info(&packet[14..]),
        _ => None,
    }
}

fn try_raw_ip(packet: &[u8]) -> Option<(IpAddr, IpAddr, u16, u16)> {
    if packet.is_empty() {
        return None;
    }
    let version = packet[0] >> 4;
    match version {
        4 => extract_ipv4_info(packet),
        6 => extract_ipv6_info(packet),
        _ => None,
    }
}

fn try_null_datalink(packet: &[u8]) -> Option<(IpAddr, IpAddr, u16, u16)> {
    if packet.len() < 4 {
        return None;
    }
    let family = u32::from_ne_bytes([packet[0], packet[1], packet[2], packet[3]]);
    match family {
        2 => extract_ipv4_info(&packet[4..]),
        30 | 28 => extract_ipv6_info(&packet[4..]),
        _ => None,
    }
}

fn extract_ipv4_info(packet: &[u8]) -> Option<(IpAddr, IpAddr, u16, u16)> {
    if packet.len() < 20 {
        return None;
    }
    if packet[9] != 6 {
        return None;
    }
    let src_ip = IpAddr::V4(Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]));
    let ihl = (packet[0] & 0x0F) as usize;
    if ihl < 5 {
        return None;
    }
    let ip_header_len = ihl.saturating_mul(4);
    let tcp_offset = ip_header_len;
    if packet.len() < tcp_offset.saturating_add(4) {
        return None;
    }
    let src_port = u16::from_be_bytes([packet[tcp_offset], packet[tcp_offset.saturating_add(1)]]);
    let dst_port = u16::from_be_bytes([
        packet[tcp_offset.saturating_add(2)],
        packet[tcp_offset.saturating_add(3)],
    ]);
    Some((src_ip, dst_ip, src_port, dst_port))
}

fn extract_ipv6_info(packet: &[u8]) -> Option<(IpAddr, IpAddr, u16, u16)> {
    if packet.len() < 40 {
        return None;
    }
    if packet[6] != 6 {
        return None;
    }
    let src_ip = IpAddr::V6(Ipv6Addr::new(
        u16::from_be_bytes([packet[8], packet[9]]),
        u16::from_be_bytes([packet[10], packet[11]]),
        u16::from_be_bytes([packet[12], packet[13]]),
        u16::from_be_bytes([packet[14], packet[15]]),
        u16::from_be_bytes([packet[16], packet[17]]),
        u16::from_be_bytes([packet[18], packet[19]]),
        u16::from_be_bytes([packet[20], packet[21]]),
        u16::from_be_bytes([packet[22], packet[23]]),
    ));
    let dst_ip = IpAddr::V6(Ipv6Addr::new(
        u16::from_be_bytes([packet[24], packet[25]]),
        u16::from_be_bytes([packet[26], packet[27]]),
        u16::from_be_bytes([packet[28], packet[29]]),
        u16::from_be_bytes([packet[30], packet[31]]),
        u16::from_be_bytes([packet[32], packet[33]]),
        u16::from_be_bytes([packet[34], packet[35]]),
        u16::from_be_bytes([packet[36], packet[37]]),
        u16::from_be_bytes([packet[38], packet[39]]),
    ));
    if packet.len() < 44 {
        return None;
    }
    let src_port = u16::from_be_bytes([packet[40], packet[41]]);
    let dst_port = u16::from_be_bytes([packet[42], packet[43]]);
    Some((src_ip, dst_ip, src_port, dst_port))
}
