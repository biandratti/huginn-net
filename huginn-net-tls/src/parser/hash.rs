//! Packet hashing utilities for worker assignment in parallel processing.
//!
//! This module provides flow-based hashing for TLS traffic, ensuring that all packets
//! from the same flow (src_ip, dst_ip, src_port, dst_port) are consistently routed to
//! the same worker thread for proper TCP reassembly and ClientHello parsing.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Computes worker assignment based on TLS flow hash.
///
/// Hashes the complete flow (src_ip, dst_ip, src_port, dst_port) to ensure
/// all packets from the same connection go to the same worker for proper
/// TCP reassembly and ClientHello parsing.
///
/// Returns `None` if the packet is too malformed to extract a flow.
pub fn hash_flow(packet: &[u8], num_workers: usize) -> Option<usize> {
    // Skip Ethernet header (14 bytes) if present
    let ip_start: usize = if packet.len() > 14
        && ((packet[12] == 0x08 && packet[13] == 0x00)
            || (packet[12] == 0x86 && packet[13] == 0xDD))
    {
        14
    } else {
        0 // Raw IP packet
    };

    let min_length = ip_start.saturating_add(40); // IP header + TCP header minimum
    if packet.len() < min_length {
        // Packet too short to extract flow, discard it
        return None;
    }

    let ip_packet = &packet[ip_start..];
    let version = (ip_packet[0] >> 4) & 0x0F;

    match version {
        4 => hash_ipv4_flow(ip_packet, num_workers),
        6 => hash_ipv6_flow(ip_packet, num_workers),
        _ => None, // Unknown IP version, discard
    }
}

/// Hashes IPv4 flow (src_ip, dst_ip, src_port, dst_port).
fn hash_ipv4_flow(ip_packet: &[u8], num_workers: usize) -> Option<usize> {
    if ip_packet.len() < 20 {
        // Packet too short, discard
        return None;
    }

    // Check if protocol is TCP (6)
    let protocol = ip_packet[9];
    if protocol != 6 {
        // Not TCP, discard (TLS requires TCP)
        return None;
    }

    // IPv4 header is variable length (IHL field)
    let ihl = (ip_packet[0] & 0x0F) as usize;
    let ip_header_len = ihl.saturating_mul(4);

    if ip_packet.len() < ip_header_len.saturating_add(4) {
        // TCP header not fully present, discard
        return None;
    }

    // Extract: src_ip, dst_ip, src_port, dst_port
    let src_ip = &ip_packet[12..16];
    let dst_ip = &ip_packet[16..20];
    let tcp_header = &ip_packet[ip_header_len..];
    let src_port = u16::from_be_bytes([tcp_header[0], tcp_header[1]]);
    let dst_port = u16::from_be_bytes([tcp_header[2], tcp_header[3]]);

    let mut hasher = DefaultHasher::new();
    src_ip.hash(&mut hasher);
    dst_ip.hash(&mut hasher);
    src_port.hash(&mut hasher);
    dst_port.hash(&mut hasher);

    Some(
        (hasher.finish() as usize)
            .checked_rem(num_workers)
            .unwrap_or(0),
    )
}

/// Hashes IPv6 flow (src_ip, dst_ip, src_port, dst_port).
fn hash_ipv6_flow(ip_packet: &[u8], num_workers: usize) -> Option<usize> {
    if ip_packet.len() < 40 {
        // Packet too short, discard
        return None;
    }

    // Check if next header is TCP (6)
    let next_header = ip_packet[6];
    if next_header != 6 {
        // Not TCP, discard (TLS requires TCP)
        return None;
    }

    if ip_packet.len() < 44 {
        // TCP header not fully present, discard
        return None;
    }

    // Extract: src_ip, dst_ip, src_port, dst_port
    let src_ip = &ip_packet[8..24];
    let dst_ip = &ip_packet[24..40];
    let tcp_header = &ip_packet[40..];
    let src_port = u16::from_be_bytes([tcp_header[0], tcp_header[1]]);
    let dst_port = u16::from_be_bytes([tcp_header[2], tcp_header[3]]);

    let mut hasher = DefaultHasher::new();
    src_ip.hash(&mut hasher);
    dst_ip.hash(&mut hasher);
    src_port.hash(&mut hasher);
    dst_port.hash(&mut hasher);

    Some(
        (hasher.finish() as usize)
            .checked_rem(num_workers)
            .unwrap_or(0),
    )
}
