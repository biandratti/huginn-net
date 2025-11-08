use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Hashes the source IP from a packet for worker assignment.
///
/// Parses the IP header to extract source IP and returns its hash.
/// This ensures packets from the same source always go to the same worker,
/// maintaining connection state consistency.
pub fn hash_source_ip(packet: &[u8]) -> usize {
    // Skip Ethernet header (14 bytes) if present
    // Both IPv4 (0x0800) and IPv6 (0x86DD) use same offset
    let ip_start: usize = if packet.len() > 14
        && ((packet[12] == 0x08 && packet[13] == 0x00)
            || (packet[12] == 0x86 && packet[13] == 0xDD))
    {
        14
    } else {
        0 // Raw IP packet
    };

    let min_length = ip_start.saturating_add(20);
    if packet.len() < min_length {
        // Packet too short, use fallback hash
        return fallback_hash(packet);
    }

    let ip_packet = &packet[ip_start..];
    let version = (ip_packet[0] >> 4) & 0x0F;

    match version {
        4 => {
            // IPv4: source IP at bytes 12-15
            if ip_packet.len() >= 16 {
                let src_ip = &ip_packet[12..16];
                hash_bytes(src_ip)
            } else {
                fallback_hash(packet)
            }
        }
        6 => {
            // IPv6: source IP at bytes 8-23
            if ip_packet.len() >= 24 {
                let src_ip = &ip_packet[8..24];
                hash_bytes(src_ip)
            } else {
                fallback_hash(packet)
            }
        }
        _ => fallback_hash(packet),
    }
}

/// Hashes a byte slice using DefaultHasher.
fn hash_bytes(bytes: &[u8]) -> usize {
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish() as usize
}

/// Fallback hash for invalid packets.
///
/// Used when a packet is too short, malformed, or has an unknown IP version.
/// Instead of discarding the packet or crashing, we hash the entire packet contents
/// to distribute it to a worker. This sacrifices per-connection state consistency
/// for that specific packet, but ensures robustness in production environments
/// with corrupted traffic, fragmentation issues, or malicious crafted packets.
///
/// Note: This is specific to TCP's hash-based routing.
fn fallback_hash(packet: &[u8]) -> usize {
    hash_bytes(packet)
}
