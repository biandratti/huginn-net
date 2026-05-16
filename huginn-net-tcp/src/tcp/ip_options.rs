use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;

pub struct IpOptions;
use pnet::packet::Packet;

/// Utility struct for handling IP header options and extension headers.
/// Provides methods to calculate the length of optional headers in both IPv4 and IPv6 packets.
impl IpOptions {
    pub fn calculate_ipv4_length(packet: &Ipv4Packet) -> u8 {
        // IHL (Internet Header Length) is in 32-bit words
        // Subtract minimum header length (20 bytes = 5 words)
        let ihl = packet.get_header_length();
        let options_length: u8 = if ihl > 5 {
            // convert words to bytes
            ihl.saturating_sub(5).saturating_mul(4)
        } else {
            0 // No options: standard header only
        };
        options_length
    }

    pub fn calculate_ipv6_length(packet: &Ipv6Packet) -> u8 {
        // Most packets will be direct TCP
        if packet.get_next_header() == IpNextHeaderProtocols::Tcp {
            return 0;
        }

        let payload = packet.payload();
        if payload.is_empty() {
            return 0;
        }

        let len = match packet.get_next_header() {
            IpNextHeaderProtocols::Ipv6Frag => 8,
            _ => {
                if payload.len() >= 2 {
                    let header_len = payload[1] as usize;
                    header_len
                        .checked_add(1)
                        .and_then(|sum| sum.checked_mul(8))
                        .unwrap_or(0)
                } else {
                    0
                }
            }
        };

        len as u8
    }
}
