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
            (ihl - 5) * 4 // Convert words to bytes
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
                    (payload[1] as usize + 1) * 8
                } else {
                    0
                }
            }
        };

        len as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_options_length() {
        let mut data = vec![0u8; 24];
        data[0] = 0x46; // Version 4, IHL 6
        let packet = Ipv4Packet::new(&data).unwrap();

        assert_eq!(IpOptions::calculate_ipv4_length(&packet), 4);
    }

    #[test]
    fn test_ipv6_direct_tcp() {
        let mut data = vec![0u8; 40];
        data[0] = 0x60; // Version 6
        data[6] = IpNextHeaderProtocols::Tcp.0; // Next Header = TCP

        let packet = Ipv6Packet::new(&data).unwrap();
        assert_eq!(IpOptions::calculate_ipv6_length(&packet), 0);
    }

    #[test]
    fn test_ipv6_fragment() {
        let mut data = vec![0u8; 48];
        data[0] = 0x60; // Version 6
        data[6] = IpNextHeaderProtocols::Ipv6Frag.0; // Next Header = Fragment
        data[4] = 0; // Length high byte
        data[5] = 8; // Length low byte
        data[40] = IpNextHeaderProtocols::Tcp.0; // Next Header = TCP

        let packet = Ipv6Packet::new(&data).unwrap();
        assert_eq!(IpOptions::calculate_ipv6_length(&packet), 8);
    }
}
