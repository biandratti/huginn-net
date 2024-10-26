use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpFlags::SYN;
use pnet::packet::tcp::TcpPacket;


fn is_client(tcp: &TcpPacket) -> bool {
    tcp.get_flags() & SYN == SYN
}
pub fn extract_from_ipv4(tcp: &TcpPacket, ipv4: &Ipv4Packet) -> Option<u16> {
    if is_client(tcp) {
        let ip_len = ipv4.get_total_length();
        let tcp_header_len = (tcp.get_data_offset() * 4) as u16;
        Some(ip_len as u16 - (tcp_header_len + ipv4.get_header_length() as u16))
    } else {
        None
    }
}

pub fn extract_from_ipv6(tcp: &TcpPacket, ipv6: &Ipv6Packet) -> Option<u16> {
    if is_client(tcp) {
        let ipv6_payload_len = ipv6.get_payload_length();
        let ipv6_header_len = 40; // IPv6 header is always 40 bytes
        let tcp_header_len = (tcp.get_data_offset() * 4) as u16;

        Some((ipv6_payload_len + ipv6_header_len) as u16 - tcp_header_len)
    } else {
        None
    }
}