use pnet::packet::tcp::TcpFlags::SYN;
use pnet::packet::tcp::TcpPacket;

fn is_client(tcp: &TcpPacket) -> bool {
    tcp.get_flags() & SYN == SYN
}

pub fn extract_from_ipv4(tcp: &TcpPacket, ipv4_header_len: u8, mss:u16) -> Option<u16> {
    if is_client(tcp) {
        let tcp_header_len = (tcp.get_data_offset() * 4) as u16;
        let ip_header_len = (ipv4_header_len * 4) as u16;
        // MTU = MSS + IPv4 Header Length + TCP Header Length
        Some(mss + ip_header_len + tcp_header_len)
    } else {
        None
    }
}

pub fn extract_from_ipv6(tcp: &TcpPacket, ipv6_header_len: u8, mss:u16) -> Option<u16> {
    if is_client(tcp) {
        let tcp_header_len = (tcp.get_data_offset() * 4) as u16;

        // MTU = MSS + IPv6 Header Length + TCP Header Length
        Some(mss + ipv6_header_len as u16 + tcp_header_len)
    } else {
        None
    }
}
