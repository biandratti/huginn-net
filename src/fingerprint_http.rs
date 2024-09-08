use pnet::packet::{ipv6::Ipv6Packet, tcp::TcpPacket, Packet};
use std::net::Ipv6Addr;

pub fn process_packet(packet: &[u8]) {
    if let Some(ipv6_packet) = Ipv6Packet::new(packet) {
        let client_ip = ipv6_packet.get_source();
        let server_ip = ipv6_packet.get_destination();

        if let Some(tcp_packet) = TcpPacket::new(ipv6_packet.payload()) {
            let client_port = tcp_packet.get_source();
            let server_port = tcp_packet.get_destination();
            let payload = tcp_packet.payload();

            process_http_payload(payload, client_ip, client_port, server_ip, server_port);
        }
    }
}

fn process_http_payload(
    payload: &[u8],
    client_ip: Ipv6Addr,
    client_port: u16,
    server_ip: Ipv6Addr,
    server_port: u16,
) {
    let payload_str = match std::str::from_utf8(payload) {
        Ok(v) => v,
        Err(_) => return, // Not valid UTF-8, skip processing
    };
    log_http_signature(client_ip, client_port, server_ip, server_port, payload_str);
}

fn log_http_signature(
    client_ip: Ipv6Addr,
    client_port: u16,
    server_ip: Ipv6Addr,
    server_port: u16,
    headers: &str,
) {
    println!(
        ".-[ {}/{} -> {}/{} ]-",
        client_ip, client_port, server_ip, server_port
    );
    println!("|");
    println!("| client   = {}/{}", client_ip, client_port);
    println!("| headers  = {}", headers);
    println!("| raw_sig  = {}", extract_raw_signature(headers));
    println!("|");
    println!("`----");
}

fn extract_raw_signature(headers: &str) -> String {
    headers.to_string()
}
