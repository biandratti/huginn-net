use pnet::packet::{ipv6::Ipv6Packet, tcp::TcpPacket, Packet};
use regex::Regex;
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
    let user_agent = extract_user_agent(headers).unwrap_or("Unknown".to_string());
    let os = detect_os_from_user_agent(&user_agent);
    println!(
        ".-[ {}/{} -> {}/{} ]-",
        client_ip, client_port, server_ip, server_port
    );
    println!("|");
    println!("| client   = {}/{}", client_ip, client_port);
    println!("| headers  = {}", headers);
    println!("| raw_sig  = {}", extract_raw_signature(headers));
    println!("| os  = {}", os);
    println!("|");
    println!("`----");
}

fn extract_raw_signature(headers: &str) -> String {
    headers.to_string()
}

fn extract_user_agent(payload: &str) -> Option<String> {
    // Basic regex to find User-Agent
    let re = Regex::new(r"(?i)User-Agent: (.+)").unwrap();
    re.captures(payload).map(|caps| {
        caps.get(1)
            .map_or("Unknown".to_string(), |m| m.as_str().to_string())
    })
}

fn detect_os_from_user_agent(user_agent: &str) -> String {
    // Define patterns and corresponding OS names
    let os_patterns = vec![
        (r"Windows NT 10\.0", "Windows 10"),
        (r"Windows NT 6\.3", "Windows 8.1"),
        (r"Macintosh; Intel Mac OS X", "Mac OS X"),
        (r"Android", "Android"),
        (r"Linux", "Linux"),
        // Add more patterns as needed
    ];

    for (pattern, os_name) in os_patterns {
        if user_agent.contains(pattern) {
            return os_name.to_string();
        }
    }

    "Unknown".to_string()
}
