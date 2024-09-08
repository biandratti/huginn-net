extern crate pnet;

use pnet::datalink::{self, Channel::Ethernet, Config, NetworkInterface};
use pnet::packet::{ipv6::Ipv6Packet, tcp::TcpPacket, Packet};
use std::net::Ipv6Addr;

fn main() {
    println!("Program started");
    let interface_name = "wlp0s20f3";  // Your interface name here
    let interfaces: Vec<NetworkInterface> = datalink::interfaces();
    let interface: NetworkInterface = interfaces.into_iter()
        .filter(|iface| iface.name == interface_name)
        .next()
        .expect("Could not find the interface");

    let mut config = Config::default();
    config.promiscuous = true;  // Enable promiscuous mode

    // Open the channel
    let (mut _tx, mut rx) = match datalink::channel(&interface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Unable to create channel: {}", e),
    };

    // Loop to capture packets
    loop {
        match rx.next() {
            Ok(packet) => {
                process_packet(packet);
            }
            Err(_) => {
                eprintln!("Failed to capture packet");
            }
        }
    }
}

fn process_packet(packet: &[u8]) {
    if let Some(ipv6_packet) = Ipv6Packet::new(packet) {
        let client_ip = ipv6_packet.get_source();
        let server_ip = ipv6_packet.get_destination();

        // Extract TCP segment
        if let Some(tcp_packet) = TcpPacket::new(ipv6_packet.payload()) {
            let client_port = tcp_packet.get_source();
            let server_port = tcp_packet.get_destination();
            let payload = tcp_packet.payload();

            process_http_payload(payload, client_ip, client_port, server_ip, server_port);
        }
    }
}

// Function to process the HTTP payload and log relevant details
fn process_http_payload(payload: &[u8], client_ip: Ipv6Addr, client_port: u16, server_ip: Ipv6Addr, server_port: u16) {
    let payload_str = match std::str::from_utf8(payload) {
        Ok(v) => v,
        Err(_) => return, // Not valid UTF-8, skip processing
    };
    log_http_signature(client_ip, client_port, server_ip, server_port, payload_str);
}

fn log_http_signature(client_ip: Ipv6Addr, client_port: u16, server_ip: Ipv6Addr, server_port: u16, headers: &str) {
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

