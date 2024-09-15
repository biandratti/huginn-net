mod fingerprint_http;
use clap::Parser;
use fingerprint_http::handle_ethernet_packet;
use pnet::datalink::{self, Channel::Ethernet, Config, NetworkInterface};
use pnet::packet::ethernet::EthernetPacket;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    interface: String,
}

fn main() {
    let args = Args::parse();
    let interface_name = args.interface;
    let interfaces: Vec<NetworkInterface> = datalink::interfaces();

    let interface: NetworkInterface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Could not find the interface");

    let config = Config {
        promiscuous: true,
        ..Config::default()
    };

    let (mut _tx, mut rx) = match datalink::channel(&interface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Unable to create channel: {}", e),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                let ethernet_packet = EthernetPacket::new(packet).unwrap();
                handle_ethernet_packet(ethernet_packet);
            }
            Err(e) => eprintln!("Failed to read: {}", e),
        }
    }
}
