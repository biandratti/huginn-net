use clap::Parser;
use log::debug;
use passivetcp::{db::Database, P0f};
use pnet::datalink::{self, Config, NetworkInterface};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    interface: String,
}

fn start_capture(interface_name: &str, p0f: &P0f) {
    let interfaces: Vec<NetworkInterface> = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Could not find the interface");

    let config = Config {
        promiscuous: true,
        ..Config::default()
    };

    let (_tx, mut rx) = match datalink::channel(&interface, config) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Unable to create channel: {}", e),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                let p0f_output = p0f.analyze_tcp(packet);
                //p0f_output.syn_ack.map(|syn_ack| println!("{}", syn_ack));
                //p0f_output.mtu.map(|mtu| println!("{}", mtu));
                p0f_output.uptime.map(|uptime| println!("{}", uptime));
            }
            Err(e) => eprintln!("Failed to read packet: {}", e),
        }
    }
}

fn main() {
    let args = Args::parse();
    let interface_name = args.interface;

    let db = Database::default();
    debug!("Loaded database: {:?}", db);

    let p0f = P0f::new(&db);
    start_capture(&interface_name, &p0f);
}
