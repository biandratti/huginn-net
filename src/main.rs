mod packet;
mod http;
mod parse;
mod tcp;
mod db;
mod display;

use clap::Parser;
use log::{debug, info, warn};
use tcp::Signature;
use pnet::datalink::{self, Channel::Ethernet, Config, NetworkInterface};
use pnet::packet::ethernet::EthernetPacket;
use crate::db::Database;

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

    let db = Database::default();
    println!("Loaded database: {:?}", db);

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
                match Signature::extract(packet) {
                    Ok(signature) => {
                        println!("{}",signature);
                    }
                    Err(e) => debug!("Failed to extract signature: {}", e),
                };
            }
            Err(e) => eprintln!("Failed to read: {}", e),
        }
    }
}


#[derive(Clone, Debug, PartialEq)]
pub struct Label {
    pub ty: Type,
    pub class: Option<String>,
    pub name: String,
    pub flavor: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Type {
    Specified,
    Generic,
}