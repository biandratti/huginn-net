mod db;
mod display;
mod http;
mod p0f_output;
mod packet;
mod parse;
mod signature_matcher;
mod tcp;

use crate::db::Database;
use crate::p0f_output::P0fOutput;
use crate::packet::SignatureDetails;
use crate::signature_matcher::SignatureMatcher;
use clap::Parser;
use log::debug;
use pnet::datalink::{self, Channel::Ethernet, Config, NetworkInterface};

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
    debug!("Loaded database: {:?}", db);
    let matcher = SignatureMatcher::new(&db);

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
                match SignatureDetails::extract(packet) {
                    //TODO: [WIP] Display output by type
                    Ok(signature_details) => {
                        if signature_details.signature.mss.is_some() {
                            if let Some((label, _matched_signature)) =
                                matcher.find_matching_signature(&signature_details.signature)
                            {
                                let p0f_output = P0fOutput {
                                    client: format!(
                                        "{}/{}",
                                        signature_details.client.ip, signature_details.client.port
                                    ),
                                    os: Some(label.name.clone()),
                                    raw_sig: signature_details.signature,
                                };
                                println!("{}", p0f_output)
                            } else {
                                println!("{}", signature_details.signature)
                            }
                        }
                    }
                    Err(e) => debug!("Failed to extract signature: {}", e),
                };
            }
            Err(e) => eprintln!("Failed to read: {}", e),
        }
    }
}
