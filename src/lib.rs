// src/lib.rs

pub mod db;
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
use pnet::datalink::{self, Config, NetworkInterface};
use crate::signature_matcher::SignatureMatcher;
use log::debug;

/// Main struct for the passive TCP fingerprinting library.
pub struct PassiveTcpFingerprinter<'a> {
    matcher: SignatureMatcher<'a>,
}

impl<'a> PassiveTcpFingerprinter<'a> {
    // Constructor for PassiveTcpFingerprinter
    pub fn new(database: &'a Database) -> Self {
        let matcher = SignatureMatcher::new(database);
        Self { matcher } // Assuming Database implements Clone
    }


    //TODO: move loop to the example
    /// Starts capturing packets on the specified network interface.
    pub fn start_capture(&self, interface_name: &str) {
        let interfaces: Vec<NetworkInterface> = datalink::interfaces();
        let interface: NetworkInterface = interfaces
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
                    match SignatureDetails::extract(packet) {
                        Ok(signature_details) => {
                            if signature_details.signature.mss.is_some() {
                                if let Some((label, _matched_signature)) =
                                    self.matcher.find_matching_signature(&signature_details.signature)
                                {
                                    let p0f_output = P0fOutput {
                                        client: signature_details.client,
                                        server: signature_details.server,
                                        is_client: signature_details.is_client,
                                        label: Some(label.clone()),
                                        sig: signature_details.signature,
                                    };
                                    println!("{}", p0f_output)
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
}
