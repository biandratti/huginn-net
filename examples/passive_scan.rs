use passivetcp::{Database, P0fOutput, SignatureDetails, SignatureMatcher};
use pnet::datalink::{self, Config, Channel::Ethernet};

fn main() {
    let db = Database::default();
    let matcher = SignatureMatcher::new(&db);

    let interface_name = "eth0";
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Could not find the interface");

    let config = Config {
        promiscuous: true,
        ..Config::default()
    };

    // Set up the datalink channel
    let (_tx, mut rx) = match datalink::channel(&interface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Unable to create channel: {}", e),
    };

    // Listen for packets and print passive scan output
    loop {
        match rx.next() {
            Ok(packet) => {
                if let Ok(signature_details) = SignatureDetails::extract(packet) {
                    if let Some((label, _)) = matcher.find_matching_signature(&signature_details.signature) {
                        let output = P0fOutput {
                            client: signature_details.client,
                            server: signature_details.server,
                            is_client: signature_details.is_client,
                            label: Some(label.clone()),
                            sig: signature_details.signature,
                        };
                        println!("{}", output);
                    }
                }
            }
            Err(e) => eprintln!("Failed to read packet: {}", e),
        }
    }
}