use passivetcp_rs::{
    db::Database, fingerprint_result::FingerprintResult, ja4_db::Ja4Database, PassiveTcp,
};
use std::str::FromStr;
use std::sync::mpsc;
use std::thread;
use tracing::{info, warn, Level};
use tracing_subscriber;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing with DEBUG level to see TLS parsing details
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();

    info!("Starting TLS JA4 fingerprinting example");

    // Load database
    let database_content = include_str!("../../../p0f.fp");
    let database = Database::from_str(database_content)?;

    info!(
        "Database loaded with {} TCP request signatures",
        database.tcp_request.entries.len()
    );

    // Load JA4 database
    let ja4_db = match Ja4Database::load_from_csv("ja4_signatures.csv") {
        Ok(db) => {
            info!("JA4 database loaded with {} signatures", db.len());
            Some(db)
        }
        Err(e) => {
            warn!("Failed to load JA4 database: {}. TLS fingerprints will not be matched to applications.", e);
            None
        }
    };

    // Create analyzer with or without JA4 database
    let mut analyzer = if let Some(ja4_db) = ja4_db {
        PassiveTcp::new_with_ja4(&database, 1000, ja4_db)
    } else {
        PassiveTcp::new(&database, 1000)
    };

    // Create channel for results with explicit type annotation
    let (sender, receiver) = mpsc::channel::<FingerprintResult>();

    // Spawn thread to handle results
    let handle = thread::spawn(move || {
        for result in receiver {
            // Print TCP analysis
            if let Some(syn) = &result.syn {
                println!("{}", syn);
            }
            if let Some(syn_ack) = &result.syn_ack {
                println!("{}", syn_ack);
            }

            // Print HTTP analysis
            if let Some(http_req) = &result.http_request {
                println!("{}", http_req);
            }
            if let Some(http_resp) = &result.http_response {
                println!("{}", http_resp);
            }

            // Print TLS analysis (JA4 fingerprinting)
            if let Some(tls) = &result.tls {
                println!("{}", tls);
                println!("JA4 Components:");
                println!("  JA4_a: {}", tls.sig.ja4.ja4_a);
                println!("  JA4_b: {}", tls.sig.ja4.ja4_b);
                println!("  JA4_c: {}", tls.sig.ja4.ja4_c);
                println!("  Full:  {}", tls.sig.ja4.ja4_full);
                println!("  Hash:  {}", tls.sig.ja4.ja4_hash);
            }

            // Print other analysis
            if let Some(mtu) = &result.mtu {
                println!("{}", mtu);
            }
            if let Some(uptime) = &result.uptime {
                println!("{}", uptime);
            }
        }
    });

    // Analyze network interface or PCAP file
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <interface_name_or_pcap_file>", args[0]);
        eprintln!("Examples:");
        eprintln!("  {} eth0", args[0]);
        eprintln!("  {} capture.pcap", args[0]);
        return Ok(());
    }

    let target = &args[1];

    if target.ends_with(".pcap") || target.ends_with(".pcapng") {
        info!("Analyzing PCAP file: {}", target);
        analyzer.analyze_pcap(target, sender)?;
    } else {
        info!("Analyzing network interface: {}", target);
        info!("Press Ctrl+C to stop...");
        analyzer.analyze_network(target, sender)?;
    }

    // Wait for the result handler thread
    handle.join().unwrap();

    Ok(())
}
