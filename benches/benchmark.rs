mod bench_tls;

use criterion::{criterion_group, criterion_main, Criterion};
use huginn_net::{Database, HuginnNet};
use pcap_file::pcap::PcapReader;
use std::error::Error;
use std::fs::File;

criterion_group!(benches, bench_analyze_tcp_on_pcap);
criterion_main!(benches);

fn load_packets_from_pcap(pcap_path: &str) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let file = File::open(pcap_path)?;
    let mut pcap_reader = PcapReader::new(file)?;
    let mut packets = Vec::new();
    while let Some(pkt) = pcap_reader.next_packet() {
        packets.push(pkt?.data.into());
    }
    Ok(packets)
}

// Before running the benchmark, you need to create the dump.pca file with tcpdump from the following command:
// ```sh
// sudo tcpdump -w dump.pca
// ```
// Then to run the test, you need to have the dump.pca file in your home directory.
fn bench_analyze_tcp_on_pcap(c: &mut Criterion) {
    let packets = match load_packets_from_pcap("dump.pca") {
        Ok(pkts) => pkts,
        Err(e) => {
            eprintln!("Failed to load pcap file: {e}");
            return;
        }
    };

    let (
        syn_count,
        syn_ack_count,
        mtu_count,
        uptime_count,
        http_request_count,
        http_response_count,
    ) = {
        let mut syn_count: u64 = 0;
        let mut syn_ack_count: u64 = 0;
        let mut mtu_count: u64 = 0;
        let mut uptime_count: u64 = 0;
        let mut http_request_count: u64 = 0;
        let mut http_response_count: u64 = 0;

        let db = match Database::load_default() {
            Ok(db) => db,
            Err(e) => {
                eprintln!("Failed to load default database: {e}");
                return;
            }
        };
        let mut huginn_net = match HuginnNet::new(Some(&db), 1000, None) {
            Ok(analyzer) => analyzer,
            Err(e) => {
                eprintln!("Failed to create HuginnNet analyzer: {e}");
                return;
            }
        };

        // Process each packet
        for packet in &packets {
            let result = huginn_net.analyze_tcp(packet);
            if result.syn.is_some() {
                syn_count = syn_count.saturating_add(1);
            }
            if result.syn_ack.is_some() {
                syn_ack_count = syn_ack_count.saturating_add(1);
            }
            if result.mtu.is_some() {
                mtu_count = mtu_count.saturating_add(1);
            }
            if result.uptime.is_some() {
                uptime_count = uptime_count.saturating_add(1);
            }
            if result.http_request.is_some() {
                http_request_count = http_request_count.saturating_add(1);
            }
            if result.http_response.is_some() {
                http_response_count = http_response_count.saturating_add(1);
            }
        }

        (
            syn_count,
            syn_ack_count,
            mtu_count,
            uptime_count,
            http_request_count,
            http_response_count,
        )
    };

    println!("Packages to analyze:");
    println!("  SYN: {syn_count}");
    println!("  SYN/ACK: {syn_ack_count}");
    println!("  MTU: {mtu_count}");
    println!("  Uptime: {uptime_count}");
    println!("  HTTP Request: {http_request_count}");
    println!("  HTTP Response: {http_response_count}");
    println!("--------------------");

    let db = match Database::load_default() {
        Ok(db) => db,
        Err(e) => {
            eprintln!("Failed to load default database: {e}");
            return;
        }
    };
    let mut huginn_net = match HuginnNet::new(Some(&db), 1000, None) {
        Ok(analyzer) => analyzer,
        Err(e) => {
            eprintln!("Failed to create HuginnNet analyzer: {e}");
            return;
        }
    };

    c.bench_function("analyze_tcp_pcap", |b| {
        b.iter(|| {
            for pkt in packets.iter() {
                let _ = huginn_net.analyze_tcp(pkt);
            }
        })
    });
}
