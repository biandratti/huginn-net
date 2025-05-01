use criterion::{criterion_group, criterion_main, Criterion};
use passivetcp_rs::db::Database;
use passivetcp_rs::P0f;
use pcap_file::pcap::PcapReader;
use std::fs::File;

fn load_packets_from_pcap(path: &str) -> Vec<Vec<u8>> {
    let file = File::open(path).expect(
        "Error: The file 'dump.pca' was not found. \
        Please make sure the file exists in the current directory or provide the correct path.",
    );
    let mut reader = PcapReader::new(file).expect("Failed to create pcap reader");
    let mut packets = Vec::new();

    while let Some(Ok(pkt)) = reader.next_packet() {
        packets.push(pkt.data.to_vec());
    }
    packets
}

// To run the benchmark, you need to have the dump.pca file in your home directory.
fn bench_analyze_tcp_on_pcap(c: &mut Criterion) {
    let db = Box::leak(Box::new(Database::default()));
    let mut p0f = P0f::new(db, 100);

    let packets = load_packets_from_pcap("~/dump.pca");

    let mut syn_count = 0;
    let mut syn_ack_count = 0;
    let mut mtu_count = 0;
    let mut uptime_count = 0;
    let mut http_request_count = 0;
    let mut http_response_count = 0;

    for pkt in &packets {
        let output = p0f.analyze_tcp(pkt);
        if output.syn.is_some() {
            syn_count += 1;
        }
        if output.syn_ack.is_some() {
            syn_ack_count += 1;
        }
        if output.mtu.is_some() {
            mtu_count += 1;
        }
        if output.uptime.is_some() {
            uptime_count += 1;
        }
        if output.http_request.is_some() {
            http_request_count += 1;
        }
        if output.http_response.is_some() {
            http_response_count += 1;
        }
    }

    println!("Packages to analyze:");
    println!("  SYN:           {}", syn_count);
    println!("  SYN-ACK:       {}", syn_ack_count);
    println!("  MTU:           {}", mtu_count);
    println!("  Uptime:        {}", uptime_count);
    println!("  HTTP Request:  {}", http_request_count);
    println!("  HTTP Response: {}", http_response_count);

    let mut group = c.benchmark_group("analyze_tcp_on_pcap");
    group.sample_size(100);
    group.measurement_time(std::time::Duration::from_secs(60));
    group.bench_function("analyze_tcp_on_pcap", |b| {
        b.iter(|| {
            for (_i, pkt) in packets.iter().enumerate() {
                let _ = p0f.analyze_tcp(pkt);
            }
        })
    });
    group.finish();
}

criterion_group!(benches, bench_analyze_tcp_on_pcap);
criterion_main!(benches);
