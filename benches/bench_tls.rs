use criterion::{criterion_group, criterion_main, Criterion};
use huginn_net_tls::{process_ipv4_packet, process_ipv6_packet};
use pcap_file::pcap::PcapReader;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use std::error::Error;
use std::fs::File;

criterion_group!(
    tls_benches,
    bench_tls_ja4_fingerprinting_tls12,
    bench_tls_ja4_fingerprinting_alpn_h2,
    bench_tls_packet_parsing_performance,
    bench_tls_ja4_calculation_overhead
);
criterion_main!(tls_benches);

fn load_packets_from_pcap(pcap_path: &str) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let file = File::open(pcap_path)?;
    let mut pcap_reader = PcapReader::new(file)?;
    let mut packets = Vec::new();
    while let Some(pkt) = pcap_reader.next_packet() {
        packets.push(pkt?.data.into());
    }
    Ok(packets)
}

/// Process a packet using the public TLS API
fn process_tls_packet(packet: &[u8]) -> Option<huginn_net_tls::TlsClientOutput> {
    match huginn_net_tls::packet_parser::parse_packet(packet) {
        huginn_net_tls::packet_parser::IpPacket::Ipv4(ip_data) => {
            if let Some(ipv4) = Ipv4Packet::new(ip_data) {
                process_ipv4_packet(&ipv4).ok().flatten()
            } else {
                None
            }
        }
        huginn_net_tls::packet_parser::IpPacket::Ipv6(ip_data) => {
            if let Some(ipv6) = Ipv6Packet::new(ip_data) {
                process_ipv6_packet(&ipv6).ok().flatten()
            } else {
                None
            }
        }
        huginn_net_tls::packet_parser::IpPacket::None => None,
    }
}

/// Benchmark TLS JA4 fingerprinting using TLS 1.2 PCAP
fn bench_tls_ja4_fingerprinting_tls12(c: &mut Criterion) {
    let packets = match load_packets_from_pcap("../pcap/tls12.pcap") {
        Ok(pkts) => pkts,
        Err(e) => {
            eprintln!("Failed to load TLS 1.2 PCAP file: {e}");
            return;
        }
    };

    if packets.is_empty() {
        eprintln!("No packets found in TLS 1.2 PCAP file");
        return;
    }

    println!("TLS 1.2 PCAP Analysis:");
    println!("  Total packets: {}", packets.len());

    // Count TLS packets for analysis
    let mut tls_packet_count = 0;

    for packet in &packets {
        if process_tls_packet(packet).is_some() {
            tls_packet_count += 1;
        }
    }

    println!("  TLS packets found: {}", tls_packet_count);
    println!("--------------------");

    let mut group = c.benchmark_group("TLS_JA4_TLS12");

    // Benchmark TLS processing
    group.bench_function("tls_processing", |b| {
        b.iter(|| {
            for packet in packets.iter() {
                let _ = process_tls_packet(packet);
            }
        })
    });

    // Benchmark TLS packet parsing only (without full analysis)
    group.bench_function("tls_packet_parsing", |b| {
        b.iter(|| {
            for packet in packets.iter() {
                // Just parse the packet structure without full analysis
                let _ = huginn_net_tls::packet_parser::parse_packet(packet);
            }
        })
    });

    group.finish();
}

/// Benchmark TLS JA4 fingerprinting using TLS ALPN H2 PCAP
fn bench_tls_ja4_fingerprinting_alpn_h2(c: &mut Criterion) {
    let packets = match load_packets_from_pcap("../pcap/tls-alpn-h2.pcap") {
        Ok(pkts) => pkts,
        Err(e) => {
            eprintln!("Failed to load TLS ALPN H2 PCAP file: {e}");
            return;
        }
    };

    if packets.is_empty() {
        eprintln!("No packets found in TLS ALPN H2 PCAP file");
        return;
    }

    println!("TLS ALPN H2 PCAP Analysis:");
    println!("  Total packets: {}", packets.len());

    // Count TLS packets for analysis
    let mut tls_packet_count = 0;

    for packet in &packets {
        if process_tls_packet(packet).is_some() {
            tls_packet_count += 1;
        }
    }

    println!("  TLS packets found: {}", tls_packet_count);
    println!("--------------------");

    let mut group = c.benchmark_group("TLS_JA4_ALPN_H2");

    // Benchmark TLS processing
    group.bench_function("tls_processing", |b| {
        b.iter(|| {
            for packet in packets.iter() {
                let _ = process_tls_packet(packet);
            }
        })
    });

    // Benchmark with TLS extensions analysis
    group.bench_function("tls_extensions_analysis", |b| {
        b.iter(|| {
            for packet in packets.iter() {
                if let Some(result) = process_tls_packet(packet) {
                    // Access JA4 fingerprint to ensure full processing
                    let _ = &result.sig.ja4.full;
                    let _ = &result.sig.ja4.raw;
                }
            }
        })
    });

    group.finish();
}

/// Benchmark TLS packet parsing performance without JA4 calculation
fn bench_tls_packet_parsing_performance(c: &mut Criterion) {
    let packets = match load_packets_from_pcap("../pcap/tls12.pcap") {
        Ok(pkts) => pkts,
        Err(e) => {
            eprintln!("Failed to load TLS PCAP file: {e}");
            return;
        }
    };

    if packets.is_empty() {
        eprintln!("No packets found in TLS PCAP file");
        return;
    }

    println!("TLS Packet Parsing Performance:");
    println!("  Total packets: {}", packets.len());

    // Count TLS packets for analysis
    let mut tls_packet_count = 0;

    for packet in &packets {
        if process_tls_packet(packet).is_some() {
            tls_packet_count += 1;
        }
    }

    println!("  TLS packets found: {}", tls_packet_count);
    println!("--------------------");

    let mut group = c.benchmark_group("TLS_Packet_Parsing");

    // Benchmark raw packet parsing (just structure, no fingerprinting)
    group.bench_function("raw_packet_parsing", |b| {
        b.iter(|| {
            for packet in packets.iter() {
                let _ = huginn_net_tls::packet_parser::parse_packet(packet);
            }
        })
    });

    // Benchmark full TLS processing with JA4 fingerprinting
    group.bench_function("full_tls_processing", |b| {
        b.iter(|| {
            for packet in packets.iter() {
                let _ = process_tls_packet(packet);
            }
        })
    });

    // Benchmark TLS processing with result extraction
    group.bench_function("tls_with_result_extraction", |b| {
        b.iter(|| {
            for packet in packets.iter() {
                if let Some(result) = process_tls_packet(packet) {
                    // Force evaluation of JA4 fingerprints
                    let _ = &result.sig.ja4.full;
                    let _ = &result.sig.ja4.raw;
                    let _ = &result.sig.version;
                }
            }
        })
    });

    group.finish();
}

/// Benchmark JA4 calculation overhead by comparing different processing levels
fn bench_tls_ja4_calculation_overhead(c: &mut Criterion) {
    let packets = match load_packets_from_pcap("../pcap/tls-alpn-h2.pcap") {
        Ok(pkts) => pkts,
        Err(e) => {
            eprintln!("Failed to load TLS ALPN H2 PCAP file: {e}");
            return;
        }
    };

    if packets.is_empty() {
        eprintln!("No packets found in TLS ALPN H2 PCAP file");
        return;
    }

    println!("JA4 Calculation Overhead Analysis:");
    println!("  Total packets: {}", packets.len());

    // Count TLS packets for analysis
    let mut tls_packet_count = 0;
    let mut ja4_count = 0;

    for packet in &packets {
        if let Some(_result) = process_tls_packet(packet) {
            tls_packet_count += 1;
            // JA4 is always generated if we have a TLS result
            ja4_count += 1;
        }
    }

    println!("  TLS packets found: {}", tls_packet_count);
    println!("  JA4 fingerprints generated: {}", ja4_count);
    println!("--------------------");

    let mut group = c.benchmark_group("TLS_JA4_Overhead");

    // Benchmark basic TLS processing
    group.bench_function("basic_tls_processing", |b| {
        b.iter(|| {
            for packet in packets.iter() {
                let _ = process_tls_packet(packet);
            }
        })
    });

    // Benchmark with JA4 fingerprint access (forces calculation)
    group.bench_function("ja4_fingerprint_access", |b| {
        b.iter(|| {
            for packet in packets.iter() {
                if let Some(result) = process_tls_packet(packet) {
                    // Access JA4 fingerprints to force calculation
                    let _ = result.sig.ja4.full.to_string();
                    let _ = result.sig.ja4.raw.to_string();
                }
            }
        })
    });

    // Benchmark with full result analysis
    group.bench_function("full_result_analysis", |b| {
        b.iter(|| {
            let mut results = Vec::new();

            for packet in packets.iter() {
                if let Some(result) = process_tls_packet(packet) {
                    // Collect all TLS information
                    results.push((
                        result.sig.version,
                        result.sig.ja4.full.clone(),
                        result.sig.ja4.raw.clone(),
                        result.source,
                        result.destination,
                    ));
                }
            }

            // Process results to simulate real-world usage
            let _ = results.len();
        })
    });

    group.finish();
}
