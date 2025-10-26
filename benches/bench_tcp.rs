use criterion::{criterion_group, criterion_main, Criterion};
use huginn_net_db::Database;
use huginn_net_tcp::{
    process_ipv4_packet, process_ipv6_packet, ConnectionKey, SignatureMatcher, TcpTimestamp,
};
use pcap_file::pcap::PcapReader;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use std::error::Error;
use std::fs::File;
use ttl_cache::TtlCache;

criterion_group!(
    tcp_benches,
    bench_tcp_os_fingerprinting,
    bench_tcp_mtu_detection,
    bench_tcp_uptime_calculation,
    bench_tcp_processing_overhead
);
criterion_main!(tcp_benches);

fn load_packets_from_pcap(pcap_path: &str) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let file = File::open(pcap_path)?;
    let mut pcap_reader = PcapReader::new(file)?;
    let mut packets = Vec::new();
    while let Some(pkt) = pcap_reader.next_packet() {
        packets.push(pkt?.data.into());
    }
    Ok(packets)
}

/// Process a packet using the public TCP API
fn process_tcp_packet(
    packet: &[u8],
    connection_tracker: &mut TtlCache<ConnectionKey, TcpTimestamp>,
    matcher: Option<&SignatureMatcher>,
) -> Option<huginn_net_tcp::TcpAnalysisResult> {
    match huginn_net_tcp::packet_parser::parse_packet(packet) {
        huginn_net_tcp::packet_parser::IpPacket::Ipv4(ip_data) => {
            if let Some(ipv4) = Ipv4Packet::new(ip_data) {
                process_ipv4_packet(&ipv4, connection_tracker, matcher).ok()
            } else {
                None
            }
        }
        huginn_net_tcp::packet_parser::IpPacket::Ipv6(ip_data) => {
            if let Some(ipv6) = Ipv6Packet::new(ip_data) {
                process_ipv6_packet(&ipv6, connection_tracker, matcher).ok()
            } else {
                None
            }
        }
        huginn_net_tcp::packet_parser::IpPacket::None => None,
    }
}

/// Benchmark TCP OS fingerprinting using macOS TCP flags PCAP
fn bench_tcp_os_fingerprinting(c: &mut Criterion) {
    let packets = match load_packets_from_pcap("../pcap/macos_tcp_flags.pcap") {
        Ok(pkts) => pkts,
        Err(e) => {
            eprintln!("Failed to load macOS TCP flags PCAP file: {e}");
            return;
        }
    };

    if packets.is_empty() {
        eprintln!("No packets found in macOS TCP flags PCAP file");
        return;
    }

    let db = match Database::load_default() {
        Ok(db) => db,
        Err(e) => {
            eprintln!("Failed to load default database: {e}");
            return;
        }
    };

    let matcher = SignatureMatcher::new(&db);

    println!("TCP OS Fingerprinting Analysis:");
    println!("  Total packets: {}", packets.len());

    // Count TCP analysis results
    let mut connection_tracker = TtlCache::new(1000);
    let mut syn_count: u32 = 0;
    let mut syn_ack_count: u32 = 0;
    let mut mtu_count: u32 = 0;
    let mut uptime_count: u32 = 0;

    for packet in &packets {
        if let Some(result) = process_tcp_packet(packet, &mut connection_tracker, Some(&matcher)) {
            if result.syn.is_some() {
                syn_count = syn_count.saturating_add(1);
            }
            if result.syn_ack.is_some() {
                syn_ack_count = syn_ack_count.saturating_add(1);
            }
            if result.mtu.is_some() {
                mtu_count = mtu_count.saturating_add(1);
            }
            if result.client_uptime.is_some() || result.server_uptime.is_some() {
                uptime_count = uptime_count.saturating_add(1);
            }
        }
    }

    println!("  SYN packets: {syn_count}");
    println!("  SYN-ACK packets: {syn_ack_count}");
    println!("  MTU detections: {mtu_count}");
    println!("  Uptime calculations: {uptime_count}");
    println!("--------------------");

    let mut group = c.benchmark_group("TCP_OS_Fingerprinting");

    // Benchmark TCP processing with OS fingerprinting
    group.bench_function("tcp_with_os_matching", |b| {
        b.iter(|| {
            let matcher = SignatureMatcher::new(&db);
            let mut tracker = TtlCache::new(1000);
            for packet in packets.iter() {
                let _ = process_tcp_packet(packet, &mut tracker, Some(&matcher));
            }
        })
    });

    // Benchmark TCP processing without OS matching
    group.bench_function("tcp_without_os_matching", |b| {
        b.iter(|| {
            let mut tracker = TtlCache::new(1000);
            for packet in packets.iter() {
                let _ = process_tcp_packet(packet, &mut tracker, None);
            }
        })
    });

    // Benchmark raw packet parsing only
    group.bench_function("tcp_packet_parsing", |b| {
        b.iter(|| {
            for packet in packets.iter() {
                let _ = huginn_net_tcp::packet_parser::parse_packet(packet);
            }
        })
    });

    group.finish();
}

/// Benchmark TCP MTU detection performance
fn bench_tcp_mtu_detection(c: &mut Criterion) {
    let packets = match load_packets_from_pcap("../pcap/macos_tcp_flags.pcap") {
        Ok(pkts) => pkts,
        Err(e) => {
            eprintln!("Failed to load TCP PCAP file: {e}");
            return;
        }
    };

    if packets.is_empty() {
        eprintln!("No packets found in TCP PCAP file");
        return;
    }

    let db = match Database::load_default() {
        Ok(db) => db,
        Err(e) => {
            eprintln!("Failed to load default database: {e}");
            return;
        }
    };

    println!("TCP MTU Detection Analysis:");
    println!("  Total packets: {}", packets.len());

    // Count MTU detections
    let matcher = SignatureMatcher::new(&db);
    let mut connection_tracker = TtlCache::new(1000);
    let mut mtu_detections: u32 = 0;

    for packet in &packets {
        if let Some(result) = process_tcp_packet(packet, &mut connection_tracker, Some(&matcher)) {
            if result.mtu.is_some() {
                mtu_detections = mtu_detections.saturating_add(1);
            }
        }
    }

    println!("  MTU detections: {mtu_detections}");
    println!("--------------------");

    let mut group = c.benchmark_group("TCP_MTU_Detection");

    // Benchmark MTU detection with link matching
    group.bench_function("mtu_with_link_matching", |b| {
        b.iter(|| {
            let matcher = SignatureMatcher::new(&db);
            let mut tracker = TtlCache::new(1000);
            for packet in packets.iter() {
                if let Some(result) = process_tcp_packet(packet, &mut tracker, Some(&matcher)) {
                    if let Some(mtu_output) = result.mtu {
                        // Access MTU information to ensure full processing
                        let _ = mtu_output.mtu;
                        let _ = &mtu_output.link;
                    }
                }
            }
        })
    });

    // Benchmark MTU detection without link matching
    group.bench_function("mtu_without_link_matching", |b| {
        b.iter(|| {
            let mut tracker = TtlCache::new(1000);
            for packet in packets.iter() {
                if let Some(result) = process_tcp_packet(packet, &mut tracker, None) {
                    if let Some(mtu_output) = result.mtu {
                        // Access MTU value only
                        let _ = mtu_output.mtu;
                    }
                }
            }
        })
    });

    group.finish();
}

/// Benchmark TCP uptime calculation performance
fn bench_tcp_uptime_calculation(c: &mut Criterion) {
    let packets = match load_packets_from_pcap("../pcap/macos_tcp_flags.pcap") {
        Ok(pkts) => pkts,
        Err(e) => {
            eprintln!("Failed to load TCP PCAP file: {e}");
            return;
        }
    };

    if packets.is_empty() {
        eprintln!("No packets found in TCP PCAP file");
        return;
    }

    println!("TCP Uptime Calculation Analysis:");
    println!("  Total packets: {}", packets.len());

    // Count uptime calculations
    let mut connection_tracker = TtlCache::new(1000);
    let mut uptime_calculations: u32 = 0;

    for packet in &packets {
        if let Some(result) = process_tcp_packet(packet, &mut connection_tracker, None) {
            if result.client_uptime.is_some() || result.server_uptime.is_some() {
                uptime_calculations = uptime_calculations.saturating_add(1);
            }
        }
    }

    println!("  Uptime calculations: {uptime_calculations}");
    println!("--------------------");

    let mut group = c.benchmark_group("TCP_Uptime_Calculation");

    // Benchmark uptime calculation with connection tracking
    group.bench_function("uptime_with_tracking", |b| {
        b.iter(|| {
            let mut tracker = TtlCache::new(1000);
            for packet in packets.iter() {
                if let Some(result) = process_tcp_packet(packet, &mut tracker, None) {
                    if let Some(uptime_output) = result.client_uptime {
                        let _ = uptime_output.days;
                        let _ = uptime_output.hours;
                        let _ = uptime_output.min;
                        let _ = uptime_output.freq;
                    }
                    if let Some(uptime_output) = result.server_uptime {
                        let _ = uptime_output.days;
                        let _ = uptime_output.hours;
                        let _ = uptime_output.min;
                        let _ = uptime_output.freq;
                    }
                }
            }
        })
    });

    // Benchmark TCP processing with different cache sizes
    group.bench_function("uptime_small_cache", |b| {
        b.iter(|| {
            let mut tracker = TtlCache::new(100); // Smaller cache
            for packet in packets.iter() {
                let _ = process_tcp_packet(packet, &mut tracker, None);
            }
        })
    });

    group.bench_function("uptime_large_cache", |b| {
        b.iter(|| {
            let mut tracker = TtlCache::new(10000); // Larger cache
            for packet in packets.iter() {
                let _ = process_tcp_packet(packet, &mut tracker, None);
            }
        })
    });

    group.finish();
}

/// Benchmark TCP processing overhead analysis
fn bench_tcp_processing_overhead(c: &mut Criterion) {
    let packets = match load_packets_from_pcap("../pcap/macos_tcp_flags.pcap") {
        Ok(pkts) => pkts,
        Err(e) => {
            eprintln!("Failed to load TCP PCAP file: {e}");
            return;
        }
    };

    if packets.is_empty() {
        eprintln!("No packets found in TCP PCAP file");
        return;
    }

    let db = match Database::load_default() {
        Ok(db) => db,
        Err(e) => {
            eprintln!("Failed to load default database: {e}");
            return;
        }
    };

    println!("TCP Processing Overhead Analysis:");
    println!("  Total packets: {}", packets.len());
    println!("--------------------");

    let mut group = c.benchmark_group("TCP_Processing_Overhead");

    // Benchmark minimal TCP processing
    group.bench_function("minimal_processing", |b| {
        b.iter(|| {
            for packet in packets.iter() {
                let _ = huginn_net_tcp::packet_parser::parse_packet(packet);
            }
        })
    });

    // Benchmark full TCP analysis
    group.bench_function("full_tcp_analysis", |b| {
        b.iter(|| {
            let matcher = SignatureMatcher::new(&db);
            let mut tracker = TtlCache::new(1000);
            for packet in packets.iter() {
                let _ = process_tcp_packet(packet, &mut tracker, Some(&matcher));
            }
        })
    });

    // Benchmark with result collection
    group.bench_function("full_analysis_with_collection", |b| {
        b.iter(|| {
            let matcher = SignatureMatcher::new(&db);
            let mut tracker = TtlCache::new(1000);
            let mut results = Vec::new();

            for packet in packets.iter() {
                if let Some(result) = process_tcp_packet(packet, &mut tracker, Some(&matcher)) {
                    // Collect all TCP analysis results
                    results.push((
                        result.syn.is_some(),
                        result.syn_ack.is_some(),
                        result.mtu.map(|m| m.mtu),
                        result
                            .client_uptime
                            .map(|u| u.days)
                            .or_else(|| result.server_uptime.map(|u| u.days)),
                    ));
                }
            }

            // Process results to simulate real-world usage
            let _ = results.len();
        })
    });

    group.finish();
}
