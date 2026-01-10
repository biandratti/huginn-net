use criterion::{criterion_group, criterion_main, Criterion};
use huginn_net_tls::TlsClientHelloReader;
use huginn_net_tls::{
    process_ipv4_packet, process_ipv6_packet, tls_process::is_tls_traffic, FlowKey,
};
use pcap_file::pcap::PcapReader;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::error::Error;
use std::fs::File;
use std::sync::Mutex;
use std::time::Duration;
use ttl_cache::TtlCache;

/// Number of times to repeat the PCAP dataset for stable benchmarks
const REPEAT_COUNT: usize = 1000;

/// Benchmark results storage for automatic reporting
static BENCHMARK_RESULTS: Mutex<Option<BenchmarkReport>> = Mutex::new(None);

#[derive(Debug, Clone)]
struct BenchmarkReport {
    packet_count: usize,
    tls_packet_count: u32,
    ja4_fingerprints: u32,
    pcap_name: String,
    timings: Vec<(String, Duration)>,
}

criterion_group!(
    tls_benches,
    bench_tls_ja4_fingerprinting_tls12,
    bench_tls_ja4_fingerprinting_alpn_h2,
    bench_tls_packet_parsing_performance,
    bench_tls_ja4_calculation_overhead,
    bench_tls_parallel_processing,
    generate_final_report
);
criterion_main!(tls_benches);

/// Calculate throughput in packets per second
fn calculate_throughput(duration: Duration, packet_count: usize) -> f64 {
    let seconds = duration.as_secs_f64();
    if seconds > 0.0 {
        (packet_count as f64) / seconds
    } else {
        0.0
    }
}

/// Format throughput for display
fn format_throughput(pps: f64) -> String {
    if pps >= 1_000_000.0 {
        format!("{:.2}M", pps / 1_000_000.0)
    } else if pps >= 1_000.0 {
        format!("{:.1}k", pps / 1_000.0)
    } else {
        format!("{pps:.0}")
    }
}

/// Calculate overhead percentage
fn calculate_overhead(baseline: Duration, target: Duration) -> f64 {
    let baseline_ns = baseline.as_nanos() as f64;
    let target_ns = target.as_nanos() as f64;
    if baseline_ns > 0.0 {
        ((target_ns - baseline_ns) / baseline_ns) * 100.0
    } else {
        0.0
    }
}

/// Measure average execution time for a benchmark
fn measure_average_time<F>(mut f: F, iterations: usize) -> Duration
where
    F: FnMut(),
{
    let start = std::time::Instant::now();
    for _ in 0..iterations {
        f();
    }
    start
        .elapsed()
        .checked_div(iterations as u32)
        .unwrap_or(Duration::ZERO)
}

/// Generate comprehensive benchmark report
fn generate_final_report(_c: &mut Criterion) {
    let report = match BENCHMARK_RESULTS.lock() {
        Ok(guard) => guard.clone(),
        Err(_) => return,
    };

    let Some(report) = report else {
        return;
    };

    println!("\n");
    println!("===============================================================================");
    println!("                   TLS BENCHMARK ANALYSIS REPORT                            ");
    println!("===============================================================================");
    println!();
    println!("PCAP Analysis Summary:");
    println!("  - PCAP file: {}", report.pcap_name);
    println!("  - Total packets analyzed: {}", report.packet_count);
    println!("  - TLS packets found: {}", report.tls_packet_count);
    println!("  - JA4 fingerprints generated: {}", report.ja4_fingerprints);
    let tls_effectiveness = (report.tls_packet_count as f64 / report.packet_count as f64) * 100.0;
    println!("  - TLS packet effectiveness: {tls_effectiveness:.1}%");
    println!();

    if report.timings.is_empty() {
        return;
    }

    // Find key timings for calculations
    let detection_time = report
        .timings
        .iter()
        .find(|(name, _)| name.contains("detection"))
        .map(|(_, t)| *t);
    let parsing_time = report
        .timings
        .iter()
        .find(|(name, _)| name.contains("parsing"))
        .map(|(_, t)| *t);
    let tls_processing = report
        .timings
        .iter()
        .find(|(name, _)| name.contains("tls_processing") && !name.contains("full"))
        .map(|(_, t)| *t);
    let full_tls = report
        .timings
        .iter()
        .find(|(name, _)| name.contains("full_tls_processing"))
        .map(|(_, t)| *t);

    println!("Performance Summary:");
    println!("+--------------------------------------------------------------------------+");
    println!("| Operation                        | Time/Packet | Throughput    | Overhead   |");
    println!("+--------------------------------------------------------------------------+");

    for (name, duration) in &report.timings {
        let per_packet = duration
            .checked_div(report.packet_count as u32)
            .unwrap_or(Duration::ZERO);
        let throughput = calculate_throughput(per_packet, 1);
        let pps_str = format_throughput(throughput);

        let overhead_str = if let Some(baseline) = detection_time {
            if name.contains("detection") {
                "    1.0x  ".to_string()
            } else {
                let overhead = calculate_overhead(baseline, per_packet);
                format!("{:>7.1}x", overhead / 100.0 + 1.0)
            }
        } else {
            "     -    ".to_string()
        };

        let display_name = name
            .replace("tls_", "")
            .replace("_", " ")
            .chars()
            .take(32)
            .collect::<String>();

        println!(
            "| {display_name:<32} | {per_packet:>11.3?} | {pps_str:>9} pps | {overhead_str:>10} |"
        );
    }
    println!("+--------------------------------------------------------------------------+");
    println!();

    // Overhead Analysis
    if let (Some(detection), Some(processing)) = (detection_time, tls_processing) {
        let overhead = calculate_overhead(detection, processing);
        println!("Overhead Analysis:");
        println!(
            "  - TLS Detection -> Full Processing: {:.1}x overhead (parsing + JA4 calculation)",
            overhead / 100.0 + 1.0
        );
    }

    if let (Some(parsing), Some(processing)) = (parsing_time, tls_processing) {
        let overhead = calculate_overhead(parsing, processing);
        println!(
            "  - Parsing -> Full Processing: {:.1}x overhead (JA4 calculation only)",
            overhead / 100.0 + 1.0
        );
    }
    println!();

    // Capacity Planning
    let capacity_time = full_tls.or(tls_processing);
    if let Some(processing) = capacity_time {
        let per_packet = processing
            .checked_div(report.packet_count as u32)
            .unwrap_or(Duration::ZERO);
        let throughput = calculate_throughput(per_packet, 1);

        let cpu_1gbps = (81274.0 / throughput) * 100.0;
        let cpu_10gbps = (812740.0 / throughput) * 100.0;

        println!("Capacity Planning:");
        println!();
        println!("Sequential Mode (1 core):");
        println!("  - Throughput: {} packets/second", format_throughput(throughput));
        println!(
            "  - 1 Gbps (81,274 pps): {:.1}% CPU{}",
            cpu_1gbps,
            if cpu_1gbps > 100.0 { " [OVERLOAD]" } else { "" }
        );
        println!(
            "  - 10 Gbps (812,740 pps): {:.1}% CPU{}",
            cpu_10gbps,
            if cpu_10gbps > 100.0 {
                " [OVERLOAD]"
            } else {
                ""
            }
        );

        // Parallel Mode Analysis
        let parallel_2 = report
            .timings
            .iter()
            .find(|(name, _)| name.contains("parallel_2_workers"))
            .map(|(_, t)| *t);
        let parallel_4 = report
            .timings
            .iter()
            .find(|(name, _)| name.contains("parallel_4_workers"))
            .map(|(_, t)| *t);
        let parallel_8 = report
            .timings
            .iter()
            .find(|(name, _)| name.contains("parallel_8_workers"))
            .map(|(_, t)| *t);

        if parallel_2.is_some() || parallel_4.is_some() || parallel_8.is_some() {
            println!();
            println!("Parallel Mode Performance:");
            println!();

            let available_cpus = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1);

            println!("  System CPUs: {available_cpus}");
            println!();

            if let Some(p2) = parallel_2 {
                let per_packet = p2
                    .checked_div(report.packet_count as u32)
                    .unwrap_or(Duration::ZERO);
                let throughput = calculate_throughput(per_packet, 1);
                println!("  2 Workers:");
                println!("    - Throughput: {} pps", format_throughput(throughput));

                let cpu_1gbps = (81274.0 / throughput) * 100.0;
                let cpu_10gbps = (812740.0 / throughput) * 100.0;
                println!("    - 1 Gbps (81,274 pps): {cpu_1gbps:.1}% CPU");
                println!("    - 10 Gbps (812,740 pps): {cpu_10gbps:.1}% CPU");
            }

            if let Some(p4) = parallel_4 {
                let per_packet = p4
                    .checked_div(report.packet_count as u32)
                    .unwrap_or(Duration::ZERO);
                let throughput = calculate_throughput(per_packet, 1);
                println!();
                println!("  4 Workers:");
                println!("    - Throughput: {} pps", format_throughput(throughput));

                let cpu_1gbps = (81274.0 / throughput) * 100.0;
                let cpu_10gbps = (812740.0 / throughput) * 100.0;
                println!("    - 1 Gbps (81,274 pps): {cpu_1gbps:.1}% CPU");
                println!("    - 10 Gbps (812,740 pps): {cpu_10gbps:.1}% CPU");
            }

            if let Some(p8) = parallel_8 {
                let per_packet = p8
                    .checked_div(report.packet_count as u32)
                    .unwrap_or(Duration::ZERO);
                let throughput = calculate_throughput(per_packet, 1);
                println!();
                println!("  8 Workers:");
                println!("    - Throughput: {} pps", format_throughput(throughput));

                let cpu_1gbps = (81274.0 / throughput) * 100.0;
                let cpu_10gbps = (812740.0 / throughput) * 100.0;
                println!("    - 1 Gbps (81,274 pps): {cpu_1gbps:.1}% CPU");
                println!("    - 10 Gbps (812,740 pps): {cpu_10gbps:.1}% CPU");
            }

            println!();
            println!("Note: TLS uses round-robin dispatch (stateless processing)");
            println!("      Parallel benchmarks include worker pool overhead");
        }
    }
    println!();
    println!("Benchmark report generation complete");
    println!();
}

fn load_packets_from_pcap(pcap_path: &str) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let file = File::open(pcap_path)?;
    let mut pcap_reader = PcapReader::new(file)?;
    let mut packets = Vec::new();
    while let Some(pkt) = pcap_reader.next_packet() {
        packets.push(pkt?.data.into());
    }
    Ok(packets)
}

/// Load packets from PCAP and repeat them for stable benchmarks
fn load_packets_repeated(pcap_path: &str, repeat: usize) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let packets = load_packets_from_pcap(pcap_path)?;
    if packets.is_empty() {
        return Ok(packets);
    }

    // Repeat packets to get a stable benchmark dataset
    let capacity = packets.len().saturating_mul(repeat);
    let mut repeated = Vec::with_capacity(capacity);
    for _ in 0..repeat {
        repeated.extend(packets.iter().cloned());
    }
    Ok(repeated)
}

/// Detect if packet contains TLS traffic (using library function)
fn detect_tls_in_packet(packet: &[u8]) -> bool {
    let ethernet = match EthernetPacket::new(packet) {
        Some(eth) => eth,
        None => return false,
    };

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ipv4 = match Ipv4Packet::new(ethernet.payload()) {
                Some(ip) => ip,
                None => return false,
            };
            if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                    return is_tls_traffic(tcp.payload());
                }
            }
            false
        }
        EtherTypes::Ipv6 => {
            let ipv6 = match Ipv6Packet::new(ethernet.payload()) {
                Some(ip) => ip,
                None => return false,
            };
            if ipv6.get_next_header() == IpNextHeaderProtocols::Tcp {
                if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                    return is_tls_traffic(tcp.payload());
                }
            }
            false
        }
        _ => false,
    }
}

/// Process a packet using the public TLS API
fn process_tls_packet(
    packet: &[u8],
    tcp_flows: &mut TtlCache<FlowKey, TlsClientHelloReader>,
) -> Option<huginn_net_tls::TlsClientOutput> {
    match huginn_net_tls::packet_parser::parse_packet(packet) {
        huginn_net_tls::packet_parser::IpPacket::Ipv4(ipv4) => {
            process_ipv4_packet(&ipv4, tcp_flows).ok().flatten()
        }
        huginn_net_tls::packet_parser::IpPacket::Ipv6(ipv6) => {
            process_ipv6_packet(&ipv6, tcp_flows).ok().flatten()
        }
        huginn_net_tls::packet_parser::IpPacket::None => None,
    }
}

/// Benchmark TLS JA4 fingerprinting using TLS 1.2 PCAP
fn bench_tls_ja4_fingerprinting_tls12(c: &mut Criterion) {
    let packets = match load_packets_repeated("../pcap/tls12.pcap", REPEAT_COUNT) {
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
    println!("  Total packets: {} (repeated {}x)", packets.len(), REPEAT_COUNT);

    // Count TLS packets for analysis
    let mut tls_packet_count: u32 = 0;
    let mut tcp_flows = TtlCache::new(10000);

    for packet in &packets {
        if process_tls_packet(packet, &mut tcp_flows).is_some() {
            tls_packet_count = tls_packet_count.saturating_add(1);
        }
    }

    println!("  TLS packets found: {tls_packet_count}");
    println!("--------------------");

    // Initialize benchmark report
    if let Ok(mut guard) = BENCHMARK_RESULTS.lock() {
        *guard = Some(BenchmarkReport {
            packet_count: packets.len(),
            tls_packet_count,
            ja4_fingerprints: tls_packet_count,
            pcap_name: format!("tls12.pcap ({REPEAT_COUNT}x)"),
            timings: Vec::new(),
        });
    }

    let mut group = c.benchmark_group("TLS_JA4_TLS12");

    // Baseline: TLS detection only
    group.bench_function("tls_detection", |b| {
        b.iter(|| {
            for packet in packets.iter() {
                let _ = detect_tls_in_packet(packet);
            }
        })
    });

    // Benchmark TLS processing
    group.bench_function("tls_processing", |b| {
        b.iter(|| {
            let mut tcp_flows = TtlCache::new(10000);
            for packet in packets.iter() {
                let _ = process_tls_packet(packet, &mut tcp_flows);
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

    // Measure and store actual times for reporting
    let tls_detection_time = measure_average_time(
        || {
            for packet in packets.iter() {
                let _ = detect_tls_in_packet(packet);
            }
        },
        10,
    );

    let tls_processing_time = measure_average_time(
        || {
            let mut tcp_flows = TtlCache::new(10000);
            for packet in packets.iter() {
                let _ = process_tls_packet(packet, &mut tcp_flows);
            }
        },
        10,
    );

    let parsing_time = measure_average_time(
        || {
            for packet in packets.iter() {
                let _ = huginn_net_tls::packet_parser::parse_packet(packet);
            }
        },
        10,
    );

    if let Ok(mut guard) = BENCHMARK_RESULTS.lock() {
        if let Some(ref mut report) = *guard {
            report
                .timings
                .push(("tls_detection".to_string(), tls_detection_time));
            report
                .timings
                .push(("tls_processing".to_string(), tls_processing_time));
            report
                .timings
                .push(("tls_packet_parsing".to_string(), parsing_time));
        }
    }
}

/// Benchmark TLS JA4 fingerprinting using TLS ALPN H2 PCAP
fn bench_tls_ja4_fingerprinting_alpn_h2(c: &mut Criterion) {
    let packets = match load_packets_repeated("../pcap/tls-alpn-h2.pcap", REPEAT_COUNT) {
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
    println!("  Total packets: {} (repeated {}x)", packets.len(), REPEAT_COUNT);

    // Count TLS packets for analysis
    let mut tls_packet_count: u32 = 0;
    let mut tcp_flows = TtlCache::new(10000);

    for packet in &packets {
        if process_tls_packet(packet, &mut tcp_flows).is_some() {
            tls_packet_count = tls_packet_count.saturating_add(1);
        }
    }

    println!("  TLS packets found: {tls_packet_count}");
    println!("--------------------");

    let mut group = c.benchmark_group("TLS_JA4_ALPN_H2");

    // Benchmark TLS processing
    group.bench_function("tls_processing", |b| {
        b.iter(|| {
            let mut tcp_flows = TtlCache::new(10000);
            for packet in packets.iter() {
                let _ = process_tls_packet(packet, &mut tcp_flows);
            }
        })
    });

    // Benchmark with TLS extensions analysis
    group.bench_function("tls_extensions_analysis", |b| {
        b.iter(|| {
            let mut tcp_flows = TtlCache::new(10000);
            for packet in packets.iter() {
                if let Some(result) = process_tls_packet(packet, &mut tcp_flows) {
                    // Access JA4 fingerprint to ensure full processing
                    let _ = &result.sig.ja4.full;
                    let _ = &result.sig.ja4.raw;
                }
            }
        })
    });

    group.finish();

    // Measure and store ALPN H2 times
    let tls_alpn_processing_time = measure_average_time(
        || {
            let mut tcp_flows = TtlCache::new(10000);
            for packet in packets.iter() {
                let _ = process_tls_packet(packet, &mut tcp_flows);
            }
        },
        10,
    );

    let tls_extensions_time = measure_average_time(
        || {
            let mut tcp_flows = TtlCache::new(10000);
            for packet in packets.iter() {
                if let Some(result) = process_tls_packet(packet, &mut tcp_flows) {
                    let _ = &result.sig.ja4.full;
                    let _ = &result.sig.ja4.raw;
                }
            }
        },
        10,
    );

    if let Ok(mut guard) = BENCHMARK_RESULTS.lock() {
        if let Some(ref mut report) = *guard {
            report
                .timings
                .push(("tls_alpn_processing".to_string(), tls_alpn_processing_time));
            report
                .timings
                .push(("tls_extensions_analysis".to_string(), tls_extensions_time));
        }
    }
}

/// Benchmark TLS packet parsing performance without JA4 calculation
fn bench_tls_packet_parsing_performance(c: &mut Criterion) {
    let packets = match load_packets_repeated("../pcap/tls12.pcap", REPEAT_COUNT) {
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
    println!("  Total packets: {} (repeated {}x)", packets.len(), REPEAT_COUNT);

    // Count TLS packets for analysis
    let mut tls_packet_count: u32 = 0;
    let mut tcp_flows = TtlCache::new(10000);

    for packet in &packets {
        if process_tls_packet(packet, &mut tcp_flows).is_some() {
            tls_packet_count = tls_packet_count.saturating_add(1);
        }
    }

    println!("  TLS packets found: {tls_packet_count}");
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
            let mut tcp_flows = TtlCache::new(10000);
            for packet in packets.iter() {
                let _ = process_tls_packet(packet, &mut tcp_flows);
            }
        })
    });

    // Benchmark TLS processing with result extraction
    group.bench_function("tls_with_result_extraction", |b| {
        b.iter(|| {
            let mut tcp_flows = TtlCache::new(10000);
            for packet in packets.iter() {
                if let Some(result) = process_tls_packet(packet, &mut tcp_flows) {
                    // Force evaluation of JA4 fingerprints
                    let _ = &result.sig.ja4.full;
                    let _ = &result.sig.ja4.raw;
                    let _ = &result.sig.version;
                }
            }
        })
    });

    group.finish();

    // Measure and store parsing performance times
    let raw_parsing_time = measure_average_time(
        || {
            for packet in packets.iter() {
                let _ = huginn_net_tls::packet_parser::parse_packet(packet);
            }
        },
        10,
    );

    let full_tls_time = measure_average_time(
        || {
            let mut tcp_flows = TtlCache::new(10000);
            for packet in packets.iter() {
                let _ = process_tls_packet(packet, &mut tcp_flows);
            }
        },
        10,
    );

    let extraction_time = measure_average_time(
        || {
            let mut tcp_flows = TtlCache::new(10000);
            for packet in packets.iter() {
                if let Some(result) = process_tls_packet(packet, &mut tcp_flows) {
                    let _ = &result.sig.ja4.full;
                    let _ = &result.sig.ja4.raw;
                    let _ = &result.sig.version;
                }
            }
        },
        10,
    );

    if let Ok(mut guard) = BENCHMARK_RESULTS.lock() {
        if let Some(ref mut report) = *guard {
            report
                .timings
                .push(("raw_packet_parsing".to_string(), raw_parsing_time));
            report
                .timings
                .push(("full_tls_processing".to_string(), full_tls_time));
            report
                .timings
                .push(("tls_with_result_extraction".to_string(), extraction_time));
        }
    }
}

/// Benchmark JA4 calculation overhead by comparing different processing levels
fn bench_tls_ja4_calculation_overhead(c: &mut Criterion) {
    let packets = match load_packets_repeated("../pcap/tls-alpn-h2.pcap", REPEAT_COUNT) {
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
    println!("  Total packets: {} (repeated {}x)", packets.len(), REPEAT_COUNT);

    // Count TLS packets for analysis
    let mut tls_packet_count: u32 = 0;
    let mut ja4_count: u32 = 0;

    let mut tcp_flows = TtlCache::new(10000);
    for packet in &packets {
        if let Some(_result) = process_tls_packet(packet, &mut tcp_flows) {
            tls_packet_count = tls_packet_count.saturating_add(1);
            // JA4 is always generated if we have a TLS result
            ja4_count = ja4_count.saturating_add(1);
        }
    }

    println!("  TLS packets found: {tls_packet_count}");
    println!("  JA4 fingerprints generated: {ja4_count}");
    println!("--------------------");

    let mut group = c.benchmark_group("TLS_JA4_Overhead");

    // Benchmark basic TLS processing
    group.bench_function("basic_tls_processing", |b| {
        b.iter(|| {
            let mut tcp_flows = TtlCache::new(10000);
            for packet in packets.iter() {
                let _ = process_tls_packet(packet, &mut tcp_flows);
            }
        })
    });

    // Benchmark with JA4 fingerprint access (forces calculation)
    group.bench_function("ja4_fingerprint_access", |b| {
        b.iter(|| {
            let mut tcp_flows = TtlCache::new(10000);
            for packet in packets.iter() {
                if let Some(result) = process_tls_packet(packet, &mut tcp_flows) {
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
            let mut tcp_flows = TtlCache::new(10000);

            for packet in packets.iter() {
                if let Some(result) = process_tls_packet(packet, &mut tcp_flows) {
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

    // Measure and store JA4 overhead times
    let basic_tls_time = measure_average_time(
        || {
            let mut tcp_flows = TtlCache::new(10000);
            for packet in packets.iter() {
                let _ = process_tls_packet(packet, &mut tcp_flows);
            }
        },
        10,
    );

    let ja4_access_time = measure_average_time(
        || {
            let mut tcp_flows = TtlCache::new(10000);
            for packet in packets.iter() {
                if let Some(result) = process_tls_packet(packet, &mut tcp_flows) {
                    let _ = result.sig.ja4.full.to_string();
                    let _ = result.sig.ja4.raw.to_string();
                }
            }
        },
        10,
    );

    let full_analysis_time = measure_average_time(
        || {
            let mut results = Vec::new();
            let mut tcp_flows = TtlCache::new(10000);
            for packet in packets.iter() {
                if let Some(result) = process_tls_packet(packet, &mut tcp_flows) {
                    results.push((
                        result.sig.version,
                        result.sig.ja4.full.clone(),
                        result.sig.ja4.raw.clone(),
                        result.source,
                        result.destination,
                    ));
                }
            }
            let _ = results.len();
        },
        10,
    );

    if let Ok(mut guard) = BENCHMARK_RESULTS.lock() {
        if let Some(ref mut report) = *guard {
            report
                .timings
                .push(("basic_tls_processing".to_string(), basic_tls_time));
            report
                .timings
                .push(("ja4_fingerprint_access".to_string(), ja4_access_time));
            report
                .timings
                .push(("full_result_analysis".to_string(), full_analysis_time));
        }
    }
}

/// Benchmark TLS parallel processing with different worker counts
fn bench_tls_parallel_processing(c: &mut Criterion) {
    let packets = match load_packets_repeated("../pcap/tls12.pcap", REPEAT_COUNT) {
        Ok(pkts) => pkts,
        Err(e) => {
            eprintln!("Failed to load TLS PCAP file for parallel benchmark: {e}");
            return;
        }
    };

    if packets.is_empty() {
        eprintln!("No packets found in TLS PCAP file for parallel benchmark");
        return;
    }

    println!("TLS Parallel Processing Analysis:");
    println!("  Total packets: {} (repeated {}x)", packets.len(), REPEAT_COUNT);
    println!("--------------------");

    let worker_counts = [2, 4, 8];
    let mut group = c.benchmark_group("TLS_Parallel_Processing");

    for &num_workers in &worker_counts {
        let bench_name = format!("parallel_{num_workers}_workers");
        group.bench_function(&bench_name, |b| {
            b.iter(|| {
                let (tx, rx) = std::sync::mpsc::channel();
                let pool = match huginn_net_tls::WorkerPool::new(
                    num_workers,
                    100,
                    32,
                    10,
                    tx,
                    10000,
                    None,
                ) {
                    Ok(p) => p,
                    Err(e) => panic!("Failed to create worker pool: {e}"),
                };

                // Dispatch all packets
                for packet in packets.iter() {
                    let _ = pool.dispatch(packet.clone());
                }

                // Shutdown and collect results
                pool.shutdown();
                let mut _result_count: usize = 0;
                while rx.recv().is_ok() {
                    _result_count = _result_count.saturating_add(1);
                }
            })
        });
    }

    group.finish();

    // Measure parallel processing times for reporting
    let parallel_2_workers_time = measure_average_time(
        || {
            let (tx, rx) = std::sync::mpsc::channel();
            let pool = match huginn_net_tls::WorkerPool::new(2, 100, 32, 10, tx, 10000, None) {
                Ok(p) => p,
                Err(e) => panic!("Failed to create worker pool: {e}"),
            };
            for packet in packets.iter() {
                let _ = pool.dispatch(packet.clone());
            }
            pool.shutdown();
            while rx.recv().is_ok() {}
        },
        3,
    );

    let parallel_4_workers_time = measure_average_time(
        || {
            let (tx, rx) = std::sync::mpsc::channel();
            let pool = match huginn_net_tls::WorkerPool::new(4, 100, 32, 10, tx, 10000, None) {
                Ok(p) => p,
                Err(e) => panic!("Failed to create worker pool: {e}"),
            };
            for packet in packets.iter() {
                let _ = pool.dispatch(packet.clone());
            }
            pool.shutdown();
            while rx.recv().is_ok() {}
        },
        3,
    );

    let parallel_8_workers_time = measure_average_time(
        || {
            let (tx, rx) = std::sync::mpsc::channel();
            let pool = match huginn_net_tls::WorkerPool::new(8, 100, 32, 10, tx, 10000, None) {
                Ok(p) => p,
                Err(e) => panic!("Failed to create worker pool: {e}"),
            };
            for packet in packets.iter() {
                let _ = pool.dispatch(packet.clone());
            }
            pool.shutdown();
            while rx.recv().is_ok() {}
        },
        3,
    );

    if let Ok(mut guard) = BENCHMARK_RESULTS.lock() {
        if let Some(ref mut report) = *guard {
            report
                .timings
                .push(("parallel_2_workers".to_string(), parallel_2_workers_time));
            report
                .timings
                .push(("parallel_4_workers".to_string(), parallel_4_workers_time));
            report
                .timings
                .push(("parallel_8_workers".to_string(), parallel_8_workers_time));
        }
    }
}
