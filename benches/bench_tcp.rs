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
    syn_count: u32,
    syn_ack_count: u32,
    mtu_count: u32,
    uptime_count: u32,
    timings: Vec<(String, Duration)>,
}

criterion_group!(
    tcp_benches,
    bench_tcp_os_fingerprinting,
    bench_tcp_mtu_detection,
    bench_tcp_uptime_calculation,
    bench_tcp_processing_overhead,
    bench_tcp_parallel_processing,
    generate_final_report
);
criterion_main!(tcp_benches);

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
    println!("                   TCP BENCHMARK ANALYSIS REPORT                            ");
    println!("===============================================================================");
    println!();
    println!("PCAP Analysis Summary:");
    println!("  - Total packets analyzed: {}", report.packet_count);
    println!("  - SYN packets: {}", report.syn_count);
    println!("  - SYN-ACK packets: {}", report.syn_ack_count);
    println!("  - MTU detections: {}", report.mtu_count);
    println!("  - Uptime calculations: {}", report.uptime_count);
    let effectiveness = ((report
        .syn_count
        .saturating_add(report.syn_ack_count)
        .saturating_add(report.mtu_count)
        .saturating_add(report.uptime_count)) as f64
        / report.packet_count as f64)
        * 100.0;
    println!("  - Analysis effectiveness: {effectiveness:.1}%");
    println!();

    if report.timings.is_empty() {
        return;
    }

    // Find key timings for calculations
    let parsing_time = report
        .timings
        .iter()
        .find(|(name, _)| name.contains("parsing"))
        .map(|(_, t)| *t);
    let tcp_no_os = report
        .timings
        .iter()
        .find(|(name, _)| name.contains("without_os"))
        .map(|(_, t)| *t);
    let tcp_with_os = report
        .timings
        .iter()
        .find(|(name, _)| name.contains("with_os"))
        .map(|(_, t)| *t);
    let full_analysis = report
        .timings
        .iter()
        .find(|(name, _)| name.contains("full_tcp_analysis"))
        .map(|(_, t)| *t);
    let mtu_no_link = report
        .timings
        .iter()
        .find(|(name, _)| name.contains("mtu_without"))
        .map(|(_, t)| *t);
    let mtu_with_link = report
        .timings
        .iter()
        .find(|(name, _)| name.contains("mtu_with"))
        .map(|(_, t)| *t);

    println!("Performance Summary:");
    println!("+--------------------------------------------------------------------------+");
    println!("| Operation                        | Time/Packet | Throughput    | vs Parsing |");
    println!("+--------------------------------------------------------------------------+");

    for (name, duration) in &report.timings {
        let per_packet = duration
            .checked_div(report.packet_count as u32)
            .unwrap_or(Duration::ZERO);
        let throughput = calculate_throughput(per_packet, 1);
        let pps_str = format_throughput(throughput);

        let overhead_str = if let Some(baseline) = parsing_time {
            if name != "tcp_packet_parsing" {
                let overhead = calculate_overhead(baseline, per_packet);
                format!("{:>7.0}x", overhead / 100.0 + 1.0)
            } else {
                "  1.0x  ".to_string()
            }
        } else {
            "   -    ".to_string()
        };

        let display_name = name
            .replace("tcp_", "")
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
    if let (Some(parsing), Some(full)) = (parsing_time, full_analysis) {
        let overhead = calculate_overhead(parsing, full);
        println!("Overhead Analysis:");
        println!(
            "  - Parsing -> Full Analysis: {:.0}x overhead (expected for comprehensive analysis)",
            overhead / 100.0 + 1.0
        );
    }

    if let (Some(no_os), Some(with_os)) = (tcp_no_os, tcp_with_os) {
        let overhead = calculate_overhead(no_os, with_os);
        println!("  - TCP without OS -> with OS: {overhead:.1}% (database lookup cost)");
    }

    if let (Some(no_link), Some(with_link)) = (mtu_no_link, mtu_with_link) {
        let overhead = calculate_overhead(no_link, with_link);
        println!("  - MTU without link -> with link: {overhead:.1}% (MTU database matching)");
    }
    println!();

    // Capacity Planning
    if let Some(full) = full_analysis {
        let per_packet = full
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
            println!("Note: TCP uses hash-based worker assignment for stateful connections");
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

/// Load packets from PCAP and repeat them for stable benchmarking
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
    let packets = match load_packets_repeated("../pcap/macos_tcp_flags.pcap", REPEAT_COUNT) {
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
    println!("  Total packets: {} (repeated {}x)", packets.len(), REPEAT_COUNT);

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

    // Initialize benchmark report
    if let Ok(mut guard) = BENCHMARK_RESULTS.lock() {
        *guard = Some(BenchmarkReport {
            packet_count: packets.len(),
            syn_count,
            syn_ack_count,
            mtu_count,
            uptime_count,
            timings: Vec::new(),
        });
    }

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

    // Measure and store actual times for reporting
    let tcp_with_os_time = measure_average_time(
        || {
            let matcher = SignatureMatcher::new(&db);
            let mut tracker = TtlCache::new(1000);
            for packet in packets.iter() {
                let _ = process_tcp_packet(packet, &mut tracker, Some(&matcher));
            }
        },
        10,
    );

    let tcp_without_os_time = measure_average_time(
        || {
            let mut tracker = TtlCache::new(1000);
            for packet in packets.iter() {
                let _ = process_tcp_packet(packet, &mut tracker, None);
            }
        },
        10,
    );

    let parsing_time = measure_average_time(
        || {
            for packet in packets.iter() {
                let _ = huginn_net_tcp::packet_parser::parse_packet(packet);
            }
        },
        10,
    );

    if let Ok(mut guard) = BENCHMARK_RESULTS.lock() {
        if let Some(ref mut report) = *guard {
            report
                .timings
                .push(("tcp_with_os_matching".to_string(), tcp_with_os_time));
            report
                .timings
                .push(("tcp_without_os_matching".to_string(), tcp_without_os_time));
            report
                .timings
                .push(("tcp_packet_parsing".to_string(), parsing_time));
        }
    }
}

/// Benchmark TCP MTU detection performance
fn bench_tcp_mtu_detection(c: &mut Criterion) {
    let packets = match load_packets_repeated("../pcap/macos_tcp_flags.pcap", REPEAT_COUNT) {
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
    println!("  Total packets: {} (repeated {}x)", packets.len(), REPEAT_COUNT);

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

    // Measure and store MTU detection times
    let mtu_with_link_time = measure_average_time(
        || {
            let matcher = SignatureMatcher::new(&db);
            let mut tracker = TtlCache::new(1000);
            for packet in packets.iter() {
                if let Some(result) = process_tcp_packet(packet, &mut tracker, Some(&matcher)) {
                    if let Some(mtu_output) = result.mtu {
                        let _ = mtu_output.mtu;
                        let _ = &mtu_output.link;
                    }
                }
            }
        },
        10,
    );

    let mtu_without_link_time = measure_average_time(
        || {
            let mut tracker = TtlCache::new(1000);
            for packet in packets.iter() {
                if let Some(result) = process_tcp_packet(packet, &mut tracker, None) {
                    if let Some(mtu_output) = result.mtu {
                        let _ = mtu_output.mtu;
                    }
                }
            }
        },
        10,
    );

    if let Ok(mut guard) = BENCHMARK_RESULTS.lock() {
        if let Some(ref mut report) = *guard {
            report
                .timings
                .push(("mtu_with_link_matching".to_string(), mtu_with_link_time));
            report
                .timings
                .push(("mtu_without_link_matching".to_string(), mtu_without_link_time));
        }
    }
}

/// Benchmark TCP uptime calculation performance
fn bench_tcp_uptime_calculation(c: &mut Criterion) {
    let packets = match load_packets_repeated("../pcap/macos_tcp_flags.pcap", REPEAT_COUNT) {
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
    println!("  Total packets: {} (repeated {}x)", packets.len(), REPEAT_COUNT);

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

    // Measure and store uptime calculation times
    let uptime_with_tracking_time = measure_average_time(
        || {
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
        },
        10,
    );

    let uptime_small_cache_time = measure_average_time(
        || {
            let mut tracker = TtlCache::new(100);
            for packet in packets.iter() {
                let _ = process_tcp_packet(packet, &mut tracker, None);
            }
        },
        10,
    );

    let uptime_large_cache_time = measure_average_time(
        || {
            let mut tracker = TtlCache::new(10000);
            for packet in packets.iter() {
                let _ = process_tcp_packet(packet, &mut tracker, None);
            }
        },
        10,
    );

    if let Ok(mut guard) = BENCHMARK_RESULTS.lock() {
        if let Some(ref mut report) = *guard {
            report
                .timings
                .push(("uptime_with_tracking".to_string(), uptime_with_tracking_time));
            report
                .timings
                .push(("uptime_small_cache".to_string(), uptime_small_cache_time));
            report
                .timings
                .push(("uptime_large_cache".to_string(), uptime_large_cache_time));
        }
    }
}

/// Benchmark TCP processing overhead analysis
fn bench_tcp_processing_overhead(c: &mut Criterion) {
    let packets = match load_packets_repeated("../pcap/macos_tcp_flags.pcap", REPEAT_COUNT) {
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
    println!("  Total packets: {} (repeated {}x)", packets.len(), REPEAT_COUNT);
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

    // Measure and store processing overhead times
    let minimal_processing_time = measure_average_time(
        || {
            for packet in packets.iter() {
                let _ = huginn_net_tcp::packet_parser::parse_packet(packet);
            }
        },
        10,
    );

    let full_tcp_analysis_time = measure_average_time(
        || {
            let matcher = SignatureMatcher::new(&db);
            let mut tracker = TtlCache::new(1000);
            for packet in packets.iter() {
                let _ = process_tcp_packet(packet, &mut tracker, Some(&matcher));
            }
        },
        10,
    );

    let full_analysis_with_collection_time = measure_average_time(
        || {
            let matcher = SignatureMatcher::new(&db);
            let mut tracker = TtlCache::new(1000);
            let mut results = Vec::new();
            for packet in packets.iter() {
                if let Some(result) = process_tcp_packet(packet, &mut tracker, Some(&matcher)) {
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
            let _ = results.len();
        },
        10,
    );

    if let Ok(mut guard) = BENCHMARK_RESULTS.lock() {
        if let Some(ref mut report) = *guard {
            report
                .timings
                .push(("minimal_processing".to_string(), minimal_processing_time));
            report
                .timings
                .push(("full_tcp_analysis".to_string(), full_tcp_analysis_time));
            report.timings.push((
                "full_analysis_with_collection".to_string(),
                full_analysis_with_collection_time,
            ));
        }
    }
}

/// Benchmark TCP parallel processing with different worker counts
fn bench_tcp_parallel_processing(c: &mut Criterion) {
    let packets = match load_packets_repeated("../pcap/macos_tcp_flags.pcap", REPEAT_COUNT) {
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
        Ok(db) => std::sync::Arc::new(db),
        Err(e) => {
            eprintln!("Failed to load default database: {e}");
            return;
        }
    };

    println!("TCP Parallel Processing Analysis:");
    println!("  Total packets: {} (repeated {}x)", packets.len(), REPEAT_COUNT);
    println!("--------------------");

    let worker_counts = [2, 4, 8];
    let mut group = c.benchmark_group("TCP_Parallel_Processing");

    for &num_workers in &worker_counts {
        let bench_name = format!("parallel_{num_workers}_workers");
        group.bench_function(&bench_name, |b| {
            b.iter(|| {
                let (tx, rx) = std::sync::mpsc::channel();
                let pool = match huginn_net_tcp::parallel::WorkerPool::new(
                    num_workers,
                    100,
                    tx,
                    Some(db.clone()),
                    1000,
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
            let pool =
                match huginn_net_tcp::parallel::WorkerPool::new(2, 100, tx, Some(db.clone()), 1000)
                {
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
            let pool =
                match huginn_net_tcp::parallel::WorkerPool::new(4, 100, tx, Some(db.clone()), 1000)
                {
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
            let pool =
                match huginn_net_tcp::parallel::WorkerPool::new(8, 100, tx, Some(db.clone()), 1000)
                {
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
