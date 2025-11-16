use criterion::{criterion_group, criterion_main, Criterion};
use huginn_net_db::Database;
use huginn_net_http::{
    process_ipv4_packet, process_ipv6_packet, FlowKey, HttpProcessors, SignatureMatcher, TcpFlow,
};
use pcap_file::pcap::PcapReader;
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
    request_count: u32,
    response_count: u32,
    browser_detections: u32,
    server_detections: u32,
    http1_requests: u32,
    http2_requests: u32,
    timings: Vec<(String, Duration)>,
}

criterion_group!(
    http_benches,
    bench_http_browser_detection,
    bench_http_server_detection,
    bench_http_protocol_analysis,
    bench_http_processing_overhead,
    bench_http_parallel_processing,
    generate_final_report
);
criterion_main!(http_benches);

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

    let original_count = report.packet_count / REPEAT_COUNT;

    println!("\n");
    println!("===============================================================================");
    println!("                   HTTP BENCHMARK ANALYSIS REPORT                           ");
    println!("===============================================================================");
    println!();
    println!("PCAP Analysis Summary:");
    println!(
        "  - Total packets analyzed: {} (repeated {}x)",
        report.packet_count, REPEAT_COUNT
    );
    println!("  - Original PCAP packets: {original_count}");
    println!("  - HTTP requests: {}", report.request_count);
    println!("  - HTTP responses: {}", report.response_count);
    println!("  - Browser detections: {}", report.browser_detections);
    println!("  - Server detections: {}", report.server_detections);
    println!("  - HTTP/1.x requests: {}", report.http1_requests);
    println!("  - HTTP/2 requests: {}", report.http2_requests);
    let http_effectiveness = ((report.request_count.saturating_add(report.response_count)) as f64
        / report.packet_count as f64)
        * 100.0;
    println!("  - HTTP packet effectiveness: {http_effectiveness:.1}%");
    let detection_rate = if report.request_count > 0 {
        (report.browser_detections as f64 / report.request_count as f64) * 100.0
    } else {
        0.0
    };
    println!("  - Browser detection rate: {detection_rate:.1}%");
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
    let http_no_match = report
        .timings
        .iter()
        .find(|(name, _)| name.contains("without"))
        .map(|(_, t)| *t);
    let http_with_match = report
        .timings
        .iter()
        .find(|(name, _)| name.contains("with"))
        .map(|(_, t)| *t);
    let full_analysis = report
        .timings
        .iter()
        .find(|(name, _)| name.contains("full_http_analysis"))
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
            if name != "http_packet_parsing" {
                let overhead = calculate_overhead(baseline, per_packet);
                format!("{:>7.0}x", overhead / 100.0 + 1.0)
            } else {
                "  1.0x  ".to_string()
            }
        } else {
            "   -    ".to_string()
        };

        let display_name = name
            .replace("http_", "")
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

    if let (Some(no_match), Some(with_match)) = (http_no_match, http_with_match) {
        let overhead = calculate_overhead(no_match, with_match);
        println!(
            "  - HTTP without matching -> with matching: {overhead:.1}% (database lookup cost)"
        );
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
            "  - 1 Gbps (81,274 pps): {cpu_1gbps:.1}% CPU{}",
            if cpu_1gbps > 100.0 { " [OVERLOAD]" } else { "" }
        );
        println!(
            "  - 10 Gbps (812,740 pps): {cpu_10gbps:.1}% CPU{}",
            if cpu_10gbps > 100.0 {
                " [OVERLOAD]"
            } else {
                ""
            }
        );
    }

    // Parallel Mode Results
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
        println!("Parallel Mode (Multi-Worker):");
        println!("Note: Includes worker pool overhead and flow-based hashing");
        println!();

        if let Some(p2) = parallel_2 {
            let per_packet = p2
                .checked_div(report.packet_count as u32)
                .unwrap_or(Duration::ZERO);
            let throughput = calculate_throughput(per_packet, 1);
            let cpu_1gbps = (81274.0 / throughput) * 100.0;
            let cpu_10gbps = (812740.0 / throughput) * 100.0;
            println!("2 Workers:");
            println!("  - Throughput: {} packets/second", format_throughput(throughput));
            println!("  - 1 Gbps CPU: {cpu_1gbps:.1}%");
            println!("  - 10 Gbps CPU: {cpu_10gbps:.1}%");
            println!();
        }

        if let Some(p4) = parallel_4 {
            let per_packet = p4
                .checked_div(report.packet_count as u32)
                .unwrap_or(Duration::ZERO);
            let throughput = calculate_throughput(per_packet, 1);
            let cpu_1gbps = (81274.0 / throughput) * 100.0;
            let cpu_10gbps = (812740.0 / throughput) * 100.0;
            println!("4 Workers:");
            println!("  - Throughput: {} packets/second", format_throughput(throughput));
            println!("  - 1 Gbps CPU: {cpu_1gbps:.1}%");
            println!("  - 10 Gbps CPU: {cpu_10gbps:.1}%");
            println!();
        }

        if let Some(p8) = parallel_8 {
            let per_packet = p8
                .checked_div(report.packet_count as u32)
                .unwrap_or(Duration::ZERO);
            let throughput = calculate_throughput(per_packet, 1);
            let cpu_1gbps = (81274.0 / throughput) * 100.0;
            let cpu_10gbps = (812740.0 / throughput) * 100.0;
            println!("8 Workers:");
            println!("  - Throughput: {} packets/second", format_throughput(throughput));
            println!("  - 1 Gbps CPU: {cpu_1gbps:.1}%");
            println!("  - 10 Gbps CPU: {cpu_10gbps:.1}%");
            println!();
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

/// Process a packet using the public HTTP API
fn process_http_packet(
    packet: &[u8],
    http_flows: &mut TtlCache<FlowKey, TcpFlow>,
    http_processors: &HttpProcessors,
    matcher: Option<&SignatureMatcher>,
) -> Option<huginn_net_http::HttpAnalysisResult> {
    match huginn_net_http::packet_parser::parse_packet(packet) {
        huginn_net_http::packet_parser::IpPacket::Ipv4(ipv4) => {
            process_ipv4_packet(&ipv4, http_flows, http_processors, matcher).ok()
        }
        huginn_net_http::packet_parser::IpPacket::Ipv6(ipv6) => {
            process_ipv6_packet(&ipv6, http_flows, http_processors, matcher).ok()
        }
        huginn_net_http::packet_parser::IpPacket::None => None,
    }
}

/// Benchmark HTTP browser detection using simple GET PCAP
fn bench_http_browser_detection(c: &mut Criterion) {
    let packets = match load_packets_repeated("../pcap/http-simple-get.pcap", REPEAT_COUNT) {
        Ok(pkts) => pkts,
        Err(e) => {
            eprintln!("Failed to load HTTP simple GET PCAP file: {e}");
            return;
        }
    };

    if packets.is_empty() {
        eprintln!("No packets found in HTTP simple GET PCAP file");
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
    let http_processors = HttpProcessors::new();

    println!("HTTP Browser Detection Analysis:");
    println!("  Total packets: {} (repeated {}x)", packets.len(), REPEAT_COUNT);

    // Count HTTP analysis results
    let mut http_flows = TtlCache::new(1000);
    let mut request_count: u32 = 0;
    let mut response_count: u32 = 0;
    let mut browser_detections: u32 = 0;
    let mut server_detections: u32 = 0;
    let mut http1_requests: u32 = 0;
    let mut http2_requests: u32 = 0;

    for packet in &packets {
        if let Some(result) =
            process_http_packet(packet, &mut http_flows, &http_processors, Some(&matcher))
        {
            if let Some(request) = &result.http_request {
                request_count = request_count.saturating_add(1);
                if request.browser_matched.browser.is_some() {
                    browser_detections = browser_detections.saturating_add(1);
                }
                match request.sig.matching.version {
                    huginn_net_http::http::Version::V10 | huginn_net_http::http::Version::V11 => {
                        http1_requests = http1_requests.saturating_add(1);
                    }
                    huginn_net_http::http::Version::V20 => {
                        http2_requests = http2_requests.saturating_add(1);
                    }
                    _ => {}
                }
            }
            if let Some(response) = &result.http_response {
                response_count = response_count.saturating_add(1);
                if response.web_server_matched.web_server.is_some() {
                    server_detections = server_detections.saturating_add(1);
                }
            }
        }
    }

    println!("  HTTP requests: {request_count}");
    println!("  HTTP responses: {response_count}");
    println!("  Browser detections: {browser_detections}");
    println!("  Server detections: {server_detections}");
    println!("--------------------");

    // Initialize benchmark report
    if let Ok(mut guard) = BENCHMARK_RESULTS.lock() {
        *guard = Some(BenchmarkReport {
            packet_count: packets.len(),
            request_count,
            response_count,
            browser_detections,
            server_detections,
            http1_requests,
            http2_requests,
            timings: Vec::new(),
        });
    }

    let mut group = c.benchmark_group("HTTP_Browser_Detection");

    // Benchmark HTTP processing with browser matching
    group.bench_function("http_with_browser_matching", |b| {
        b.iter(|| {
            let matcher = SignatureMatcher::new(&db);
            let processors = HttpProcessors::new();
            let mut flows = TtlCache::new(1000);
            for packet in packets.iter() {
                let _ = process_http_packet(packet, &mut flows, &processors, Some(&matcher));
            }
        })
    });

    // Benchmark HTTP processing without browser matching
    group.bench_function("http_without_browser_matching", |b| {
        b.iter(|| {
            let processors = HttpProcessors::new();
            let mut flows = TtlCache::new(1000);
            for packet in packets.iter() {
                let _ = process_http_packet(packet, &mut flows, &processors, None);
            }
        })
    });

    // Benchmark raw packet parsing only
    group.bench_function("http_packet_parsing", |b| {
        b.iter(|| {
            for packet in packets.iter() {
                let _ = huginn_net_http::packet_parser::parse_packet(packet);
            }
        })
    });

    group.finish();

    // Measure and store actual times for reporting
    let http_with_match_time = measure_average_time(
        || {
            let matcher = SignatureMatcher::new(&db);
            let processors = HttpProcessors::new();
            let mut flows = TtlCache::new(1000);
            for packet in packets.iter() {
                let _ = process_http_packet(packet, &mut flows, &processors, Some(&matcher));
            }
        },
        10,
    );

    let http_without_match_time = measure_average_time(
        || {
            let processors = HttpProcessors::new();
            let mut flows = TtlCache::new(1000);
            for packet in packets.iter() {
                let _ = process_http_packet(packet, &mut flows, &processors, None);
            }
        },
        10,
    );

    let parsing_time = measure_average_time(
        || {
            for packet in packets.iter() {
                let _ = huginn_net_http::packet_parser::parse_packet(packet);
            }
        },
        10,
    );

    if let Ok(mut guard) = BENCHMARK_RESULTS.lock() {
        if let Some(ref mut report) = *guard {
            report
                .timings
                .push(("http_with_browser_matching".to_string(), http_with_match_time));
            report
                .timings
                .push(("http_without_browser_matching".to_string(), http_without_match_time));
            report
                .timings
                .push(("http_packet_parsing".to_string(), parsing_time));
        }
    }
}

/// Benchmark HTTP server detection performance
fn bench_http_server_detection(c: &mut Criterion) {
    let packets = match load_packets_repeated("../pcap/http-simple-get.pcap", REPEAT_COUNT) {
        Ok(pkts) => pkts,
        Err(e) => {
            eprintln!("Failed to load HTTP PCAP file: {e}");
            return;
        }
    };

    if packets.is_empty() {
        eprintln!("No packets found in HTTP PCAP file");
        return;
    }

    let db = match Database::load_default() {
        Ok(db) => db,
        Err(e) => {
            eprintln!("Failed to load default database: {e}");
            return;
        }
    };

    println!("HTTP Server Detection Analysis:");
    println!("  Total packets: {} (repeated {}x)", packets.len(), REPEAT_COUNT);

    // Count server detections
    let matcher = SignatureMatcher::new(&db);
    let http_processors = HttpProcessors::new();
    let mut http_flows = TtlCache::new(1000);
    let mut server_detections: u32 = 0;

    for packet in &packets {
        if let Some(result) =
            process_http_packet(packet, &mut http_flows, &http_processors, Some(&matcher))
        {
            if let Some(response) = result.http_response {
                if response.web_server_matched.web_server.is_some() {
                    server_detections = server_detections.saturating_add(1);
                }
            }
        }
    }

    println!("  Server detections: {server_detections}");
    println!("--------------------");

    let mut group = c.benchmark_group("HTTP_Server_Detection");

    // Benchmark server detection with database matching
    group.bench_function("server_with_matching", |b| {
        b.iter(|| {
            let matcher = SignatureMatcher::new(&db);
            let processors = HttpProcessors::new();
            let mut flows = TtlCache::new(1000);
            for packet in packets.iter() {
                if let Some(result) =
                    process_http_packet(packet, &mut flows, &processors, Some(&matcher))
                {
                    if let Some(response) = result.http_response {
                        // Access server information to ensure full processing
                        let _ = &response.web_server_matched;
                        let _ = &response.diagnosis;
                    }
                }
            }
        })
    });

    // Benchmark server detection without database matching
    group.bench_function("server_without_matching", |b| {
        b.iter(|| {
            let processors = HttpProcessors::new();
            let mut flows = TtlCache::new(1000);
            for packet in packets.iter() {
                if let Some(result) = process_http_packet(packet, &mut flows, &processors, None) {
                    if let Some(response) = result.http_response {
                        // Access basic response information
                        let _ = &response.diagnosis;
                    }
                }
            }
        })
    });

    group.finish();

    // Measure and store server detection times
    let server_with_match_time = measure_average_time(
        || {
            let matcher = SignatureMatcher::new(&db);
            let processors = HttpProcessors::new();
            let mut flows = TtlCache::new(1000);
            for packet in packets.iter() {
                if let Some(result) =
                    process_http_packet(packet, &mut flows, &processors, Some(&matcher))
                {
                    if let Some(response) = result.http_response {
                        let _ = &response.web_server_matched;
                        let _ = &response.diagnosis;
                    }
                }
            }
        },
        10,
    );

    let server_without_match_time = measure_average_time(
        || {
            let processors = HttpProcessors::new();
            let mut flows = TtlCache::new(1000);
            for packet in packets.iter() {
                if let Some(result) = process_http_packet(packet, &mut flows, &processors, None) {
                    if let Some(response) = result.http_response {
                        let _ = &response.diagnosis;
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
                .push(("server_with_matching".to_string(), server_with_match_time));
            report
                .timings
                .push(("server_without_matching".to_string(), server_without_match_time));
        }
    }
}

/// Benchmark HTTP protocol analysis performance (HTTP/1 vs HTTP/2)
fn bench_http_protocol_analysis(c: &mut Criterion) {
    let packets = match load_packets_repeated("../pcap/http-simple-get.pcap", REPEAT_COUNT) {
        Ok(pkts) => pkts,
        Err(e) => {
            eprintln!("Failed to load HTTP PCAP file: {e}");
            return;
        }
    };

    if packets.is_empty() {
        eprintln!("No packets found in HTTP PCAP file");
        return;
    }

    println!("HTTP Protocol Analysis:");
    println!("  Total packets: {} (repeated {}x)", packets.len(), REPEAT_COUNT);

    // Count HTTP protocol versions
    let http_processors = HttpProcessors::new();
    let mut http_flows = TtlCache::new(1000);
    let mut http1_requests: u32 = 0;
    let mut http2_requests: u32 = 0;

    for packet in &packets {
        if let Some(result) = process_http_packet(packet, &mut http_flows, &http_processors, None) {
            if let Some(request) = result.http_request {
                match request.sig.matching.version {
                    huginn_net_http::http::Version::V10 | huginn_net_http::http::Version::V11 => {
                        http1_requests = http1_requests.saturating_add(1);
                    }
                    huginn_net_http::http::Version::V20 => {
                        http2_requests = http2_requests.saturating_add(1);
                    }
                    _ => {} // V30, Any, etc.
                }
            }
        }
    }

    println!("  HTTP/1.x requests: {http1_requests}");
    println!("  HTTP/2 requests: {http2_requests}");
    println!("--------------------");

    let mut group = c.benchmark_group("HTTP_Protocol_Analysis");

    // Benchmark HTTP protocol detection
    group.bench_function("protocol_detection", |b| {
        b.iter(|| {
            let processors = HttpProcessors::new();
            let mut flows = TtlCache::new(1000);
            for packet in packets.iter() {
                if let Some(result) = process_http_packet(packet, &mut flows, &processors, None) {
                    // Access protocol version information
                    if let Some(request) = &result.http_request {
                        let _ = request.sig.matching.version;
                    }
                    if let Some(response) = &result.http_response {
                        let _ = response.sig.matching.version;
                    }
                }
            }
        })
    });

    // Benchmark HTTP header analysis
    group.bench_function("header_analysis", |b| {
        b.iter(|| {
            let processors = HttpProcessors::new();
            let mut flows = TtlCache::new(1000);
            for packet in packets.iter() {
                if let Some(result) = process_http_packet(packet, &mut flows, &processors, None) {
                    if let Some(request) = &result.http_request {
                        // Access header information to ensure full processing
                        let _ = &request.sig.headers;
                        let _ = &request.lang;
                    }
                    if let Some(response) = &result.http_response {
                        let _ = &response.sig.headers;
                    }
                }
            }
        })
    });

    // Benchmark with different flow cache sizes
    group.bench_function("small_flow_cache", |b| {
        b.iter(|| {
            let processors = HttpProcessors::new();
            let mut flows = TtlCache::new(100); // Smaller cache
            for packet in packets.iter() {
                let _ = process_http_packet(packet, &mut flows, &processors, None);
            }
        })
    });

    group.bench_function("large_flow_cache", |b| {
        b.iter(|| {
            let processors = HttpProcessors::new();
            let mut flows = TtlCache::new(10000); // Larger cache
            for packet in packets.iter() {
                let _ = process_http_packet(packet, &mut flows, &processors, None);
            }
        })
    });

    group.finish();

    // Measure and store protocol analysis times
    let protocol_detection_time = measure_average_time(
        || {
            let processors = HttpProcessors::new();
            let mut flows = TtlCache::new(1000);
            for packet in packets.iter() {
                if let Some(result) = process_http_packet(packet, &mut flows, &processors, None) {
                    if let Some(request) = &result.http_request {
                        let _ = request.sig.matching.version;
                    }
                    if let Some(response) = &result.http_response {
                        let _ = response.sig.matching.version;
                    }
                }
            }
        },
        10,
    );

    let header_analysis_time = measure_average_time(
        || {
            let processors = HttpProcessors::new();
            let mut flows = TtlCache::new(1000);
            for packet in packets.iter() {
                if let Some(result) = process_http_packet(packet, &mut flows, &processors, None) {
                    if let Some(request) = &result.http_request {
                        let _ = &request.sig.headers;
                        let _ = &request.lang;
                    }
                    if let Some(response) = &result.http_response {
                        let _ = &response.sig.headers;
                    }
                }
            }
        },
        10,
    );

    let small_cache_time = measure_average_time(
        || {
            let processors = HttpProcessors::new();
            let mut flows = TtlCache::new(100);
            for packet in packets.iter() {
                let _ = process_http_packet(packet, &mut flows, &processors, None);
            }
        },
        10,
    );

    let large_cache_time = measure_average_time(
        || {
            let processors = HttpProcessors::new();
            let mut flows = TtlCache::new(10000);
            for packet in packets.iter() {
                let _ = process_http_packet(packet, &mut flows, &processors, None);
            }
        },
        10,
    );

    if let Ok(mut guard) = BENCHMARK_RESULTS.lock() {
        if let Some(ref mut report) = *guard {
            report
                .timings
                .push(("protocol_detection".to_string(), protocol_detection_time));
            report
                .timings
                .push(("header_analysis".to_string(), header_analysis_time));
            report
                .timings
                .push(("small_flow_cache".to_string(), small_cache_time));
            report
                .timings
                .push(("large_flow_cache".to_string(), large_cache_time));
        }
    }
}

/// Benchmark HTTP processing overhead analysis
fn bench_http_processing_overhead(c: &mut Criterion) {
    let packets = match load_packets_repeated("../pcap/http-simple-get.pcap", REPEAT_COUNT) {
        Ok(pkts) => pkts,
        Err(e) => {
            eprintln!("Failed to load HTTP PCAP file: {e}");
            return;
        }
    };

    if packets.is_empty() {
        eprintln!("No packets found in HTTP PCAP file");
        return;
    }

    let db = match Database::load_default() {
        Ok(db) => db,
        Err(e) => {
            eprintln!("Failed to load default database: {e}");
            return;
        }
    };

    println!("HTTP Processing Overhead Analysis:");
    println!("  Total packets: {} (repeated {}x)", packets.len(), REPEAT_COUNT);
    println!("--------------------");

    let mut group = c.benchmark_group("HTTP_Processing_Overhead");

    // Benchmark minimal HTTP processing
    group.bench_function("minimal_processing", |b| {
        b.iter(|| {
            for packet in packets.iter() {
                let _ = huginn_net_http::packet_parser::parse_packet(packet);
            }
        })
    });

    // Benchmark full HTTP analysis
    group.bench_function("full_http_analysis", |b| {
        b.iter(|| {
            let matcher = SignatureMatcher::new(&db);
            let processors = HttpProcessors::new();
            let mut flows = TtlCache::new(1000);
            for packet in packets.iter() {
                let _ = process_http_packet(packet, &mut flows, &processors, Some(&matcher));
            }
        })
    });

    // Benchmark with result collection
    group.bench_function("full_analysis_with_collection", |b| {
        b.iter(|| {
            let matcher = SignatureMatcher::new(&db);
            let processors = HttpProcessors::new();
            let mut flows = TtlCache::new(1000);
            let mut results = Vec::new();

            for packet in packets.iter() {
                if let Some(result) =
                    process_http_packet(packet, &mut flows, &processors, Some(&matcher))
                {
                    // Collect all HTTP analysis results
                    results.push((
                        result.http_request.is_some(),
                        result.http_response.is_some(),
                        result.http_request.as_ref().and_then(|r| {
                            r.browser_matched.browser.as_ref().map(|b| b.name.clone())
                        }),
                        result.http_response.as_ref().and_then(|r| {
                            r.web_server_matched
                                .web_server
                                .as_ref()
                                .map(|s| s.name.clone())
                        }),
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
                let _ = huginn_net_http::packet_parser::parse_packet(packet);
            }
        },
        10,
    );

    let full_http_analysis_time = measure_average_time(
        || {
            let matcher = SignatureMatcher::new(&db);
            let processors = HttpProcessors::new();
            let mut flows = TtlCache::new(1000);
            for packet in packets.iter() {
                let _ = process_http_packet(packet, &mut flows, &processors, Some(&matcher));
            }
        },
        10,
    );

    let full_analysis_with_collection_time = measure_average_time(
        || {
            let matcher = SignatureMatcher::new(&db);
            let processors = HttpProcessors::new();
            let mut flows = TtlCache::new(1000);
            let mut results = Vec::new();
            for packet in packets.iter() {
                if let Some(result) =
                    process_http_packet(packet, &mut flows, &processors, Some(&matcher))
                {
                    results.push((
                        result.http_request.is_some(),
                        result.http_response.is_some(),
                        result.http_request.as_ref().and_then(|r| {
                            r.browser_matched.browser.as_ref().map(|b| b.name.clone())
                        }),
                        result.http_response.as_ref().and_then(|r| {
                            r.web_server_matched
                                .web_server
                                .as_ref()
                                .map(|s| s.name.clone())
                        }),
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
                .push(("full_http_analysis".to_string(), full_http_analysis_time));
            report.timings.push((
                "full_analysis_with_collection".to_string(),
                full_analysis_with_collection_time,
            ));
        }
    }
}

/// Benchmark HTTP parallel processing with different worker counts
fn bench_http_parallel_processing(c: &mut Criterion) {
    use std::sync::Arc;

    let packets = match load_packets_repeated("../pcap/http-simple-get.pcap", REPEAT_COUNT) {
        Ok(pkts) => pkts,
        Err(e) => {
            eprintln!("Failed to load HTTP PCAP file for parallel benchmark: {e}");
            return;
        }
    };

    if packets.is_empty() {
        eprintln!("No packets found in HTTP PCAP file for parallel benchmark");
        return;
    }

    let db = match Database::load_default() {
        Ok(db) => Arc::new(db),
        Err(e) => {
            eprintln!("Failed to load default database: {e}");
            return;
        }
    };

    println!("HTTP Parallel Processing Analysis:");
    println!("  Total packets: {} (repeated {}x)", packets.len(), REPEAT_COUNT);
    println!("--------------------");

    let worker_counts = [2, 4, 8];
    let mut group = c.benchmark_group("HTTP_Parallel_Processing");

    for &num_workers in &worker_counts {
        let bench_name = format!("parallel_{num_workers}_workers");
        group.bench_function(&bench_name, |b| {
            b.iter(|| {
                let (tx, rx) = std::sync::mpsc::channel();
                let pool = match huginn_net_http::WorkerPool::new(
                    num_workers,
                    100,
                    16,
                    10,
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
            let pool = match huginn_net_http::WorkerPool::new(
                2,
                100,
                16,
                10,
                tx,
                Some(db.clone()),
                1000,
            ) {
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
            let pool = match huginn_net_http::WorkerPool::new(
                4,
                100,
                16,
                10,
                tx,
                Some(db.clone()),
                1000,
            ) {
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
            let pool = match huginn_net_http::WorkerPool::new(
                8,
                100,
                16,
                10,
                tx,
                Some(db.clone()),
                1000,
            ) {
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
