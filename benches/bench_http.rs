use criterion::{criterion_group, criterion_main, Criterion};
use huginn_net_db::Database;
use huginn_net_http::{
    process_ipv4_packet, process_ipv6_packet, FlowKey, HttpProcessors, SignatureMatcher, TcpFlow,
};
use pcap_file::pcap::PcapReader;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use std::error::Error;
use std::fs::File;
use ttl_cache::TtlCache;

criterion_group!(
    http_benches,
    bench_http_browser_detection,
    bench_http_server_detection,
    bench_http_protocol_analysis,
    bench_http_processing_overhead
);
criterion_main!(http_benches);

fn load_packets_from_pcap(pcap_path: &str) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let file = File::open(pcap_path)?;
    let mut pcap_reader = PcapReader::new(file)?;
    let mut packets = Vec::new();
    while let Some(pkt) = pcap_reader.next_packet() {
        packets.push(pkt?.data.into());
    }
    Ok(packets)
}

/// Process a packet using the public HTTP API
fn process_http_packet(
    packet: &[u8],
    http_flows: &mut TtlCache<FlowKey, TcpFlow>,
    http_processors: &HttpProcessors,
    matcher: Option<&SignatureMatcher>,
) -> Option<huginn_net_http::HttpAnalysisResult> {
    match huginn_net_http::packet_parser::parse_packet(packet) {
        huginn_net_http::packet_parser::IpPacket::Ipv4(ip_data) => {
            if let Some(ipv4) = Ipv4Packet::new(ip_data) {
                process_ipv4_packet(&ipv4, http_flows, http_processors, matcher).ok()
            } else {
                None
            }
        }
        huginn_net_http::packet_parser::IpPacket::Ipv6(ip_data) => {
            if let Some(ipv6) = Ipv6Packet::new(ip_data) {
                process_ipv6_packet(&ipv6, http_flows, http_processors, matcher).ok()
            } else {
                None
            }
        }
        huginn_net_http::packet_parser::IpPacket::None => None,
    }
}

/// Benchmark HTTP browser detection using simple GET PCAP
fn bench_http_browser_detection(c: &mut Criterion) {
    let packets = match load_packets_from_pcap("../pcap/http-simple-get.pcap") {
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
    println!("  Total packets: {}", packets.len());

    // Count HTTP analysis results
    let mut http_flows = TtlCache::new(1000);
    let mut request_count: u32 = 0;
    let mut response_count: u32 = 0;
    let mut browser_detections: u32 = 0;
    let mut server_detections: u32 = 0;

    for packet in &packets {
        if let Some(result) =
            process_http_packet(packet, &mut http_flows, &http_processors, Some(&matcher))
        {
            if let Some(request) = &result.http_request {
                request_count = request_count.saturating_add(1);
                if request.browser_matched.browser.is_some() {
                    browser_detections = browser_detections.saturating_add(1);
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
}

/// Benchmark HTTP server detection performance
fn bench_http_server_detection(c: &mut Criterion) {
    let packets = match load_packets_from_pcap("../pcap/http-simple-get.pcap") {
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
    println!("  Total packets: {}", packets.len());

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
}

/// Benchmark HTTP protocol analysis performance (HTTP/1 vs HTTP/2)
fn bench_http_protocol_analysis(c: &mut Criterion) {
    let packets = match load_packets_from_pcap("../pcap/http-simple-get.pcap") {
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
    println!("  Total packets: {}", packets.len());

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
}

/// Benchmark HTTP processing overhead analysis
fn bench_http_processing_overhead(c: &mut Criterion) {
    let packets = match load_packets_from_pcap("../pcap/http-simple-get.pcap") {
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
    println!("  Total packets: {}", packets.len());
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
}
