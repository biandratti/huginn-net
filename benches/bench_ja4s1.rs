//! `JA4_s1` list cost: hardcoded denylist vs the caller workaround.
//!
//! Measures at `Signature` level. Packet benches in `bench_tls.rs` sit around
//! 5.6 µs/packet, dominated by TCP reassembly; tens of nanoseconds in the
//! extension filter are invisible there.
//!
//! The workaround (drop a caller-supplied denylist from `Signature::extensions`,
//! then `generate_ja4()`) is byte-identical to `generate_ja4_stable_v1()` when
//! the list is `S1_SESSION_EXTENSIONS`. `generate_ja4_stable_v1_with_extra`
//! is the labeled form of that path: empty `extra` delegates to the hardcoded
//! method; a non-empty `extra` clones and drops those IDs, then calls s1.
//!
//! ```bash
//! cargo bench -p huginn-net-tls --bench bench_ja4s1 --features stable-v1
//! ```

use criterion::{criterion_group, criterion_main, Criterion};
use huginn_net_tls::{
    packet_parser, process_ipv4_packet, process_ipv6_packet, FlowKey, Ja4Payload, Signature,
    TlsClientHelloReader, S1_SESSION_EXTENSIONS,
};
use pcap_file::pcap::PcapReader;
use std::fs::File;
use std::hint::black_box;
use std::time::Duration;
use ttl_cache::TtlCache;

/// Captures holding a ClientHello, tried in order until one parses.
/// Anchored at the crate manifest so the bench does not depend on cwd.
const PCAP_CANDIDATES: [&str; 3] = [
    concat!(env!("CARGO_MANIFEST_DIR"), "/../pcap/macos_safari_tls_extensions.pcap"),
    concat!(env!("CARGO_MANIFEST_DIR"), "/../pcap/tls12.pcap"),
    concat!(env!("CARGO_MANIFEST_DIR"), "/../pcap/tls-alpn-h2.pcap"),
];

/// Hypothetical extra session types a caller would add to widen the denylist.
const EXTRA_IDS: [u16; 3] = [0x7550, 0x0aaa, 0xca34];

criterion_group!(ja4s1_benches, bench_ja4s1_list_cost);
criterion_main!(ja4s1_benches);

fn process_tls_packet(
    packet: &[u8],
    tcp_flows: &mut TtlCache<FlowKey, TlsClientHelloReader>,
) -> Option<huginn_net_tls::TlsClientOutput> {
    match packet_parser::parse_packet(packet) {
        packet_parser::IpPacket::Ipv4(ipv4) => process_ipv4_packet(&ipv4, tcp_flows).ok().flatten(),
        packet_parser::IpPacket::Ipv6(ipv6) => process_ipv6_packet(&ipv6, tcp_flows).ok().flatten(),
        packet_parser::IpPacket::None => None,
    }
}

fn signature_from_output(out: huginn_net_tls::TlsClientOutput) -> Signature {
    Signature {
        version: out.sig.version,
        cipher_suites: out.sig.cipher_suites,
        extensions: out.sig.extensions,
        elliptic_curves: out.sig.elliptic_curves,
        elliptic_curve_point_formats: Vec::new(),
        signature_algorithms: out.sig.signature_algorithms,
        sni: out.sig.sni,
        alpn: out.sig.alpn,
    }
}

/// First real ClientHello from the candidate captures, via the public packet API.
fn load_signature() -> Option<(Signature, &'static str)> {
    for path in PCAP_CANDIDATES {
        let Ok(file) = File::open(path) else {
            continue;
        };
        let Ok(mut reader) = PcapReader::new(file) else {
            continue;
        };
        let mut tcp_flows = TtlCache::new(256);
        while let Some(Ok(pkt)) = reader.next_packet() {
            if let Some(out) = process_tls_packet(&pkt.data, &mut tcp_flows) {
                return Some((signature_from_output(out), path));
            }
        }
    }
    None
}

/// Drop `deny` from a clone, then official sorted JA4.
fn s1_via_prefilter(sig: &Signature, deny: &[u16]) -> Ja4Payload {
    let mut custom = sig.clone();
    custom.extensions.retain(|e| !deny.contains(e));
    custom.generate_ja4()
}

fn bench_ja4s1_list_cost(c: &mut Criterion) {
    let Some((sig, path)) = load_signature() else {
        eprintln!("bench_ja4s1: no ClientHello found in {PCAP_CANDIDATES:?}, skipping");
        return;
    };

    let session_dropped = sig
        .extensions
        .iter()
        .filter(|e| S1_SESSION_EXTENSIONS.contains(e))
        .count();
    let canonical = sig.generate_ja4_stable_v1();
    let emulated = s1_via_prefilter(&sig, S1_SESSION_EXTENSIONS);

    println!("JA4_s1 list cost");
    println!("  capture:               {path}");
    println!("  extensions:            {}", sig.extensions.len());
    println!("  ciphers:               {}", sig.cipher_suites.len());
    println!("  session types dropped: {session_dropped}");
    println!("  JA4:                   {}", sig.generate_ja4().full.value());
    println!("  JA4_s1:                {}", canonical.full.value());
    println!("--------------------");
    println!("Equivalence (canonical list, value only):");
    println!("  generate_ja4_stable_v1  {}", canonical.full.value());
    println!("  pre-filter + ja4        {}", emulated.full.value());
    println!(
        "  full equal: {}   raw equal: {}   tags: {} vs {}",
        canonical.full.value() == emulated.full.value(),
        canonical.raw.value() == emulated.raw.value(),
        canonical.full.variant_name(),
        emulated.full.variant_name()
    );
    println!("--------------------");

    let mut wider = S1_SESSION_EXTENSIONS.to_vec();
    wider.extend_from_slice(&EXTRA_IDS);

    let mut group = c.benchmark_group("JA4_S1_ListCost");
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));

    group.bench_function("ja4_official", |b| b.iter(|| black_box(black_box(&sig).generate_ja4())));

    group.bench_function("s1_canonical_hardcoded", |b| {
        b.iter(|| black_box(black_box(&sig).generate_ja4_stable_v1()))
    });

    group.bench_function("s1_prefilter_canonical_list", |b| {
        b.iter(|| black_box(s1_via_prefilter(black_box(&sig), black_box(S1_SESSION_EXTENSIONS))))
    });

    group.bench_function("s1_prefilter_wider_list", |b| {
        b.iter(|| black_box(s1_via_prefilter(black_box(&sig), black_box(&wider))))
    });

    group.bench_function("s1_extra_empty", |b| {
        b.iter(|| black_box(black_box(&sig).generate_ja4_stable_v1_with_extra(&[])))
    });

    group.bench_function("s1_extra_three", |b| {
        b.iter(|| {
            black_box(black_box(&sig).generate_ja4_stable_v1_with_extra(black_box(&EXTRA_IDS)))
        })
    });

    group.finish();
}
