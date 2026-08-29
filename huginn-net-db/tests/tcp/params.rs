//! `Dist:` / `params` from a TCP match: hop distance, `random_ttl`, `excess_dist`, `tos`.

use huginn_net_db::database::{FingerprintCollection, Label, Type};
use huginn_net_db::tcp::{
    report_hop_distance, IpVersion, PayloadSize, QuirkSet, Signature, Ttl, WindowSize,
    MAX_TTL_DISTANCE,
};
use huginn_net_db::{TcpDatabase, TcpSignatureMatcher};
use huginn_net_tcp::matcher_api::TcpMatcher;
use huginn_net_tcp::observable::TcpObservation;
use huginn_net_tcp::output::{MatchQuality, OSQualityMatched};
use huginn_net_tcp::ttl::guess_distance;

fn observation(ittl: Ttl, tos: u8) -> TcpObservation {
    TcpObservation {
        version: IpVersion::V4,
        ittl,
        olen: 0,
        mss: Some(1460),
        wsize: 65535,
        tot_hdr: 40,
        wscale: Some(6),
        olayout: Vec::new(),
        quirks: QuirkSet::EMPTY,
        pclass: PayloadSize::Zero,
        peer_mss: None,
        tos,
    }
}

fn signature(ittl: Ttl) -> Signature {
    Signature {
        version: IpVersion::V4,
        ittl,
        olen: 0,
        mss: Some(1460),
        wsize: WindowSize::Value(65535),
        wscale: Some(6),
        olayout: Vec::new(),
        quirks: QuirkSet::EMPTY,
        pclass: PayloadSize::Zero,
    }
}

fn label(name: &str) -> Label {
    Label {
        name: name.into(),
        class: Some("unix".into()),
        flavor: Some("test".into()),
        ty: Type::Specified,
    }
}

#[test]
fn report_hop_distance_uses_signature_hops_when_in_range() {
    assert_eq!(report_hop_distance(&Ttl::Value(58), &Ttl::Value(64)), 6);
}

#[test]
fn report_hop_distance_guesses_when_out_of_range() {
    let observed = Ttl::Value(20);
    assert_eq!(report_hop_distance(&observed, &Ttl::Value(64)), guess_distance(20));
}

#[test]
fn tcp_matcher_fills_random_ttl_dist_and_params_tos() {
    let db = TcpDatabase {
        classes: vec!["unix".into()],
        mtu: vec![],
        tcp_request: FingerprintCollection::new(vec![(
            label("RandomTTL"),
            vec![signature(Ttl::Bad(64))],
        )]),
        tcp_response: FingerprintCollection::default(),
    };
    let obs = observation(Ttl::Value(50), 0x2e);
    let found = TcpSignatureMatcher::new(&db)
        .match_tcp_request(&obs)
        .unwrap_or_else(|| panic!("bad-ttl signature should match"));

    assert!(found.random_ttl);
    assert_eq!(found.dist, 14);
    assert!(!found.excess_dist);

    let matched = OSQualityMatched {
        os: Some(found.os),
        quality: MatchQuality::Matched(found.rank),
        dist: found.dist,
        random_ttl: found.random_ttl,
        excess_dist: found.excess_dist,
        tos: obs.tos,
    };
    let params = matched.params();
    assert!(params.contains("random_ttl"), "{params}");
    assert!(params.contains("tos:0x2e"), "{params}");
}

#[test]
fn unmatched_params_can_still_report_tos_and_excess_dist() {
    // Observed TTL 65 → guess_dist = 63 (> 35).
    let obs = observation(Ttl::Value(65), 0x10);
    let unmatched = OSQualityMatched::without_match(MatchQuality::NotMatched, &obs);
    let params = unmatched.params();
    assert!(params.contains("excess_dist"), "{params}");
    assert!(params.contains("tos:0x10"), "{params}");
    assert_eq!(unmatched.dist, guess_distance(65));
    assert!(unmatched.dist > MAX_TTL_DISTANCE);
}
