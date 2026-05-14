//! Layer 2 golden test: feed known-good raw TCP signatures through the
//! database matcher and check the resulting OS.
//!
//! This complements the Layer 1 test in
//! `huginn-net-tcp/tests/golden_tests.rs`, which only verifies that
//! `huginn-net-tcp` extracts the same raw signature from a PCAP. Here we
//! exercise the `huginn-net-db` matching half: given a textual signature,
//! we parse it as a `tcp::Signature`, construct an equivalent
//! `TcpObservation`, and ask `TcpSignatureMatcher` to identify the OS.

#![cfg(feature = "tcp")]
use huginn_net_db::observable_signals::TcpObservation;
use huginn_net_db::tcp::Signature;
use huginn_net_db::{TcpDatabase, TcpSignatureMatcher};
use huginn_net_tcp::ObservableTcp;

/// Build a `TcpObservation` whose fields exactly mirror a parsed `tcp::Signature`.
///
/// Database signatures (`tcp::Signature`) and observed fingerprints
/// (`TcpObservation`) share the same field shape; this helper makes the
/// round-trip "string → DB signature → observation" explicit.
fn observation_from_signature(sig: &Signature) -> TcpObservation {
    TcpObservation {
        version: sig.version,
        ittl: sig.ittl.clone(),
        olen: sig.olen,
        mss: sig.mss,
        wsize: sig.wsize.clone(),
        wscale: sig.wscale,
        olayout: sig.olayout.clone(),
        quirks: sig.quirks.clone(),
        pclass: sig.pclass,
    }
}

/// Parses `raw` as a TCP signature and runs it through `matching_by_tcp_request`.
///
/// Returns `(name, class, flavor, quality)` of the matched OS.
fn match_request(
    matcher: &TcpSignatureMatcher,
    raw: &str,
) -> Option<(String, Option<String>, Option<String>, f32)> {
    let sig: Signature = match raw.parse() {
        Ok(sig) => sig,
        Err(e) => panic!("Failed to parse signature {raw}: {e}"),
    };
    let obs = ObservableTcp { matching: observation_from_signature(&sig) };
    let (label, _, quality) = matcher.matching_by_tcp_request(&obs)?;
    Some((label.name.clone(), label.class.clone(), label.flavor.clone(), quality))
}

#[test]
fn matches_known_request_signatures() {
    let db = match TcpDatabase::load_default() {
        Ok(db) => db,
        Err(e) => panic!("Failed to load default database: {e}"),
    };
    let matcher = TcpSignatureMatcher::new(&db);

    // Each entry is: (raw signature, expected OS name, expected flavor, expected quality).
    // The quality must be 1.0 for an exact match against the bundled p0f.fp.
    let cases = [
        // Generic Linux 2.2.x-3.x SYN signature.
        (
            "4:58+6:0:1452:mss*44,7:mss,sok,ts,nop,ws:df,id+:0",
            "Linux",
            Some("2.2.x-3.x"),
            1.0,
        ),
        // Android SYN (raw value 65535 / WS 8 — matches the Android variant).
        (
            "4:64+0:0:1460:65535,8:mss,sok,ts,nop,ws:df,id+:0",
            "Linux",
            Some("Android"),
            1.0,
        ),
    ];

    for (raw, expected_name, expected_flavor, expected_quality) in cases {
        match match_request(&matcher, raw) {
            Some((name, _class, flavor, quality)) => {
                assert_eq!(name, expected_name, "name mismatch for sig: {raw}");
                assert_eq!(flavor.as_deref(), expected_flavor, "flavor mismatch for sig: {raw}");
                assert!(
                    (quality - expected_quality).abs() < f32::EPSILON,
                    "quality mismatch for sig {raw}: got {quality}, expected {expected_quality}"
                );
            }
            None => panic!("expected a match for: {raw}"),
        }
    }
}

#[test]
fn unknown_request_signature_does_not_match() {
    let db = match TcpDatabase::load_default() {
        Ok(db) => db,
        Err(e) => panic!("Failed to load default database: {e}"),
    };
    let matcher = TcpSignatureMatcher::new(&db);

    // From the macOS golden snapshot: this signature has no exact entry in
    // p0f.fp and historically produced `os: None / quality: NotMatched`.
    let raw = "4:64+0:0:1460:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1,eol+0:df,ecn:0";
    let result = match_request(&matcher, raw);
    assert!(
        result.is_none(),
        "expected no match for synthetic signature: {raw}, got {result:?}"
    );
}
