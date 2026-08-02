#![cfg(feature = "tcp")]
//! Which candidate wins when several signatures fit the same observation.
//!
//! p0f does not pick the numerically closest signature. It returns the first
//! exact match on a signature naming a concrete product, falls back to a
//! catch-all one only after exhausting the list, and treats a match that needed
//! a tolerance as the last resort (`fp_tcp.c:221-271`). These tests build small
//! databases by hand so the order of preference is the only thing under test.

use huginn_net_db::database::{FingerprintCollection, Label, TcpIndexKey, Type};
use huginn_net_db::db_matching_trait::FingerprintDb;
use huginn_net_db::tcp::{IpVersion, PayloadSize, Quirk, QuirkSet, Signature, Ttl, WindowSize};
use huginn_net_tcp::observable::TcpObservation;

type TcpCollection = FingerprintCollection<TcpObservation, Signature, TcpIndexKey>;

fn observation() -> TcpObservation {
    TcpObservation {
        version: IpVersion::V4,
        ittl: Ttl::Value(64),
        olen: 0,
        mss: Some(1460),
        wsize: 65535,
        tot_hdr: 40,
        wscale: Some(6),
        olayout: Vec::new(),
        quirks: QuirkSet::EMPTY,
        pclass: PayloadSize::Zero,
        peer_mss: None,
        tos: 0,
    }
}

/// Fits [`observation`] exactly.
fn signature() -> Signature {
    Signature {
        version: IpVersion::V4,
        ittl: Ttl::Value(64),
        olen: 0,
        mss: Some(1460),
        wsize: WindowSize::Value(65535),
        wscale: Some(6),
        olayout: Vec::new(),
        quirks: QuirkSet::EMPTY,
        pclass: PayloadSize::Zero,
    }
}

/// Only fits [`observation`] through the quirks whitelist: p0f lets `df`
/// disappear from the traffic, but the match is fuzzy.
fn fuzzy_signature() -> Signature {
    Signature { quirks: QuirkSet::from([Quirk::Df]), ..signature() }
}

fn label(name: &str, ty: Type) -> Label {
    Label { ty, class: Some("unix".to_string()), name: name.to_string(), flavor: None }
}

/// An application rather than an OS: p0f writes these as `s:!:…`, which parses
/// to a label with no class.
fn application_label(name: &str) -> Label {
    Label { ty: Type::Specified, class: None, name: name.to_string(), flavor: None }
}

fn best_match(entries: Vec<(Label, Vec<Signature>)>) -> Option<(String, f32)> {
    let collection = TcpCollection::new(entries);
    collection
        .find_best_match(&observation())
        .map(|found| (found.label.name.clone(), found.quality))
}

#[test]
fn a_specific_signature_wins_over_a_generic_one_whatever_the_database_order() {
    for reversed in [false, true] {
        let mut entries = vec![
            (label("Generic OS", Type::Generic), vec![signature()]),
            (label("Specific OS", Type::Specified), vec![signature()]),
        ];
        if reversed {
            entries.reverse();
        }

        let (name, quality) = best_match(entries).unwrap_or_else(|| panic!("expected a match"));
        assert_eq!(name, "Specific OS");
        assert_eq!(quality, 1.0);
    }
}

#[test]
fn an_exact_generic_match_wins_over_a_fuzzy_specific_one() {
    // p0f keeps its fuzzy candidate aside and only reaches for it once no
    // generic signature fit either, so a tolerance never outranks an exact fit.
    let (name, quality) = best_match(vec![
        (label("Fuzzy Specific OS", Type::Specified), vec![fuzzy_signature()]),
        (label("Generic OS", Type::Generic), vec![signature()]),
    ])
    .unwrap_or_else(|| panic!("expected a match"));

    assert_eq!(name, "Generic OS");
    assert_eq!(quality, 0.8);
}

#[test]
fn a_fuzzy_match_is_reported_when_nothing_fits_exactly() {
    let (name, quality) =
        best_match(vec![(label("Fuzzy OS", Type::Specified), vec![fuzzy_signature()])])
            .unwrap_or_else(|| panic!("expected a fuzzy match"));

    assert_eq!(name, "Fuzzy OS");
    assert_eq!(quality, 0.5);
}

#[test]
fn an_application_is_never_reported_on_a_fuzzy_match() {
    // "No fuzzy matching for userland tools": guessing which tool sent a packet
    // from an approximate match is worse than saying nothing.
    assert_eq!(best_match(vec![(application_label("NMap"), vec![fuzzy_signature()])]), None);
}

#[test]
fn an_application_is_still_reported_on_an_exact_match() {
    let (name, _quality) = best_match(vec![(application_label("NMap"), vec![signature()])])
        .unwrap_or_else(|| panic!("an exact fit against an application signature is a match"));

    assert_eq!(name, "NMap");
}

#[test]
fn a_userland_fuzzy_first_blocks_a_later_fuzzy_os_match() {
    // p0f stores the first fuzzy whatever its class, then refuses to report it
    // when that fuzzy is userland (`fp_tcp.c:234,256`). Skipping NMap and
    // returning Linux would be our old behaviour, not p0f's.
    assert_eq!(
        best_match(vec![
            (application_label("NMap"), vec![fuzzy_signature()]),
            (label("Linux", Type::Specified), vec![fuzzy_signature()]),
        ]),
        None
    );
}

#[test]
fn within_a_tier_the_first_signature_in_database_order_wins() {
    // p0f does not break ties by hop distance: the first exact specific in the
    // `.fp` / bucket wins. Both of these fit exactly (observed TTL 64 is within
    // range of an initial 255).
    let far = Signature { ittl: Ttl::Bad(255), ..signature() };
    let near = signature();

    let (name, _) = best_match(vec![
        (label("Far OS", Type::Specified), vec![far.clone()]),
        (label("Near OS", Type::Specified), vec![near.clone()]),
    ])
    .unwrap_or_else(|| panic!("expected a match"));
    assert_eq!(name, "Far OS");

    let (name, _) = best_match(vec![
        (label("Near OS", Type::Specified), vec![near]),
        (label("Far OS", Type::Specified), vec![far]),
    ])
    .unwrap_or_else(|| panic!("expected a match"));
    assert_eq!(name, "Near OS");
}
