#![cfg(feature = "tcp")]
//! Window match: raw `wsize` vs the signature form (`mss*n`, literal, peer MSS).

use huginn_net_db::tcp::{IpVersion, PayloadSize, Quirk, TcpOption};
use huginn_net_db::{TcpDatabase, TcpSignatureMatcher};
use huginn_net_tcp::observable::TcpObservation;
use huginn_net_tcp::ObservableTcp;

/// Builds an observation the way the packet pipeline does: from wire values,
/// not from a database signature.
fn observed(
    raw_ttl: u8,
    mss: Option<u16>,
    window: u16,
    wscale: Option<u8>,
    olayout: Vec<TcpOption>,
    quirks: Vec<Quirk>,
    peer_mss: Option<u16>,
) -> ObservableTcp {
    ObservableTcp {
        matching: TcpObservation {
            version: IpVersion::V4,
            ittl: huginn_net_tcp::ttl::calculate_ttl(raw_ttl),
            olen: 0,
            mss,
            wsize: window,
            tot_hdr: u16::try_from(olayout.len())
                .unwrap_or(0)
                .saturating_add(5)
                .saturating_mul(4)
                .saturating_add(20),
            wscale,
            olayout,
            quirks,
            pclass: PayloadSize::Zero,
            peer_mss,
            tos: 0,
        },
    }
}

fn observed_syn(
    raw_ttl: u8,
    mss: Option<u16>,
    window: u16,
    wscale: Option<u8>,
    olayout: Vec<TcpOption>,
    quirks: Vec<Quirk>,
) -> ObservableTcp {
    observed(raw_ttl, mss, window, wscale, olayout, quirks, None)
}

fn matched_request_flavor(syn: &ObservableTcp) -> Option<(String, Option<String>)> {
    let db = match TcpDatabase::load_default() {
        Ok(db) => db,
        Err(e) => panic!("failed to load default database: {e}"),
    };
    let found = TcpSignatureMatcher::new(&db).matching_by_tcp_request(syn)?;
    Some((found.label.name.clone(), found.label.flavor.clone()))
}

fn matched_response_flavor(syn_ack: &ObservableTcp) -> Option<(String, Option<String>)> {
    let db = match TcpDatabase::load_default() {
        Ok(db) => db,
        Err(e) => panic!("failed to load default database: {e}"),
    };
    let found = TcpSignatureMatcher::new(&db).matching_by_tcp_response(syn_ack)?;
    Some((found.label.name.clone(), found.label.flavor.clone()))
}

#[test]
fn a_windows_syn_matches_its_literal_window() {
    // s:win:Windows:7, 8 or 8.1 -> *:128:0:*:8192,0:mss,nop,nop,sok:df,id+:0
    let syn = observed_syn(
        128,
        Some(1460),
        8192,
        Some(0),
        vec![TcpOption::Mss, TcpOption::Nop, TcpOption::Nop, TcpOption::Sok],
        vec![Quirk::Df, Quirk::NonZeroID],
    );

    assert_eq!(
        matched_request_flavor(&syn),
        Some(("Windows".to_string(), Some("7, 8 or 8.1".to_string()))),
        "a window of 8192 is the literal value the signature declares"
    );
}

#[test]
fn an_nmap_scan_matches_its_literal_window() {
    // s:!:NMap:SYN scan -> *:64-:0:1460:1024,0:mss::0
    let syn = observed_syn(64, Some(1460), 1024, Some(0), vec![TcpOption::Mss], vec![]);

    assert_eq!(
        matched_request_flavor(&syn),
        Some(("NMap".to_string(), Some("SYN scan".to_string()))),
        "a window of 1024 is the literal value the signature declares"
    );
}

#[test]
fn a_window_that_is_a_multiple_of_the_mss_matches_an_mss_signature() {
    // g:unix:Linux:2.2.x-3.x accepts any window, so aim at the specific
    // s:unix:Linux:3.11 and newer -> *:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0
    let syn = observed_syn(
        64,
        Some(1460),
        1460 * 20,
        Some(10),
        vec![TcpOption::Mss, TcpOption::Sok, TcpOption::TS, TcpOption::Nop, TcpOption::Ws],
        vec![Quirk::Df, Quirk::NonZeroID],
    );

    assert_eq!(
        matched_request_flavor(&syn),
        Some(("Linux".to_string(), Some("3.11 and newer".to_string()))),
        "29200 is exactly 20 times the MSS"
    );
}

#[test]
fn a_window_that_is_not_a_multiple_of_the_mss_does_not_match_an_mss_signature() {
    // Same signature as above, but 65535 is only 44.8 times an MSS of 1460:
    // p0f rejects it because the remainder is not zero.
    let syn = observed_syn(
        64,
        Some(1460),
        65535,
        Some(10),
        vec![TcpOption::Mss, TcpOption::Sok, TcpOption::TS, TcpOption::Nop, TcpOption::Ws],
        vec![Quirk::Df, Quirk::NonZeroID],
    );

    assert_ne!(
        matched_request_flavor(&syn).and_then(|(_, flavor)| flavor),
        Some("3.11 and newer".to_string()),
        "65535 leaves a remainder of 1295 over an MSS of 1460"
    );
}

#[test]
fn a_syn_ack_window_sized_off_the_peer_mss_matches_and_renders() {
    // s:unix:Linux:3.x -> *:64:0:*:mss*10,*:mss,sok,ts,nop,ws:df:0
    // Own MSS 1460 does not divide 14000; the client's 1400 does (10×).
    let syn_ack = observed(
        64,
        Some(1460),
        1400 * 10,
        Some(7),
        vec![TcpOption::Mss, TcpOption::Sok, TcpOption::TS, TcpOption::Nop, TcpOption::Ws],
        vec![Quirk::Df],
        Some(1400),
    );

    assert!(
        syn_ack.to_string().contains(":mss*10,"),
        "raw signature should classify the window via the peer MSS, got {}",
        syn_ack
    );
    assert_eq!(
        matched_response_flavor(&syn_ack),
        Some(("Linux".to_string(), Some("3.x".to_string()))),
        "mss*10 against the peer is what the Linux 3.x response signature declares"
    );
}

#[test]
fn without_the_peer_mss_that_same_window_does_not_match() {
    let syn_ack = observed(
        64,
        Some(1460),
        1400 * 10,
        Some(7),
        vec![TcpOption::Mss, TcpOption::Sok, TcpOption::TS, TcpOption::Nop, TcpOption::Ws],
        vec![Quirk::Df],
        None,
    );

    assert!(
        !syn_ack.to_string().contains(":mss*10,"),
        "without a peer MSS the window is not 10× anything we try"
    );
    assert_ne!(
        matched_response_flavor(&syn_ack).and_then(|(_, flavor)| flavor),
        Some("3.x".to_string())
    );
}
