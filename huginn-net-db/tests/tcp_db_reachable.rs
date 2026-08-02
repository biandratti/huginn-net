#![cfg(feature = "tcp")]
//! Every signature in the database has to be reachable.
//!
//! Each signature is replayed as the packet that declared it —the observation a
//! host matching it would produce— and has to come back with a match. A
//! signature that no packet can reach is dead weight in the database, and the
//! way to end up with one is to compare a field in a form the observation no
//! longer carries.
//!
//! The match is not required to be the signature's *own* label: `p0f.fp` ships
//! signatures that are indistinguishable from each other, so a specific one can
//! legitimately answer for another. That ambiguity is a property of the data, not
//! of the matcher, and it belongs to the coverage check.

use huginn_net_db::database::Label;
use huginn_net_db::tcp::{IpVersion, PayloadSize, Signature, Ttl, WindowSize};
use huginn_net_db::{TcpDatabase, TcpSignatureMatcher};
use huginn_net_tcp::observable::TcpObservation;
use huginn_net_tcp::ObservableTcp;

/// What a packet would carry when its MSS is not what the signature pins down.
const TYPICAL_MSS: u16 = 1460;
/// Twenty bytes of IP header plus twenty of TCP, plus room for the options.
const TYPICAL_TOT_HDR: u16 = 60;

/// Turns a signature into the observation a host matching it would produce,
/// resolving every wildcard into one concrete value a packet could carry.
fn replay(sig: &Signature) -> ObservableTcp {
    let mss = sig.mss.unwrap_or(TYPICAL_MSS);
    let wsize = match sig.wsize {
        WindowSize::Value(value) => value,
        WindowSize::Mod(modulus) => modulus,
        WindowSize::Mss(multiple) => mss.saturating_mul(u16::from(multiple)),
        WindowSize::Mtu(multiple) => mss
            .saturating_add(TYPICAL_TOT_HDR)
            .saturating_mul(u16::from(multiple)),
        WindowSize::Any => 65535,
    };

    ObservableTcp {
        matching: TcpObservation {
            version: if sig.version == IpVersion::Any {
                IpVersion::V4
            } else {
                sig.version
            },
            ittl: observed_ttl(&sig.ittl),
            olen: sig.olen,
            mss: Some(mss),
            wsize,
            tot_hdr: TYPICAL_TOT_HDR,
            wscale: Some(sig.wscale.unwrap_or(0)),
            olayout: sig.olayout.clone(),
            quirks: sig.quirks,
            pclass: if sig.pclass == PayloadSize::Any {
                PayloadSize::Zero
            } else {
                sig.pclass
            },
            peer_mss: None,
            tos: 0,
        },
    }
}

/// The TTL such a packet carries when it reaches the sensor without crossing a
/// router, which is the one reading that supports any signature.
fn observed_ttl(declared: &Ttl) -> Ttl {
    match declared {
        Ttl::Value(ttl) | Ttl::Guess(ttl) | Ttl::Bad(ttl) => Ttl::Value(*ttl),
        Ttl::Distance(ttl, distance) => Ttl::Value(ttl.saturating_add(*distance)),
    }
}

fn unreachable_signatures(
    entries: &[(Label, Vec<Signature>)],
    matches: impl Fn(&ObservableTcp) -> bool,
) -> Vec<String> {
    let mut unreachable = Vec::new();
    for (label, signatures) in entries {
        for sig in signatures {
            if !matches(&replay(sig)) {
                unreachable.push(format!("{} -> {sig}", label.name));
            }
        }
    }
    unreachable
}

#[test]
fn every_request_signature_is_reachable() {
    let db = match TcpDatabase::load_default() {
        Ok(db) => db,
        Err(e) => panic!("failed to load default database: {e}"),
    };
    let matcher = TcpSignatureMatcher::new(&db);

    let unreachable = unreachable_signatures(&db.tcp_request.entries, |obs| {
        matcher.matching_by_tcp_request(obs).is_some()
    });

    assert!(
        unreachable.is_empty(),
        "{} request signatures no packet can reach:\n  {}",
        unreachable.len(),
        unreachable.join("\n  ")
    );
}

#[test]
fn every_response_signature_is_reachable() {
    let db = match TcpDatabase::load_default() {
        Ok(db) => db,
        Err(e) => panic!("failed to load default database: {e}"),
    };
    let matcher = TcpSignatureMatcher::new(&db);

    let unreachable = unreachable_signatures(&db.tcp_response.entries, |obs| {
        matcher.matching_by_tcp_response(obs).is_some()
    });

    assert!(
        unreachable.is_empty(),
        "{} response signatures no packet can reach:\n  {}",
        unreachable.len(),
        unreachable.join("\n  ")
    );
}
