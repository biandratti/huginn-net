#![cfg(feature = "tcp")]
use huginn_net_db::tcp::{IpVersion, PayloadSize, Quirk, Signature, TcpOption, Ttl, WindowSize};
use huginn_net_db::{TcpDatabase, TcpSignatureMatcher, Type};
use huginn_net_tcp::observable::TcpObservation;
use huginn_net_tcp::ObservableTcp;

/// Resolves the window a signature declares into a concrete value a packet
/// could have carried, so the signature can be replayed as an observation.
fn raw_window(sig: &Signature) -> u16 {
    let mss = sig.mss.unwrap_or(1460);
    match sig.wsize {
        WindowSize::Value(value) => value,
        WindowSize::Mod(modulus) => modulus,
        WindowSize::Mss(multiple) => mss.saturating_mul(u16::from(multiple)),
        WindowSize::Mtu(multiple) => mss.saturating_add(40).saturating_mul(u16::from(multiple)),
        WindowSize::Any => 65535,
    }
}

fn observation_from_signature(sig: &Signature) -> TcpObservation {
    TcpObservation {
        version: sig.version,
        ittl: sig.ittl.clone(),
        olen: sig.olen,
        mss: sig.mss,
        wsize: raw_window(sig),
        tot_hdr: 60,
        wscale: sig.wscale,
        olayout: sig.olayout.clone(),
        quirks: sig.quirks.clone(),
        pclass: sig.pclass,
        peer_mss: None,
        tos: 0,
    }
}

/// Parses `raw` as a TCP signature and runs it through `matching_by_tcp_request`.
fn match_request(
    matcher: &TcpSignatureMatcher,
    raw: &str,
) -> Option<(String, Option<String>, Option<String>, f32)> {
    let sig: Signature = match raw.parse() {
        Ok(sig) => sig,
        Err(e) => panic!("Failed to parse signature {raw}: {e}"),
    };
    let obs = ObservableTcp { matching: observation_from_signature(&sig) };
    let found = matcher.matching_by_tcp_request(&obs)?;
    Some((
        found.label.name.clone(),
        found.label.class.clone(),
        found.label.flavor.clone(),
        found.quality,
    ))
}

#[test]
fn matching_linux_by_tcp_request() {
    let db = match TcpDatabase::load_default() {
        Ok(db) => db,
        Err(e) => {
            panic!("Failed to create default database: {e}");
        }
    };

    //sig: 4:58+6:0:1452:mss*44,7:mss,sok,ts,nop,ws:df,id+:0
    let linux_signature = ObservableTcp {
        matching: TcpObservation {
            version: IpVersion::V4,
            ittl: Ttl::Distance(58, 6),
            olen: 0,
            mss: Some(1452),
            wsize: 1452 * 44,
            tot_hdr: 60,
            wscale: Some(7),
            olayout: vec![
                TcpOption::Mss,
                TcpOption::Sok,
                TcpOption::TS,
                TcpOption::Nop,
                TcpOption::Ws,
            ],
            quirks: vec![Quirk::Df, Quirk::NonZeroID],
            pclass: PayloadSize::Zero,
            peer_mss: None,
            tos: 0,
        },
    };

    let matcher = TcpSignatureMatcher::new(&db);

    if let Some(found) = matcher.matching_by_tcp_request(&linux_signature) {
        assert_eq!(found.label.name, "Linux");
        assert_eq!(found.label.class, Some("unix".to_string()));
        assert_eq!(found.label.flavor, Some("2.2.x-3.x".to_string()));
        assert_eq!(found.label.ty, Type::Generic);
        // A catch-all signature fits, so the match is real but ranks below what
        // a signature naming a concrete release would have scored.
        assert_eq!(found.quality, 0.8);
        assert_eq!(found.fuzzy, None, "every field fit, nothing was tolerated");
    } else {
        panic!("No match found");
    }
}

#[test]
fn matching_android_by_tcp_request() {
    let db = match TcpDatabase::load_default() {
        Ok(db) => db,
        Err(e) => {
            panic!("Failed to create default database: {e}");
        }
    };

    //sig: "4:64+0:0:1460:65535,8:mss,sok,ts,nop,ws:df,id+:0"
    let android_signature = ObservableTcp {
        matching: TcpObservation {
            version: IpVersion::V4,
            ittl: Ttl::Value(64),
            olen: 0,
            mss: Some(1460),
            wsize: 65535,
            tot_hdr: 60,
            wscale: Some(8),
            olayout: vec![
                TcpOption::Mss,
                TcpOption::Sok,
                TcpOption::TS,
                TcpOption::Nop,
                TcpOption::Ws,
            ],
            quirks: vec![Quirk::Df, Quirk::NonZeroID],
            pclass: PayloadSize::Zero,
            peer_mss: None,
            tos: 0,
        },
    };

    //sig: "4:57+7:0:1460:65535,8:mss,sok,ts,nop,ws:df,id+:0"
    let android_signature_with_distance = ObservableTcp {
        matching: TcpObservation {
            version: IpVersion::V4,
            ittl: Ttl::Distance(57, 7),
            olen: 0,
            mss: Some(1460),
            wsize: 65535,
            tot_hdr: 60,
            wscale: Some(8),
            olayout: vec![
                TcpOption::Mss,
                TcpOption::Sok,
                TcpOption::TS,
                TcpOption::Nop,
                TcpOption::Ws,
            ],
            quirks: vec![Quirk::Df, Quirk::NonZeroID],
            pclass: PayloadSize::Zero,
            peer_mss: None,
            tos: 0,
        },
    };

    let matcher = TcpSignatureMatcher::new(&db);

    if let Some(found) = matcher.matching_by_tcp_request(&android_signature) {
        assert_eq!(found.label.name, "Linux");
        assert_eq!(found.label.class, Some("unix".to_string()));
        assert_eq!(found.label.flavor, Some("Android".to_string()));
        assert_eq!(found.label.ty, Type::Specified);
        assert_eq!(found.quality, 1.0);
        assert_eq!(found.fuzzy, None);
    } else {
        panic!("No match found");
    }

    if let Some(found) = matcher.matching_by_tcp_request(&android_signature_with_distance) {
        assert_eq!(found.label.name, "Linux");
        assert_eq!(found.label.class, Some("unix".to_string()));
        assert_eq!(found.label.flavor, Some("Android".to_string()));
        assert_eq!(found.label.ty, Type::Specified);
        assert_eq!(found.quality, 1.0);
        // The packet crossed routers, which is ordinary: a plausible hop count
        // is not a tolerance.
        assert_eq!(found.fuzzy, None);
    } else {
        panic!("No match found");
    }
}

#[test]
fn unknown_request_signature_does_not_match() {
    let db = match TcpDatabase::load_default() {
        Ok(db) => db,
        Err(e) => panic!("Failed to load default database: {e}"),
    };
    let matcher = TcpSignatureMatcher::new(&db);

    let raw = "4:64+0:0:1460:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1,eol+0:df,ecn:0";
    let result = match_request(&matcher, raw);
    assert!(
        result.is_none(),
        "expected no match for synthetic signature: {raw}, got {result:?}"
    );
}
