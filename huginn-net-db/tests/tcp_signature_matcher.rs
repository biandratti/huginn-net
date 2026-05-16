#![cfg(feature = "tcp")]
use huginn_net_db::observable_signals::TcpObservation;
use huginn_net_db::tcp::{IpVersion, PayloadSize, Quirk, Signature, TcpOption, Ttl, WindowSize};
use huginn_net_db::{TcpDatabase, TcpSignatureMatcher, Type};
use huginn_net_tcp::ObservableTcp;

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
            wsize: WindowSize::Mss(44),
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
        },
    };

    let matcher = TcpSignatureMatcher::new(&db);

    if let Some((label, _matched_db_sig, quality)) =
        matcher.matching_by_tcp_request(&linux_signature)
    {
        assert_eq!(label.name, "Linux");
        assert_eq!(label.class, Some("unix".to_string()));
        assert_eq!(label.flavor, Some("2.2.x-3.x".to_string()));
        assert_eq!(label.ty, Type::Generic);
        assert_eq!(quality, 1.0);
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
            wsize: WindowSize::Value(65535),
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
        },
    };

    //sig: "4:57+7:0:1460:65535,8:mss,sok,ts,nop,ws:df,id+:0"
    let android_signature_with_distance = ObservableTcp {
        matching: TcpObservation {
            version: IpVersion::V4,
            ittl: Ttl::Distance(57, 7),
            olen: 0,
            mss: Some(1460),
            wsize: WindowSize::Value(65535),
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
        },
    };

    let matcher = TcpSignatureMatcher::new(&db);

    if let Some((label, _matched_db_sig, quality)) =
        matcher.matching_by_tcp_request(&android_signature)
    {
        assert_eq!(label.name, "Linux");
        assert_eq!(label.class, Some("unix".to_string()));
        assert_eq!(label.flavor, Some("Android".to_string()));
        assert_eq!(label.ty, Type::Specified);
        assert_eq!(quality, 1.0);
    } else {
        panic!("No match found");
    }

    if let Some((label, _matched_db_sig, quality)) =
        matcher.matching_by_tcp_request(&android_signature_with_distance)
    {
        assert_eq!(label.name, "Linux");
        assert_eq!(label.class, Some("unix".to_string()));
        assert_eq!(label.flavor, Some("Android".to_string()));
        assert_eq!(label.ty, Type::Specified);
        assert_eq!(quality, 1.0);
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
