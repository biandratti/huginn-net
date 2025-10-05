use huginn_net_db::http::{
    Header as HttpHeader, Signature as HttpSignature, Version as HttpVersion,
};
use huginn_net_db::tcp::Quirk::{AckNumNonZero, Df, NonZeroID};
use huginn_net_db::tcp::TcpOption::{Mss, Nop, Sok, Ws, TS};
use huginn_net_db::tcp::{IpVersion, PayloadSize, Signature as TcpSignature, Ttl, WindowSize};
use huginn_net_db::{Label, Type};
use lazy_static::lazy_static;

lazy_static! {
        static ref LABELS: Vec<(&'static str, Label)> = vec![
            (
                "s:!:Uncle John's Networked ls Utility:2.3.0.1",
                Label {
                    ty: Type::Specified,
                    class: None,
                    name: "Uncle John's Networked ls Utility".to_owned(),
                    flavor: Some("2.3.0.1".to_owned()),
                },
            ),
            (
                "s:unix:Linux:3.11 and newer",
                Label {
                    ty: Type::Specified,
                    class: Some("unix".to_owned()),
                    name: "Linux".to_owned(),
                    flavor: Some("3.11 and newer".to_owned()),
                },
            ),
            (
                "s:!:Chrome:11.x to 26.x",
                Label {
                    ty: Type::Specified,
                    class: None,
                    name: "Chrome".to_owned(),
                    flavor: Some("11.x to 26.x".to_owned()),
                },
            ),
            (
                "s:!:curl:",
                Label {
                    ty: Type::Specified,
                    class: None,
                    name: "curl".to_owned(),
                    flavor: None,
                },
            )
        ];
        static ref TCP_SIGNATURES: Vec<(&'static str, TcpSignature)> = vec![
            (
                "*:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0",
                TcpSignature {
                    version: IpVersion::Any,
                    ittl: Ttl::Value(64),
                    olen: 0,
                    mss: None,
                    wsize: WindowSize::Mss(20),
                    wscale: Some(10),
                    olayout: vec![Mss, Sok, TS, Nop, Ws],
                    quirks: vec![Df, NonZeroID],
                    pclass: PayloadSize::Zero,
                }
            ),
            (
                "*:64:0:*:16384,0:mss::0",
                TcpSignature {
                    version: IpVersion::Any,
                    ittl: Ttl::Value(64),
                    olen: 0,
                    mss: None,
                    wsize: WindowSize::Value(16384),
                    wscale: Some(0),
                    olayout: vec![Mss],
                    quirks: vec![],
                    pclass: PayloadSize::Zero,
                }
            ),
            (
                "4:128:0:1460:mtu*2,0:mss,nop,ws::0",
                TcpSignature {
                    version: IpVersion::V4,
                    ittl: Ttl::Value(128),
                    olen: 0,
                    mss: Some(1460),
                    wsize: WindowSize::Mtu(2),
                    wscale: Some(0),
                    olayout: vec![Mss, Nop, Ws],
                    quirks: vec![],
                    pclass: PayloadSize::Zero,
                }
            ),
            (
                "*:64-:0:265:%512,0:mss,sok,ts:ack+:0",
                TcpSignature {
                    version: IpVersion::Any,
                    ittl: Ttl::Bad(64),
                    olen: 0,
                    mss: Some(265),
                    wsize: WindowSize::Mod(512),
                    wscale: Some(0),
                    olayout: vec![Mss, Sok, TS],
                    quirks: vec![AckNumNonZero],
                    pclass: PayloadSize::Zero,
                }
            ),
            (
                "*:64:0:*:mss*44,1:mss,sok,ts,nop,ws:df,id+:0",
                TcpSignature {
                    version: IpVersion::Any,
                    ittl: Ttl::Value(64),
                    olen: 0,
                    mss: None,
                    wsize: WindowSize::Mss(44),
                    wscale: Some(1),
                    olayout: vec![Mss, Sok, TS, Nop, Ws],
                    quirks: vec![Df, NonZeroID],
                    pclass: PayloadSize::Zero,
                }
            ),
            (
                "*:64:0:*:*,*:mss,sok,ts,nop,ws:df,id+:0",
                TcpSignature {
                    version: IpVersion::Any,
                    ittl: Ttl::Value(64),
                    olen: 0,
                    mss: None,
                    wsize: WindowSize::Any,
                    wscale: None,
                    olayout: vec![Mss, Sok, TS, Nop, Ws],
                    quirks: vec![Df, NonZeroID],
                    pclass: PayloadSize::Zero,
                }

            )
        ];
        static ref TTLS: Vec<(&'static str, Ttl)> = vec![
            (
                "64",
                Ttl::Value(64)
            ),
            (
                "54+10",
                Ttl::Distance(54, 10)
            ),
            (
                "64-",
                Ttl::Bad(64)
            ),
            (
                "54+?",
                Ttl::Guess(54)
            )
        ];
        static ref HTTP_SIGNATURES: Vec<(&'static str, HttpSignature)> = vec![
            (
                "*:Host,User-Agent,Accept=[,*/*;q=],?Accept-Language,Accept-Encoding=[gzip,deflate],Accept-Charset=[utf-8;q=0.7,*;q=0.7],Keep-Alive=[300],Connection=[keep-alive]::Firefox/",
                HttpSignature {
                    version: HttpVersion::Any,
                    horder: vec![
                        header("Host"),
                        header("User-Agent"),
                        header("Accept").with_value(",*/*;q="),
                        header("Accept-Language").optional(),
                        header("Accept-Encoding").with_value("gzip,deflate"),
                        header("Accept-Charset").with_value("utf-8;q=0.7,*;q=0.7"),
                        header("Keep-Alive").with_value("300"),
                        header("Connection").with_value("keep-alive"),
                    ],
                    habsent: vec![],
                    expsw: "Firefox/".to_owned(),
                }
            )
        ];
        static ref HTTP_HEADERS: Vec<(&'static str, HttpHeader)> = vec![
            ("Host", HttpHeader{ optional: false, name: "Host".to_owned(), value: None}),
            ("User-Agent", HttpHeader{ optional: false, name: "User-Agent".to_owned(), value: None}),
            ("Accept=[,*/*;q=]", HttpHeader{ optional: false, name: "Accept".to_owned(), value: Some(",*/*;q=".to_owned())}),
            ("?Accept-Language", HttpHeader{ optional: true, name: "Accept-Language".to_owned(), value: None}),
        ];
    }

#[test]
fn test_label() {
    for (s, l) in LABELS.iter() {
        let result = s.parse::<Label>();
        assert!(result.is_ok(), "Failed to parse label: {s}");
        if let Ok(ref parsed) = result {
            assert_eq!(parsed, l);
        }
    }
}

#[test]
fn test_tcp_signature() {
    for (s, sig) in TCP_SIGNATURES.iter() {
        let result = s.parse::<TcpSignature>();
        assert!(result.is_ok(), "Failed to parse TCP signature: {s}");
        if let Ok(ref parsed) = result {
            assert_eq!(parsed, sig);
        }
        assert_eq!(&sig.to_string(), s);
    }
}

#[test]
fn test_ttl() {
    for (s, ttl) in TTLS.iter() {
        let result = s.parse::<Ttl>();
        assert!(result.is_ok(), "Failed to parse TTL: {s}");
        if let Ok(ref parsed) = result {
            assert_eq!(parsed, ttl);
        }
        assert_eq!(&ttl.to_string(), s);
    }
}

#[test]
fn test_http_signature() {
    for (s, sig) in HTTP_SIGNATURES.iter() {
        let result = s.parse::<HttpSignature>();
        assert!(result.is_ok(), "Failed to parse HTTP signature: {s}");
        if let Ok(ref parsed) = result {
            assert_eq!(parsed, sig);
        }
        assert_eq!(&sig.to_string(), s);
    }
}

#[test]
fn test_http_header() {
    for (s, h) in HTTP_HEADERS.iter() {
        let result = s.parse::<HttpHeader>();
        assert!(result.is_ok(), "Failed to parse HTTP header: {s}");
        if let Ok(ref parsed) = result {
            assert_eq!(parsed, h);
        }
        assert_eq!(&h.to_string(), s);
    }
}

/// Test helper function to create HTTP headers
fn header<S: AsRef<str>>(name: S) -> HttpHeader {
    HttpHeader::new(name)
}
