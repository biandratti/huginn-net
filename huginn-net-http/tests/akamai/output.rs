//! `AkamaiOutput` formatting (human and JSON).

use huginn_net_http::{
    AkamaiOutput, AkamaiTransport, Http2Frame, IpPort, TlsVersion, extract_akamai_fingerprint,
};
use std::net::{IpAddr, Ipv4Addr};

fn chrome_61_output(transport: AkamaiTransport) -> AkamaiOutput {
    let frames = vec![
        Http2Frame::new(0x4, 0x0, 0, vec![0, 3, 0, 0, 0, 100, 0, 4, 0, 96, 0, 0, 0, 2, 0, 0, 0, 0]),
        Http2Frame::new(0x8, 0x0, 0, vec![0, 238, 255, 1]),
        Http2Frame::new(0x2, 0x0, 3, vec![0, 0, 0, 0, 200]),
    ];
    let fingerprint = extract_akamai_fingerprint(&frames)
        .unwrap_or_else(|e| panic!("paper frames must produce a fingerprint: {e}"));
    AkamaiOutput::new(
        IpPort::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 52344),
        IpPort::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443),
        transport,
        fingerprint,
    )
}

#[test]
fn display_prints_fingerprint_and_hash_verbatim() {
    let out = chrome_61_output(AkamaiTransport::TlsDecrypted {
        version: TlsVersion::Tls13,
        cipher_suite: 0x1301,
    });
    let text = out.to_string();
    assert!(text.contains("(http/2 akamai)"));
    assert!(text.contains("| client    = 192.168.1.10/52344"));
    assert!(text.contains("| transport = tls1.3 decrypted (0x1301)"));
    assert!(text.contains(&format!("| akamai    = {}", out.fingerprint.fingerprint)));
    assert!(text.contains(&format!("| hash      = {}", out.fingerprint.hash)));
}

#[test]
fn display_cleartext_transport() {
    let out = chrome_61_output(AkamaiTransport::Cleartext);
    assert!(out.to_string().contains("| transport = cleartext"));
}

#[cfg(feature = "json")]
#[test]
fn json_transport_kind() {
    let decrypted = chrome_61_output(AkamaiTransport::TlsDecrypted {
        version: TlsVersion::Tls12,
        cipher_suite: 0xC02F,
    });
    let value = serde_json::to_value(&decrypted)
        .unwrap_or_else(|e| panic!("AkamaiOutput must serialize: {e}"));
    assert_eq!(value["transport"]["kind"], "tls_decrypted");
    assert_eq!(value["transport"]["version"], "tls1.2");
    assert_eq!(value["transport"]["cipher_suite"], 0xC02F);
    assert_eq!(value["fingerprint"]["hash"], decrypted.fingerprint.hash.as_str());

    let clear = serde_json::to_value(chrome_61_output(AkamaiTransport::Cleartext))
        .unwrap_or_else(|e| panic!("AkamaiOutput must serialize: {e}"));
    assert_eq!(clear["transport"]["kind"], "cleartext");
}
