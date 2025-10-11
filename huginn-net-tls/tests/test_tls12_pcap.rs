use huginn_net_tls::{HuginnNetTls, TlsClientOutput, TlsVersion};
use std::path::Path;
use std::sync::mpsc;
use std::thread;

#[test]
fn test_tls12_pcap() {
    let pcap_path = "../../huginn-net/pcap/tls12.pcap";

    assert!(
        Path::new(pcap_path).exists(),
        "PCAP file must exist: {pcap_path}"
    );

    let mut analyzer = HuginnNetTls::new();
    let (sender, receiver) = mpsc::channel::<TlsClientOutput>();

    let pcap_file = pcap_path.to_string();
    let handle = thread::spawn(move || analyzer.analyze_pcap(&pcap_file, sender, None));

    let mut results = Vec::new();
    for tls_output in receiver {
        results.push(tls_output);
    }

    match handle.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            panic!("PCAP analysis failed: {e}");
        }
        Err(e) => {
            panic!("Thread join failed: {e:?}");
        }
    }

    assert_eq!(
        results.len(),
        1,
        "Must find exactly 1 TLS connection in tls12.pcap"
    );

    let tls_client_output_parsed: &TlsClientOutput = &results[0];

    assert_eq!(
        tls_client_output_parsed.source.ip.to_string(),
        "192.168.133.129",
        "Source IP must match expected"
    );
    assert_eq!(
        tls_client_output_parsed.source.port, 36372,
        "Source port must match expected"
    );

    assert_eq!(
        tls_client_output_parsed.destination.ip.to_string(),
        "34.117.237.239",
        "Destination IP must match expected"
    );

    assert_eq!(
        tls_client_output_parsed.destination.port, 443,
        "Destination port must match expected"
    );

    assert_eq!(
        tls_client_output_parsed.sig.sni,
        Some("contile.services.mozilla.com".to_string()),
        "SNI must match expected value"
    );

    assert!(
        matches!(
            tls_client_output_parsed.sig.version,
            huginn_net_tls::TlsVersion::V1_3
        ),
        "Expected TLS 1.3 in tls12.pcap, got {:?}",
        tls_client_output_parsed.sig.version
    );

    assert!(
        !tls_client_output_parsed.sig.cipher_suites.is_empty(),
        "Should have cipher suites"
    );
    assert!(
        !tls_client_output_parsed.sig.extensions.is_empty(),
        "Should have extensions"
    );

    assert_eq!(
        tls_client_output_parsed.source.port, 36372,
        "Source port must match expected"
    );
    assert_eq!(
        tls_client_output_parsed.destination.port, 443,
        "Destination port must match expected"
    );

    assert_eq!(
        tls_client_output_parsed.sig.version,
        TlsVersion::V1_3,
        "TLS version must match expected value"
    );

    if let Some(ref sni) = tls_client_output_parsed.sig.sni {
        assert_eq!(
            sni, "contile.services.mozilla.com",
            "SNI must match expected value"
        );
    } else {
        panic!("SNI must be present");
    }

    assert_eq!(
        tls_client_output_parsed.sig.alpn,
        Some("h2".to_string()),
        "ALPN must match expected value"
    );

    assert!(
        !tls_client_output_parsed.sig.cipher_suites.is_empty(),
        "Should have cipher suites"
    );

    assert!(
        !tls_client_output_parsed.sig.extensions.is_empty(),
        "Should have extensions"
    );

    assert!(
        !tls_client_output_parsed.sig.signature_algorithms.is_empty(),
        "Should have signature algorithms"
    );

    assert!(
        !tls_client_output_parsed.sig.elliptic_curves.is_empty(),
        "Should have elliptic curves"
    );

    assert_eq!(
        tls_client_output_parsed.sig.ja4.ja4_a, "t13d1715h2",
        "JA4_a must match expected value"
    );

    assert_eq!(
        tls_client_output_parsed.sig.ja4.ja4_b,
        "002f,0035,009c,009d,1301,1302,1303,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9",
        "JA4_b must match expected value"
    );

    assert_eq!(
        tls_client_output_parsed.sig.ja4.ja4_c,
        "0005,000a,000b,000d,0015,0017,001c,0022,0023,002b,002d,0033,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201",
        "JA4_c must match expected value"
    );

    assert_eq!(
        tls_client_output_parsed.sig.ja4.full.to_string(),
        "t13d1715h2_5b57614c22b0_3d5424432f57",
        "JA4 must match expected value"
    );

    assert_eq!(
        tls_client_output_parsed.sig.ja4.raw.to_string(),
        "t13d1715h2_002f,0035,009c,009d,1301,1302,1303,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0015,0017,001c,0022,0023,002b,002d,0033,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201",
        "JA4_raw must match expected value"
    );

    assert_eq!(
        tls_client_output_parsed.sig.ja4_original.ja4_a, "t13d1715h2",
        "JA4_a must match expected value"
    );

    assert_eq!(
        tls_client_output_parsed.sig.ja4_original.ja4_b,
        "1301,1303,1302,c02b,c02f,cca9,cca8,c02c,c030,c00a,c009,c013,c014,009c,009d,002f,0035",
        "JA4_b must match expected value"
    );

    assert_eq!(
        tls_client_output_parsed.sig.ja4_original.ja4_c,
        "0000,0017,ff01,000a,000b,0023,0010,0005,0022,0033,002b,000d,002d,001c,0015_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201",
        "JA4_c must match expected value"
    );

    assert_eq!(
        tls_client_output_parsed.sig.ja4_original.full.to_string(),
        "t13d1715h2_5b234860e130_014157ec0da2",
        "JA4_original must match expected value"
    );
    assert_eq!(
        tls_client_output_parsed.sig.ja4_original.raw.to_string(),
        "t13d1715h2_1301,1303,1302,c02b,c02f,cca9,cca8,c02c,c030,c00a,c009,c013,c014,009c,009d,002f,0035_0000,0017,ff01,000a,000b,0023,0010,0005,0022,0033,002b,000d,002d,001c,0015_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201",
        "JA4_original_raw must match expected value"
    );
}
