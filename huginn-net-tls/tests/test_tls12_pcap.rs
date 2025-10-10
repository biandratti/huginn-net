use huginn_net_tls::{HuginnNetTls, TlsClientOutput};
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

    let connection = &results[0];

    assert!(
        matches!(connection.sig.version, huginn_net_tls::TlsVersion::V1_3),
        "Expected TLS 1.3 in tls12.pcap, got {:?}",
        connection.sig.version
    );

    assert!(
        !connection.sig.cipher_suites.is_empty(),
        "Should have cipher suites"
    );
    assert!(
        !connection.sig.extensions.is_empty(),
        "Should have extensions"
    );

    assert_eq!(
        connection.source.ip.to_string(),
        "192.168.133.129",
        "Source IP must match expected"
    );
    assert_eq!(
        connection.destination.ip.to_string(),
        "34.117.237.239",
        "Destination IP must match expected"
    );
    assert_eq!(
        connection.source.port, 36372,
        "Source port must match expected"
    );
    assert_eq!(
        connection.destination.port, 443,
        "Destination port must match expected"
    );

    if let Some(ref sni) = connection.sig.sni {
        assert_eq!(
            sni, "contile.services.mozilla.com",
            "SNI must match expected value"
        );
    } else {
        panic!("SNI must be present");
    }

    let ja4 = connection.sig.ja4.full.to_string();
    let expected_ja4 = "t13d1715h2_5b57614c22b0_3d5424432f57";

    assert_eq!(
        ja4, expected_ja4,
        "JA4 fingerprint must exactly match expected value for tls12.pcap"
    );

    let ja4_orig = connection.sig.ja4_original.full.to_string();
    let ja4_orig_parts: Vec<&str> = ja4_orig.split('_').collect();
    assert_eq!(
        ja4_orig_parts.len(),
        3,
        "JA4_O must have exactly 3 parts separated by underscores"
    );

    for &cipher in &connection.sig.cipher_suites {
        assert!(cipher > 0, "Cipher suite must not be zero");
    }
}
