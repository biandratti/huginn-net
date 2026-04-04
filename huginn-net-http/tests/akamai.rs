use huginn_net_http::akamai_extractor::extract_akamai_fingerprint;
use huginn_net_http::{
    AkamaiFingerprint, Http2Frame, Http2Priority, PseudoHeader, SettingId, SettingParameter,
};

#[test]
fn test_akamai_fingerprint_chrome() {
    let settings = vec![
        SettingParameter { id: SettingId::HeaderTableSize, value: 65536 },
        SettingParameter { id: SettingId::EnablePush, value: 0 },
        SettingParameter { id: SettingId::MaxConcurrentStreams, value: 1000 },
        SettingParameter { id: SettingId::InitialWindowSize, value: 6291456 },
        SettingParameter { id: SettingId::MaxFrameSize, value: 16384 },
        SettingParameter { id: SettingId::MaxHeaderListSize, value: 262144 },
    ];
    let pseudo_headers = vec![
        PseudoHeader::Method,
        PseudoHeader::Path,
        PseudoHeader::Authority,
        PseudoHeader::Scheme,
    ];
    let fp = AkamaiFingerprint::new(settings, 15663105, vec![], pseudo_headers);
    assert_eq!(
        fp.fingerprint,
        "1:65536;2:0;3:1000;4:6291456;5:16384;6:262144|15663105|0|m,p,a,s"
    );
    assert!(!fp.hash.is_empty());
    assert_eq!(fp.hash.len(), 32);
}

#[test]
fn test_akamai_fingerprint_firefox() {
    let settings = vec![
        SettingParameter { id: SettingId::HeaderTableSize, value: 65536 },
        SettingParameter { id: SettingId::InitialWindowSize, value: 131072 },
        SettingParameter { id: SettingId::MaxFrameSize, value: 16384 },
    ];
    let pseudo_headers = vec![
        PseudoHeader::Method,
        PseudoHeader::Path,
        PseudoHeader::Authority,
        PseudoHeader::Scheme,
    ];
    let fp = AkamaiFingerprint::new(settings, 12517377, vec![], pseudo_headers);
    assert_eq!(fp.fingerprint, "1:65536;4:131072;5:16384|12517377|0|m,p,a,s");
}

#[test]
fn test_akamai_fingerprint_with_priorities() {
    let settings = vec![
        SettingParameter { id: SettingId::HeaderTableSize, value: 65536 },
        SettingParameter { id: SettingId::EnablePush, value: 1 },
    ];
    let priorities = vec![
        Http2Priority { stream_id: 1, exclusive: false, depends_on: 0, weight: 220 },
        Http2Priority { stream_id: 3, exclusive: false, depends_on: 0, weight: 200 },
    ];
    let pseudo_headers = vec![
        PseudoHeader::Method,
        PseudoHeader::Path,
        PseudoHeader::Authority,
        PseudoHeader::Scheme,
    ];
    let fp = AkamaiFingerprint::new(settings, 15663105, priorities, pseudo_headers);
    assert_eq!(fp.fingerprint, "1:65536;2:1|15663105|1:0:0:221,3:0:0:201|m,p,a,s");
}

#[test]
fn test_empty_fingerprint() {
    let fp = AkamaiFingerprint::new(vec![], 0, vec![], vec![]);
    assert_eq!(fp.fingerprint, "|00|0|");
}

#[test]
fn test_fingerprint_hash_consistency() {
    let settings = vec![SettingParameter { id: SettingId::HeaderTableSize, value: 65536 }];
    let pseudo_headers = vec![PseudoHeader::Method];
    let fp1 = AkamaiFingerprint::new(settings.clone(), 1000, vec![], pseudo_headers.clone());
    let fp2 = AkamaiFingerprint::new(settings, 1000, vec![], pseudo_headers);
    assert_eq!(fp1.hash, fp2.hash);
}

#[test]
fn test_fingerprint_hash_differs_for_different_fingerprints() {
    let settings1 = vec![SettingParameter { id: SettingId::HeaderTableSize, value: 65536 }];
    let settings2 = vec![SettingParameter { id: SettingId::HeaderTableSize, value: 4096 }];
    let pseudo_headers = vec![PseudoHeader::Method];
    let fp1 = AkamaiFingerprint::new(settings1, 1000, vec![], pseudo_headers.clone());
    let fp2 = AkamaiFingerprint::new(settings2, 1000, vec![], pseudo_headers);
    assert_ne!(fp1.hash, fp2.hash);
}

#[test]
fn test_priority_weight_display() {
    let priority = Http2Priority { stream_id: 1, exclusive: false, depends_on: 0, weight: 220 };
    assert!(format!("{priority}").contains("weight=221"));
}

#[test]
fn test_setting_id_conversion() {
    assert_eq!(SettingId::from(1), SettingId::HeaderTableSize);
    assert_eq!(SettingId::from(2), SettingId::EnablePush);
    assert_eq!(SettingId::from(9), SettingId::NoRfc7540Priorities);
    assert_eq!(SettingId::from(255), SettingId::Unknown(255));
}

#[test]
fn test_pseudo_header_display() {
    assert_eq!(PseudoHeader::Method.to_string(), "m");
    assert_eq!(PseudoHeader::Path.to_string(), "p");
    assert_eq!(PseudoHeader::Authority.to_string(), "a");
    assert_eq!(PseudoHeader::Scheme.to_string(), "s");
    assert_eq!(PseudoHeader::Status.to_string(), "st");
}

#[test]
fn test_no_settings_returns_error() {
    use huginn_net_http::HuginnNetHttpError;
    let result = extract_akamai_fingerprint(&[]);
    assert!(matches!(result, Err(HuginnNetHttpError::NoSettingsFrame)));
}

#[test]
fn test_malformed_headers_returns_error() {
    use huginn_net_http::HuginnNetHttpError;
    let settings = Http2Frame::new(0x4, 0x00, 0, vec![0x00, 0x01, 0x00, 0x01, 0x00, 0x00]);
    // HEADERS frame with FLAG_PRIORITY (0x20) but only 2 bytes — truncated, needs 5
    let bad_headers = Http2Frame::new(0x1, 0x20, 1, vec![0x00, 0x00]);
    let result = extract_akamai_fingerprint(&[settings, bad_headers]);
    assert!(matches!(result, Err(HuginnNetHttpError::MalformedPseudoHeaders(_))));
}
