use huginn_net_db::observable_signals::TcpObservation;
use huginn_net_tcp::syn_options::parse_options_raw;
use huginn_net_tcp::tcp::{IpVersion, PayloadSize, TcpOption};

/// Common Linux SYN options: MSS(1460), NOP, WS(6), NOP, NOP, TS, SACK-permitted
fn linux_syn_options() -> Vec<u8> {
    vec![
        2, 4, 0x05, 0xb4, // MSS = 1460
        1,    // NOP
        3, 3, 6, // WS = 6
        1, 1, // NOP NOP
        8, 10, 0, 0, 0, 1, 0, 0, 0, 0, // Timestamps
        4, 2, // SACK permitted
    ]
}

#[allow(clippy::too_many_arguments)]
fn build_obs(
    version: IpVersion,
    ip_hdr_len: u16,
    raw_ttl: u8,
    window: u16,
    olen: u8,
    options: &[u8],
    quirks: Vec<huginn_net_db::tcp::Quirk>,
    pclass: PayloadSize,
) -> TcpObservation {
    let parsed = parse_options_raw(options);
    let ittl = huginn_net_tcp::ttl::calculate_ttl(raw_ttl);
    let wsize = huginn_net_tcp::window_size::detect_win_multiplicator(
        window,
        parsed.mss.unwrap_or(0),
        ip_hdr_len,
        parsed.olayout.contains(&TcpOption::TS),
        &version,
    );
    TcpObservation {
        version,
        ittl,
        olen,
        mss: parsed.mss,
        wsize,
        wscale: parsed.wscale,
        olayout: parsed.olayout,
        quirks,
        pclass,
    }
}

fn ipv4_obs(raw_ttl: u8, window: u16, options: &[u8]) -> TcpObservation {
    build_obs(IpVersion::V4, 20, raw_ttl, window, 0, options, vec![], PayloadSize::Zero)
}

#[test]
fn test_extracts_mss() {
    let obs = ipv4_obs(64, 65535, &linux_syn_options());
    assert_eq!(obs.mss, Some(1460));
}

#[test]
fn test_extracts_wscale() {
    let obs = ipv4_obs(64, 65535, &linux_syn_options());
    assert_eq!(obs.wscale, Some(6));
}

#[test]
fn test_olayout_order_and_contents() {
    let obs = ipv4_obs(64, 65535, &linux_syn_options());
    assert_eq!(
        obs.olayout,
        vec![
            TcpOption::Mss,
            TcpOption::Nop,
            TcpOption::Ws,
            TcpOption::Nop,
            TcpOption::Nop,
            TcpOption::TS,
            TcpOption::Sok,
        ]
    );
}

#[test]
fn test_empty_options() {
    let obs = ipv4_obs(64, 8192, &[]);
    assert!(obs.olayout.is_empty());
    assert!(obs.mss.is_none());
    assert!(obs.wscale.is_none());
}

#[test]
fn test_eol_stops_parsing() {
    // MSS, EOL, then a NOP that should be ignored
    let buf: &[u8] = &[2, 4, 0x05, 0xb4, 0, 1];
    let obs = ipv4_obs(64, 65535, buf);
    assert_eq!(obs.mss, Some(1460));
    assert!(obs.olayout.contains(&TcpOption::Eol(1)));
    assert!(!obs.olayout.contains(&TcpOption::Nop));
}

#[test]
fn test_unknown_option_kind() {
    let buf: &[u8] = &[254, 4, 0xde, 0xad];
    let obs = ipv4_obs(64, 65535, buf);
    assert_eq!(obs.olayout, vec![TcpOption::Unknown(254)]);
}

#[test]
fn test_truncated_tlv_stops_gracefully() {
    // MSS option declares length=4 but only 3 bytes are available — truncated.
    // Parser stops at the bad entry, returns what came before, and sets malformed=true.
    let buf: &[u8] = &[1, 2, 4, 0x05]; // NOP, then truncated MSS
    let parsed = parse_options_raw(buf);
    assert_eq!(parsed.olayout, vec![TcpOption::Nop]);
    assert!(parsed.mss.is_none());
    assert!(parsed.wscale.is_none());
    assert!(parsed.malformed);
}

#[test]
fn test_valid_options_not_malformed() {
    let parsed = parse_options_raw(&linux_syn_options());
    assert!(!parsed.malformed);
}

#[test]
fn test_partial_data_returned_on_malformed() {
    // MSS(1460) + NOP + WS(6) parsed correctly, then a Timestamps option that
    // declares length=10 but only 4 bytes of data are present (truncated).
    let buf: &[u8] = &[
        2, 4, 0x05, 0xb4, // MSS = 1460
        1,    // NOP
        3, 3, 6, // WS = 6
        8, 10, 0, 0, 0, 1, // Timestamps declares length=10, only 4 data bytes present
    ];
    let parsed = parse_options_raw(buf);
    assert_eq!(parsed.mss, Some(1460));
    assert_eq!(parsed.wscale, Some(6));
    assert_eq!(parsed.olayout, vec![TcpOption::Mss, TcpOption::Nop, TcpOption::Ws]);
    assert!(parsed.malformed);
}

#[test]
fn test_windows_syn_options() {
    // Typical Windows SYN: MSS(1460), NOP, WS(8), NOP, NOP, SACK-permitted
    let buf: &[u8] = &[2, 4, 0x05, 0xb4, 1, 3, 3, 8, 1, 1, 4, 2];
    let obs = ipv4_obs(128, 65535, buf);
    assert_eq!(obs.mss, Some(1460));
    assert_eq!(obs.wscale, Some(8));
    assert_eq!(
        obs.olayout,
        vec![
            TcpOption::Mss,
            TcpOption::Nop,
            TcpOption::Ws,
            TcpOption::Nop,
            TcpOption::Nop,
            TcpOption::Sok
        ]
    );
}

#[test]
fn test_macos_syn_options() {
    let obs = ipv4_obs(64, 65535, &linux_syn_options());
    assert_eq!(obs.mss, Some(1460));
    assert_eq!(obs.wscale, Some(6));
    assert!(obs.olayout.contains(&TcpOption::TS));
}

#[test]
fn test_ipv4_fields_set_correctly() {
    let obs = ipv4_obs(64, 65535, &linux_syn_options());
    assert_eq!(obs.version, IpVersion::V4);
    assert_eq!(obs.olen, 0);
    assert!(obs.quirks.is_empty());
    assert_eq!(obs.pclass, PayloadSize::Zero);
}

#[test]
fn test_ipv6_observation() {
    // IPv6: ip_hdr_len=40, hop_limit=128
    let buf: &[u8] = &[2, 4, 0x05, 0xb4, 1, 3, 3, 6]; // MSS=1460, NOP, WS=6
    let obs = build_obs(IpVersion::V6, 40, 128, 65535, 0, buf, vec![], PayloadSize::Zero);
    assert_eq!(obs.version, IpVersion::V6);
    assert_eq!(obs.mss, Some(1460));
    assert_eq!(obs.wscale, Some(6));
}
