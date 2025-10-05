use huginn_net_db::tcp::{IpVersion, WindowSize};
use huginn_net_tcp::window_size::detect_win_multiplicator;

#[test]
fn test_mss_multiple() {
    let mss = 1000;
    let multiplier = 40;
    let window = mss * multiplier; // 1000 * 40 = 40000 (within u16)
    let result = detect_win_multiplicator(window, mss, 40, false, &IpVersion::V4);
    assert!(matches!(result, WindowSize::Mss(40)));
}

#[test]
fn test_mtu_multiple() {
    let window = 4500; // 1500 * 3
    let result = detect_win_multiplicator(window, 1460, 40, false, &IpVersion::V4);
    assert!(matches!(result, WindowSize::Mtu(3)));
}

#[test]
fn test_modulo_pattern() {
    let window = 8192; // Power of 2, should match largest modulo (4096)
    let mss = 1337; // Prime number MSS to avoid any accidental divisions
    let result = detect_win_multiplicator(window, mss, 40, false, &IpVersion::V4);
    println!("Result for window {window}: {result:?}");
    assert!(matches!(result, WindowSize::Mod(4096)));
}

#[test]
fn test_timestamp_adjustment() {
    let window = 43800; // (1460 - 12) * 30
    let result = detect_win_multiplicator(window, 1460, 40, true, &IpVersion::V4);
    assert!(matches!(result, WindowSize::Mss(30)));
}

#[test]
fn test_direct_value() {
    let window = 12345; // Arbitrary value
    let result = detect_win_multiplicator(window, 1460, 40, false, &IpVersion::V4);
    assert!(matches!(result, WindowSize::Value(12345)));
}
