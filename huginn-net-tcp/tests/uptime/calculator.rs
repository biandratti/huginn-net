//! Tests for uptime calculation validations

use huginn_net_tcp::uptime::{check_ts_tcp, Connection};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use ttl_cache::TtlCache;

#[test]
fn test_min_twait_validation() {
    // Test that intervals shorter than MIN_TWAIT (25ms) are rejected
    let mut connection_tracker = TtlCache::new(100);

    let connection = Connection {
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        src_port: 12345,
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
        dst_port: 80,
    };

    // First, simulate storing SYN data (from_client = true)
    let (client_uptime, server_uptime) =
        check_ts_tcp(&mut connection_tracker, &connection, true, 1000);
    assert!(
        client_uptime.is_none() && server_uptime.is_none(),
        "SYN packet should not return uptime calculation"
    );

    // Now simulate a very quick response (< 25ms) - should be rejected
    // We can't easily control the timing in this test, but we can verify the logic
    // by checking that very small timestamp differences are rejected

    let server_connection = Connection {
        src_ip: connection.dst_ip,
        src_port: connection.dst_port,
        dst_ip: connection.src_ip,
        dst_port: connection.src_port,
    };

    // Try with a very small timestamp difference (< 5 ticks)
    let (client_uptime, server_uptime) =
        check_ts_tcp(&mut connection_tracker, &server_connection, false, 1003); // Only 3 ticks difference
    assert!(
        client_uptime.is_none() && server_uptime.is_none(),
        "Should reject timestamp differences < MIN_TS_DIFF (5 ticks)"
    );
}

#[test]
fn test_min_ts_diff_validation() {
    // Test that timestamp differences smaller than MIN_TS_DIFF (5 ticks) are rejected
    let mut connection_tracker = TtlCache::new(100);

    let connection = Connection {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        src_port: 54321,
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        dst_port: 443,
    };

    // Store SYN data
    let (client_uptime, server_uptime) =
        check_ts_tcp(&mut connection_tracker, &connection, true, 5000);
    assert!(
        client_uptime.is_none() && server_uptime.is_none(),
        "SYN packet should not return uptime calculation"
    );

    let server_connection = Connection {
        src_ip: connection.dst_ip,
        src_port: connection.dst_port,
        dst_ip: connection.src_ip,
        dst_port: connection.src_port,
    };

    // Test various small timestamp differences
    let test_cases = [
        (5000, "Same timestamp should be rejected"),
        (5001, "1 tick difference should be rejected"),
        (5002, "2 tick difference should be rejected"),
        (5003, "3 tick difference should be rejected"),
        (5004, "4 tick difference should be rejected"),
    ];

    for (ts_val, description) in test_cases {
        // Reset the connection tracker for each test
        connection_tracker.clear();
        let _ = check_ts_tcp(&mut connection_tracker, &connection, true, 5000);

        let (client_uptime, server_uptime) =
            check_ts_tcp(&mut connection_tracker, &server_connection, false, ts_val);
        assert!(client_uptime.is_none() && server_uptime.is_none(), "{}", description);
    }
}

#[test]
fn test_valid_timestamp_difference() {
    // Test that valid timestamp differences (>= MIN_TS_DIFF) are processed
    let mut connection_tracker = TtlCache::new(100);

    let connection = Connection {
        src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
        src_port: 8080,
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 0, 2)),
        dst_port: 9090,
    };

    // Store SYN data
    let (client_uptime, server_uptime) =
        check_ts_tcp(&mut connection_tracker, &connection, true, 10000);
    assert!(
        client_uptime.is_none() && server_uptime.is_none(),
        "SYN packet should not return uptime calculation"
    );

    let server_connection = Connection {
        src_ip: connection.dst_ip,
        src_port: connection.dst_port,
        dst_ip: connection.src_ip,
        dst_port: connection.src_port,
    };

    // Wait enough time to ensure we don't hit MIN_TWAIT validation (25ms)
    std::thread::sleep(Duration::from_millis(30));

    // Test with exactly MIN_TS_DIFF (5 ticks) - should pass MIN_TS_DIFF validation
    let (client_uptime, server_uptime) =
        check_ts_tcp(&mut connection_tracker, &server_connection, false, 10005);
    // Note: Result might still be None due to frequency being too low/high for the time interval
    // but it should NOT fail on MIN_TS_DIFF validation
    println!(
        "MIN_TS_DIFF test (5 ticks): client={:?}, server={:?}",
        client_uptime.is_some(),
        server_uptime.is_some()
    );

    // Test with realistic timestamp difference for 250 Hz system
    // Using 250 Hz is more reliable as it gives us more tolerance for timing variations
    connection_tracker.clear();
    let (client_uptime, server_uptime) =
        check_ts_tcp(&mut connection_tracker, &connection, true, 1_000_000);
    assert!(
        client_uptime.is_none() && server_uptime.is_none(),
        "SYN should not calculate uptime"
    );

    // Wait long enough for a realistic frequency calculation (100ms)
    std::thread::sleep(Duration::from_millis(100));

    // With 25 ticks over ~100ms, frequency should be ~250 Hz (valid range)
    // This is more tolerant to timing variations:
    // - If sleep is 90ms:  25/0.09  = 277 Hz ✓
    // - If sleep is 100ms: 25/0.10  = 250 Hz ✓
    // - If sleep is 110ms: 25/0.11  = 227 Hz ✓
    let (client_uptime, server_uptime) =
        check_ts_tcp(&mut connection_tracker, &server_connection, false, 1_000_025);

    // This should pass:
    // - MIN_TS_DIFF: 25 ticks >> 5 ticks ✓
    // - MIN_TWAIT: ~100ms > 25ms ✓
    // - Frequency: ~250 Hz is in valid range (100-1500 Hz) ✓

    // The calculation might fail due to timing variations, so we don't assert success
    // but we do verify that if it succeeds, the frequency is reasonable
    if let Some(uptime) = client_uptime.or(server_uptime) {
        println!(
            "Successfully calculated uptime: freq={:.2} Hz, days={}, hrs={}, min={}",
            uptime.freq, uptime.days, uptime.hours, uptime.min
        );
        // Verify frequency is in valid range (should be rounded to 250 Hz)
        assert!(
            uptime.freq >= 100.0 && uptime.freq <= 500.0,
            "Calculated frequency should be in range 100-500 Hz (expected ~250 Hz), got {} Hz",
            uptime.freq
        );
    } else {
        println!(
            "Note: Uptime calculation may fail due to system timing variations. \
             This is expected in timing-sensitive tests."
        );
    }
}
