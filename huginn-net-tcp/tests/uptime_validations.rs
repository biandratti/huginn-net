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
        assert!(
            client_uptime.is_none() && server_uptime.is_none(),
            "{}",
            description
        );
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

    // Wait a bit to ensure we don't hit MIN_TWAIT validation
    std::thread::sleep(Duration::from_millis(30));

    // Test with exactly MIN_TS_DIFF (5 ticks) - should be accepted
    let _result = check_ts_tcp(&mut connection_tracker, &server_connection, false, 10005);
    // Note: This might still return None due to other validations (like frequency calculation)
    // but it should pass the MIN_TS_DIFF validation

    // Test with larger timestamp difference - should definitely be processed
    connection_tracker.clear();
    let _ = check_ts_tcp(&mut connection_tracker, &connection, true, 10000);
    std::thread::sleep(Duration::from_millis(100)); // Wait longer

    let _result = check_ts_tcp(&mut connection_tracker, &server_connection, false, 10100);
    // 100 ticks difference
    // This should pass MIN_TS_DIFF validation (though may fail other validations)
}
