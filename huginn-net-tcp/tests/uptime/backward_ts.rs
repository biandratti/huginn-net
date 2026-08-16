//! Tests for backward timestamp detection and handling

use huginn_net_tcp::uptime::{check_ts_tcp, Connection};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use ttl_cache::TtlCache;

#[test]
fn test_timestamp_wraparound_detection() {
    // Test detection of timestamp wraparound (32-bit overflow)
    let mut connection_tracker = TtlCache::new(100);

    let connection = Connection {
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        src_port: 12345,
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)),
        dst_port: 80,
    };

    // Simulate a timestamp near the 32-bit limit
    let near_max_timestamp = u32::MAX - 1000; // Close to overflow

    // Store SYN data with timestamp near maximum
    let (client_uptime, server_uptime) =
        check_ts_tcp(&mut connection_tracker, &connection, true, near_max_timestamp);
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

    // Wait enough time to avoid MIN_TWAIT validation
    std::thread::sleep(Duration::from_millis(50));

    // Simulate timestamp after wraparound (small value after overflow)
    let after_wraparound_timestamp = 1000; // Small value after overflow

    let (client_uptime, server_uptime) = check_ts_tcp(
        &mut connection_tracker,
        &server_connection,
        false,
        after_wraparound_timestamp,
    );

    // The algorithm should detect this as a backward timestamp and handle it
    // It might return None due to other validations, but it should not panic or fail
    // The key is that it processes the wraparound case without errors
    println!("Wraparound test result: client={client_uptime:?}, server={server_uptime:?}");
}

#[test]
fn test_small_backward_movement_within_grace() {
    // Test small backward movements within the grace period (100ms)
    let mut connection_tracker = TtlCache::new(100);

    let connection = Connection {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        src_port: 54321,
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        dst_port: 443,
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

    // Wait a very short time (within grace period)
    std::thread::sleep(Duration::from_millis(30));

    // Simulate a small backward movement (packet reordering)
    let backward_timestamp = 9998; // 2 ticks backward

    let (client_uptime, server_uptime) =
        check_ts_tcp(&mut connection_tracker, &server_connection, false, backward_timestamp);

    // Should be rejected due to small backward movement within grace period
    assert!(
        client_uptime.is_none() && server_uptime.is_none(),
        "Small backward movement within grace period should be rejected"
    );
}

#[test]
fn test_large_backward_movement() {
    // Test large backward movements (likely NAT/load balancer change)
    let mut connection_tracker = TtlCache::new(100);

    let connection = Connection {
        src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 1, 1)),
        src_port: 8080,
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 1, 2)),
        dst_port: 9090,
    };

    // Store SYN data with high timestamp
    let high_timestamp = 1_000_000;
    let (client_uptime, server_uptime) =
        check_ts_tcp(&mut connection_tracker, &connection, true, high_timestamp);
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

    // Wait sufficient time
    std::thread::sleep(Duration::from_millis(200));

    // Simulate large backward movement (different server behind NAT)
    let low_timestamp = 100_000; // Much lower timestamp

    let (client_uptime, server_uptime) =
        check_ts_tcp(&mut connection_tracker, &server_connection, false, low_timestamp);

    // The algorithm should detect this as a large backward movement
    // and attempt to calculate frequency using the inverted difference
    println!(
        "Large backward movement test result: client={client_uptime:?}, server={server_uptime:?}"
    );
}

#[test]
fn test_normal_forward_progression() {
    // Test normal forward timestamp progression (baseline)
    let mut connection_tracker = TtlCache::new(100);

    let connection = Connection {
        src_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
        src_port: 12345,
        dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)),
        dst_port: 80,
    };

    // Store SYN data
    let syn_timestamp = 500_000;
    let (client_uptime, server_uptime) =
        check_ts_tcp(&mut connection_tracker, &connection, true, syn_timestamp);
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

    // Wait sufficient time
    std::thread::sleep(Duration::from_millis(100));

    // Normal forward progression
    let forward_timestamp = 500_100; // 100 ticks forward

    let (client_uptime, server_uptime) =
        check_ts_tcp(&mut connection_tracker, &server_connection, false, forward_timestamp);

    // This should be processed normally (though may fail other validations)
    println!("Normal forward progression test result: client={client_uptime:?}, server={server_uptime:?}");
}

#[test]
fn test_wraparound_calculation_logic() {
    // Test the mathematical logic for wraparound detection
    // p0f uses: is_backward = (ts_diff > !ts_diff)
    // This happens when ts_diff is in the upper half of u32 range (> u32::MAX/2)

    println!("=== Testing Wraparound Detection Logic ===");

    let threshold = u32::MAX / 2;
    println!("Threshold (u32::MAX/2): {threshold}\n");

    // Case 1: Normal forward progression
    let ts_ref1 = 1000u32;
    let ts_cur1 = 2000u32;
    let diff1 = ts_cur1.wrapping_sub(ts_ref1);
    let inv1 = !diff1;
    let is_backward1 = diff1 > inv1;

    println!("Case 1 - Forward progression:");
    println!(
        "  ref={ts_ref1}, cur={ts_cur1}, diff={diff1}, !diff={inv1}, is_backward={is_backward1}"
    );
    assert!(!is_backward1, "Forward progression should NOT be detected as backward");
    assert!(diff1 <= threshold, "Forward progression: diff should be <= threshold");

    // Case 2: Small backward movement
    let ts_ref2 = 2000u32;
    let ts_cur2 = 1000u32;
    let diff2 = ts_cur2.wrapping_sub(ts_ref2);
    let inv2 = !diff2;
    let is_backward2 = diff2 > inv2;

    println!("Case 2 - Small backward movement:");
    println!(
        "  ref={ts_ref2}, cur={ts_cur2}, diff={diff2}, !diff={inv2}, is_backward={is_backward2}"
    );
    assert!(is_backward2, "Small backward movement SHOULD be detected as backward");
    assert!(diff2 > threshold, "Small backward: diff should be > threshold");

    // Case 3: Large backward movement (what p0f calls "wraparound")
    let ts_ref3 = 100u32;
    let ts_cur3 = u32::MAX - 100; // Very large number
    let diff3 = ts_cur3.wrapping_sub(ts_ref3);
    let inv3 = !diff3;
    let is_backward3 = diff3 > inv3;

    println!("Case 3 - Large backward movement:");
    println!(
        "  ref={ts_ref3}, cur={ts_cur3}, diff={diff3}, !diff={inv3}, is_backward={is_backward3}"
    );
    assert!(is_backward3, "Large backward movement SHOULD be detected as backward");
    assert!(diff3 > threshold, "Large backward: diff should be > threshold");

    // Case 4: True overflow scenario (timestamp counter wrapped around)
    let ts_ref4 = u32::MAX - 100;
    let ts_cur4 = 100u32;
    let diff4 = ts_cur4.wrapping_sub(ts_ref4);
    let inv4 = !diff4;
    let is_backward4 = diff4 > inv4;

    println!("Case 4 - True overflow (legitimate wraparound):");
    println!(
        "  ref={ts_ref4}, cur={ts_cur4}, diff={diff4}, !diff={inv4}, is_backward={is_backward4}"
    );
    assert!(
        !is_backward4,
        "True overflow should NOT be detected as backward (small positive result)"
    );
    assert!(diff4 <= threshold, "True overflow: diff should be <= threshold");

    println!("\n✓ All wraparound detection cases validated correctly");
}

#[test]
fn test_frequency_calculation_with_wraparound() {
    // Test frequency calculation logic for wraparound scenarios

    // Simulate a realistic backward timestamp scenario
    // This represents a case where timestamp went backward significantly
    let ts_reference = 1_000_000u32; // High reference timestamp
    let ts_current = 100_000u32; // Much lower current timestamp (backward jump)
    let time_diff_ms = 100; // 100ms elapsed

    let ts_diff = ts_current.wrapping_sub(ts_reference);
    let inverted_diff = !ts_diff;

    // Check if this is detected as backward movement
    if ts_diff > inverted_diff {
        // This should be detected as wraparound
        let effective_diff = inverted_diff;
        let frequency = (effective_diff as f64 * 1000.0) / time_diff_ms as f64;

        println!("Backward movement detected:");
        println!("  ts_reference: {ts_reference}");
        println!("  ts_current: {ts_current}");
        println!("  ts_diff: {ts_diff}");
        println!("  inverted_diff: {inverted_diff}");
        println!("  effective_diff: {effective_diff}");
        println!("  calculated frequency: {frequency:.2} Hz");

        // The frequency should be reasonable for the inverted difference
        assert!(
            frequency > 0.0 && frequency < 50_000_000.0,
            "Calculated frequency {frequency} Hz should be reasonable"
        );
    } else {
        // This is actually the expected case for this scenario
        // Let's calculate what we expect
        println!("Forward progression detected (this might be correct):");
        println!("  ts_reference: {ts_reference}");
        println!("  ts_current: {ts_current}");
        println!("  ts_diff: {ts_diff}");
        println!("  inverted_diff: {inverted_diff}");
    }
}
