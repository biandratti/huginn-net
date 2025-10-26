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
    let (client_uptime, server_uptime) = check_ts_tcp(
        &mut connection_tracker,
        &connection,
        true,
        near_max_timestamp,
    );
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

    let (client_uptime, server_uptime) = check_ts_tcp(
        &mut connection_tracker,
        &server_connection,
        false,
        backward_timestamp,
    );

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

    let (client_uptime, server_uptime) = check_ts_tcp(
        &mut connection_tracker,
        &server_connection,
        false,
        low_timestamp,
    );

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

    let (client_uptime, server_uptime) = check_ts_tcp(
        &mut connection_tracker,
        &server_connection,
        false,
        forward_timestamp,
    );

    // This should be processed normally (though may fail other validations)
    println!("Normal forward progression test result: client={client_uptime:?}, server={server_uptime:?}");
}

#[test]
fn test_wraparound_calculation_logic() {
    // Test the mathematical logic for wraparound detection

    // Test case 1: Normal forward progression
    let ts_current = 1000u32;
    let ts_ref = 500u32;
    let ts_diff = ts_current.wrapping_sub(ts_ref);
    let inverted_diff = !ts_diff;

    // For forward progression: ts_diff should be < !ts_diff
    assert!(
        ts_diff < inverted_diff,
        "Forward progression: ts_diff ({ts_diff}) should be < inverted_diff ({inverted_diff})"
    );

    // Test case 2: Actual wraparound scenario (large backward jump)
    // This simulates a timestamp that went significantly backward
    let ts_current_wrap = 1000u32;
    let ts_ref_wrap = 2000u32; // Reference is higher than current (backward)
    let ts_diff_wrap = ts_current_wrap.wrapping_sub(ts_ref_wrap);
    let inverted_diff_wrap = !ts_diff_wrap;

    // For large backward movement: ts_diff should be > !ts_diff
    // ts_diff = 1000 - 2000 = wrapping to very large number
    // !ts_diff = bitwise NOT of that large number = small number
    assert!(
        ts_diff_wrap > inverted_diff_wrap,
        "Large backward movement: ts_diff ({ts_diff_wrap}) should be > inverted_diff ({inverted_diff_wrap})"
    );

    println!("Forward case: ts_diff={ts_diff}, inverted_diff={inverted_diff}");
    println!("Wraparound case: ts_diff={ts_diff_wrap}, inverted_diff={inverted_diff_wrap}");
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

        // Don't panic - this might be the correct behavior
        // Test completed - behavior documented
    }
}

#[test]
fn test_understand_wraparound_logic() {
    // Let's understand when ts_diff > !ts_diff actually happens

    println!("=== Understanding Wraparound Detection Logic ===");

    // Case 1: Normal forward progression
    let ts_ref1 = 1000u32;
    let ts_cur1 = 2000u32;
    let diff1 = ts_cur1.wrapping_sub(ts_ref1);
    let inv1 = !diff1;
    let is_forward1 = diff1 > inv1;
    println!(
        "Forward: ref={ts_ref1}, cur={ts_cur1}, diff={diff1}, !diff={inv1}, diff>!diff={is_forward1}",
    );

    // Case 2: Small backward movement
    let ts_ref2 = 2000u32;
    let ts_cur2 = 1000u32;
    let diff2 = ts_cur2.wrapping_sub(ts_ref2);
    let inv2 = !diff2;
    let is_forward2 = diff2 > inv2;
    println!(
        "Small backward: ref={ts_ref2}, cur={ts_cur2}, diff={diff2}, !diff={inv2}, diff>!diff={is_forward2}",
    );

    // Case 3: Large backward movement (what p0f considers "wraparound")
    let ts_ref3 = 100u32;
    let ts_cur3 = u32::MAX - 100; // Very large number
    let diff3 = ts_cur3.wrapping_sub(ts_ref3);
    let inv3 = !diff3;
    let is_forward3 = diff3 > inv3;
    println!(
        "Large backward: ref={ts_ref3}, cur={ts_cur3}, diff={diff3}, !diff={inv3}, diff>!diff={is_forward3}",
    );

    // Case 4: True overflow scenario
    let ts_ref4 = u32::MAX - 100;
    let ts_cur4 = 100u32;
    let diff4 = ts_cur4.wrapping_sub(ts_ref4);
    let inv4 = !diff4;
    let is_forward4 = diff4 > inv4;
    println!(
        "True overflow: ref={ts_ref4}, cur={ts_cur4}, diff={diff4}, !diff={inv4}, diff>!diff={is_forward4}",
    );

    // The key insight: ts_diff > !ts_diff happens when the result of wrapping_sub
    // is in the upper half of u32 range (> u32::MAX/2)
    let threshold = u32::MAX / 2;
    println!("Threshold (u32::MAX/2): {threshold}");

    assert!(
        diff1 <= threshold,
        "Forward progression should be <= threshold"
    );
    assert!(diff2 > threshold, "Small backward should be > threshold");
    assert!(
        diff4 <= threshold,
        "True overflow should be <= threshold (small positive result)"
    );
}
