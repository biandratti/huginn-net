use huginn_net_tcp::{calculate_uptime_improved, TcpTimestamp, UptimeTracker};

#[test]
fn test_improved_uptime_tracking() {
    let mut tracker = UptimeTracker::new();

    // Test initial state
    assert!(!tracker.has_valid_client_frequency());
    assert!(!tracker.has_valid_server_frequency());
    assert_eq!(tracker.cli_tps, 0);
    assert_eq!(tracker.srv_tps, 0);

    // Simulate SYN packet (client -> server)
    let syn_result = calculate_uptime_improved(&mut tracker, 1000000, true);
    assert!(syn_result.is_none()); // SYN packets don't calculate uptime
    assert!(tracker.last_syn.is_some());

    // Simulate SYN+ACK packet (server -> client) after 100ms
    // This should calculate frequency and uptime
    std::thread::sleep(std::time::Duration::from_millis(100));
    let synack_result = calculate_uptime_improved(&mut tracker, 1001000, false);

    if let Some(uptime) = synack_result {
        println!("Calculated uptime: {uptime:?}");

        // Should have calculated a reasonable frequency (around 1000 Hz)
        assert!(tracker.has_valid_client_frequency());
        assert!(tracker.cli_tps > 900 && tracker.cli_tps < 1100);

        // Uptime should be reasonable (based on timestamp value)
        assert!(uptime.freq > 900.0 && uptime.freq < 1100.0);
        assert!(uptime.up_mod_days > 40 && uptime.up_mod_days < 60); // ~50 days for 1000 Hz
    } else {
        // If calculation failed, check why
        if tracker.cli_tps == -1 {
            println!("Client frequency marked as bad");
        } else {
            println!("No uptime calculated - tracker state: {tracker:?}");
        }
    }
}

#[test]
fn test_bad_frequency_handling() {
    let mut tracker = UptimeTracker::new();

    // Store SYN timestamp
    let _syn_result = calculate_uptime_improved(&mut tracker, 1000000, true);

    // Try with a timestamp that would result in invalid frequency
    // (too small time difference)
    let bad_result = calculate_uptime_improved(&mut tracker, 1000001, false);

    // Should fail and mark frequency as bad
    assert!(bad_result.is_none());
    // The frequency might be marked as bad depending on timing

    // Try again - should skip calculation since frequency is bad
    let retry_result = calculate_uptime_improved(&mut tracker, 1000100, false);
    if tracker.cli_tps == -1 {
        assert!(retry_result.is_none());
        println!("Correctly skipped calculation for bad frequency");
    }
}

#[test]
fn test_frequency_reuse() {
    let mut tracker = UptimeTracker::new();

    // Store SYN timestamp
    let _syn_result = calculate_uptime_improved(&mut tracker, 1000000, true);

    // Calculate frequency once
    std::thread::sleep(std::time::Duration::from_millis(100));
    let first_result = calculate_uptime_improved(&mut tracker, 1001000, false);

    if let Some(_uptime1) = first_result {
        let stored_frequency = tracker.cli_tps;
        assert!(tracker.has_valid_client_frequency());

        // Use the same frequency for subsequent calculations
        let second_result = calculate_uptime_improved(&mut tracker, 1002000, false);

        if let Some(_uptime2) = second_result {
            // Frequency should remain the same (reused)
            assert_eq!(tracker.cli_tps, stored_frequency);
            println!("Successfully reused frequency: {stored_frequency} Hz");
        }
    }
}

#[test]
fn test_tcp_timestamp_creation() {
    // Test TcpTimestamp creation methods
    let ts1 = TcpTimestamp::new(12345, 67890);
    assert_eq!(ts1.ts_val, 12345);
    assert_eq!(ts1.recv_time_ms, 67890);

    let ts2 = TcpTimestamp::now(54321);
    assert_eq!(ts2.ts_val, 54321);
    assert!(ts2.recv_time_ms > 0); // Should have current time
}

#[test]
fn test_uptime_tracker_methods() {
    let mut tracker = UptimeTracker::new();

    // Test initial state
    assert!(!tracker.has_valid_client_frequency());
    assert!(!tracker.has_valid_server_frequency());

    // Test marking frequencies as bad
    tracker.mark_client_frequency_bad();
    assert_eq!(tracker.cli_tps, -1);
    assert!(!tracker.has_valid_client_frequency());

    tracker.mark_server_frequency_bad();
    assert_eq!(tracker.srv_tps, -1);
    assert!(!tracker.has_valid_server_frequency());

    // Test setting valid frequencies
    tracker.cli_tps = 1000;
    tracker.srv_tps = 100;
    assert!(tracker.has_valid_client_frequency());
    assert!(tracker.has_valid_server_frequency());
}
