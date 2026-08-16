#[test]
fn test_tcp_timestamp_endianness() {
    // Simulate TCP timestamp option data in big-endian format
    // Option 8 (TIMESTAMPS), length 10, TSval=0x12345678, TSecr=0x87654321
    let tcp_option_data = [
        8, 10, // Kind=8, Length=10
        0x12, 0x34, 0x56, 0x78, // TSval = 0x12345678 (big-endian)
        0x87, 0x65, 0x43, 0x21, // TSecr = 0x87654321 (big-endian)
    ];

    // Extract TSval using big-endian (correct according to RFC 1323)
    let ts_val_bytes: [u8; 4] =
        [tcp_option_data[2], tcp_option_data[3], tcp_option_data[4], tcp_option_data[5]];
    let ts_val_be = u32::from_be_bytes(ts_val_bytes);

    // Extract TSval using native-endian (incorrect)
    let ts_val_ne = u32::from_ne_bytes(ts_val_bytes);

    // On little-endian systems, these should be different
    println!("Big-endian TSval: 0x{ts_val_be:08x} ({ts_val_be})",);
    println!("Native-endian TSval: 0x{ts_val_ne:08x} ({ts_val_ne})");

    // The correct value should be 0x12345678
    assert_eq!(ts_val_be, 0x12345678);

    // On little-endian systems, native-endian would give 0x78563412
    #[cfg(target_endian = "little")]
    {
        assert_eq!(ts_val_ne, 0x78563412);
        assert_ne!(
            ts_val_be, ts_val_ne,
            "Big-endian and native-endian should be different on little-endian systems"
        );
    }

    // On big-endian systems, they would be equal
    #[cfg(target_endian = "big")]
    {
        assert_eq!(
            ts_val_be, ts_val_ne,
            "Big-endian and native-endian should be equal on big-endian systems"
        );
    }
}

#[test]
fn test_timestamp_zero_detection() {
    // Test to verify that zero timestamp detection works correctly
    let zero_timestamp = [
        8, 10, // Kind=8, Length=10
        0x00, 0x00, 0x00, 0x00, // TSval = 0 (big-endian)
        0x00, 0x00, 0x00, 0x00, // TSecr = 0 (big-endian)
    ];

    let ts_val_bytes: [u8; 4] =
        [zero_timestamp[2], zero_timestamp[3], zero_timestamp[4], zero_timestamp[5]];
    let ts_val = u32::from_be_bytes(ts_val_bytes);

    assert_eq!(ts_val, 0, "Zero timestamp should be detected correctly");
}

#[test]
fn test_realistic_timestamp_values() {
    // Test with realistic timestamp values
    // Simulate a Linux system with 1000 Hz that has been up for ~1 hour
    // 1 hour = 3600 seconds = 3,600,000 ticks at 1000 Hz
    let realistic_timestamp = [
        8, 10, // Kind=8, Length=10
        0x00, 0x36, 0xEE, 0x80, // TSval = 3,600,000 (big-endian)
        0x00, 0x00, 0x00, 0x00, // TSecr = 0 (big-endian)
    ];

    let ts_val_bytes: [u8; 4] = [
        realistic_timestamp[2],
        realistic_timestamp[3],
        realistic_timestamp[4],
        realistic_timestamp[5],
    ];
    let ts_val = u32::from_be_bytes(ts_val_bytes);

    assert_eq!(ts_val, 3_600_000);

    // Calculate estimated uptime at 1000 Hz
    let estimated_uptime_seconds = ts_val / 1000;
    let estimated_uptime_hours = estimated_uptime_seconds / 3600;

    assert_eq!(estimated_uptime_hours, 1, "Should estimate ~1 hour of uptime");
}
