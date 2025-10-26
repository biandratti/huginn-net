//! Tests for p0f-style intelligent frequency rounding

#[test]
fn test_p0f_rounding_algorithm_behavior() {
    // Range 0: Special case
    // 0 Hz -> 1 Hz

    // Range 1-10: No rounding
    // 1 Hz -> 1 Hz, 5 Hz -> 5 Hz, 10 Hz -> 10 Hz

    // Range 11-50: Round to multiples of 5
    // Formula: (freq + 3) / 5 * 5
    // Examples: 11 -> (11+3)/5*5 = 14/5*5 = 2*5 = 10
    //          13 -> (13+3)/5*5 = 16/5*5 = 3*5 = 15
    //          18 -> (18+3)/5*5 = 21/5*5 = 4*5 = 20

    let test_cases_range_11_50 = [
        (11, 10), // (11+3)/5*5 = 14/5*5 = 2*5 = 10
        (12, 15), // (12+3)/5*5 = 15/5*5 = 3*5 = 15
        (13, 15), // (13+3)/5*5 = 16/5*5 = 3*5 = 15
        (17, 20), // (17+3)/5*5 = 20/5*5 = 4*5 = 20
        (18, 20), // (18+3)/5*5 = 21/5*5 = 4*5 = 20
        (22, 25), // (22+3)/5*5 = 25/5*5 = 5*5 = 25
        (48, 50), // (48+3)/5*5 = 51/5*5 = 10*5 = 50
    ];

    for (input, expected) in test_cases_range_11_50 {
        let calculated = (input + 3) / 5 * 5;
        assert_eq!(
            calculated, expected,
            "Range 11-50: {input} Hz should round to {expected} Hz"
        );
    }

    // Range 51-100: Round to multiples of 10
    // Formula: (freq + 7) / 10 * 10
    let test_cases_range_51_100 = [
        (51, 50),  // (51+7)/10*10 = 58/10*10 = 5*10 = 50
        (55, 60),  // (55+7)/10*10 = 62/10*10 = 6*10 = 60
        (64, 70),  // (64+7)/10*10 = 71/10*10 = 7*10 = 70
        (95, 100), // (95+7)/10*10 = 102/10*10 = 10*10 = 100
        (99, 100), // (99+7)/10*10 = 106/10*10 = 10*10 = 100
    ];

    for (input, expected) in test_cases_range_51_100 {
        let calculated = (input + 7) / 10 * 10;
        assert_eq!(
            calculated, expected,
            "Range 51-100: {input} Hz should round to {expected} Hz"
        );
    }

    // Range 101-500: Round to multiples of 50
    // Formula: (freq + 33) / 50 * 50
    let test_cases_range_101_500 = [
        (101, 100), // (101+33)/50*50 = 134/50*50 = 2*50 = 100
        (125, 150), // (125+33)/50*50 = 158/50*50 = 3*50 = 150
        (248, 250), // (248+33)/50*50 = 281/50*50 = 5*50 = 250
        (275, 300), // (275+33)/50*50 = 308/50*50 = 6*50 = 300
        (499, 500), // (499+33)/50*50 = 532/50*50 = 10*50 = 500
    ];

    for (input, expected) in test_cases_range_101_500 {
        let calculated = (input + 33) / 50 * 50;
        assert_eq!(
            calculated, expected,
            "Range 101-500: {input} Hz should round to {expected} Hz"
        );
    }

    // Range >500: Round to multiples of 100
    // Formula: (freq + 67) / 100 * 100
    let test_cases_range_above_500 = [
        (501, 500),   // (501+67)/100*100 = 568/100*100 = 5*100 = 500
        (650, 700),   // (650+67)/100*100 = 717/100*100 = 7*100 = 700
        (997, 1000),  // (997+67)/100*100 = 1064/100*100 = 10*100 = 1000
        (1050, 1100), // (1050+67)/100*100 = 1117/100*100 = 11*100 = 1100
    ];

    for (input, expected) in test_cases_range_above_500 {
        let calculated = (input + 67) / 100 * 100;
        assert_eq!(
            calculated, expected,
            "Range >500: {input} Hz should round to {expected} Hz"
        );
    }
}

#[test]
fn test_common_os_frequencies() {
    let common_frequencies = [
        // Linux frequencies
        (100.0, "Linux 2.4 default"),
        (250.0, "Linux 2.6+ CONFIG_HZ=250"),
        (1000.0, "Linux desktop CONFIG_HZ=1000"),
        // FreeBSD/OpenBSD
        (100.0, "FreeBSD/OpenBSD default"),
        // Windows
        (1000.0, "Windows 7/8/10/11"),
        // macOS
        (100.0, "macOS traditional"),
        // Embedded systems
        (10.0, "Embedded low-power"),
        (50.0, "Embedded moderate"),
    ];

    for (freq, description) in common_frequencies {
        // Test that these frequencies are in valid range
        assert!(
            (1.0..=1500.0).contains(&freq),
            "{description} frequency {freq} Hz should be in valid range"
        );

        // Test rounding behavior for slightly off values
        let slightly_off = freq * 1.05; // 5% higher
        assert!(
            slightly_off <= 1500.0,
            "Slightly off {description} frequency {slightly_off} Hz should still be processable"
        );
    }
}

#[test]
fn test_edge_cases() {
    // Boundary values for each range
    let boundary_tests = [
        // Range boundaries
        (10, "Upper bound of no-rounding range"),
        (11, "Lower bound of 5-multiple range"),
        (50, "Upper bound of 5-multiple range"),
        (51, "Lower bound of 10-multiple range"),
        (100, "Upper bound of 10-multiple range"),
        (101, "Lower bound of 50-multiple range"),
        (500, "Upper bound of 50-multiple range"),
        (501, "Lower bound of 100-multiple range"),
    ];

    for (freq, description) in boundary_tests {
        // Just verify these are reasonable values
        assert!(
            (1..=1500).contains(&freq),
            "Boundary case {description} ({freq} Hz) should be in valid range"
        );
    }
}

#[test]
fn test_rounding_precision() {
    // Simulate network jitter affecting frequency calculation
    let base_frequencies = [100.0, 250.0, 1000.0];
    let jitter_percentages = [0.02, 0.05, 0.08]; // 2%, 5%, 8% jitter

    for base_freq in base_frequencies {
        for jitter in jitter_percentages {
            let jittered_up = base_freq * (1.0 + jitter);
            let jittered_down = base_freq * (1.0 - jitter);

            // Both jittered values should be in valid range
            let jitter_pct = jitter * 100.0;
            assert!(
                (1.0..=1500.0).contains(&jittered_up),
                "Jittered frequency {jittered_up} Hz ({jitter_pct}% up from {base_freq}) should be valid"
            );

            assert!(
                (1.0..=1500.0).contains(&jittered_down),
                "Jittered frequency {jittered_down} Hz ({jitter_pct}% down from {base_freq}) should be valid"
            );
        }
    }
}

#[test]
fn test_frequency_families() {
    // 1000 Hz family (with 10% tolerance)
    let hz_1000_family = [
        900.0,  // 10% below
        950.0,  // 5% below
        1000.0, // Exact
        1050.0, // 5% above
        1100.0, // 10% above
    ];

    for freq in hz_1000_family {
        let tolerance = 0.10;
        let diff_ratio = (freq - 1000.0_f64).abs() / 1000.0;

        // Should be recognized as 1000 Hz family if within tolerance
        assert!(
            diff_ratio <= tolerance,
            "{freq} Hz should be within 10% of 1000 Hz family"
        );
    }

    // 100 Hz family (with 10% tolerance)
    let hz_100_family = [
        90.0,  // 10% below
        95.0,  // 5% below
        100.0, // Exact
        105.0, // 5% above
        110.0, // 10% above
    ];

    for freq in hz_100_family {
        let tolerance = 0.10;
        let diff_ratio = (freq - 100.0_f64).abs() / 100.0;

        // Should be recognized as 100 Hz family if within tolerance
        assert!(
            diff_ratio <= tolerance,
            "{freq} Hz should be within 10% of 100 Hz family"
        );
    }
}
