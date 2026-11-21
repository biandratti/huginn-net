#![cfg(feature = "http")]

// Shared by every test module in this target: helpers return this so that
// failures propagate with `?` instead of panicking.
type TestResult = Result<(), Box<dyn std::error::Error>>;

mod distance_habsent;
mod distance_header;
mod expsw;
mod matcher;
mod pcap_golden;
