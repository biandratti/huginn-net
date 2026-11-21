#![cfg(feature = "tcp")]

// Shared by every test module in this target: helpers return this so that
// failures propagate with `?` instead of panicking.
type TestResult = Result<(), Box<dyn std::error::Error>>;

mod db_coverage;
mod db_reachable;
mod distances;
mod match_selection;
mod matcher;
mod matching;
mod params;
mod pcap_golden;
mod window_size;
