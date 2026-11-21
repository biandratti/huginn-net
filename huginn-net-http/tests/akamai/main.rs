#![cfg(feature = "akamai")]

// Shared by every test module in this target: helpers return this so that
// failures propagate with `?` instead of panicking.
type TestResult = Result<(), Box<dyn std::error::Error>>;

mod extractor;
mod fingerprint;
mod paper_golden;
mod pcap_golden;
