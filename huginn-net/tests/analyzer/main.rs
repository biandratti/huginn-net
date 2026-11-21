#![cfg(all(
    feature = "db",
    feature = "tcp-syn",
    feature = "tcp-syn-ack",
    feature = "tcp-mtu",
    feature = "http-p0f-request",
    feature = "http-p0f-response"
))]

// Shared by every test module in this target: helpers return this so that
// failures propagate with `?` instead of panicking.
type TestResult = Result<(), Box<dyn std::error::Error>>;

mod observed_os;
mod pcap_golden;
mod smoke;
