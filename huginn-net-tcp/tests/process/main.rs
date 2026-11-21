// Shared by every test module in this target: helpers return this so that
// failures propagate with `?` instead of panicking.
type TestResult = Result<(), Box<dyn std::error::Error>>;

mod flow;
#[cfg(feature = "syn-ack")]
mod flow_state;
mod parallel;
