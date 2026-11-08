# Fuzzing

Standalone [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) crate for the parsers that
read untrusted input in the Akamai key log pipeline. It is not part of the root workspace
and is not built by CI.

| Target | What it feeds |
|--------|---------------|
| `keylog_line` | `KeyLogStore::insert_line_bytes` and the line splitter used to follow a key log file |
| `record_layer` | `split_records` and `RecordDecryptor::open` with a fixed dummy key, every supported AEAD |
| `reassembler` | a random sequence of `StreamReassembler::push` / `consume` calls |
| `akamai_accumulator` | client bytes after the HTTP/2 preface into the Akamai accumulator |
| `hpack_decode` | differential: the HTTP/2 parsers' HPACK decoder against `hpack_patched`, two consecutive blocks |
| `hpack_pseudo_order` | differential: the extractor's pseudo-header order (values not decoded) against a full `hpack_patched` decode |

The targets use the `#[doc(hidden)] huginn_net_http::keylog_internals` module, which is not
a stable API.

## Running

Needs a nightly toolchain and `cargo install cargo-fuzz`. From the repository root:

```
cargo +nightly fuzz list --fuzz-dir fuzz

# One target for 10 minutes. libFuzzer writes new inputs to the first directory and also
# reads the committed seeds from the second one.
t=keylog_line   # or record_layer, reassembler, akamai_accumulator, hpack_pseudo_order, hpack_decode
mkdir -p fuzz/corpus/$t
cargo +nightly fuzz run --fuzz-dir fuzz $t fuzz/corpus/$t fuzz/seeds/$t -- -max_total_time=600
```

## Seeds and corpus

- `fuzz/seeds/<target>/` (committed): a few hand-made inputs built from the checked-in
  fixtures in `pcap/` (key log lines, TLS client records, HTTP/2 client frames, a TCP
  segment sequence). Keep it small; add a seed only for a case the fuzzer would not find
  on its own.
- `fuzz/corpus/<target>/` (ignored by git): everything libFuzzer generates. It can be
  thrown away at any time; a few seconds of fuzzing from the seeds rebuilds it.

Crash inputs are written to `fuzz/artifacts/<target>/` (also ignored). Reproduce one with
`cargo +nightly fuzz run --fuzz-dir fuzz <target> <path-to-crash-file>`. When a crash is
fixed, add its input to `fuzz/seeds/<target>/` so it keeps being replayed.
