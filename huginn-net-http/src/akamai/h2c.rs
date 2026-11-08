//! Cleartext HTTP/2 (h2c) detection for the packet pipeline.
//!
//! A connection is h2c when the client opens with the HTTP/2 connection preface (prior
//! knowledge), or sends an HTTP/1.1 request with `Upgrade: h2c` and then the preface right
//! after that request. The server's `101 Switching Protocols` is not needed: per RFC 7540
//! section 3.2 the client only sends the preface once the upgrade was accepted.
//!
//! Tracking stops as soon as the connection is known not to be h2c, so TLS and plain HTTP/1
//! flows hold no buffers after their first request.

use super::AkamaiFingerprint;
use super::pipeline::AkamaiAccumulator;
use crate::http2::HTTP2_CONNECTION_PREFACE;
use crate::process::reassembly::StreamReassembler;

/// Most client bytes buffered per connection before giving up.
pub const MAX_CLIENT_BYTES: usize = 64 * 1024;

enum Phase {
    /// Not known yet whether the client speaks HTTP/2.
    Detect,
    /// The preface was found; HTTP/2 frames go to the accumulator.
    Http2(AkamaiAccumulator),
    /// Fingerprint emitted, or the connection is not h2c.
    Done,
}

/// Per-connection h2c state: rebuilds the client stream and emits one fingerprint.
pub struct H2cTracker {
    stream: StreamReassembler,
    phase: Phase,
}

impl H2cTracker {
    /// Starts tracking a connection whose client SYN carried sequence number `syn_seq`.
    pub fn new(syn_seq: u32) -> Self {
        let mut stream = StreamReassembler::new(MAX_CLIENT_BYTES);
        stream.set_isn(syn_seq);
        Self { stream, phase: Phase::Detect }
    }

    /// `true` once a fingerprint was emitted or the connection was found not to be h2c.
    pub fn is_done(&self) -> bool {
        matches!(self.phase, Phase::Done)
    }

    /// Adds one client TCP segment. Returns the fingerprint the first time it is complete.
    pub fn push(&mut self, seq: u32, data: &[u8]) -> Option<AkamaiFingerprint> {
        if self.is_done() {
            return None;
        }
        if self.stream.push(seq, data).is_err() {
            return self.finish(None);
        }
        if matches!(self.phase, Phase::Detect) {
            let ready = self.stream.ready_bytes();
            match detect(ready) {
                Detection::NeedMore => return None,
                Detection::NotH2c => return self.finish(None),
                // The upgrade request body has not fully arrived yet.
                Detection::Http2At(start) if start > ready.len() => return None,
                Detection::Http2At(start) => {
                    self.stream.consume(start);
                    self.phase = Phase::Http2(AkamaiAccumulator::new(MAX_CLIENT_BYTES));
                }
            }
        }
        let Phase::Http2(acc) = &mut self.phase else {
            return None;
        };
        let ready = self.stream.ready_bytes();
        if ready.is_empty() {
            return None;
        }
        let result = acc.push(ready);
        let used = ready.len();
        self.stream.consume(used);
        match result {
            Ok(None) => None,
            Ok(Some(fingerprint)) => self.finish(Some(fingerprint)),
            Err(_) => self.finish(None),
        }
    }

    fn finish(&mut self, fingerprint: Option<AkamaiFingerprint>) -> Option<AkamaiFingerprint> {
        self.phase = Phase::Done;
        self.stream = StreamReassembler::new(0);
        fingerprint
    }
}

enum Detection {
    NeedMore,
    NotH2c,
    Http2At(usize),
}

fn detect(stream: &[u8]) -> Detection {
    if stream.starts_with(HTTP2_CONNECTION_PREFACE) {
        return Detection::Http2At(0);
    }
    if HTTP2_CONNECTION_PREFACE.starts_with(stream) {
        // "P" or "PRI ..." so far: could still be the preface (or POST / PUT / PATCH).
        return Detection::NeedMore;
    }
    match stream.first() {
        Some(b) if b.is_ascii_uppercase() => upgrade_offset(stream),
        _ => Detection::NotH2c,
    }
}

/// For an HTTP/1.1 request asking for `Upgrade: h2c`, the offset right after the request
/// (headers plus a `Content-Length` body), where the client preface must start.
fn upgrade_offset(stream: &[u8]) -> Detection {
    let Some(head_len) = stream.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Detection::NeedMore;
    };
    let mut upgrade_h2c = false;
    let mut body_len = 0usize;
    for line in stream[..head_len].split(|b| *b == b'\n').skip(1) {
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            continue;
        };
        let name = &line[..colon];
        let value = line[colon.saturating_add(1)..].trim_ascii();
        if name.eq_ignore_ascii_case(b"upgrade") {
            upgrade_h2c |= value
                .split(|b| *b == b',')
                .any(|token| token.trim_ascii().eq_ignore_ascii_case(b"h2c"));
        } else if name.eq_ignore_ascii_case(b"content-length") {
            match std::str::from_utf8(value).ok().and_then(|v| v.parse().ok()) {
                Some(len) => body_len = len,
                None => return Detection::NotH2c,
            }
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            // A chunked upgrade request is legal but no client sends one.
            return Detection::NotH2c;
        }
    }
    if !upgrade_h2c {
        return Detection::NotH2c;
    }
    match head_len
        .checked_add(4)
        .and_then(|v| v.checked_add(body_len))
    {
        Some(start) if start <= MAX_CLIENT_BYTES => Detection::Http2At(start),
        _ => Detection::NotH2c,
    }
}
