//! Cleartext HTTP/2 (h2c) detection for the packet pipeline.
//!
//! A connection is h2c when the client opens with the HTTP/2 connection preface (prior
//! knowledge), or sends an HTTP/1.1 request with `Upgrade: h2c` and then the preface right
//! after that request. The server's `101 Switching Protocols` is not needed: per RFC 7540
//! section 3.2 the client only sends the preface once the upgrade was accepted.
//!
//! The client byte stream is rebuilt from TCP segments (out of order, duplicated and
//! overlapping segments are handled) and handed to [`AkamaiAccumulator`], which waits for the
//! first HEADERS frame. Tracking stops as soon as the connection is known not to be h2c, so
//! TLS and plain HTTP/1 flows hold no buffers after their first request.

use super::AkamaiFingerprint;
use super::pipeline::AkamaiAccumulator;
use crate::http2::HTTP2_CONNECTION_PREFACE;
use std::collections::BTreeMap;

/// Most client bytes buffered per connection before giving up.
pub const MAX_CLIENT_BYTES: usize = 64 * 1024;
/// Most out-of-order segments kept per connection.
const MAX_PENDING_SEGMENTS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Not known yet whether the client speaks HTTP/2.
    Detect,
    /// HTTP/2 frames are expected from this stream offset on.
    Http2 { start: usize },
    /// Fingerprint emitted, or the connection is not h2c.
    Done,
}

/// Per-connection h2c state: rebuilds the client stream and emits one fingerprint.
pub struct H2cTracker {
    /// TCP sequence number of the first client data byte (SYN sequence + 1).
    base: u32,
    /// Contiguous client bytes from `base` on.
    stream: Vec<u8>,
    /// Segments that arrived ahead of a gap, keyed by stream offset.
    pending: BTreeMap<usize, Vec<u8>>,
    phase: Phase,
}

impl H2cTracker {
    /// Starts tracking a connection whose client SYN carried sequence number `syn_seq`.
    pub fn new(syn_seq: u32) -> Self {
        Self {
            base: syn_seq.wrapping_add(1),
            stream: Vec::new(),
            pending: BTreeMap::new(),
            phase: Phase::Detect,
        }
    }

    /// `true` once a fingerprint was emitted or the connection was found not to be h2c.
    pub fn is_done(&self) -> bool {
        self.phase == Phase::Done
    }

    /// Adds one client TCP segment. Returns the fingerprint the first time it is complete.
    pub fn push(&mut self, seq: u32, data: &[u8]) -> Option<AkamaiFingerprint> {
        if self.is_done() || data.is_empty() {
            return None;
        }
        self.add_segment(seq, data);
        if self.stream.len() > MAX_CLIENT_BYTES {
            self.finish();
            return None;
        }
        loop {
            match self.phase {
                Phase::Done => return None,
                Phase::Detect => match detect(&self.stream) {
                    Detection::NeedMore => return None,
                    Detection::NotH2c => {
                        self.finish();
                        return None;
                    }
                    Detection::Http2At(start) => self.phase = Phase::Http2 { start },
                },
                Phase::Http2 { start } => {
                    let frames = self.stream.get(start..).filter(|f| !f.is_empty())?;
                    let mut acc = AkamaiAccumulator::new(MAX_CLIENT_BYTES);
                    return match acc.push(frames) {
                        Ok(None) => None,
                        Ok(Some(fingerprint)) => {
                            self.finish();
                            Some(fingerprint)
                        }
                        Err(_) => {
                            self.finish();
                            None
                        }
                    };
                }
            }
        }
    }

    fn finish(&mut self) {
        self.phase = Phase::Done;
        self.stream = Vec::new();
        self.pending = BTreeMap::new();
    }

    fn add_segment(&mut self, seq: u32, data: &[u8]) {
        // Offsets past the buffer limit are either far ahead or a retransmission from before
        // `base` (the wrapping difference is then huge); both are dropped.
        let offset = usize::try_from(seq.wrapping_sub(self.base)).unwrap_or(usize::MAX);
        if offset > MAX_CLIENT_BYTES {
            return;
        }
        let keep = match self.pending.get(&offset) {
            Some(existing) => existing.len() < data.len(),
            None => self.pending.len() < MAX_PENDING_SEGMENTS,
        };
        if keep {
            self.pending.insert(offset, data.to_vec());
        }
        while let Some(entry) = self.pending.first_entry() {
            let end = self.stream.len();
            if *entry.key() > end {
                break;
            }
            let (start, segment) = entry.remove_entry();
            let skip = end.saturating_sub(start);
            if let Some(fresh) = segment.get(skip..) {
                self.stream.extend_from_slice(fresh);
            }
        }
    }
}

enum Detection {
    NeedMore,
    NotH2c,
    Http2At(usize),
}

fn detect(stream: &[u8]) -> Detection {
    let preface_len = HTTP2_CONNECTION_PREFACE.len();
    if stream.starts_with(HTTP2_CONNECTION_PREFACE) {
        return Detection::Http2At(0);
    }
    if stream.len() < preface_len && HTTP2_CONNECTION_PREFACE.starts_with(stream) {
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
    let Some(head_len) = find(stream, b"\r\n\r\n") else {
        return Detection::NeedMore;
    };
    let head = &stream[..head_len];
    let mut upgrade_h2c = false;
    let mut body_len = 0usize;
    for line in head.split(|b| *b == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            continue;
        };
        let (name, value) = (&line[..colon], trim(&line[colon.saturating_add(1)..]));
        if name.eq_ignore_ascii_case(b"upgrade") {
            upgrade_h2c |= value
                .split(|b| *b == b',')
                .any(|token| trim(token).eq_ignore_ascii_case(b"h2c"));
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

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn trim(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(start, |p| p.saturating_add(1));
    bytes.get(start..end).unwrap_or(&[])
}
