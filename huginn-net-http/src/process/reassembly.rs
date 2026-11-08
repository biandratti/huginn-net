//! Bounded, in-order TCP stream reassembly for one direction of a connection.
//!
//! Used by the h2c tracker and the key log sessions: both need the exact client byte stream,
//! so duplicated, overlapping or out-of-order segments are resolved before parsing. Offsets
//! are relative to the first payload byte and computed with wrapping arithmetic, so
//! sequence-number wraparound is handled.

use std::collections::BTreeMap;

/// The direction buffered more than its limit, or a segment lies too far ahead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverLimit;

pub struct StreamReassembler {
    /// Sequence number of the first payload byte.
    base: Option<u32>,
    /// Relative offset just past the last contiguous byte (end of `ready`).
    next: u32,
    /// Out-of-order segments keyed by relative offset.
    pending: BTreeMap<u32, Vec<u8>>,
    pending_bytes: usize,
    /// Contiguous bytes not yet consumed by the caller.
    ready: Vec<u8>,
    limit: usize,
}

impl StreamReassembler {
    pub fn new(limit: usize) -> Self {
        Self {
            base: None,
            next: 0,
            pending: BTreeMap::new(),
            pending_bytes: 0,
            ready: Vec::new(),
            limit,
        }
    }

    /// Fixes the stream start from the SYN: the first payload byte is `isn + 1`.
    pub fn set_isn(&mut self, isn: u32) {
        if self.base.is_none() {
            self.base = Some(isn.wrapping_add(1));
        }
    }

    /// Adds a segment. Duplicate and already-delivered bytes are dropped.
    pub fn push(&mut self, seq: u32, data: &[u8]) -> Result<(), OverLimit> {
        if data.is_empty() {
            return Ok(());
        }
        let base = *self.base.get_or_insert(seq);
        let mut rel = seq.wrapping_sub(base);
        let mut data = data;

        // A relative offset in the upper half means the segment starts before the base.
        if rel >= 0x8000_0000 {
            let before = usize::try_from(base.wrapping_sub(seq)).map_err(|_| OverLimit)?;
            if before >= data.len() {
                return Ok(());
            }
            data = &data[before..];
            rel = 0;
        }

        // Trim bytes already delivered.
        if rel < self.next {
            let skip = usize::try_from(self.next.wrapping_sub(rel)).map_err(|_| OverLimit)?;
            if skip >= data.len() {
                return Ok(());
            }
            data = &data[skip..];
            rel = self.next;
        }

        let ahead = usize::try_from(rel.wrapping_sub(self.next)).map_err(|_| OverLimit)?;
        if ahead > self.limit {
            return Err(OverLimit);
        }

        if rel == self.next {
            self.append_ready(data)?;
            self.drain_pending()?;
        } else {
            let keep = match self.pending.get(&rel) {
                Some(existing) => existing.len() < data.len(),
                None => true,
            };
            if keep {
                if let Some(old) = self.pending.insert(rel, data.to_vec()) {
                    self.pending_bytes = self.pending_bytes.saturating_sub(old.len());
                }
                self.pending_bytes = self.pending_bytes.saturating_add(data.len());
            }
        }

        if self.buffered() > self.limit {
            return Err(OverLimit);
        }
        Ok(())
    }

    fn append_ready(&mut self, data: &[u8]) -> Result<(), OverLimit> {
        let len = u32::try_from(data.len()).map_err(|_| OverLimit)?;
        self.ready.extend_from_slice(data);
        self.next = self.next.wrapping_add(len);
        Ok(())
    }

    fn drain_pending(&mut self) -> Result<(), OverLimit> {
        while let Some((&rel, _)) = self.pending.first_key_value() {
            if rel > self.next {
                break;
            }
            let Some((rel, data)) = self.pending.pop_first() else {
                break;
            };
            self.pending_bytes = self.pending_bytes.saturating_sub(data.len());
            let skip = usize::try_from(self.next.wrapping_sub(rel)).map_err(|_| OverLimit)?;
            if skip < data.len() {
                self.append_ready(&data[skip..])?;
            }
        }
        Ok(())
    }

    /// Contiguous bytes available to the caller.
    pub fn ready_bytes(&self) -> &[u8] {
        &self.ready
    }

    /// Drops the first `n` ready bytes after the caller has parsed them.
    pub fn consume(&mut self, n: usize) {
        let n = n.min(self.ready.len());
        self.ready.drain(..n);
    }

    /// `true` while out-of-order data is waiting for a missing segment.
    #[cfg(feature = "akamai-keylog")]
    pub fn has_gap(&self) -> bool {
        !self.pending.is_empty()
    }

    fn buffered(&self) -> usize {
        self.ready.len().saturating_add(self.pending_bytes)
    }
}
