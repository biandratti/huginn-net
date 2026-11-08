//! Pseudo-header order of an HPACK header block, without decoding the header values.
//!
//! The Akamai fingerprint only needs the order of the pseudo-header names, so values are
//! skipped by length instead of decoded. Huffman strings are still checked for validity (and
//! decoded only when the value of a pseudo-header has to be checked for UTF-8). The dynamic
//! table is tracked (names and sizes only), so indexed references resolve exactly as in a
//! full decode.
//!
//! The result equals a full decode followed by keeping the names that start with `:`, for
//! headers whose name and value are valid UTF-8. For any block a full decoder would reject,
//! `None` is returned and the caller falls back to the full decoder ([`crate::http2::hpack`]),
//! which reports the error.

use super::PseudoHeader;
use crate::http2::hpack::{
    DEFAULT_TABLE_SIZE, ENTRY_OVERHEAD, huffman_decode, integer, static_name, static_table_len,
    string,
};
use std::collections::VecDeque;

/// A header name, as far as the fingerprint is concerned.
#[derive(Clone)]
enum Name {
    /// Valid UTF-8 starting with `:`.
    Pseudo(PseudoHeader),
    /// A regular name, or one that is not valid UTF-8.
    Other,
}

#[derive(Clone)]
struct Entry {
    name: Name,
    name_len: usize,
    value_utf8: bool,
    size: usize,
}

struct Walker {
    table: VecDeque<Entry>,
    table_size: usize,
    max_table_size: usize,
    scratch: Vec<u8>,
    order: Vec<PseudoHeader>,
}

/// Pseudo-header order of `block`, or `None` when the block must go through a full decoder.
pub(crate) fn pseudo_header_order(block: &[u8]) -> Option<Vec<PseudoHeader>> {
    let mut walker = Walker {
        table: VecDeque::new(),
        table_size: 0,
        max_table_size: DEFAULT_TABLE_SIZE,
        scratch: Vec::new(),
        order: Vec::new(),
    };
    let mut pos = 0usize;
    while let Some(rest) = block.get(pos..) {
        let Some(&first) = rest.first() else {
            break;
        };
        let used = if first & 0x80 != 0 {
            walker.indexed(rest)?
        } else if first & 0x40 != 0 {
            walker.literal(rest, 6, true)?
        } else if first & 0x20 != 0 {
            walker.size_update(rest)?
        } else {
            walker.literal(rest, 4, false)?
        };
        pos = pos.checked_add(used)?;
    }
    Some(walker.order)
}

impl Walker {
    fn indexed(&mut self, buf: &[u8]) -> Option<usize> {
        let (index, used) = integer(buf, 7)?;
        let entry = self.lookup(index)?;
        self.emit(&entry.name, entry.value_utf8);
        Some(used)
    }

    fn literal(&mut self, buf: &[u8], prefix: u8, add_to_table: bool) -> Option<usize> {
        let (index, mut used) = integer(buf, prefix)?;
        let (name, name_len) = if index == 0 {
            let (raw, huffman, n) = string(buf.get(used..)?)?;
            used = used.checked_add(n)?;
            self.scratch.clear();
            if huffman {
                huffman_decode(raw, Some(&mut self.scratch))?;
            } else {
                self.scratch.extend_from_slice(raw);
            }
            (classify(&self.scratch), self.scratch.len())
        } else {
            let entry = self.lookup(index)?;
            (entry.name, entry.name_len)
        };

        let (raw, huffman, n) = string(buf.get(used..)?)?;
        used = used.checked_add(n)?;
        let is_pseudo = matches!(name, Name::Pseudo(_));
        let (value_len, value_utf8) = match (huffman, is_pseudo) {
            (false, false) => (raw.len(), true),
            (false, true) => (raw.len(), std::str::from_utf8(raw).is_ok()),
            (true, false) => (huffman_decode(raw, None)?, true),
            (true, true) => {
                self.scratch.clear();
                let len = huffman_decode(raw, Some(&mut self.scratch))?;
                (len, std::str::from_utf8(&self.scratch).is_ok())
            }
        };

        self.emit(&name, value_utf8);
        if add_to_table {
            let size = name_len
                .checked_add(value_len)?
                .checked_add(ENTRY_OVERHEAD)?;
            self.table_size = self.table_size.checked_add(size)?;
            self.table
                .push_front(Entry { name, name_len, value_utf8, size });
            self.evict();
        }
        Some(used)
    }

    fn size_update(&mut self, buf: &[u8]) -> Option<usize> {
        let (size, used) = integer(buf, 5)?;
        self.max_table_size = size;
        self.evict();
        Some(used)
    }

    fn evict(&mut self) {
        while self.table_size > self.max_table_size {
            let Some(oldest) = self.table.pop_back() else {
                break;
            };
            self.table_size = self.table_size.saturating_sub(oldest.size);
        }
    }

    fn lookup(&self, index: usize) -> Option<Entry> {
        match index {
            0 => None,
            i if i <= static_table_len() => {
                let name = match index {
                    1 => Name::Pseudo(PseudoHeader::Authority),
                    2 | 3 => Name::Pseudo(PseudoHeader::Method),
                    4 | 5 => Name::Pseudo(PseudoHeader::Path),
                    6 | 7 => Name::Pseudo(PseudoHeader::Scheme),
                    8..=14 => Name::Pseudo(PseudoHeader::Status),
                    _ => Name::Other,
                };
                let name_len = static_name(index)?.len();
                // Static table values are ASCII; the size is not needed for a lookup.
                Some(Entry { name, name_len, value_utf8: true, size: 0 })
            }
            _ => self
                .table
                .get(index.checked_sub(static_table_len().checked_add(1)?)?)
                .cloned(),
        }
    }

    fn emit(&mut self, name: &Name, value_utf8: bool) {
        if let (Name::Pseudo(pseudo), true) = (name, value_utf8) {
            self.order.push(pseudo.clone());
        }
    }
}

fn classify(name: &[u8]) -> Name {
    match std::str::from_utf8(name) {
        Ok(text) if text.starts_with(':') => Name::Pseudo(PseudoHeader::from(text)),
        _ => Name::Other,
    }
}
