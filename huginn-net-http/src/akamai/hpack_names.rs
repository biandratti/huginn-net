//! Pseudo-header order of an HPACK header block, without decoding the header values.
//!
//! The Akamai fingerprint only needs the order of the pseudo-header names. A general HPACK
//! decoder decodes every value, and `hpack_patched` rebuilds its Huffman tables for every
//! Huffman-coded string, which costs tens of microseconds per string. Here values are skipped
//! by length. Huffman strings are still checked for validity (and decoded only when the value
//! of a pseudo-header has to be checked for UTF-8), with a canonical decoder built from the
//! RFC 7541 Appendix B code lengths. The dynamic table is tracked (names and sizes only), so
//! indexed references resolve exactly as in a full decode.
//!
//! The result equals a full decode followed by keeping the names that start with `:`, for
//! headers whose name and value are valid UTF-8. For any block a full decoder would reject,
//! `None` is returned and the caller falls back to the full decoder, which reports the error.

use super::PseudoHeader;
use std::collections::VecDeque;

const STATIC_TABLE_LEN: usize = 61;
/// Initial dynamic table size (`SETTINGS_HEADER_TABLE_SIZE` default).
const DEFAULT_TABLE_SIZE: usize = 4096;
/// Per-entry overhead in the dynamic table size (RFC 7541 section 4.1).
const ENTRY_OVERHEAD: usize = 32;
/// Huffman end-of-string symbol, an error inside a string.
const EOS: u16 = 256;
/// Most continuation octets accepted in an integer, as in `hpack_patched`.
const MAX_INTEGER_OCTETS: usize = 5;

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
            1..=STATIC_TABLE_LEN => {
                let name = match index {
                    1 => Name::Pseudo(PseudoHeader::Authority),
                    2 | 3 => Name::Pseudo(PseudoHeader::Method),
                    4 | 5 => Name::Pseudo(PseudoHeader::Path),
                    6 | 7 => Name::Pseudo(PseudoHeader::Scheme),
                    8..=14 => Name::Pseudo(PseudoHeader::Status),
                    _ => Name::Other,
                };
                let name_len = usize::from(*STATIC_NAME_LEN.get(index.checked_sub(1)?)?);
                // Static table values are ASCII; the size is not needed for a lookup.
                Some(Entry { name, name_len, value_utf8: true, size: 0 })
            }
            _ => self
                .table
                .get(index.checked_sub(STATIC_TABLE_LEN.checked_add(1)?)?)
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

/// HPACK integer with an `prefix`-bit prefix (RFC 7541 section 5.1): `(value, bytes used)`.
fn integer(buf: &[u8], prefix: u8) -> Option<(usize, usize)> {
    let mask = 1u8.checked_shl(u32::from(prefix))?.wrapping_sub(1);
    let mut value = usize::from(buf.first()? & mask);
    if value < usize::from(mask) {
        return Some((value, 1));
    }
    let mut shift = 0u32;
    for (i, &byte) in buf.iter().enumerate().skip(1) {
        let part = usize::from(byte & 0x7f).checked_shl(shift)?;
        value = value.checked_add(part)?;
        shift = shift.checked_add(7)?;
        let used = i.checked_add(1)?;
        if byte & 0x80 == 0 {
            return Some((value, used));
        }
        if used == MAX_INTEGER_OCTETS {
            return None;
        }
    }
    None
}

/// HPACK string literal (RFC 7541 section 5.2): `(raw bytes, Huffman coded, bytes used)`.
fn string(buf: &[u8]) -> Option<(&[u8], bool, usize)> {
    let huffman = buf.first()? & 0x80 != 0;
    let (len, header) = integer(buf, 7)?;
    let end = header.checked_add(len)?;
    Some((buf.get(header..end)?, huffman, end))
}

/// Decodes (into `out`, if given) or just validates a Huffman string; returns the decoded
/// length. Canonical decoding: within each code length, codes are consecutive and assigned
/// to symbols in increasing order, so the code lengths alone define the code.
fn huffman_decode(data: &[u8], mut out: Option<&mut Vec<u8>>) -> Option<usize> {
    let mut decoded = 0usize;
    let mut code = 0u32;
    let mut first = 0u32;
    let mut index = 0u32;
    let mut len = 0usize;
    let mut all_ones = true;
    for &byte in data {
        for shift in (0..8).rev() {
            let bit = u32::from((byte >> shift) & 1);
            code |= bit;
            all_ones &= bit == 1;
            len = len.checked_add(1)?;
            let count = u32::from(*HUFFMAN_COUNT.get(len)?);
            let offset = code.checked_sub(first)?;
            if offset < count {
                let slot = usize::try_from(index.checked_add(offset)?).ok()?;
                let symbol = *HUFFMAN_SYMBOLS.get(slot)?;
                if symbol == EOS {
                    return None;
                }
                if let Some(out) = out.as_deref_mut() {
                    out.push(u8::try_from(symbol).ok()?);
                }
                decoded = decoded.checked_add(1)?;
                (code, first, index, len, all_ones) = (0, 0, 0, 0, true);
            } else {
                index = index.checked_add(count)?;
                first = first.checked_add(count)?.checked_shl(1)?;
                code = code.checked_shl(1)?;
            }
        }
    }
    // Padding: at most 7 bits, all ones (the most significant bits of EOS).
    (len <= 7 && all_ones).then_some(decoded)
}

/// Number of Huffman codes of each length (index = length in bits), RFC 7541 Appendix B.
const HUFFMAN_COUNT: [u16; 31] = [
    0, 0, 0, 0, 0, 10, 26, 32, 6, 0, 5, 3, 2, 6, 2, 3, 0, 0, 0, 3, 8, 13, 26, 29, 12, 4, 15, 19,
    29, 0, 4,
];

/// Symbols ordered by (code length, symbol), the canonical code order.
const HUFFMAN_SYMBOLS: [u16; 257] = [
    48, 49, 50, 97, 99, 101, 105, 111, 115, 116, 32, 37, 45, 46, 47, 51, 52, 53, 54, 55, 56, 57,
    61, 65, 95, 98, 100, 102, 103, 104, 108, 109, 110, 112, 114, 117, 58, 66, 67, 68, 69, 70, 71,
    72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 89, 106, 107, 113, 118, 119,
    120, 121, 122, 38, 42, 44, 59, 88, 90, 33, 34, 40, 41, 63, 39, 43, 124, 35, 62, 0, 36, 64, 91,
    93, 126, 94, 125, 60, 96, 123, 92, 195, 208, 128, 130, 131, 162, 184, 194, 224, 226, 153, 161,
    167, 172, 176, 177, 179, 209, 216, 217, 227, 229, 230, 129, 132, 133, 134, 136, 146, 154, 156,
    160, 163, 164, 169, 170, 173, 178, 181, 185, 186, 187, 189, 190, 196, 198, 228, 232, 233, 1,
    135, 137, 138, 139, 140, 141, 143, 147, 149, 150, 151, 152, 155, 157, 158, 165, 166, 168, 174,
    175, 180, 182, 183, 188, 191, 197, 231, 239, 9, 142, 144, 145, 148, 159, 171, 206, 215, 225,
    236, 237, 199, 207, 234, 235, 192, 193, 200, 201, 202, 205, 210, 213, 218, 219, 238, 240, 242,
    243, 255, 203, 204, 211, 212, 214, 221, 222, 223, 241, 244, 245, 246, 247, 248, 250, 251, 252,
    253, 254, 2, 3, 4, 5, 6, 7, 8, 11, 12, 14, 15, 16, 17, 18, 19, 20, 21, 23, 24, 25, 26, 27, 28,
    29, 30, 31, 127, 220, 249, 10, 13, 22, 256,
];

/// Name length of each static table entry, RFC 7541 Appendix A.
const STATIC_NAME_LEN: [u8; 61] = [
    10, 7, 7, 5, 5, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 15, 15, 13, 6, 27, 3, 5, 13, 13, 19, 16, 16, 14,
    16, 13, 12, 6, 4, 4, 6, 7, 4, 4, 8, 17, 13, 8, 19, 13, 4, 8, 12, 18, 19, 5, 7, 7, 11, 6, 10,
    25, 17, 10, 4, 3, 16,
];
