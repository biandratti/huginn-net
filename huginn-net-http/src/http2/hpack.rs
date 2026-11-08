//! HPACK header block decoding (RFC 7541) for the HTTP/2 parsers.
//!
//! Behaves like `hpack_patched` (same integer limits, dynamic table rules and Huffman
//! validation), but Huffman strings are decoded with a canonical decoder built from the
//! RFC 7541 Appendix B code lengths instead of a table rebuilt for every string.
//! `tests/http2/hpack.rs` and the `hpack_pseudo_order` fuzz target check it against
//! `hpack_patched`.

use std::collections::VecDeque;

const STATIC_TABLE_LEN: usize = 61;
/// Initial dynamic table size (`SETTINGS_HEADER_TABLE_SIZE` default).
pub(crate) const DEFAULT_TABLE_SIZE: usize = 4096;
/// Per-entry overhead in the dynamic table size (RFC 7541 section 4.1).
pub(crate) const ENTRY_OVERHEAD: usize = 32;
/// Huffman end-of-string symbol, an error inside a string.
const EOS: u16 = 256;
/// Most octets accepted in an integer, as in `hpack_patched`.
const MAX_INTEGER_OCTETS: usize = 5;

/// The header block is not valid HPACK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HpackError;

/// One decoded header: `(name, value)`.
pub type Header = (Vec<u8>, Vec<u8>);

/// HPACK decoder. The dynamic table persists across [`Decoder::decode`] calls, as for the
/// blocks of one connection.
#[derive(Debug)]
pub struct Decoder {
    table: VecDeque<Header>,
    table_size: usize,
    max_table_size: usize,
}

impl Default for Decoder {
    fn default() -> Self {
        Self { table: VecDeque::new(), table_size: 0, max_table_size: DEFAULT_TABLE_SIZE }
    }
}

impl Decoder {
    /// Decodes a whole header block. On error, entries added before the error stay in the
    /// dynamic table (as in `hpack_patched`).
    pub fn decode(&mut self, block: &[u8]) -> Result<Vec<Header>, HpackError> {
        let mut headers = Vec::new();
        let mut pos = 0usize;
        while let Some(rest) = block.get(pos..) {
            let Some(&first) = rest.first() else {
                break;
            };
            let used = if first & 0x80 != 0 {
                let (index, used) = integer(rest, 7).ok_or(HpackError)?;
                headers.push(self.lookup(index).ok_or(HpackError)?);
                used
            } else if first & 0x40 != 0 {
                let (header, used) = self.literal(rest, 6)?;
                headers.push(header.clone());
                self.add(header);
                used
            } else if first & 0x20 != 0 {
                let (size, used) = integer(rest, 5).ok_or(HpackError)?;
                self.max_table_size = size;
                self.evict();
                used
            } else {
                let (header, used) = self.literal(rest, 4)?;
                headers.push(header);
                used
            };
            pos = pos.checked_add(used).ok_or(HpackError)?;
        }
        Ok(headers)
    }

    fn literal(&self, buf: &[u8], prefix: u8) -> Result<(Header, usize), HpackError> {
        let (index, mut used) = integer(buf, prefix).ok_or(HpackError)?;
        let name = if index == 0 {
            let (name, n) = decode_string(buf.get(used..).ok_or(HpackError)?)?;
            used = used.checked_add(n).ok_or(HpackError)?;
            name
        } else {
            self.lookup(index).ok_or(HpackError)?.0
        };
        let (value, n) = decode_string(buf.get(used..).ok_or(HpackError)?)?;
        used = used.checked_add(n).ok_or(HpackError)?;
        Ok(((name, value), used))
    }

    fn lookup(&self, index: usize) -> Option<Header> {
        match index {
            0 => None,
            1..=STATIC_TABLE_LEN => {
                let (name, value) = STATIC_TABLE.get(index.checked_sub(1)?)?;
                Some((name.to_vec(), value.to_vec()))
            }
            _ => self
                .table
                .get(index.checked_sub(STATIC_TABLE_LEN.checked_add(1)?)?)
                .cloned(),
        }
    }

    fn add(&mut self, header: Header) {
        let size = header
            .0
            .len()
            .saturating_add(header.1.len())
            .saturating_add(ENTRY_OVERHEAD);
        self.table_size = self.table_size.saturating_add(size);
        self.table.push_front(header);
        self.evict();
    }

    fn evict(&mut self) {
        while self.table_size > self.max_table_size {
            let Some((name, value)) = self.table.pop_back() else {
                break;
            };
            let size = name
                .len()
                .saturating_add(value.len())
                .saturating_add(ENTRY_OVERHEAD);
            self.table_size = self.table_size.saturating_sub(size);
        }
    }
}

/// Name of static table entry `index` (1-based), if it exists.
#[cfg(feature = "akamai")]
pub(crate) fn static_name(index: usize) -> Option<&'static [u8]> {
    STATIC_TABLE
        .get(index.checked_sub(1)?)
        .map(|(name, _)| *name)
}

/// Number of static table entries.
#[cfg(feature = "akamai")]
pub(crate) const fn static_table_len() -> usize {
    STATIC_TABLE_LEN
}

fn decode_string(buf: &[u8]) -> Result<(Vec<u8>, usize), HpackError> {
    let (raw, huffman, used) = string(buf).ok_or(HpackError)?;
    if !huffman {
        return Ok((raw.to_vec(), used));
    }
    let mut out = Vec::with_capacity(raw.len().saturating_mul(8) / 5);
    huffman_decode(raw, Some(&mut out)).ok_or(HpackError)?;
    Ok((out, used))
}

/// HPACK integer with an `prefix`-bit prefix (RFC 7541 section 5.1): `(value, bytes used)`.
pub(crate) fn integer(buf: &[u8], prefix: u8) -> Option<(usize, usize)> {
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
pub(crate) fn string(buf: &[u8]) -> Option<(&[u8], bool, usize)> {
    let huffman = buf.first()? & 0x80 != 0;
    let (len, header) = integer(buf, 7)?;
    let end = header.checked_add(len)?;
    Some((buf.get(header..end)?, huffman, end))
}

/// Decodes (into `out`, if given) or just validates a Huffman string; returns the decoded
/// length. Canonical decoding: within each code length, codes are consecutive and assigned
/// to symbols in increasing order, so the code lengths alone define the code.
pub(crate) fn huffman_decode(data: &[u8], mut out: Option<&mut Vec<u8>>) -> Option<usize> {
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

/// RFC 7541 Appendix A.
const STATIC_TABLE: [(&[u8], &[u8]); 61] = [
    (b":authority", b""),
    (b":method", b"GET"),
    (b":method", b"POST"),
    (b":path", b"/"),
    (b":path", b"/index.html"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"200"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"304"),
    (b":status", b"400"),
    (b":status", b"404"),
    (b":status", b"500"),
    (b"accept-", b""),
    (b"accept-encoding", b"gzip, deflate"),
    (b"accept-language", b""),
    (b"accept-ranges", b""),
    (b"accept", b""),
    (b"access-control-allow-origin", b""),
    (b"age", b""),
    (b"allow", b""),
    (b"authorization", b""),
    (b"cache-control", b""),
    (b"content-disposition", b""),
    (b"content-encoding", b""),
    (b"content-language", b""),
    (b"content-length", b""),
    (b"content-location", b""),
    (b"content-range", b""),
    (b"content-type", b""),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"expect", b""),
    (b"expires", b""),
    (b"from", b""),
    (b"host", b""),
    (b"if-match", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"if-range", b""),
    (b"if-unmodified-since", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"max-forwards", b""),
    (b"proxy-authenticate", b""),
    (b"proxy-authorization", b""),
    (b"range", b""),
    (b"referer", b""),
    (b"refresh", b""),
    (b"retry-after", b""),
    (b"server", b""),
    (b"set-cookie", b""),
    (b"strict-transport-security", b""),
    (b"transfer-encoding", b""),
    (b"user-agent", b""),
    (b"vary", b""),
    (b"via", b""),
    (b"www-authenticate", b""),
];
