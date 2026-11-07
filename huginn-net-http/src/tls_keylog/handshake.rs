//! Extracts the fields decryption needs from the cleartext TLS handshake: the client random
//! (ClientHello) and the server random, negotiated version and cipher suite (ServerHello).
//!
//! Handshake messages are parsed from the concatenated payloads of handshake records, so a
//! message split over several records (e.g. a large post-quantum ClientHello) is handled.

use crate::output::TlsVersion;

pub const HS_CLIENT_HELLO: u8 = 1;
pub const HS_SERVER_HELLO: u8 = 2;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;

/// ServerHello random of a HelloRetryRequest (RFC 8446 section 4.1.3).
pub const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// The handshake bytes are not a valid ClientHello / ServerHello.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerHelloInfo {
    pub random: [u8; 32],
    pub cipher_suite: u16,
    pub version: TlsVersion,
}

/// Outcome of scanning server handshake bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerHelloScan {
    /// More bytes are needed.
    Incomplete,
    /// A ServerHello (not a HelloRetryRequest) was found.
    Found(ServerHelloInfo),
}

/// Reads one handshake message header: `(type, body, total_len)` if complete.
fn next_message(buf: &[u8]) -> Option<(u8, &[u8], usize)> {
    let header = buf.get(..4)?;
    let len = usize::from(header[1]) << 16 | usize::from(header[2]) << 8 | usize::from(header[3]);
    let total = len.checked_add(4)?;
    let body = buf.get(4..total)?;
    Some((header[0], body, total))
}

/// Client random from the first handshake message, if it is complete.
pub fn parse_client_hello(buf: &[u8]) -> Result<Option<[u8; 32]>, HandshakeError> {
    if buf.is_empty() {
        return Ok(None);
    }
    if buf[0] != HS_CLIENT_HELLO {
        return Err(HandshakeError);
    }
    // The random sits right after the 2-byte legacy version; it is usable before the whole
    // message arrives, but wait for the full message so malformed input is rejected.
    let Some((_, body, _)) = next_message(buf) else {
        return Ok(None);
    };
    let random = body.get(2..34).ok_or(HandshakeError)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(random);
    Ok(Some(out))
}

/// Scans server handshake bytes for the ServerHello, skipping a HelloRetryRequest.
pub fn parse_server_hello(buf: &[u8]) -> Result<ServerHelloScan, HandshakeError> {
    let mut pos = 0usize;
    while let Some((msg_type, body, total)) = buf.get(pos..).and_then(next_message) {
        pos = pos.saturating_add(total);
        if msg_type != HS_SERVER_HELLO {
            continue;
        }
        let info = server_hello_fields(body)?;
        if info.random == HRR_RANDOM {
            continue;
        }
        return Ok(ServerHelloScan::Found(info));
    }
    Ok(ServerHelloScan::Incomplete)
}

fn server_hello_fields(body: &[u8]) -> Result<ServerHelloInfo, HandshakeError> {
    let legacy_version = body.get(..2).ok_or(HandshakeError)?;
    let mut random = [0u8; 32];
    random.copy_from_slice(body.get(2..34).ok_or(HandshakeError)?);
    let sid_len = usize::from(*body.get(34).ok_or(HandshakeError)?);
    let mut pos = 35usize.checked_add(sid_len).ok_or(HandshakeError)?;
    let suite = body.get(pos..pos.saturating_add(2)).ok_or(HandshakeError)?;
    let cipher_suite = u16::from_be_bytes([suite[0], suite[1]]);
    pos = pos.saturating_add(3); // cipher suite + compression method

    let mut version = match legacy_version {
        [0x03, 0x03] => TlsVersion::Tls12,
        _ => return Err(HandshakeError),
    };

    if let Some(ext_len) = body.get(pos..pos.saturating_add(2)) {
        let ext_len = usize::from(u16::from_be_bytes([ext_len[0], ext_len[1]]));
        pos = pos.saturating_add(2);
        let exts = body
            .get(pos..pos.saturating_add(ext_len))
            .ok_or(HandshakeError)?;
        let mut epos = 0usize;
        while let Some(hdr) = exts.get(epos..epos.saturating_add(4)) {
            let ext_type = u16::from_be_bytes([hdr[0], hdr[1]]);
            let len = usize::from(u16::from_be_bytes([hdr[2], hdr[3]]));
            let start = epos.saturating_add(4);
            let data = exts
                .get(start..start.saturating_add(len))
                .ok_or(HandshakeError)?;
            if ext_type == EXT_SUPPORTED_VERSIONS {
                match data {
                    [0x03, 0x04] => version = TlsVersion::Tls13,
                    [0x03, 0x03] => version = TlsVersion::Tls12,
                    _ => return Err(HandshakeError),
                }
            }
            epos = start.saturating_add(len);
        }
    }

    Ok(ServerHelloInfo { random, cipher_suite, version })
}
