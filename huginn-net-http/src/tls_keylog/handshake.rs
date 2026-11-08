//! Extracts the fields decryption needs from the cleartext TLS handshake: the client random
//! (ClientHello) and the server random, negotiated version and cipher suite (ServerHello).
//!
//! Handshake messages are parsed from the concatenated payloads of handshake records, so a
//! message split over several records (e.g. a large post-quantum ClientHello) is handled.
//! The messages themselves are decoded with `tls-parser`, as in `huginn-net-tls`.

use crate::output::TlsVersion;
use tls_parser::{
    TlsExtension, TlsMessage, TlsMessageHandshake, parse_tls_message_handshake,
    parse_tls_server_hello_extensions,
};

pub const HS_CLIENT_HELLO: u8 = 1;
pub const HS_SERVER_HELLO: u8 = 2;

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

/// Total length (header included) of the handshake message at the start of `buf`, if its
/// header is there.
fn message_len(buf: &[u8]) -> Option<usize> {
    let header = buf.get(..4)?;
    let len = usize::from(header[1]) << 16 | usize::from(header[2]) << 8 | usize::from(header[3]);
    len.checked_add(4)
}

/// Client random from the first handshake message, if it is complete.
pub fn parse_client_hello(buf: &[u8]) -> Result<Option<[u8; 32]>, HandshakeError> {
    match buf.first() {
        None => return Ok(None),
        Some(&HS_CLIENT_HELLO) => {}
        Some(_) => return Err(HandshakeError),
    }
    match parse_tls_message_handshake(buf) {
        Ok((_, TlsMessage::Handshake(TlsMessageHandshake::ClientHello(hello)))) => hello
            .random
            .try_into()
            .map(Some)
            .map_err(|_| HandshakeError),
        Err(tls_parser::Err::Incomplete(_)) => Ok(None),
        _ => Err(HandshakeError),
    }
}

/// Scans server handshake bytes for the ServerHello, skipping a HelloRetryRequest and any
/// other message before it.
pub fn parse_server_hello(buf: &[u8]) -> Result<ServerHelloScan, HandshakeError> {
    let mut rest = buf;
    while let Some(total) = message_len(rest) {
        let Some(message) = rest.get(..total) else {
            break; // the rest of this message has not arrived yet
        };
        rest = &rest[total..];
        if message[0] != HS_SERVER_HELLO {
            continue;
        }
        let hello = match parse_tls_message_handshake(message) {
            Ok((_, TlsMessage::Handshake(TlsMessageHandshake::ServerHello(hello)))) => hello,
            _ => return Err(HandshakeError),
        };
        let random: [u8; 32] = hello.random.try_into().map_err(|_| HandshakeError)?;
        if random == HRR_RANDOM {
            continue;
        }
        return Ok(ServerHelloScan::Found(ServerHelloInfo {
            random,
            cipher_suite: hello.cipher.0,
            version: negotiated_version(hello.version, hello.ext)?,
        }));
    }
    Ok(ServerHelloScan::Incomplete)
}

/// TLS 1.3 is announced by `supported_versions`; the legacy version field stays 1.2.
fn negotiated_version(
    legacy: tls_parser::TlsVersion,
    extensions: Option<&[u8]>,
) -> Result<TlsVersion, HandshakeError> {
    if legacy != tls_parser::TlsVersion::Tls12 {
        return Err(HandshakeError);
    }
    let Some(extensions) = extensions else {
        return Ok(TlsVersion::Tls12);
    };
    let (_, extensions) =
        parse_tls_server_hello_extensions(extensions).map_err(|_| HandshakeError)?;
    let mut version = TlsVersion::Tls12;
    for extension in extensions {
        if let TlsExtension::SupportedVersions(versions) = extension {
            version = match versions.as_slice() {
                [tls_parser::TlsVersion::Tls13] => TlsVersion::Tls13,
                [tls_parser::TlsVersion::Tls12] => TlsVersion::Tls12,
                _ => return Err(HandshakeError),
            };
        }
    }
    Ok(version)
}
