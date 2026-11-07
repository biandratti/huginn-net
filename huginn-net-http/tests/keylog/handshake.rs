use huginn_net_http::TlsVersion;
use huginn_net_http::keylog_internals::{
    HRR_RANDOM, HS_CLIENT_HELLO, HS_SERVER_HELLO, HandshakeError, ServerHelloInfo, ServerHelloScan,
    parse_client_hello, parse_server_hello,
};

fn message(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let len = u32::try_from(body.len()).unwrap_or(0).to_be_bytes();
    let mut m = vec![msg_type, len[1], len[2], len[3]];
    m.extend_from_slice(body);
    m
}

fn server_hello(random: [u8; 32], suite: u16, supported_version: Option<[u8; 2]>) -> Vec<u8> {
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&random);
    body.push(0); // empty session id
    body.extend_from_slice(&suite.to_be_bytes());
    body.push(0); // compression
    let mut exts = Vec::new();
    if let Some(v) = supported_version {
        exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02]);
        exts.extend_from_slice(&v);
    }
    body.extend_from_slice(&u16::try_from(exts.len()).unwrap_or(0).to_be_bytes());
    body.extend(exts);
    message(HS_SERVER_HELLO, &body)
}

#[test]
fn client_hello_random() {
    let mut body = vec![0x03, 0x03];
    body.extend(1u8..=32);
    body.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
    let msg = message(HS_CLIENT_HELLO, &body);
    assert_eq!(parse_client_hello(&msg[..20]), Ok(None), "incomplete message");
    let expected: Vec<u8> = (1u8..=32).collect();
    assert_eq!(parse_client_hello(&msg).ok().flatten().map(|r| r.to_vec()), Some(expected));
    assert_eq!(parse_client_hello(&[2, 0, 0, 0]), Err(HandshakeError));
}

#[test]
fn server_hello_tls13_and_tls12() {
    let tls13 = server_hello([7u8; 32], 0x1301, Some([0x03, 0x04]));
    assert_eq!(
        parse_server_hello(&tls13),
        Ok(ServerHelloScan::Found(ServerHelloInfo {
            random: [7u8; 32],
            cipher_suite: 0x1301,
            version: TlsVersion::Tls13
        }))
    );
    let tls12 = server_hello([8u8; 32], 0xC02F, None);
    assert!(matches!(
        parse_server_hello(&tls12),
        Ok(ServerHelloScan::Found(ServerHelloInfo {
            version: TlsVersion::Tls12,
            cipher_suite: 0xC02F,
            ..
        }))
    ));
    assert_eq!(parse_server_hello(&tls13[..30]), Ok(ServerHelloScan::Incomplete));
}

#[test]
fn hello_retry_request_is_skipped() {
    let mut buf = server_hello(HRR_RANDOM, 0x1301, Some([0x03, 0x04]));
    assert_eq!(parse_server_hello(&buf), Ok(ServerHelloScan::Incomplete));
    buf.extend(server_hello([9u8; 32], 0x1302, Some([0x03, 0x04])));
    assert_eq!(
        parse_server_hello(&buf),
        Ok(ServerHelloScan::Found(ServerHelloInfo {
            random: [9u8; 32],
            cipher_suite: 0x1302,
            version: TlsVersion::Tls13,
        }))
    );
}

#[test]
fn truncated_server_hello_fields_are_rejected() {
    assert_eq!(
        parse_server_hello(&message(HS_SERVER_HELLO, &[0x03, 0x03, 1, 2])),
        Err(HandshakeError)
    );
}
