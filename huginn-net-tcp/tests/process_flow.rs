use huginn_net_tcp::tcp_process::{from_client, from_server, is_fingerprintable, is_valid};
use pnet::packet::tcp::TcpFlags;

#[test]
fn test_from_client() {
    assert!(from_client(TcpFlags::SYN));
    assert!(!from_client(TcpFlags::SYN | TcpFlags::ACK));
    assert!(!from_client(TcpFlags::ACK));
}

#[test]
fn test_from_server() {
    assert!(from_server(TcpFlags::SYN | TcpFlags::ACK));
    assert!(!from_server(TcpFlags::SYN));
    assert!(!from_server(TcpFlags::ACK));
    assert!(!from_server(TcpFlags::RST));
}

/// Only the two packets that open a connection describe the stack that sent
/// them. Everything after the handshake has no MSS, no window scale and an
/// already-scaled window, so fingerprinting it can only produce noise.
#[test]
fn only_the_handshake_is_fingerprintable() {
    use TcpFlags::*;

    assert!(is_fingerprintable(SYN));
    assert!(is_fingerprintable(SYN | ACK));

    assert!(!is_fingerprintable(ACK));
    assert!(!is_fingerprintable(FIN | ACK));
    assert!(!is_fingerprintable(RST));
    assert!(!is_fingerprintable(RST | ACK));
}

#[test]
fn test_is_valid() {
    assert!(is_valid(TcpFlags::SYN, TcpFlags::SYN));
    assert!(!is_valid(TcpFlags::SYN | TcpFlags::FIN, TcpFlags::SYN));
    assert!(!is_valid(TcpFlags::SYN | TcpFlags::RST, TcpFlags::SYN));
    assert!(!is_valid(TcpFlags::FIN | TcpFlags::RST, TcpFlags::FIN | TcpFlags::RST));
    assert!(!is_valid(TcpFlags::SYN, 0));
}
