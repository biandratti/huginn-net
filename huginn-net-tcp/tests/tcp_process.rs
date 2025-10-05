use huginn_net_tcp::tcp_process::{from_client, from_server, is_valid};
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

#[test]
fn test_is_valid() {
    assert!(is_valid(TcpFlags::SYN, TcpFlags::SYN));
    assert!(!is_valid(TcpFlags::SYN | TcpFlags::FIN, TcpFlags::SYN));
    assert!(!is_valid(TcpFlags::SYN | TcpFlags::RST, TcpFlags::SYN));
    assert!(!is_valid(
        TcpFlags::FIN | TcpFlags::RST,
        TcpFlags::FIN | TcpFlags::RST
    ));
    assert!(!is_valid(TcpFlags::SYN, 0));
}
