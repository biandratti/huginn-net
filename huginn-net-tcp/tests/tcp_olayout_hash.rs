use huginn_net_tcp::tcp::{hash_olayout, TcpOption};

#[test]
fn same_layout_hashes_equal() {
    let a = [TcpOption::Mss, TcpOption::Sok, TcpOption::TS, TcpOption::Nop, TcpOption::Ws];
    let b = a.clone();
    assert_eq!(hash_olayout(&a), hash_olayout(&b));
}

#[test]
fn empty_layout_is_stable() {
    assert_eq!(hash_olayout(&[]), hash_olayout(&[]));
}

#[test]
fn different_layouts_usually_differ() {
    let linux = [TcpOption::Mss, TcpOption::Sok, TcpOption::TS, TcpOption::Nop, TcpOption::Ws];
    let windows = [TcpOption::Mss, TcpOption::Nop, TcpOption::Ws];
    assert_ne!(hash_olayout(&linux), hash_olayout(&windows));
}

#[test]
fn eol_padding_and_unknown_id_affect_the_hash() {
    assert_ne!(hash_olayout(&[TcpOption::Eol(0)]), hash_olayout(&[TcpOption::Eol(1)]));
    assert_ne!(hash_olayout(&[TcpOption::Unknown(10)]), hash_olayout(&[TcpOption::Unknown(11)]));
}
