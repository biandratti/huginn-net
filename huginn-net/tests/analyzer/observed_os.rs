use huginn_net::analyzer::observed_os::ObservedOsCache;
use std::net::{IpAddr, Ipv4Addr};

fn ip(a: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, a))
}

#[test]
fn exact_port_is_found() {
    let mut cache = ObservedOsCache::new(8);
    cache.remember(ip(1), 40000, "Linux".to_owned());
    let found = match cache.lookup(ip(1), 40000) {
        Some(os) => os,
        None => panic!("connection hit"),
    };
    assert_eq!(found.name, "Linux");
}

#[test]
fn same_ip_other_port_is_missing() {
    let mut cache = ObservedOsCache::new(8);
    cache.remember(ip(1), 40000, "Windows".to_owned());
    assert!(
        cache.lookup(ip(1), 50000).is_none(),
        "another port on the same IP is a different connection"
    );
}

#[test]
fn unknown_ip_is_missing() {
    let mut cache = ObservedOsCache::new(8);
    cache.remember(ip(1), 40000, "Linux".to_owned());
    assert!(cache.lookup(ip(2), 40000).is_none());
}

#[test]
fn later_syn_does_not_overwrite_other_ports() {
    let mut cache = ObservedOsCache::new(8);
    cache.remember(ip(1), 40000, "Linux".to_owned());
    cache.remember(ip(1), 40001, "Windows".to_owned());
    assert_eq!(cache.lookup(ip(1), 40000).map(|o| o.name), Some("Linux".to_owned()));
    assert_eq!(cache.lookup(ip(1), 40001).map(|o| o.name), Some("Windows".to_owned()));
    assert!(cache.lookup(ip(1), 9).is_none());
}
