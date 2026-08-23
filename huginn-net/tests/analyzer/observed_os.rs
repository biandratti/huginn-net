use huginn_net::analyzer::observed_os::ObservedOsCache;
use huginn_net::ObservedOsScope;
use std::net::{IpAddr, Ipv4Addr};

fn ip(a: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, a))
}

#[test]
fn exact_port_is_flow_scoped() {
    let mut cache = ObservedOsCache::new(8);
    cache.remember(ip(1), 40000, "Linux".to_owned());
    let found = match cache.lookup(ip(1), 40000) {
        Some(os) => os,
        None => panic!("flow hit"),
    };
    assert_eq!(found.name, "Linux");
    assert_eq!(found.scope, ObservedOsScope::Flow);
}

#[test]
fn same_ip_other_port_is_host_scoped() {
    let mut cache = ObservedOsCache::new(8);
    cache.remember(ip(1), 40000, "Windows".to_owned());
    let found = match cache.lookup(ip(1), 50000) {
        Some(os) => os,
        None => panic!("host fallback"),
    };
    assert_eq!(found.name, "Windows");
    assert_eq!(found.scope, ObservedOsScope::Host);
}

#[test]
fn unknown_ip_is_missing() {
    let mut cache = ObservedOsCache::new(8);
    cache.remember(ip(1), 40000, "Linux".to_owned());
    assert!(cache.lookup(ip(2), 40000).is_none());
}

#[test]
fn later_syn_updates_both_indexes() {
    let mut cache = ObservedOsCache::new(8);
    cache.remember(ip(1), 40000, "Linux".to_owned());
    cache.remember(ip(1), 40001, "Windows".to_owned());
    assert_eq!(cache.lookup(ip(1), 40000).map(|o| o.name), Some("Linux".to_owned()));
    assert_eq!(
        cache.lookup(ip(1), 40001).map(|o| (o.name, o.scope)),
        Some(("Windows".to_owned(), ObservedOsScope::Flow))
    );
    assert_eq!(
        cache.lookup(ip(1), 9).map(|o| (o.name, o.scope)),
        Some(("Windows".to_owned(), ObservedOsScope::Host))
    );
}
