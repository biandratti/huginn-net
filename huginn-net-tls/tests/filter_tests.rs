use huginn_net_tls::{FilterConfig, FilterMode, IpFilter, PortFilter, SubnetFilter};
use std::net::IpAddr;

#[test]
fn test_port_filter_destination() {
    let filter = PortFilter::new().destination(443);
    assert!(filter.matches(12345, 443));
    assert!(!filter.matches(12345, 80));
}

#[test]
fn test_port_filter_source() {
    let filter = PortFilter::new().source(12345);
    assert!(filter.matches(12345, 80));
    assert!(!filter.matches(54321, 80));
}

#[test]
fn test_port_filter_list() {
    let filter = PortFilter::new().destination_list(vec![80, 443, 8080]);
    assert!(filter.matches(12345, 80));
    assert!(filter.matches(12345, 443));
    assert!(filter.matches(12345, 8080));
    assert!(!filter.matches(12345, 22));
}

#[test]
fn test_port_filter_range() {
    let filter = PortFilter::new().destination_range(8000..9000);
    assert!(filter.matches(12345, 8000));
    assert!(filter.matches(12345, 8500));
    assert!(filter.matches(12345, 8999));
    assert!(!filter.matches(12345, 9000));
    assert!(!filter.matches(12345, 7999));
}

#[test]
fn test_port_filter_any_port() {
    let filter = PortFilter::new().destination(443).any_port();
    // Matches if destination is 443
    assert!(filter.matches(12345, 443));
    // Or if source is 443 (because of any_port)
    assert!(filter.matches(443, 80));
    // But not if neither matches
    assert!(!filter.matches(12345, 80));
}

#[test]
fn test_port_filter_combined() {
    let filter = PortFilter::new().source(12345).destination(443);
    assert!(filter.matches(12345, 443));
    assert!(!filter.matches(12345, 80));
    assert!(!filter.matches(54321, 443));
}

#[test]
fn test_ip_filter_v4() {
    let filter = IpFilter::new()
        .allow("192.168.1.100")
        .unwrap_or_else(|e| panic!("Invalid IPv4 address: {e}"));
    let ip_match: IpAddr = "192.168.1.100"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IPv4: {e}"));
    let ip_other: IpAddr = "192.168.1.200"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IPv4: {e}"));

    assert!(filter.matches(&ip_match, &ip_other));
    assert!(filter.matches(&ip_other, &ip_match));
    assert!(!filter.matches(
        &ip_other,
        &"10.0.0.1"
            .parse()
            .unwrap_or_else(|e| panic!("Invalid IPv4: {e}"))
    ));
}

#[test]
fn test_ip_filter_v6() {
    let filter = IpFilter::new()
        .allow("2001:db8::1")
        .unwrap_or_else(|e| panic!("Invalid IPv6 address: {e}"));
    let ip_match: IpAddr = "2001:db8::1"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IPv6: {e}"));
    let ip_other: IpAddr = "2001:db8::2"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IPv6: {e}"));

    assert!(filter.matches(&ip_match, &ip_other));
    assert!(!filter.matches(
        &ip_other,
        &"2001:db8::3"
            .parse()
            .unwrap_or_else(|e| panic!("Invalid IPv6: {e}"))
    ));
}

#[test]
fn test_ip_filter_source_only() {
    let filter = IpFilter::new()
        .allow("192.168.1.100")
        .unwrap_or_else(|e| panic!("Invalid IPv4 address: {e}"))
        .source_only();
    let ip_match: IpAddr = "192.168.1.100"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IPv4: {e}"));
    let ip_other: IpAddr = "192.168.1.200"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IPv4: {e}"));

    // Matches when source is the filtered IP
    assert!(filter.matches(&ip_match, &ip_other));
    // Doesn't match when only destination is the filtered IP
    assert!(!filter.matches(&ip_other, &ip_match));
}

#[test]
fn test_ip_filter_destination_only() {
    let filter = IpFilter::new()
        .allow("192.168.1.100")
        .unwrap_or_else(|e| panic!("Invalid IPv4 address: {e}"))
        .destination_only();
    let ip_match: IpAddr = "192.168.1.100"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IPv4: {e}"));
    let ip_other: IpAddr = "192.168.1.200"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IPv4: {e}"));

    // Matches when destination is the filtered IP
    assert!(filter.matches(&ip_other, &ip_match));
    // Doesn't match when only source is the filtered IP
    assert!(!filter.matches(&ip_match, &ip_other));
}

#[test]
fn test_subnet_filter_v4() {
    let filter = SubnetFilter::new()
        .allow("192.168.1.0/24")
        .unwrap_or_else(|e| panic!("Invalid CIDR notation: {e}"));
    let ip_in: IpAddr = "192.168.1.100"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IPv4: {e}"));
    let ip_out: IpAddr = "192.168.2.100"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IPv4: {e}"));

    assert!(filter.matches(&ip_in, &ip_out));
    assert!(!filter.matches(
        &ip_out,
        &"10.0.0.1"
            .parse()
            .unwrap_or_else(|e| panic!("Invalid IPv4: {e}"))
    ));
}

#[test]
fn test_subnet_filter_v6() {
    let filter = SubnetFilter::new()
        .allow("2001:db8::/32")
        .unwrap_or_else(|e| panic!("Invalid CIDR notation: {e}"));
    let ip_in: IpAddr = "2001:db8::1"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IPv6: {e}"));
    let ip_out: IpAddr = "2001:db9::1"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IPv6: {e}"));

    assert!(filter.matches(&ip_in, &ip_out));
    assert!(!filter.matches(
        &ip_out,
        &"2001:dba::1"
            .parse()
            .unwrap_or_else(|e| panic!("Invalid IPv6: {e}"))
    ));
}

#[test]
fn test_subnet_filter_multiple() {
    let filter = SubnetFilter::new()
        .allow_list(vec!["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
        .unwrap_or_else(|e| panic!("Invalid CIDR notations: {e}"));

    let ip1: IpAddr = "10.1.2.3"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IPv4: {e}"));
    let ip2: IpAddr = "172.16.1.1"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IPv4: {e}"));
    let ip3: IpAddr = "192.168.1.1"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IPv4: {e}"));
    let ip_out: IpAddr = "8.8.8.8"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IPv4: {e}"));

    assert!(filter.matches(&ip1, &ip_out));
    assert!(filter.matches(&ip2, &ip_out));
    assert!(filter.matches(&ip3, &ip_out));
    assert!(!filter.matches(
        &ip_out,
        &"1.1.1.1"
            .parse()
            .unwrap_or_else(|e| panic!("Invalid IPv4: {e}"))
    ));
}

#[test]
fn test_combined_filter_allow() {
    let filter = FilterConfig::new()
        .mode(FilterMode::Allow)
        .with_port_filter(PortFilter::new().destination(443))
        .with_subnet_filter(
            SubnetFilter::new()
                .allow("192.168.0.0/16")
                .unwrap_or_else(|e| panic!("Invalid CIDR notation: {e}")),
        );

    let ip_in: IpAddr = "192.168.1.100"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IPv4: {e}"));
    let ip_out: IpAddr = "8.8.8.8"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IPv4: {e}"));

    // Both filters pass
    assert!(filter.should_process(&ip_in, &ip_out, 12345, 443));

    // Port filter fails
    assert!(!filter.should_process(&ip_in, &ip_out, 12345, 80));

    // Subnet filter fails
    assert!(!filter.should_process(
        &ip_out,
        &"10.0.0.1"
            .parse()
            .unwrap_or_else(|e| panic!("Invalid IPv4: {e}")),
        12345,
        443
    ));
}

#[test]
fn test_combined_filter_deny() {
    let filter = FilterConfig::new()
        .mode(FilterMode::Deny)
        .with_subnet_filter(
            SubnetFilter::new()
                .allow_list(vec!["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
                .unwrap_or_else(|e| panic!("Invalid CIDR notations: {e}")),
        );

    let ip_private: IpAddr = "192.168.1.100"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IPv4: {e}"));
    let ip_public: IpAddr = "8.8.8.8"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IPv4: {e}"));

    // Private IP should be denied
    assert!(!filter.should_process(&ip_private, &ip_public, 12345, 443));

    // Public IP should be allowed
    assert!(filter.should_process(&ip_public, &ip_public, 12345, 443));
}

#[test]
fn test_no_filters() {
    let filter = FilterConfig::new();
    let ip1: IpAddr = "192.168.1.100"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IPv4: {e}"));
    let ip2: IpAddr = "8.8.8.8"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IPv4: {e}"));

    // No filters = process everything
    assert!(filter.should_process(&ip1, &ip2, 12345, 443));
    assert!(filter.should_process(&ip2, &ip1, 80, 12345));
}

#[test]
fn test_port_only_filter() {
    let filter = FilterConfig::new().with_port_filter(PortFilter::new().destination(443));

    let ip1: IpAddr = "192.168.1.100"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IPv4: {e}"));
    let ip2: IpAddr = "8.8.8.8"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IPv4: {e}"));

    // Port matches
    assert!(filter.should_process(&ip1, &ip2, 12345, 443));
    // Port doesn't match
    assert!(!filter.should_process(&ip1, &ip2, 12345, 80));
}

#[test]
fn test_ip_only_filter() {
    let filter = FilterConfig::new().with_ip_filter(
        IpFilter::new()
            .allow("8.8.8.8")
            .unwrap_or_else(|e| panic!("Invalid IPv4 address: {e}")),
    );

    let ip_match: IpAddr = "8.8.8.8"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IPv4: {e}"));
    let ip_other: IpAddr = "192.168.1.100"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IPv4: {e}"));

    // IP matches (as source)
    assert!(filter.should_process(&ip_match, &ip_other, 12345, 443));
    // IP matches (as destination)
    assert!(filter.should_process(&ip_other, &ip_match, 12345, 443));
    // IP doesn't match
    assert!(!filter.should_process(
        &ip_other,
        &"1.1.1.1"
            .parse()
            .unwrap_or_else(|e| panic!("Invalid IPv4: {e}")),
        12345,
        443
    ));
}

#[test]
fn test_invalid_ip() {
    let result = IpFilter::new().allow("not-an-ip");
    assert!(result.is_err());
}

#[test]
fn test_invalid_cidr() {
    let result = SubnetFilter::new().allow("192.168.1.0/99");
    assert!(result.is_err());
}
