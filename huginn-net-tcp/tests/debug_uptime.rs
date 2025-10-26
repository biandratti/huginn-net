//! Test simple para debug de uptime

use huginn_net_tcp::uptime::{check_ts_tcp, Connection};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use ttl_cache::TtlCache;

#[test]
fn test_debug_uptime_simple() {
    let mut connection_tracker = TtlCache::new(100);

    let connection = Connection {
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        src_port: 12345,
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
        dst_port: 80,
    };

    println!("=== Testing uptime calculation ===");

    // Step 1: Store SYN data (client -> server)
    println!("Step 1: Storing SYN data");
    let (client_uptime, server_uptime) =
        check_ts_tcp(&mut connection_tracker, &connection, true, 1000000);
    println!("SYN result: client={client_uptime:?}, server={server_uptime:?}");
    assert!(
        client_uptime.is_none() && server_uptime.is_none(),
        "SYN should return (None, None)"
    );

    // Step 2: Wait a bit
    std::thread::sleep(Duration::from_millis(100));

    // Step 3: Process SYN+ACK (server -> client)
    // For 1000 Hz system: 100ms = 100 ticks, so 1000000 + 100 = 1000100
    let server_connection = Connection {
        src_ip: connection.dst_ip,
        src_port: connection.dst_port,
        dst_ip: connection.src_ip,
        dst_port: connection.src_port,
    };

    println!("Step 2: Processing SYN+ACK");
    let (client_uptime2, server_uptime2) =
        check_ts_tcp(&mut connection_tracker, &server_connection, false, 1000100);
    println!("SYN+ACK result: client={client_uptime2:?}, server={server_uptime2:?}");

    if client_uptime2.is_some() || server_uptime2.is_some() {
        println!("SUCCESS: Uptime calculation worked!");
    } else {
        println!("FAILED: No uptime calculated");
    }
}
