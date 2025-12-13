# Migration Guide

This document helps you migrate between versions of the `huginn-net` ecosystem that introduce breaking changes.

---

## v1.6.x → v1.7.0

### Summary

Added optional packet filtering system that allows filtering packets before analysis. New public APIs include `FilterConfig`, `FilterMode`, `PortFilter`, `IpFilter`, `SubnetFilter`, and the `with_filter()` method on all analyzer types.

This is an **additive change** - existing code continues to work without modification.

### Migration Steps

No migration required. Filters are optional and disabled by default. To use the new filtering features, see the README files for each crate.

---

## v1.5.2 → v1.6.0

### Summary

Renamed fields in `FingerprintResult` for consistency across all protocols. All TCP fields now use the `tcp_` prefix to match HTTP and TLS naming conventions.

**Note:** This change **only affects** the unified `huginn-net` crate. Protocol-specific crates (`huginn-net-tcp`, `huginn-net-http`, `huginn-net-tls`) remain unchanged.

### Breaking Changes

| Old Field (v1.5.2) | New Field (v1.6.0) |
|--------------------|-------------------|
| `syn` | `tcp_syn` |
| `syn_ack` | `tcp_syn_ack` |
| `mtu` | `tcp_mtu` |
| `client_uptime` | `tcp_client_uptime` |
| `server_uptime` | `tcp_server_uptime` |

### Migration Steps

**Before (v1.5.2):**
```rust
for result in receiver {
    if let Some(syn) = result.syn { println!("{syn}"); }
    if let Some(mtu) = result.mtu { println!("{mtu}"); }
    if let Some(client_uptime) = result.client_uptime { println!("{client_uptime}"); }
}
```

**After (v1.6.0):**
```rust
for result in receiver {
    if let Some(tcp_syn) = result.tcp_syn { println!("{tcp_syn}"); }
    if let Some(tcp_mtu) = result.tcp_mtu { println!("{tcp_mtu}"); }
    if let Some(tcp_client_uptime) = result.tcp_client_uptime { println!("{tcp_client_uptime}"); }
}
```

---
## Need Help?

- **Issues:** https://github.com/biandratti/huginn-net/issues
- **Examples:** https://github.com/biandratti/huginn-net/tree/master/examples
