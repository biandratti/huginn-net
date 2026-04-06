---
title: TCP MTU
description: MTU analysis for TCP traffic and link type identification.
---

**Huginn Net** supports MTU analysis for TCP traffic.  
The Maximum Transmission Unit is the largest size of a packet (including headers) that can be sent over a network interface without requiring fragmentation.  
Understanding the MTU can provide insights into the type of network link being used and its configuration.

## MTU Signature

Many operating systems derive the maximum segment size specified in TCP options from the MTU of their network interface; that value, in turn, normally depends on the design of the link-layer protocol. A different MTU is associated with PPPoE, a different one with IPSec, and a different one with Juniper VPN.

The format of the signatures in the [mtu] section is exceedingly simple, consisting just of a description and a list of values. Each label corresponds to a specific networking technology or use case, and the associated sig values indicate typical MTU sizes for those technologies.

## MTU Analyzed

```bash
[TCP MTU] 1.2.3.4:1524 → 4.3.2.1:80
  Link:   DSL
  MTU:    1492
```

## MTU Key Fields

- **Link**: The networking technology type (DSL, Ethernet, PPPoE, etc.) matched from the database signature.
- **MTU**: The Maximum Transmission Unit value detected from the TCP packet.
