---
title: TCP Uptime
description: TCP timestamp-based uptime estimation for client and server.
---

**Huginn Net** provides an estimate of how long the system has been running since its last boot for TCP traffic. Uptime is calculated separately for both client and server endpoints based on TCP timestamp analysis.

:::caution
**Important:** Uptime estimation has **limited accuracy on modern systems**. Most modern operating systems (Windows 10+, Linux 4.10+, macOS 10.12+) randomize TCP timestamps for privacy/security, making uptime estimation unreliable or impossible. This feature works best on legacy systems, embedded devices, IoT hardware, and some server distributions.
:::

## Client Uptime

Estimates uptime for the client (connection initiator) based on TCP timestamps from outgoing packets.

```bash
[TCP Uptime - Client] 1.2.3.4:1524 → 4.3.2.1:80
  Uptime: 0 days, 11 hrs, 16 min (modulo 198 days)
  Freq:   250.00 Hz
```

## Server Uptime

Estimates uptime for the server (connection responder) based on TCP timestamps from response packets.

```bash
[TCP Uptime - Server] 4.3.2.1:80 → 1.2.3.4:1524
  Uptime: 12 days, 5 hrs, 32 min (modulo 198 days)
  Freq:   100.00 Hz
```

## Uptime Key Fields

- **Uptime**: Estimated time the system has been running since last reboot, shown in days, hours, and minutes. The "modulo" value indicates the maximum time range before the counter would wrap around.
- **Freq**: Frequency of the system's TCP timestamp clock in Hz, typically derived from the kernel timer (common values: 100 Hz, 250 Hz, 1000 Hz).

## Known Limitations

- **Modern OS Randomization:** Windows 10+, Linux 4.10+, and macOS 10.12+ randomize TCP timestamps for privacy, rendering uptime estimation unreliable.
- **Counter Wraparound:** TCP timestamp counters eventually wrap around, leading to ambiguity in absolute uptime values.
- **Best Effort:** Uptime estimation is a best-effort technique and should not be relied upon for critical security decisions on modern systems.
- **Works Best On:** Legacy systems, embedded devices, IoT hardware, and some server distributions that haven't implemented timestamp randomization.
