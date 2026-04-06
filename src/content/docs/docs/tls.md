---
title: TLS
description: TLS ClientHello analysis and JA4 fingerprinting.
---

**Huginn Net** supports TLS analysis. TLS is a cryptographic protocol used to secure communications over a network. By analyzing the characteristics of TLS handshakes, Huginn Net can identify the client based on the JA4 signature.

## TLS Signature (JA4)

Huginn Net based on JA4 (FoxIO-style) TLS fingerprinting, which encodes the structure of the ClientHello message into a compact signature. This allows for identification of client software and detection of anomalies or evasion techniques.

```
ja4 = version:ciphers:extensions:groups:point_formats
```

| Key             | Description                                              |
| --------------- | -------------------------------------------------------- |
| `version`       | TLS version used in the handshake (e.g., 771 for TLS 1.2). |
| `ciphers`       | Ordered list of cipher suites offered by the client.     |
| `extensions`    | Ordered list of TLS extensions present in the ClientHello. |
| `groups`        | Supported groups (elliptic curves, etc.).                  |
| `point_formats` | Supported EC point formats.                              |

## TLS Client

```bash
[TLS Client] 192.168.1.10:45234 → 172.217.5.46:443
  SNI:     www.google.com
  Version: TLS 1.3
  JA4:     t13d1516h2_8daaf6152771_b0da82dd1658
  JA4_r:   t13d1516h2_002f,0035,009c,009d,1301,1302,1303_0005,000a,000b,000d,0012,0015,002b,0033,002d
  JA4_o:   t13d1516h2_8daaf6152771_b0da82dd1658
  JA4_or:  t13d1516h2_002f,0035,009c,009d,1301,1302,1303_0005,000a,000b,000d,0012,0015,002b,0033,002d
```

## TLS Key Fields

- **SNI**: Server Name Indication, the hostname the client is connecting to.
- **Version**: TLS protocol version (e.g., TLS 1.3, TLS 1.2).
- **JA4**: JA4 fingerprint with sorted cipher suites and extensions (hashed).
- **JA4_r**: JA4 raw fingerprint with sorted cipher suites and extensions (full).
- **JA4_o**: JA4 fingerprint with original order (unsorted, hashed).
- **JA4_or**: JA4 raw fingerprint with original order (unsorted, full).
