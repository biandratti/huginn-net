---
title: TCP SYN and SYN+ACK Packets
description: TCP SYN and SYN+ACK packet analysis and signatures.
---

TCP packets are the backbone of network communication, and two of the most significant types are SYN and SYN+ACK.  
**Huginn Net** analyzes the behavior and characteristics of these packets to infer the operating system (OS) of the client or server, and the geographic or logical distance (network hop count).

## TCP Signature

For TCP traffic, signature layout is as follows:

```
sig = ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass
```

| Key       | Description                                                                                                                                                                                                                                                                                                                                 |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ver`     | Signature for IPv4 ('4'), IPv6 ('6'), or both ('*').                                                                                                                                                                                                                                                                                        |
| `ittl`    | Initial TTL used by the OS. Almost all operating systems use 64, 128, or 255; ancient versions of Windows sometimes used 32, and several obscure systems sometimes resort to odd values such as 60.                                                                                                                                           |
| `olen`    | Length of IPv4 options or IPv6 extension headers.                                                                                                                                                                                                                                                                                           |
| `mss`     | Maximum segment size, if specified in TCP options. Special value of '\*' can be used to denote that MSS varies depending on the parameters of sender's network link, and should not be a part of the signature. In this case, MSS will be used to guess the type of network hookup according to the [mtu] rules.                              |
| `wsize`   | Window size. Can be expressed as a fixed value, but many operating systems set it to a multiple of MSS or MTU, or a multiple of some random integer. P0f automatically detects these cases, and allows notation such as 'mss\*4', 'mtu\*4', or '%8192' to be used. Wildcard ('\*') is possible too.                                             |
| `scale`   | Window scaling factor, if specified in TCP options. Fixed value or '\*'.                                                                                                                                                                                                                                                                    |
| `olayout` | Comma-delimited layout and ordering of TCP options, if any. This is one of the most valuable TCP fingerprinting signals. See supported values below.                                                                                                                                                                                       |
| `quirks`  | Comma-delimited properties and quirks observed in IP or TCP headers. See supported values below.                                                                                                                                                                                                                                           |
| `pclass`  | Payload size classification: '0' for zero, '+' for non-zero, '\*' for any. The packets we fingerprint right now normally have no payloads, but some corner cases exist.                                                                                                                                                                    |

#### TCP Options (olayout)

Supported values for the `olayout` field:

| Value     | Description                                          |
| --------- | ---------------------------------------------------- |
| `eol+n`   | Explicit end of options, followed by n bytes of padding |
| `nop`     | No-op option                                         |
| `mss`     | Maximum segment size                                 |
| `ws`      | Window scaling                                       |
| `sok`     | Selective ACK permitted                              |
| `sack`    | Selective ACK (should not be seen)                   |
| `ts`      | Timestamp                                            |
| `?n`      | Unknown option ID n                                  |

#### Quirks

Supported values for the `quirks` field:

| Value     | Description                                                |
| --------- | ---------------------------------------------------------- |
| `df`      | "Don't fragment" set (probably PMTUD); ignored for IPv6      |
| `id+`     | DF set but IPID non-zero; ignored for IPv6                 |
| `id-`     | DF not set but IPID is zero; ignored for IPv6             |
| `ecn`     | Explicit congestion notification support                   |
| `0+`      | "Must be zero" field not zero; ignored for IPv6            |
| `flow`    | Non-zero IPv6 flow ID; ignored for IPv4                    |
| `seq-`    | Sequence number is zero                                    |
| `ack+`    | ACK number is non-zero, but ACK flag not set              |
| `ack-`    | ACK number is zero, but ACK flag set                       |
| `uptr+`   | URG pointer is non-zero, but URG flag not set             |
| `urgf+`   | URG flag used                                              |
| `pushf+`  | PUSH flag used                                             |
| `ts1-`    | Own timestamp specified as zero                            |
| `ts2+`    | Non-zero peer timestamp on initial SYN                     |
| `opt+`    | Trailing non-zero data in options segment                  |
| `exws`    | Excessive window scaling factor (> 14)                     |
| `bad`     | Malformed TCP options                                      |

## SYN Packet

Initiate a TCP connection. Sent by the client to a server.

### SYN Packet Analyzed

```bash
[TCP SYN] 1.2.3.4:1524 → 4.3.2.1:80
  OS:     Windows XP
  Dist:   8
  Params: none
  Sig:    4:120+8:0:1452:65535,0:mss,nop,nop,sok:df,id+:0
```

### SYN Key Fields

- **OS**: The identified operating system matched from the database signature.
- **Dist**: The distance in network hops to the server.
- **Params**: Optional TCP parameters.
- **Sig**: The TCP signature showing packet structure (ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass).

## SYN+ACK Packet

Sent by the server in response to a SYN, signaling acknowledgment and readiness to establish the connection.

### SYN+ACK Packet Analyzed

```bash
[TCP SYN+ACK] 4.3.2.1:80 → 1.2.3.4:1524
  OS:     Linux 3.x
  Dist:   0
  Params: none
  Sig:    4:64+0:0:1460:mss*10,0:mss,nop,nop,sok:df:0
```

### SYN+ACK Key Fields

- **OS**: The identified operating system matched from the database signature.
- **Dist**: The distance in network hops (always 0 for server responses).
- **Params**: Optional TCP parameters.
- **Sig**: The TCP signature showing packet structure (ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass).
