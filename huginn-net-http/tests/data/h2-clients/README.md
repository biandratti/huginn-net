# Real HTTP/2 client streams

The client half of one HTTP/2 connection per file, as decrypted by a local TLS test server:
connection preface, SETTINGS, WINDOW_UPDATE and the first HEADERS of a `GET /` to
`localhost:8443`. Recorded on Linux with headless browsers and curl.

| File | Client | Akamai fingerprint (also reported by huginn-proxy for the same client) |
|------|--------|------------------------------------------------------------------------|
| `curl-8.5.bin` | curl 8.5.0 (nghttp2 1.59) | `3:100;4:10485760;2:0\|1048510465\|0\|m,s,a,p` |
| `chrome-157.bin` | Chrome 157 | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` |
| `chromium-156.bin` | Chromium 156 | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` |
| `firefox-159.bin` | Firefox 159 | `1:65536;2:0;4:131072;5:16384\|12517377\|0\|m,p,a,s` |

The browsers send HEADERS with the PRIORITY flag and Huffman-coded HPACK, which the
synthetic fixtures in `pcap/` do not cover.
