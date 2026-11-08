#!/usr/bin/env python3
"""Generate Akamai HTTP/2 test fixtures: pcap + TLS key log + expected snapshot (dev-only).

Never used at runtime or in CI. CI only reads the committed outputs.

A real OpenSSL TLS client and server (Python `ssl`) talk to each other in-process through
memory BIOs, so no network, root or packet capture is needed. Every byte the two sides
exchange is recorded and wrapped in synthetic Ethernet/IPv4/TCP framing to build a classic
pcap. The client writes a standard NSS key log (`SSLKEYLOGFILE` format) via OpenSSL.

The HTTP/2 client frames are built here from fixed "profiles", so the expected Akamai
fingerprint is computed from what was sent, independently of huginn's decryption code.
The profiles are synthetic: they mimic the shape of common clients but are not captures of
real browsers.

Usage (from the repository root):
    python3 scripts/gen-akamai-fixtures.py            # regenerate every fixture
    python3 scripts/gen-akamai-fixtures.py --only akamai-tls13-aes128-chrome
"""

import argparse
import hashlib
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile

PCAP_DIR = "pcap"
SNAPSHOT_DIR = "huginn-net-http/tests/snapshots"
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
AUTHORITY = b"localhost:8443"
CLIENT_IP = "10.0.0.2"
SERVER_IP = "10.0.0.1"
SERVER_PORT = 8443
MSS = 1448

# IANA values for the suites the fixtures negotiate.
SUITE_IDS = {
    "TLS_AES_128_GCM_SHA256": 0x1301,
    "TLS_AES_256_GCM_SHA384": 0x1302,
    "TLS_CHACHA20_POLY1305_SHA256": 0x1303,
    "ECDHE-RSA-AES128-GCM-SHA256": 0xC02F,
    "ECDHE-RSA-AES256-GCM-SHA384": 0xC030,
    "ECDHE-RSA-CHACHA20-POLY1305": 0xCCA8,
}

# HTTP/2 client profiles: SETTINGS, WINDOW_UPDATE increment, PRIORITY frames, pseudo-header order.
PROFILES = {
    "chrome": {
        "settings": [(1, 65536), (2, 0), (4, 6291456), (6, 262144)],
        "window_update": 15663105,
        "priority": [],
        "pseudo": "masp",
    },
    "firefox": {
        "settings": [(1, 65536), (2, 0), (4, 131072), (5, 16384)],
        "window_update": 12517377,
        "priority": [],
        "pseudo": "mpas",
    },
    "curl": {
        "settings": [(3, 100), (4, 10485760), (2, 0)],
        "window_update": 1048510465,
        "priority": [],
        "pseudo": "mpsa",
    },
    # Legacy priority tree (RFC 7540 PRIORITY frames), weight byte is printed + 1.
    "prio": {
        "settings": [(1, 65536), (4, 131072), (5, 16384)],
        "window_update": 12517377,
        "priority": [(3, 0, 0, 200), (5, 0, 0, 100), (7, 0, 0, 0), (9, 0, 7, 0)],
        "pseudo": "mpas",
    },
}


# --------------------------------------------------------------------------- HTTP/2 frames


def h2_frame(ftype, flags, stream, payload):
    return struct.pack(">I", len(payload))[1:] + bytes([ftype, flags]) + struct.pack(
        ">I", stream & 0x7FFFFFFF
    ) + payload


def hpack_literal_indexed_name(index, value):
    # Literal Header Field with Incremental Indexing, indexed name, no Huffman (RFC 7541 6.2.1).
    assert index < 64 and len(value) < 127
    return bytes([0x40 | index, len(value)]) + value


def pseudo_block(order):
    parts = {
        "m": b"\x82",  # :method GET
        "p": b"\x84",  # :path /
        "s": b"\x87",  # :scheme https
        "a": hpack_literal_indexed_name(1, AUTHORITY),  # :authority
    }
    block = b"".join(parts[c] for c in order)
    return block + hpack_literal_indexed_name(58, b"huginn-fixture/1.0")  # user-agent


def client_frames(profile):
    """Two application writes: (preface + SETTINGS + WINDOW_UPDATE + PRIORITY*, HEADERS)."""
    settings = b"".join(struct.pack(">HI", k, v) for k, v in profile["settings"])
    first = PREFACE + h2_frame(4, 0, 0, settings)
    if profile["window_update"]:
        first += h2_frame(8, 0, 0, struct.pack(">I", profile["window_update"]))
    for stream, excl, dep, weight in profile["priority"]:
        first += h2_frame(2, 0, stream, struct.pack(">I", (excl << 31) | dep) + bytes([weight]))
    headers = h2_frame(1, 0x05, 1, pseudo_block(profile["pseudo"]))  # END_STREAM|END_HEADERS
    return first, headers


SERVER_H2 = (
    h2_frame(4, 0, 0, struct.pack(">HI", 3, 128))
    + h2_frame(4, 0x01, 0, b"")
    + h2_frame(1, 0x04, 1, b"\x88")  # :status 200
    + h2_frame(0, 0x01, 1, b"ok")
)


def expected_fingerprint(profile):
    settings = ";".join(f"{k}:{v}" for k, v in profile["settings"])
    wu = str(profile["window_update"]) if profile["window_update"] else "00"
    prio = (
        ",".join(f"{s}:{e}:{d}:{w + 1}" for s, e, d, w in profile["priority"])
        if profile["priority"]
        else "0"
    )
    pseudo = ",".join(profile["pseudo"])
    text = f"{settings}|{wu}|{prio}|{pseudo}"
    return text, hashlib.sha256(text.encode()).digest()[:16].hex()


# --------------------------------------------------------------------------- TLS in memory


def pump(c_out, s_in, s_out, c_in, segments):
    moved = False
    data = c_out.read()
    if data:
        segments.append(("c", data))
        s_in.write(data)
        moved = True
    data = s_out.read()
    if data:
        segments.append(("s", data))
        c_in.write(data)
        moved = True
    return moved


def read_all(obj):
    out = b""
    while True:
        try:
            chunk = obj.read(65536)
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            return out
        if not chunk:
            return out
        out += chunk


def tls_connection(client_ctx, server_ctx, writes, server_reply, session=None):
    c_in, c_out, s_in, s_out = (ssl.MemoryBIO() for _ in range(4))
    client = client_ctx.wrap_bio(c_in, c_out, server_hostname="localhost", session=session)
    server = server_ctx.wrap_bio(s_in, s_out, server_side=True)
    segments = []
    c_done = s_done = False
    for _ in range(64):
        if not c_done:
            c_done = handshake(client)
        if not s_done:
            s_done = handshake(server)
        moved = pump(c_out, s_in, s_out, c_in, segments)
        if c_done and s_done and not moved:
            break
    assert c_done and s_done, "TLS handshake did not complete"
    for data in writes:
        client.write(data)
        pump(c_out, s_in, s_out, c_in, segments)
    received = read_all(server)
    assert received == b"".join(writes), "server did not receive the client bytes"
    server.write(server_reply)
    pump(c_out, s_in, s_out, c_in, segments)
    read_all(client)  # consumes session tickets (TLS 1.3) and the reply
    pump(c_out, s_in, s_out, c_in, segments)
    return {
        "segments": segments,
        "session": client.session,
        "reused": client.session_reused,
        "version": client.version(),
        "cipher": client.cipher()[0],
        "alpn": client.selected_alpn_protocol(),
    }


def handshake(obj):
    """Advance the handshake; True once it has completed."""
    try:
        obj.do_handshake()
        return True
    except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
        return False


# --------------------------------------------------------------------------- pcap writer


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f">{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


class PcapWriter:
    def __init__(self):
        self.records = []
        self.clock = 1_700_000_000_000_000  # microseconds
        self.ip_id = 1

    def frame(self, src, dst, sport, dport, seq, ack, flags, payload=b""):
        tcp = struct.pack(
            ">HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, 65535, 0, 0
        )
        pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack(
            ">BBH", 0, 6, len(tcp) + len(payload)
        )
        csum = checksum(pseudo + tcp + payload)
        tcp = tcp[:16] + struct.pack(">H", csum) + tcp[18:]
        total = 20 + len(tcp) + len(payload)
        ip = struct.pack(
            ">BBHHHBBH4s4s",
            0x45, 0, total, self.ip_id & 0xFFFF, 0x4000, 64, 6, 0,
            socket.inet_aton(src), socket.inet_aton(dst),
        )
        ip = ip[:10] + struct.pack(">H", checksum(ip)) + ip[12:]
        self.ip_id += 1
        eth = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00"
        self.clock += 1000
        self.records.append((self.clock, eth + ip + tcp + payload))

    def connection(self, client_port, isn_c, isn_s, segments):
        c, s = (CLIENT_IP, client_port), (SERVER_IP, SERVER_PORT)
        SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01
        self.frame(c[0], s[0], c[1], s[1], isn_c, 0, SYN)
        self.frame(s[0], c[0], s[1], c[1], isn_s, isn_c + 1, SYN | ACK)
        seq = {"c": isn_c + 1, "s": isn_s + 1}
        self.frame(c[0], s[0], c[1], s[1], seq["c"], seq["s"], ACK)
        for direction, data in segments:
            src, dst = (c, s) if direction == "c" else (s, c)
            other = "s" if direction == "c" else "c"
            for off in range(0, len(data), MSS):
                chunk = data[off : off + MSS]
                self.frame(src[0], dst[0], src[1], dst[1], seq[direction], seq[other], PSH | ACK, chunk)
                seq[direction] += len(chunk)
        self.frame(c[0], s[0], c[1], s[1], seq["c"], seq["s"], FIN | ACK)
        self.frame(s[0], c[0], s[1], c[1], seq["s"], seq["c"] + 1, FIN | ACK)
        self.frame(c[0], s[0], c[1], s[1], seq["c"] + 1, seq["s"] + 1, ACK)

    def write(self, path):
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for ts, data in self.records:
                f.write(struct.pack("<IIII", ts // 1_000_000, ts % 1_000_000, len(data), len(data)))
                f.write(data)


# --------------------------------------------------------------------------- fixtures

FIXTURES = {
    # name: (tls version, cipher, profile or None for http/1.1, connections, client ISN)
    "akamai-tls13-aes128-chrome": ("1.3", "TLS_AES_128_GCM_SHA256", "chrome", 1, 0xFFFFFF00),
    "akamai-tls13-aes256-firefox": ("1.3", "TLS_AES_256_GCM_SHA384", "firefox", 1, 1000),
    "akamai-tls13-chacha-curl": ("1.3", "TLS_CHACHA20_POLY1305_SHA256", "curl", 1, 2000),
    "akamai-tls12-aes128-curl": ("1.2", "ECDHE-RSA-AES128-GCM-SHA256", "curl", 1, 3000),
    "akamai-tls12-aes256-prio": ("1.2", "ECDHE-RSA-AES256-GCM-SHA384", "prio", 1, 4000),
    "akamai-tls12-chacha-chrome": ("1.2", "ECDHE-RSA-CHACHA20-POLY1305", "chrome", 1, 5000),
    "akamai-tls13-http11": ("1.3", "TLS_AES_128_GCM_SHA256", None, 1, 6000),
    "akamai-tls13-resume": ("1.3", "TLS_AES_128_GCM_SHA256", "chrome", 2, 7000),
    "akamai-tls12-resume": ("1.2", "ECDHE-RSA-AES128-GCM-SHA256", "firefox", 2, 8000),
    "akamai-tls13-clientauth": ("1.3", "TLS_AES_128_GCM_SHA256", "chrome", 1, 9800),
    "akamai-h2c-prior": (None, None, "curl", 1, 9000),
    "akamai-h2c-upgrade": (None, None, "firefox", 1, 9500),
}


# Fixtures where the client authenticates with a certificate.
CLIENT_AUTH = {"akamai-tls13-clientauth"}


def make_cert(tmp, prefix="", extra=()):
    key, crt = os.path.join(tmp, f"{prefix}k.pem"), os.path.join(tmp, f"{prefix}c.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
         "-subj", "/CN=localhost", "-keyout", key, "-out", crt, *extra],
        check=True, capture_output=True,
    )
    return crt, key


def contexts(version, cipher, alpn, keylog, tmp, client_auth=False):
    crt, key = make_cert(tmp)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(crt, key)
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.check_hostname = False
    client.verify_mode = ssl.CERT_NONE
    client.keylog_filename = keylog
    if client_auth:
        # A client certificate over 16 KiB: TLS 1.3 then splits the Certificate message over
        # two records, so the client sends four encrypted handshake records before its data.
        names = ",".join(f"DNS:client{i:04d}.example.invalid" for i in range(700))
        client_crt, client_key = make_cert(tmp, "client-", ("-addext", f"subjectAltName={names}"))
        client.load_cert_chain(client_crt, client_key)
        server.verify_mode = ssl.CERT_REQUIRED
        server.load_verify_locations(client_crt)
    for ctx in (server, client):
        ctx.set_alpn_protocols([alpn])
        if version == "1.2":
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.set_ciphers(cipher)
        else:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return client, server


def generate(name):
    version, cipher, profile_name, conns, isn_c = FIXTURES[name]
    pcap_path = os.path.join(PCAP_DIR, f"{name}.pcap")
    keys_path = os.path.join(PCAP_DIR, f"{name}.keys")
    writer = PcapWriter()
    expected = []
    not_http2 = 0

    if profile_name is not None:
        profile = PROFILES[profile_name]
        fp_text, fp_hash = expected_fingerprint(profile)
        first, headers = client_frames(profile)
    if version is None:
        # Cleartext HTTP/2.
        if name.endswith("upgrade"):
            upgrade = (
                b"GET / HTTP/1.1\r\nHost: localhost:8443\r\nConnection: Upgrade, HTTP2-Settings\r\n"
                b"Upgrade: h2c\r\nHTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\r\n"
            )
            segments = [
                ("c", upgrade),
                ("s", b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"),
                ("c", first),
                ("c", headers),
                ("s", SERVER_H2),
            ]
        else:
            segments = [("c", first), ("c", headers), ("s", SERVER_H2)]
        writer.connection(50000, isn_c, 0x10000000, segments)
        expected.append(conn_entry(50000, None, None, fp_text, fp_hash))
    else:
        if os.path.exists(keys_path):
            os.remove(keys_path)
        with tempfile.TemporaryDirectory() as tmp:
            alpn = "h2" if profile_name else "http/1.1"
            client_ctx, server_ctx = contexts(
                version, cipher, alpn, keys_path, tmp, client_auth=name in CLIENT_AUTH
            )
            session = None
            for i in range(conns):
                if profile_name:
                    writes, reply = [first, headers], SERVER_H2
                else:
                    writes = [b"GET / HTTP/1.1\r\nHost: localhost:8443\r\nUser-Agent: huginn-fixture/1.0\r\n\r\n"]
                    reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                result = tls_connection(client_ctx, server_ctx, writes, reply, session)
                assert result["alpn"] == alpn, result["alpn"]
                want_version = "TLSv1.3" if version == "1.3" else "TLSv1.2"
                assert result["version"] == want_version, result["version"]
                assert result["cipher"] == cipher, f"negotiated {result['cipher']}, wanted {cipher}"
                if i > 0:
                    assert result["reused"], "second connection did not resume the session"
                session = result["session"]
                port = 50000 + i
                writer.connection(port, isn_c + i * 100000, 0x20000000 + i * 100000, result["segments"])
                if profile_name:
                    expected.append(
                        conn_entry(port, f"tls{version}", SUITE_IDS[cipher], fp_text, fp_hash)
                    )
                else:
                    not_http2 += 1

    writer.write(pcap_path)
    snapshot = {
        "generator": "scripts/gen-akamai-fixtures.py",
        "pcap": f"{name}.pcap",
        "keys": f"{name}.keys" if version else None,
        "connections": expected,
        "not_http2": not_http2,
    }
    with open(os.path.join(SNAPSHOT_DIR, f"{name}.pcap.json"), "w") as f:
        json.dump(snapshot, f, indent=2)
        f.write("\n")
    print(f"wrote {pcap_path} ({len(writer.records)} frames)")


def conn_entry(port, tls_version, cipher_suite, fp_text, fp_hash):
    return {
        "source": {"ip": CLIENT_IP, "port": port},
        "destination": {"ip": SERVER_IP, "port": SERVER_PORT},
        "tls_version": tls_version,
        "cipher_suite": cipher_suite,
        "fingerprint": fp_text,
        "hash": fp_hash,
    }


OPENSSL_CONF_TEMPLATE = """openssl_conf = default_conf
[default_conf]
ssl_conf = ssl_sect
[ssl_sect]
system_default = system_default_sect
[system_default_sect]
Ciphersuites = {suite}
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--only")
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.child:
        generate(args.only)
        return

    names = [args.only] if args.only else list(FIXTURES)
    for name in names:
        version, cipher, *_ = FIXTURES[name]
        env = dict(os.environ)
        with tempfile.NamedTemporaryFile("w", suffix=".cnf", delete=False) as conf:
            # TLS 1.3 suites can only be chosen through OpenSSL config (Python has no
            # set_ciphersuites), and the config is read at process start: run a child.
            suite = cipher if version == "1.3" else "TLS_AES_128_GCM_SHA256"
            conf.write(OPENSSL_CONF_TEMPLATE.format(suite=suite))
        env["OPENSSL_CONF"] = conf.name
        try:
            subprocess.run([sys.executable, "-I", __file__, "--child", "--only", name], check=True, env=env)
        finally:
            os.unlink(conf.name)


if __name__ == "__main__":
    main()
