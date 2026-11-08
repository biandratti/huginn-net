#!/usr/bin/env python3
"""Reference Akamai HTTP/2 fingerprints for a real capture, via tshark (dev-only).

Never used at runtime or in CI. Use it to produce the expected snapshot for captures of
real clients (browsers, curl). CI only compares against the committed JSON.

tshark does the TCP reassembly and TLS decryption (with the key log); this script only reads
the decrypted client byte stream (`-z follow,tls,raw`, or `follow,tcp,raw` for h2c) and
computes the Akamai string from the first client SETTINGS, WINDOW_UPDATE (stream 0), PRIORITY
frames and the first HEADERS pseudo-header order, independently of huginn's code.

Usage:
    python3 scripts/akamai-oracle.py <capture.pcap> <keys.log|-> [--name NAME] > snapshot.json
    (pass "-" as the key log for cleartext h2c captures)
"""

import argparse
import hashlib
import json
import shutil
import struct
import subprocess
import sys

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
# RFC 7541 Appendix A static table indices of the pseudo-headers.
PSEUDO_BY_INDEX = {1: "a", 2: "m", 3: "m", 4: "p", 5: "p", 6: "s", 7: "s"}
PSEUDO_BY_NAME = {b":authority": "a", b":method": "m", b":path": "p", b":scheme": "s"}


def tshark(*args):
    return subprocess.run(["tshark", *args], check=True, capture_output=True, text=True).stdout


def streams(pcap):
    out = tshark("-r", pcap, "-T", "fields", "-e", "tcp.stream", "-Y", "tcp.flags.syn==1 && tcp.flags.ack==0")
    return sorted({int(x) for x in out.split()})


def endpoints(pcap, stream):
    out = tshark(
        "-r", pcap, "-Y", f"tcp.stream=={stream} && tcp.flags.syn==1 && tcp.flags.ack==0",
        "-T", "fields", "-e", "ip.src", "-e", "tcp.srcport", "-e", "ip.dst", "-e", "tcp.dstport",
    ).split()
    return {"ip": out[0], "port": int(out[1])}, {"ip": out[2], "port": int(out[3])}


def client_bytes(pcap, keys, stream):
    mode = "tcp" if keys == "-" else "tls"
    args = ["-r", pcap, "-q", "-z", f"follow,{mode},raw,{stream}"]
    if keys != "-":
        args = ["-o", f"tls.keylog_file:{keys}", *args]
    data = b""
    for line in tshark(*args).splitlines():
        # Client-to-server lines start in column 0; server lines are indented with a tab.
        if not line or line.startswith(("\t", "=", "Follow", "Filter", "Node")):
            continue
        try:
            data += bytes.fromhex(line.strip())
        except ValueError:
            continue
    return data


def hpack_int(buf, pos, prefix):
    mask = (1 << prefix) - 1
    value = buf[pos] & mask
    pos += 1
    if value < mask:
        return value, pos
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        value += (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return value, pos


def pseudo_order(block):
    order, pos = [], 0
    while pos < len(block):
        b = block[pos]
        if b & 0x80:  # indexed field
            idx, pos = hpack_int(block, pos, 7)
            name_idx, literal_name = idx, None
        elif b & 0xE0 == 0x20:  # dynamic table size update
            _, pos = hpack_int(block, pos, 5)
            continue
        else:
            prefix = 6 if b & 0xC0 == 0x40 else 4
            name_idx, pos = hpack_int(block, pos, prefix)
            literal_name = None
            if name_idx == 0:
                huffman = block[pos] & 0x80
                length, pos = hpack_int(block, pos, 7)
                literal_name = None if huffman else bytes(block[pos : pos + length])
                pos += length
            vlen, pos = hpack_int(block, pos, 7)
            pos += vlen
        letter = PSEUDO_BY_INDEX.get(name_idx) if name_idx else PSEUDO_BY_NAME.get(literal_name)
        if letter is None:
            break  # pseudo-headers come first; stop at the first regular header
        order.append(letter)
    return order


def akamai(data):
    if not data.startswith(PREFACE):
        return None
    pos, settings, wu, prio, pseudo = len(PREFACE), None, 0, [], None
    while pos + 9 <= len(data) and pseudo is None:
        length = int.from_bytes(data[pos : pos + 3], "big")
        ftype, flags = data[pos + 3], data[pos + 4]
        stream = struct.unpack(">I", data[pos + 5 : pos + 9])[0] & 0x7FFFFFFF
        payload = data[pos + 9 : pos + 9 + length]
        pos += 9 + length
        if ftype == 4 and stream == 0 and not flags & 1 and settings is None:
            settings = [struct.unpack(">HI", payload[i : i + 6]) for i in range(0, len(payload), 6)]
        elif ftype == 8 and stream == 0 and wu == 0:
            wu = struct.unpack(">I", payload[:4])[0] & 0x7FFFFFFF
        elif ftype == 2:
            dep = struct.unpack(">I", payload[:4])[0]
            prio.append((stream, dep >> 31, dep & 0x7FFFFFFF, payload[4] + 1))
        elif ftype == 1:
            block = payload
            if flags & 0x08:  # PADDED
                block = block[1 : len(block) - block[0]]
            if flags & 0x20:  # PRIORITY
                block = block[5:]
            pseudo = pseudo_order(block)
    if settings is None:
        return None
    text = "{}|{}|{}|{}".format(
        ";".join(f"{k}:{v}" for k, v in settings),
        wu if wu else "00",
        ",".join(f"{s}:{e}:{d}:{w}" for s, e, d, w in prio) if prio else "0",
        ",".join(pseudo or []),
    )
    return text, hashlib.sha256(text.encode()).digest()[:16].hex()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap")
    parser.add_argument("keys")
    parser.add_argument("--name")
    args = parser.parse_args()
    if shutil.which("tshark") is None:
        sys.exit("tshark not found (e.g. `sudo apt install tshark`); this script is dev-only")

    connections, not_http2 = [], 0
    for stream in streams(args.pcap):
        src, dst = endpoints(args.pcap, stream)
        result = akamai(client_bytes(args.pcap, args.keys, stream))
        if result is None:
            not_http2 += 1
            continue
        connections.append(
            {"source": src, "destination": dst, "tls_version": None, "cipher_suite": None,
             "fingerprint": result[0], "hash": result[1]}
        )
    json.dump(
        {"generator": "scripts/akamai-oracle.py (tshark)", "pcap": args.name or args.pcap.split("/")[-1],
         "keys": None if args.keys == "-" else args.keys.split("/")[-1],
         "connections": connections, "not_http2": not_http2},
        sys.stdout, indent=2,
    )
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
