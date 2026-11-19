"""Create a harmless PCAP demo for TunnelSniff using only the Python standard library."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import struct
import time
from pathlib import Path


CLIENT = "192.0.2.10"
DNS_SERVER = "192.0.2.53"
HTTP_SERVER = "192.0.2.80"
HTTPS_SERVER = "192.0.2.44"
MDNS_GROUP = "224.0.0.251"
CLIENT_MAC = bytes.fromhex("020000000010")
SERVER_MAC = bytes.fromhex("020000000020")
MULTICAST_MAC = bytes.fromhex("01005e0000fb")


def checksum(data: bytes) -> int:
    """Internet checksum used by IPv4, UDP, and TCP."""
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def dns_question(name: str, qtype: int, ident: int = 0) -> bytes:
    encoded_name = b"".join(bytes([len(label)]) + label.encode("ascii")
                            for label in name.rstrip(".").split(".")) + b"\0"
    header = struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0)
    return header + encoded_name + struct.pack("!HH", qtype, 1)


def udp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    src = ipaddress.ip_address(src_ip).packed
    dst = ipaddress.ip_address(dst_ip).packed
    length = 8 + len(payload)
    header = struct.pack("!HHHH", src_port, dst_port, length, 0)
    pseudo = src + dst + b"\0\x11" + struct.pack("!H", length)
    value = checksum(pseudo + header + payload) or 0xffff
    return struct.pack("!HHHH", src_port, dst_port, length, value) + payload


def tcp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
               payload: bytes, sequence: int) -> bytes:
    src = ipaddress.ip_address(src_ip).packed
    dst = ipaddress.ip_address(dst_ip).packed
    offset_flags = (5 << 12) | 0x18  # data offset 5, PSH + ACK
    header = struct.pack("!HHIIHHHH", src_port, dst_port, sequence, 1,
                         offset_flags, 64240, 0, 0)
    pseudo = src + dst + b"\0\x06" + struct.pack("!H", len(header) + len(payload))
    value = checksum(pseudo + header + payload)
    header = struct.pack("!HHIIHHHH", src_port, dst_port, sequence, 1,
                         offset_flags, 64240, value, 0)
    return header + payload


def ipv4_ethernet(src_ip: str, dst_ip: str, protocol: int, transport: bytes,
                  src_mac: bytes, dst_mac: bytes, ident: int) -> bytes:
    src = ipaddress.ip_address(src_ip).packed
    dst = ipaddress.ip_address(dst_ip).packed
    total_length = 20 + len(transport)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_length, ident,
                         0x4000, 64, protocol, 0, src, dst)
    value = checksum(header)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_length, ident,
                         0x4000, 64, protocol, value, src, dst)
    return struct.pack("!6s6sH", dst_mac, src_mac, 0x0800) + header + transport


def tls_client_hello(server_name: str, seed: int) -> bytes:
    """Build a small TLS 1.2 ClientHello with an ordinary SNI extension."""
    hostname = server_name.encode("ascii")
    entry = b"\0" + struct.pack("!H", len(hostname)) + hostname
    name_list = struct.pack("!H", len(entry)) + entry
    sni = struct.pack("!HH", 0, len(name_list)) + name_list
    random_bytes = hashlib.sha256(f"synthetic-demo-{seed}".encode()).digest()
    body = (b"\x03\x03" + random_bytes + b"\x00" +
            struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00" +
            struct.pack("!H", len(sni)) + sni)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def demo_packets() -> list[tuple[float, bytes]]:
    packets: list[tuple[float, bytes]] = []
    ident = 1
    start = int(time.time()) - 120

    # Synthetic DNS tunnel-like pattern: long high-entropy TXT queries and volume.
    long_label = "a8f3e9c1b2d4e6f708192a3b4c5d6e7f90123456"
    for index in range(31):
        payload = dns_question(f"{long_label}.example.test", 16, ident)
        udp = udp_packet(CLIENT, DNS_SERVER, 53000 + index, 53, payload)
        frame = ipv4_ethernet(CLIENT, DNS_SERVER, 17, udp, CLIENT_MAC, SERVER_MAC, ident)
        packets.append((start + index, frame))
        ident += 1

    # Plain HTTP with a long encoded-looking path and regular timing.
    encoded = "QWxwaGFCZXRhR2FtbWFEZWx0YUVwc2lsb25aZXRhMTIzNDU2Nzg5MDEyMzQ1Njc4OTA="
    for index in range(10):
        request = (f"GET /{encoded} HTTP/1.1\r\nHost: web.example.test\r\n"
                   "User-Agent: TunnelSniff-Synthetic-Demo\r\nConnection: close\r\n\r\n").encode()
        tcp = tcp_packet(CLIENT, HTTP_SERVER, 54000 + index, 80, request, 1000 + index)
        frame = ipv4_ethernet(CLIENT, HTTP_SERVER, 6, tcp, CLIENT_MAC, SERVER_MAC, ident)
        packets.append((start + 40 + index * 10, frame))
        ident += 1

    # HTTPS channel contains valid synthetic TLS ClientHello packets with SNI.
    for index in range(10):
        hello = tls_client_hello("secure.example.test", index)
        tcp = tcp_packet(CLIENT, HTTPS_SERVER, 55000 + index, 443, hello, 2000 + index)
        frame = ipv4_ethernet(CLIENT, HTTPS_SERVER, 6, tcp, CLIENT_MAC, SERVER_MAC, ident)
        packets.append((start + 45 + index * 10, frame))
        ident += 1

    # Synthetic mDNS service-name pattern and query volume.
    instance = "q8x2z9m4n1b7c6d3e5f0a2g4h8j1k3p5"
    for index in range(21):
        payload = dns_question(f"{instance}._http._tcp.local", 12, 0)
        udp = udp_packet(CLIENT, MDNS_GROUP, 5353, 5353, payload)
        frame = ipv4_ethernet(CLIENT, MDNS_GROUP, 17, udp, CLIENT_MAC, MULTICAST_MAC, ident)
        packets.append((start + 80 + index, frame))
        ident += 1

    return sorted(packets, key=lambda item: item[0])


def write_pcap(path: Path, packets: list[tuple[float, bytes]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as stream:
        # Classic little-endian PCAP, Ethernet link type.
        stream.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for timestamp, frame in packets:
            seconds = int(timestamp)
            microseconds = int((timestamp - seconds) * 1_000_000)
            stream.write(struct.pack("<IIII", seconds, microseconds, len(frame), len(frame)))
            stream.write(frame)


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a harmless all-channel TunnelSniff demo capture.")
    default_path = Path(__file__).resolve().parents[1] / "samples" / "tunnelsniff_synthetic_demo.pcap"
    parser.add_argument("--output", type=Path, default=default_path,
                        help=f"output PCAP path (default: {default_path})")
    args = parser.parse_args()
    packets = demo_packets()
    write_pcap(args.output, packets)
    print(f"Created {args.output} ({len(packets)} synthetic packets).")
    print("Addresses use 192.0.2.0/24 and names use example.test; no real traffic is included.")


if __name__ == "__main__":
    main()
