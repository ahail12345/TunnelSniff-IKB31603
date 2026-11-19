"""Extract only protocol metadata from an offline PCAP using Scapy."""

from __future__ import annotations

import ipaddress
from pathlib import Path


def _text(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").rstrip(".\x00")
    return str(value or "").rstrip(".\x00")


def parse_capture(path: str, channels: set[str]) -> dict[str, list[dict]]:
    """Return DNS, HTTP/TLS and mDNS metadata records from a PCAP file."""
    try:
        from scapy.all import DNS, DNSQR, DNSRR, IP, IPv6, TCP, UDP, rdpcap
        from scapy.layers.http import HTTPRequest
        from scapy.layers.tls.handshake import TLSClientHello
        from scapy.layers.tls.extensions import ServerName
    except ImportError as exc:
        raise RuntimeError("Scapy is required. Install dependencies with pip install -r requirements.txt") from exc
    capture = Path(path)
    if not capture.is_file():
        raise FileNotFoundError(f"PCAP file not found: {capture}")
    result = {name: [] for name in ("dns", "http", "https", "mdns") if name in channels}
    for packet in rdpcap(str(capture)):
        timestamp = float(packet.time)
        src = packet[IP].src if packet.haslayer(IP) else packet[IPv6].src if packet.haslayer(IPv6) else "unknown"
        dst = packet[IP].dst if packet.haslayer(IP) else packet[IPv6].dst if packet.haslayer(IPv6) else "unknown"
        if packet.haslayer(UDP) and packet.haslayer(DNS):
            udp = packet[UDP]
            dns = packet[DNS]
            is_mdns = udp.sport == 5353 or udp.dport == 5353
            if is_mdns and "mdns" in channels:
                name = _text(packet[DNSQR].qname) if packet.haslayer(DNSQR) else ""
                txt_size = 0
                try:
                    for answer in dns.an:
                        if isinstance(answer, DNSRR) and answer.type == 16:
                            txt_size += len(bytes(answer.rdata))
                except (AttributeError, TypeError):
                    pass
                result["mdns"].append({"name": name, "src": src, "dst": dst, "time": timestamp,
                                       "txt_size": txt_size})
            elif not is_mdns and "dns" in channels and packet.haslayer(DNSQR):
                query = packet[DNSQR]
                result["dns"].append({"domain": _text(query.qname), "src": src, "dst": dst,
                                      "time": timestamp, "qtype": int(query.qtype)})
        if "http" in channels and packet.haslayer(HTTPRequest):
            request = packet[HTTPRequest]
            host = _text(getattr(request, "Host", b"")) or dst
            visible = " ".join(_text(getattr(request, key, b"")) for key in
                               ("Path", "Cookie", "Authorization", "User_Agent"))
            body = bytes(packet[TCP].payload) if packet.haslayer(TCP) else b""
            result["http"].append({"host": host, "src": src, "dst": dst, "time": timestamp,
                                   "encoded_indicator": _encoded(visible),
                                   "large_body": len(body) > 4096, "source": "HTTP"})
        if "https" in channels and packet.haslayer(TCP) and (
                packet[TCP].dport == 443 or packet[TCP].sport == 443):
            sni = dst
            if packet.haslayer(TLSClientHello):
                hello = packet[TLSClientHello]
                for extension in getattr(hello, "ext", []) or []:
                    if isinstance(extension, ServerName):
                        names = getattr(extension, "servernames", [])
                        if names:
                            sni = _text(getattr(names[0], "servername", b"")) or dst
            result["https"].append({"host": sni, "src": src, "dst": dst, "time": timestamp,
                                    "packet_size": len(packet), "source": "TLS metadata"})
    return result


def _encoded(value: str) -> bool:
    import re
    return bool(re.search(r"(?:[A-Fa-f0-9]{48,}|[A-Za-z0-9+/]{48,}={0,2})", value))


def in_scope(host: str, scopes: set[str]) -> bool:
    """Match an exact IP, an address in a CIDR range, or a DNS subdomain."""
    normalized = host.lower().strip().rstrip(".")
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        address = None
    for scope in scopes:
        if not scope:
            continue
        if normalized == scope or normalized.endswith("." + scope):
            return True
        try:
            if address is not None and address in ipaddress.ip_network(scope, strict=False):
                return True
        except ValueError:
            continue
    return False
