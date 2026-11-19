"""TunnelSniff: passive tunneling-indicator analysis for authorized PCAP files."""

import argparse
import sys
from pathlib import Path

from tunnelsniff.parser import in_scope, parse_capture
from tunnelsniff.report import print_report, render_report, save_report
from tunnelsniff.rules_dns import analyze_dns
<<<<<<< HEAD
from tunnelsniff.rules_http import analyze_http
=======
from tunnelsniff.rules_http import analyze_http, analyze_https
>>>>>>> 0a7b656 (Update tunnelsniff.py)
from tunnelsniff.rules_mdns import analyze_mdns

LEGAL_NOTICE = ("LEGAL NOTICE: Unauthorized access or interception may violate Malaysia's "
                "Computer Crimes Act 1997. Analyze only captures you own or are explicitly "
                "authorized to review. TunnelSniff does not decrypt TLS.")
<<<<<<< HEAD
CHANNELS = {"dns", "http", "mdns"}
=======
CHANNELS = {"dns", "http", "https", "mdns"}
>>>>>>> 0a7b656 (Update tunnelsniff.py)


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
<<<<<<< HEAD
        description="Offline, metadata-only detection of possible DNS, HTTP/TLS and mDNS tunneling.",
        epilog="Examples:\n  python tunnelsniff.py --pcap instructor_sample.pcap --scope example.com\n"
               "  python tunnelsniff.py --pcap lab.pcap --scope 192.0.2.10,example.test --channels dns,mdns\n"
               "  python tunnelsniff.py --pcap lab.pcap --scope localhost --no-save",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pcap", required=True, help="offline PCAP/PCAPNG file to analyze")
    parser.add_argument("--scope", default="localhost,127.0.0.1,example.com",
                        help="authorized IPs/domains to include (default: localhost, loopback, example.com)")
    parser.add_argument("--channels", default="dns,http,mdns",
                        help="comma-separated subset: dns,http,mdns (default: all)")
=======
        description="Offline, metadata-only detection of possible DNS, HTTP, HTTPS and mDNS tunneling.",
        epilog="Examples:\n  python tunnelsniff.py --pcap lab.pcap\n"
               "  python tunnelsniff.py --pcap lab.pcap --scope 192.168.1.0/24,example.test\n"
               "  python tunnelsniff.py --pcap lab.pcap --scope 192.0.2.10 --channels https,mdns",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pcap", required=True, help="offline PCAP/PCAPNG file to analyze")
    parser.add_argument("--scope", default=None,
                        help="optional filter: authorized domains, IPs, or CIDR ranges; omitted means automatic scope")
    parser.add_argument("--channels", default="dns,http,https,mdns",
                        help="comma-separated subset: dns,http,https,mdns (default: all)")
>>>>>>> 0a7b656 (Update tunnelsniff.py)
    parser.add_argument("--threshold", type=int, default=3, help="minimum score to report (default: 3)")
    parser.add_argument("--output", default="output", help="local report folder (default: output)")
    parser.add_argument("--no-save", action="store_true", help="print results without writing a report")
    return parser.parse_args()


<<<<<<< HEAD
def confirm_authorization(scope: list[str]) -> bool:
    print(LEGAL_NOTICE)
    print("Declared in-scope targets: " + ", ".join(scope))
    answer = input("Confirm you own or are authorized to analyze this capture and scope? (yes/no): ")
    return answer.strip().lower() == "yes"


def main() -> int:
    args = arguments()
    channels = {part.strip().lower() for part in args.channels.split(",") if part.strip()}
    scopes = {part.strip().lower().rstrip(".") for part in args.scope.split(",") if part.strip()}
    if not channels or not channels <= CHANNELS:
        print("Error: --channels must contain one or more of dns,http,mdns.", file=sys.stderr)
        return 2
    if not scopes or args.threshold < 1:
        print("Error: provide a scope and a threshold of at least 1.", file=sys.stderr)
        return 2
    if not confirm_authorization(sorted(scopes)):
=======
def confirm_authorization(scope: list[str] | None) -> bool:
    print(LEGAL_NOTICE)
    if scope is None:
        print("Scope mode: automatic; all observed hosts, domains, and IPs in this capture will be analyzed.")
        prompt = "Confirm you are authorized to analyze the entire capture? (yes/no): "
    else:
        print("Declared in-scope targets: " + ", ".join(sorted(scope)))
        print("Note: the entire capture must still be authorized because parsing occurs before filtering.")
        prompt = "Confirm you are authorized to analyze this capture and filter scope? (yes/no): "
    answer = input(prompt)
    return answer.strip().lower() == "yes"


def get_scope(scope_argument: str | None) -> set[str] | None:
    """Parse an optional filter; omitted means automatic scope discovery."""
    if scope_argument is None:
        return None
    scopes = {normalize_scope(part) for part in scope_argument.split(",") if part.strip()}
    if not scopes:
        raise ValueError("Scope filter cannot be empty. Omit --scope for automatic discovery.")
    return scopes


def normalize_scope(value: str) -> str:
    """Normalize IP addresses and networks; keep domain scopes lowercase."""
    import ipaddress
    value = value.strip().lower().rstrip(".")
    if not value or any(char.isspace() for char in value):
        raise ValueError("Each scope item must be a domain, IP address, or CIDR range.")
    if "/" in value or ":" in value:
        try:
            return ipaddress.ip_network(value, strict=False).with_prefixlen
        except ValueError as exc:
            raise ValueError(f"Invalid IP address or CIDR range: {value}") from exc
    try:
        return ipaddress.ip_network(value, strict=False).with_prefixlen
    except ValueError:
        if value.startswith(".") or ".." in value or "/" in value:
            raise ValueError(f"Invalid domain scope: {value}")
        return value


def discover_scope(records: dict[str, list[dict]]) -> list[str]:
    """Collect observed domains, hosts, service names, and IPs as the auto scope."""
    observed = set()
    for channel_records in records.values():
        for record in channel_records:
            for key in ("domain", "host", "name", "src", "dst"):
                value = str(record.get(key, "")).strip().rstrip(".")
                if value and value.lower() != "unknown":
                    observed.add(value.lower())
    return sorted(observed)


def main() -> int:
    args = arguments()
    channels = {part.strip().lower() for part in args.channels.split(",") if part.strip()}
    if not channels or not channels <= CHANNELS:
        print("Error: --channels must contain one or more of dns,http,https,mdns.", file=sys.stderr)
        return 2
    if args.threshold < 1:
        print("Error: threshold must be at least 1.", file=sys.stderr)
        return 2
    try:
        scopes = get_scope(args.scope)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    if not confirm_authorization(None if scopes is None else sorted(scopes)):
>>>>>>> 0a7b656 (Update tunnelsniff.py)
        print("Authorization not confirmed. Exiting without reading the capture.")
        return 1
    try:
        records = parse_capture(args.pcap, channels)
        # Scope filtering is applied independently to each protocol's host/domain field.
<<<<<<< HEAD
        records["dns"] = [r for r in records["dns"]
                          if in_scope(r["domain"], scopes) or r["src"] in scopes or r["dst"] in scopes]
        records["http"] = [r for r in records["http"]
                           if in_scope(r["host"], scopes) or r["src"] in scopes or r["dst"] in scopes]
        records["mdns"] = [r for r in records["mdns"] if in_scope(r["src"], scopes)]
        analyzers = {"dns": analyze_dns, "http": analyze_http, "mdns": analyze_mdns}
        findings = {channel: [item for item in analyzers[channel](records[channel])
                              if item["score"] >= args.threshold] for channel in channels}
        report = render_report(args.pcap, sorted(scopes), records, findings)
=======
        if scopes is not None:
            if "dns" in records:
                records["dns"] = [r for r in records["dns"]
                                   if any(in_scope(r[key], scopes) for key in ("domain", "src", "dst"))]
            if "http" in records:
                records["http"] = [r for r in records["http"]
                                    if any(in_scope(r[key], scopes) for key in ("host", "src", "dst"))]
            if "https" in records:
                records["https"] = [r for r in records["https"]
                                     if any(in_scope(r[key], scopes) for key in ("host", "src", "dst"))]
            if "mdns" in records:
                records["mdns"] = [r for r in records["mdns"] if in_scope(r["src"], scopes)]
        effective_scope = sorted(scopes) if scopes is not None else discover_scope(records)
        analyzers = {"dns": analyze_dns, "http": analyze_http, "https": analyze_https,
                     "mdns": analyze_mdns}
        findings = {channel: [item for item in analyzers[channel](records[channel])
                              if item["score"] >= args.threshold] for channel in channels}
        report = render_report(args.pcap, effective_scope, records, findings,
                               scope_mode="filter" if scopes is not None else "automatic")
>>>>>>> 0a7b656 (Update tunnelsniff.py)
        print_report(report)
        if not args.no_save:
            saved = save_report(report, args.output)
            print(f"Saved local report: {saved}")
        return 0
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nStopped by user. No network capture was active; any completed report remains local.")
        raise SystemExit(130)
