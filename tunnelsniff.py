"""TunnelSniff: passive tunneling-indicator analysis for authorized PCAP files."""

import argparse
import sys
from pathlib import Path

from tunnelsniff.parser import in_scope, parse_capture
from tunnelsniff.report import print_report, render_report, save_report
from tunnelsniff.rules_dns import analyze_dns
from tunnelsniff.rules_http import analyze_http
from tunnelsniff.rules_mdns import analyze_mdns

LEGAL_NOTICE = ("LEGAL NOTICE: Unauthorized access or interception may violate Malaysia's "
                "Computer Crimes Act 1997. Analyze only captures you own or are explicitly "
                "authorized to review. TunnelSniff does not decrypt TLS.")
CHANNELS = {"dns", "http", "mdns"}


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
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
    parser.add_argument("--threshold", type=int, default=3, help="minimum score to report (default: 3)")
    parser.add_argument("--output", default="output", help="local report folder (default: output)")
    parser.add_argument("--no-save", action="store_true", help="print results without writing a report")
    return parser.parse_args()


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
        print("Authorization not confirmed. Exiting without reading the capture.")
        return 1
    try:
        records = parse_capture(args.pcap, channels)
        # Scope filtering is applied independently to each protocol's host/domain field.
        records["dns"] = [r for r in records["dns"]
                          if in_scope(r["domain"], scopes) or r["src"] in scopes or r["dst"] in scopes]
        records["http"] = [r for r in records["http"]
                           if in_scope(r["host"], scopes) or r["src"] in scopes or r["dst"] in scopes]
        records["mdns"] = [r for r in records["mdns"] if in_scope(r["src"], scopes)]
        analyzers = {"dns": analyze_dns, "http": analyze_http, "mdns": analyze_mdns}
        findings = {channel: [item for item in analyzers[channel](records[channel])
                              if item["score"] >= args.threshold] for channel in channels}
        report = render_report(args.pcap, sorted(scopes), records, findings)
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
