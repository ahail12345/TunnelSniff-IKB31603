"""Human-readable and JSON output for TunnelSniff."""

import json
from datetime import datetime, timezone
from pathlib import Path


def render_report(source: str, scope: list[str], records: dict, findings: dict,
                  scope_mode: str = "automatic") -> dict:
    indicators_found = any(findings.values())
    return {
        "tool": "TunnelSniff",
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_file": Path(source).name,
        "scope": scope,
        "scope_mode": scope_mode,
        "channels_analyzed": list(records),
        "records_analyzed": {key: len(value) for key, value in records.items()},
        "findings": findings,
        "assessment": ("Potential tunneling indicators detected; review findings."
                       if indicators_found else
                       "No indicators detected above threshold; this does not prove the capture is clean."),
        "notice": "Heuristic indicators only; findings require human validation.",
    }


def print_report(report: dict) -> None:
    print(f"\n=== TunnelSniff report: {report['source_file']} ===")
    print("Assessment: " + report["assessment"])
    print(f"Scope mode: {report.get('scope_mode', 'filter')}")
    scope = report["scope"]
    if len(scope) <= 25:
        print("Observed scope: " + (", ".join(scope) if scope else "no endpoints identified"))
    else:
        print("Observed scope (first 25): " + ", ".join(scope[:25]) +
              f" ... and {len(scope) - 25} more in the JSON report")
    for channel, count in report["records_analyzed"].items():
        print(f"{channel.upper():5} records analyzed: {count}")
        entries = report["findings"].get(channel, [])
        if not entries:
            print("  No indicators above configured threshold.")
        for entry in entries:
            severity = "HIGH" if entry["score"] >= 6 else "MEDIUM" if entry["score"] >= 4 else "LOW"
            print(f"  [{severity}] {entry['host']} (score {entry['score']})")
            for reason in entry["reasons"]:
                print(f"      - {reason}")
    print("\nHeuristic results are indicators, not proof of tunneling.")


def save_report(report: dict, directory: str = "output") -> Path:
    folder = Path(directory)
    folder.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output = folder / f"tunnelsniff_{stamp}.json"
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return output
