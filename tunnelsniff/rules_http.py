"""HTTP and TLS-metadata tunneling indicators. TLS payloads are never decrypted."""

from .scoring import interval_jitter, rate_over_window


def analyze_http(records: list[dict]) -> list[dict]:
    findings = []
    by_host: dict[str, list[dict]] = {}
    for record in records:
        by_host.setdefault(record.get("host", "unknown"), []).append(record)
    for host, items in by_host.items():
        score, reasons = 0, []
        timestamps = [item["time"] for item in items]
        jitter = interval_jitter(timestamps)
        if len(items) >= 10 and jitter is not None and jitter < 2.0:
            score += 3
            reasons.append(f"regular request timing (interval jitter {jitter:.2f}s)")
        if rate_over_window(timestamps) > 60:
            score += 2
            reasons.append("high HTTP/TLS record volume")
        for item in items:
            if item.get("encoded_indicator"):
                score += 3
                reasons.append("long encoded-looking value in visible HTTP metadata")
                break
        if any(item.get("large_body") for item in items):
            score += 2
            reasons.append("unusually large visible HTTP body")
        if score:
            findings.append({"host": host, "score": score, "reasons": reasons,
                             "count": len(items)})
    return findings


def analyze_https(records: list[dict]) -> list[dict]:
    """Score possible HTTPS beaconing from visible TLS packet timing only."""
    findings = []
    by_host: dict[str, list[dict]] = {}
    for record in records:
        by_host.setdefault(record.get("host", "unknown"), []).append(record)
    for host, items in by_host.items():
        score, reasons = 0, []
        timestamps = [item["time"] for item in items]
        jitter = interval_jitter(timestamps)
        if len(items) >= 10 and jitter is not None and jitter < 2.0:
            score += 3
            reasons.append(f"regular HTTPS packet timing (interval jitter {jitter:.2f}s)")
        volume = rate_over_window(timestamps)
        if volume > 60:
            score += 2
            reasons.append(f"high HTTPS packet volume ({volume} in 60 seconds)")
        if score:
            findings.append({"host": host, "score": score, "reasons": reasons,
                             "count": len(items)})
    return findings
