"""Heuristic mDNS tunneling and service-name indicators."""

from .scoring import rate_over_window, shannon_entropy


def analyze_mdns(records: list[dict]) -> list[dict]:
    findings = []
    by_host: dict[str, list[dict]] = {}
    for record in records:
        by_host.setdefault(record.get("src", "unknown"), []).append(record)
    for host, items in by_host.items():
        score, reasons = 0, []
        for item in items:
            name = item.get("name", "")
            label = max(name.split("."), key=len, default="")
            if len(label) >= 28 and shannon_entropy(label) >= 3.5:
                score += 3
                reasons.append("long high-entropy service/instance label")
                break
        max_txt = max((item.get("txt_size", 0) for item in items), default=0)
        if max_txt > 180:
            score += 2
            reasons.append(f"large TXT data ({max_txt} bytes)")
        volume = rate_over_window([item["time"] for item in items])
        if volume > 20:
            score += 2
            reasons.append(f"high mDNS activity ({volume} records in 60 seconds)")
        if score:
            findings.append({"host": host, "score": score, "reasons": reasons,
                             "count": len(items)})
    return findings
