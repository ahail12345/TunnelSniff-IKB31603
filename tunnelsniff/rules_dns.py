"""Heuristic DNS tunneling indicators."""

from .scoring import rate_over_window, shannon_entropy


def analyze_dns(records: list[dict]) -> list[dict]:
    findings = []
    by_domain: dict[str, list[dict]] = {}
    for record in records:
        domain = record.get("domain", "").lower().rstrip(".")
        labels = domain.split(".")
        # Group by a simple two-label parent to catch rotating tunnel labels.
        # This is a heuristic, not a public-suffix database.
        group = ".".join(labels[-2:]) if len(labels) >= 2 else domain
        by_domain.setdefault(group, []).append(record)
    for domain, items in by_domain.items():
        score, reasons = 0, []
        suspicious_label = max(
            (label for item in items for label in item.get("domain", "").lower().rstrip(".").split(".")),
            key=lambda label: len(label) * shannon_entropy(label), default="")
        entropy = shannon_entropy(suspicious_label)
        if len(suspicious_label) >= 35 and entropy >= 3.5:
            score += 3
            reasons.append(f"long high-entropy label ({len(suspicious_label)} chars, {entropy:.2f} bits/char)")
        if any(item.get("qtype") in {10, 16} for item in items):
            score += 2
            reasons.append("NULL/TXT query type observed")
        count = rate_over_window([item["time"] for item in items])
        if count > 30:
            score += 3
            reasons.append(f"high query volume ({count} in 60 seconds)")
        if score:
            findings.append({"host": domain or "(empty name)", "score": score,
                             "reasons": reasons, "count": len(items)})
    return findings
