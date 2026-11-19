"""Reusable, explainable scoring helpers shared by protocol detectors."""

from collections import Counter
from math import log2
from statistics import pstdev


def shannon_entropy(value: str) -> float:
    """Return Shannon entropy in bits per character."""
    if not value:
        return 0.0
    counts = Counter(value)
    size = len(value)
    return -sum((count / size) * log2(count / size) for count in counts.values())


def rate_over_window(timestamps: list[float], window: float = 60.0) -> int:
    """Return the highest number of events in any sliding time window."""
    ordered = sorted(timestamps)
    left = peak = 0
    for right, timestamp in enumerate(ordered):
        while timestamp - ordered[left] > window:
            left += 1
        peak = max(peak, right - left + 1)
    return peak


def interval_jitter(timestamps: list[float]) -> float | None:
    """Measure standard deviation of intervals; None when too few events."""
    ordered = sorted(timestamps)
    if len(ordered) < 3:
        return None
    intervals = [b - a for a, b in zip(ordered, ordered[1:])]
    return pstdev(intervals)


def encoded_like(value: str) -> bool:
    """Conservatively recognize long base64/hex-like runs without decoding."""
    import re
    return bool(re.search(r"(?:[A-Fa-f0-9]{48,}|[A-Za-z0-9+/]{48,}={0,2})", value or ""))
