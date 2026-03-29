"""ingest.ner.tier1_regex — Tier 1 deterministic IOC extraction.

Extracts indicators of compromise (IOCs) from unstructured text using
compiled regular expressions. No ML models; pure pattern matching.
"""

from __future__ import annotations

import ipaddress
import re
from typing import TypedDict


class IOCMatch(TypedDict):
    type: str
    value: str
    start: int
    end: int


# False-positive domains to reject
_FALSE_POSITIVE_DOMAINS: frozenset[str] = frozenset(
    {
        "localhost",
        "example.com",
        "example.org",
        "example.net",
        "test.com",
        "test.org",
        "invalid",
        "localhost.localdomain",
    }
)

PATTERNS: dict[str, re.Pattern[str]] = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
    ),
    "ipv6": re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
        r"|"
        r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b"
        r"|"
        r"\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b"
        r"|"
        r"\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b"
        r"|"
        r"\b[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}\b"
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
        r"+[a-zA-Z]{2,63}\b"
    ),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "cve": re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE),
    "mitre_attack": re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
    "email": re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}\b"),
}


def _is_rfc1918(ip_str: str) -> bool:
    """Check if an IPv4 address is in RFC 1918 private space."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private
    except ValueError:
        return False


def extract_iocs(
    text: str,
    *,
    reject_private_ips: bool = True,
    reject_false_positive_domains: bool = True,
) -> list[IOCMatch]:
    """Extract IOCs from text using compiled regex patterns.

    Args:
        text: Input text to scan.
        reject_private_ips: If True, skip RFC 1918 / private IPv4 addresses.
        reject_false_positive_domains: If True, skip common false-positive domains.

    Returns:
        List of IOCMatch dicts with type, value, start, end.
    """
    results: list[IOCMatch] = []
    seen: set[tuple[str, str]] = set()

    # Process longer hash patterns first to avoid substring matches
    ordered_types = [
        "sha256",
        "sha1",
        "md5",
        "ipv4",
        "ipv6",
        "domain",
        "cve",
        "mitre_attack",
        "email",
    ]

    matched_spans: list[tuple[int, int]] = []

    for ioc_type in ordered_types:
        pattern = PATTERNS[ioc_type]
        for match in pattern.finditer(text):
            value = match.group()
            start, end = match.start(), match.end()

            # Skip if this span overlaps with an already-matched longer pattern
            if any(start >= ms and end <= me for ms, me in matched_spans):
                continue

            # Deduplicate within a single extraction run
            key = (ioc_type, value.lower())
            if key in seen:
                continue

            # Validation: reject private IPs
            if ioc_type == "ipv4" and reject_private_ips and _is_rfc1918(value):
                continue

            # Validation: reject false-positive domains
            if ioc_type == "domain" and reject_false_positive_domains:
                if value.lower() in _FALSE_POSITIVE_DOMAINS:
                    continue

            seen.add(key)
            matched_spans.append((start, end))
            results.append(IOCMatch(type=ioc_type, value=value, start=start, end=end))

    return results
