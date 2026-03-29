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
        r"(?:^|(?<=\s)|(?<=\[))"
        r"("
        # Full form: 8 groups
        r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
        r"|"
        # :: at the start with up to 7 groups after
        r"::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}"
        r"|"
        # :: at the end
        r"(?:[0-9a-fA-F]{1,4}:){1,7}:"
        r"|"
        # :: in the middle
        r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
        r"|"
        r"(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"
        r"|"
        r"(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"
        r"|"
        r"(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"
        r"|"
        r"(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}"
        r"|"
        r"[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}"
        r"|"
        # Bare ::
        r"::"
        r")"
        r"(?=\s|$|[\].,;)])",
    ),
    "url": re.compile(
        r"https?://[a-zA-Z0-9](?:[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=-])*",
        re.ASCII,
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
        r"+[a-zA-Z]{2,63}\b"
    ),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "cve": re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE),
    "mitre_attack": re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
    "email": re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}\b"),
    "bitcoin": re.compile(
        r"\b(?:1[a-km-zA-HJ-NP-Z1-9]{25,34}"
        r"|3[a-km-zA-HJ-NP-Z1-9]{25,34}"
        r"|bc1[a-zA-HJ-NP-Z0-9]{25,90})\b"
    ),
    "yara_rule": re.compile(r"\brule\s+(\w+)"),
    "sigma_rule_id": re.compile(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
        r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
    ),
}


_RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),  # multicast
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("255.255.255.255/32"),  # broadcast
)


def _is_rfc1918(ip_str: str) -> bool:
    """Check if an IPv4 address is in RFC 1918 or other non-routable space."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _RFC1918_NETWORKS)
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
        "url",
        "ipv4",
        "ipv6",
        "domain",
        "cve",
        "mitre_attack",
        "email",
        "bitcoin",
        "yara_rule",
        "sigma_rule_id",
    ]

    matched_spans: list[tuple[int, int]] = []

    for ioc_type in ordered_types:
        pattern = PATTERNS[ioc_type]
        for match in pattern.finditer(text):
            # For yara_rule, capture the rule name (group 1)
            if ioc_type == "yara_rule" and match.lastindex:
                value = match.group(1)
                start, end = match.start(1), match.end(1)
            else:
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


def extract_from_stix_pattern(pattern: str) -> list[IOCMatch]:
    """Parse a STIX 2.1 indicator pattern and extract embedded observables.

    Supports patterns like:
        [ipv4-addr:value = '198.51.100.1']
        [domain-name:value = 'evil.example.org']
        [file:hashes.'SHA-256' = 'abc...']
        [ipv4-addr:value = '1.2.3.4'] OR [domain-name:value = 'bad.com']

    Args:
        pattern: STIX 2.1 indicator pattern string.

    Returns:
        List of IOCMatch dicts extracted from the pattern.
    """
    results: list[IOCMatch] = []
    seen: set[tuple[str, str]] = set()

    # Extract quoted values from STIX comparison expressions
    stix_value_re = re.compile(r"(\w[\w-]*(?:\.\w[\w-]*)*):(\w[\w.']*)\s*=\s*'([^']+)'")

    # Map STIX object types to IOC types
    stix_type_map = {
        "ipv4-addr": "ipv4",
        "ipv6-addr": "ipv6",
        "domain-name": "domain",
        "email-addr": "email",
        "url": "url",
    }

    for match in stix_value_re.finditer(pattern):
        obj_type = match.group(1)
        prop_path = match.group(2)
        value = match.group(3)

        # Determine IOC type from STIX object type
        ioc_type = stix_type_map.get(obj_type)

        # Handle file hashes
        if obj_type == "file" and "hashes" in prop_path:
            prop_lower = prop_path.lower()
            if "sha-256" in prop_lower or "sha256" in prop_lower:
                ioc_type = "sha256"
            elif "sha-1" in prop_lower or "sha1" in prop_lower:
                ioc_type = "sha1"
            elif "md5" in prop_lower:
                ioc_type = "md5"

        if ioc_type is None:
            continue

        key = (ioc_type, value.lower())
        if key in seen:
            continue
        seen.add(key)

        results.append(
            IOCMatch(
                type=ioc_type,
                value=value,
                start=match.start(3),
                end=match.end(3),
            )
        )

    return results
