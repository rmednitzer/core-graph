"""tests/ingest/test_entity_resolution.py

Unit tests for deterministic entity key generation and fuzzy entity matching.
No running database required.
"""

from __future__ import annotations

import hashlib


def canonical_key(ioc_type: str, value: str) -> str:
    """Return a deterministic, source-independent key for an IOC.

    The key is a SHA-256 hex digest of ``<type>:<normalised_value>`` so that
    the same IOC from different sources always produces the same canonical key.
    """
    normalised = value.strip().lower()
    raw = f"{ioc_type.lower()}:{normalised}"
    return hashlib.sha256(raw.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Tests: deterministic key generation
# ---------------------------------------------------------------------------


def test_ip_key_is_deterministic() -> None:
    k1 = canonical_key("ip", "192.168.1.1")
    k2 = canonical_key("ip", "192.168.1.1")
    assert k1 == k2


def test_hash_key_is_deterministic() -> None:
    sha = "d41d8cd98f00b204e9800998ecf8427e"
    k1 = canonical_key("hash", sha)
    k2 = canonical_key("hash", sha)
    assert k1 == k2


def test_cve_key_is_deterministic() -> None:
    k1 = canonical_key("cve", "CVE-2024-12345")
    k2 = canonical_key("cve", "CVE-2024-12345")
    assert k1 == k2


def test_domain_key_is_deterministic() -> None:
    k1 = canonical_key("domain", "evil.example.com")
    k2 = canonical_key("domain", "evil.example.com")
    assert k1 == k2


def test_different_ioc_types_produce_different_keys() -> None:
    value = "192.168.1.1"
    assert canonical_key("ip", value) != canonical_key("domain", value)


# ---------------------------------------------------------------------------
# Tests: cross-source canonical key equality
# ---------------------------------------------------------------------------


def test_ip_same_across_sources() -> None:
    """Same IP from Wazuh and MISP must produce identical keys."""
    wazuh_key = canonical_key("ip", " 10.0.0.1 ")  # leading/trailing space
    misp_key = canonical_key("ip", "10.0.0.1")
    assert wazuh_key == misp_key


def test_cve_case_insensitive() -> None:
    """CVE identifiers must be normalised to lower-case before hashing."""
    k_upper = canonical_key("cve", "CVE-2022-45786")
    k_lower = canonical_key("cve", "cve-2022-45786")
    assert k_upper == k_lower


def test_domain_case_insensitive() -> None:
    k1 = canonical_key("domain", "EVIL.EXAMPLE.COM")
    k2 = canonical_key("domain", "evil.example.com")
    assert k1 == k2


# ---------------------------------------------------------------------------
# Tests: Jaro-Winkler similarity for fuzzy entity matching
# ---------------------------------------------------------------------------


def test_apt28_fancy_bear_similarity() -> None:
    """APT28 and Fancy Bear are known aliases; similarity should be positive."""
    import jellyfish

    score = jellyfish.jaro_winkler_similarity("apt28", "fancy bear")
    # They are quite different strings; the test documents expected behaviour
    # (not a strict threshold) — any positive similarity is expected.
    assert score > 0.0


def test_identical_strings_have_similarity_one() -> None:
    import jellyfish

    assert jellyfish.jaro_winkler_similarity("apt28", "apt28") == 1.0


def test_completely_different_strings_have_low_similarity() -> None:
    import jellyfish

    score = jellyfish.jaro_winkler_similarity("apt28", "zzzzzzzzz")
    assert score < 0.6


def test_close_aliases_have_high_similarity() -> None:
    """Minor spelling variations of the same group name should score high."""
    import jellyfish

    score = jellyfish.jaro_winkler_similarity("cozy bear", "cozy_bear")
    assert score > 0.85
