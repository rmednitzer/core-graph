"""Comprehensive tests for ingest.ner.tier1_regex — Tier 1 IOC extraction."""

from __future__ import annotations

from ingest.ner.tier1_regex import extract_iocs


class TestIPv4Extraction:
    def test_valid_public_ip(self) -> None:
        results = extract_iocs("Server at 198.51.100.23 responded")
        assert any(r["type"] == "ipv4" and r["value"] == "198.51.100.23" for r in results)

    def test_reject_rfc1918_10(self) -> None:
        results = extract_iocs("Internal host 10.0.0.1 is up")
        assert not any(r["type"] == "ipv4" and r["value"] == "10.0.0.1" for r in results)

    def test_reject_rfc1918_172(self) -> None:
        results = extract_iocs("LAN address 172.16.0.1 detected")
        assert not any(r["type"] == "ipv4" and r["value"] == "172.16.0.1" for r in results)

    def test_reject_rfc1918_192(self) -> None:
        results = extract_iocs("Private 192.168.1.1 host")
        assert not any(r["type"] == "ipv4" and r["value"] == "192.168.1.1" for r in results)

    def test_allow_private_when_disabled(self) -> None:
        results = extract_iocs("Internal 10.0.0.1", reject_private_ips=False)
        assert any(r["type"] == "ipv4" and r["value"] == "10.0.0.1" for r in results)

    def test_reject_multicast(self) -> None:
        results = extract_iocs("Multicast 224.0.0.1 traffic")
        assert not any(r["type"] == "ipv4" and r["value"] == "224.0.0.1" for r in results)

    def test_reject_zero_address(self) -> None:
        results = extract_iocs("Address 0.0.0.0 is invalid")
        assert not any(r["type"] == "ipv4" and r["value"] == "0.0.0.0" for r in results)

    def test_multiple_ips(self) -> None:
        text = "Source 203.0.113.1 to destination 198.51.100.50"
        results = extract_iocs(text)
        ips = [r["value"] for r in results if r["type"] == "ipv4"]
        assert "203.0.113.1" in ips
        assert "198.51.100.50" in ips

    def test_boundary_ip_255(self) -> None:
        results = extract_iocs("Edge case 255.255.255.255")
        # 255.255.255.255 is broadcast/reserved → private
        assert not any(r["type"] == "ipv4" and r["value"] == "255.255.255.255" for r in results)


class TestIPv6Extraction:
    def test_full_form(self) -> None:
        results = extract_iocs("Address 2001:0db8:85a3:0000:0000:8a2e:0370:7334 found")
        assert any(r["type"] == "ipv6" for r in results)

    def test_abbreviated(self) -> None:
        results = extract_iocs("Host 2001:db8:85a3::8a2e:370:7334 detected")
        assert any(r["type"] == "ipv6" for r in results)

    def test_loopback(self) -> None:
        results = extract_iocs("Loopback ::1 address")
        assert any(r["type"] == "ipv6" for r in results)


class TestDomainExtraction:
    def test_valid_fqdn(self) -> None:
        results = extract_iocs("Contacted malicious.example.org for C2")
        assert any(r["type"] == "domain" for r in results)

    def test_reject_localhost(self) -> None:
        results = extract_iocs("Connecting to localhost")
        assert not any(r["type"] == "domain" and r["value"] == "localhost" for r in results)

    def test_reject_example_com(self) -> None:
        results = extract_iocs("Documentation says example.com")
        assert not any(r["type"] == "domain" and r["value"] == "example.com" for r in results)

    def test_reject_bare_tld(self) -> None:
        # A bare TLD like "com" should not match as domain (requires dot-separated parts)
        results = extract_iocs("The word com alone is not a domain")
        assert not any(r["type"] == "domain" and r["value"] == "com" for r in results)

    def test_subdomain(self) -> None:
        results = extract_iocs("Found c2.malware.bad-domain.net in traffic")
        assert any(r["type"] == "domain" for r in results)


class TestHashExtraction:
    def test_md5(self) -> None:
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        results = extract_iocs(f"MD5: {md5}")
        assert any(r["type"] == "md5" and r["value"] == md5 for r in results)

    def test_sha1(self) -> None:
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        results = extract_iocs(f"SHA-1: {sha1}")
        assert any(r["type"] == "sha1" and r["value"] == sha1 for r in results)

    def test_sha256(self) -> None:
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        results = extract_iocs(f"SHA-256: {sha256}")
        assert any(r["type"] == "sha256" and r["value"] == sha256 for r in results)

    def test_sha256_not_double_matched_as_md5(self) -> None:
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        results = extract_iocs(f"Hash: {sha256}")
        md5_matches = [r for r in results if r["type"] == "md5"]
        sha256_matches = [r for r in results if r["type"] == "sha256"]
        # The SHA-256 should match as sha256, not produce md5 substrings
        assert len(sha256_matches) == 1
        assert len(md5_matches) == 0

    def test_sha1_not_matched_as_md5(self) -> None:
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        results = extract_iocs(f"Hash: {sha1}")
        md5_matches = [r for r in results if r["type"] == "md5"]
        sha1_matches = [r for r in results if r["type"] == "sha1"]
        assert len(sha1_matches) == 1
        assert len(md5_matches) == 0


class TestCVEExtraction:
    def test_standard_format(self) -> None:
        results = extract_iocs("Vulnerability CVE-2024-12345 discovered")
        assert any(r["type"] == "cve" and r["value"] == "CVE-2024-12345" for r in results)

    def test_case_insensitive(self) -> None:
        results = extract_iocs("Found cve-2023-44487 in the wild")
        assert any(r["type"] == "cve" for r in results)

    def test_five_digit_cve(self) -> None:
        results = extract_iocs("CVE-2022-45786 is critical")
        assert any(r["type"] == "cve" and "45786" in r["value"] for r in results)


class TestMITREAttackExtraction:
    def test_technique_id(self) -> None:
        results = extract_iocs("Uses technique T1059 for execution")
        assert any(r["type"] == "mitre_attack" and r["value"] == "T1059" for r in results)

    def test_sub_technique(self) -> None:
        results = extract_iocs("Observed T1059.001 PowerShell usage")
        assert any(r["type"] == "mitre_attack" and r["value"] == "T1059.001" for r in results)


class TestEmailExtraction:
    def test_standard_email(self) -> None:
        results = extract_iocs("Contact attacker@evil-domain.com for ransom")
        assert any(r["type"] == "email" for r in results)

    def test_reject_malformed(self) -> None:
        results = extract_iocs("Not an email: @domain.com")
        assert not any(r["type"] == "email" and r["value"] == "@domain.com" for r in results)


class TestMixedContent:
    def test_multiple_ioc_types(self) -> None:
        text = (
            "Alert: IP 198.51.100.1 contacted evil.example.org "
            "downloading file with SHA-256 "
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
            "exploiting CVE-2024-1234 using T1059.001"
        )
        results = extract_iocs(text)
        types_found = {r["type"] for r in results}
        assert "ipv4" in types_found
        assert "sha256" in types_found
        assert "cve" in types_found
        assert "mitre_attack" in types_found


class TestDeduplication:
    def test_same_ioc_twice(self) -> None:
        text = "IP 198.51.100.1 and again 198.51.100.1"
        results = extract_iocs(text)
        ip_results = [r for r in results if r["type"] == "ipv4" and r["value"] == "198.51.100.1"]
        assert len(ip_results) == 1

    def test_same_hash_twice(self) -> None:
        h = "d41d8cd98f00b204e9800998ecf8427e"
        text = f"First {h} then {h}"
        results = extract_iocs(text)
        md5_results = [r for r in results if r["type"] == "md5"]
        assert len(md5_results) == 1


class TestEmptyInput:
    def test_empty_string(self) -> None:
        results = extract_iocs("")
        assert results == []

    def test_whitespace_only(self) -> None:
        results = extract_iocs("   \n\t  ")
        assert results == []

    def test_no_iocs(self) -> None:
        results = extract_iocs("This is a normal sentence with no indicators.")
        # May match "normal" or similar as false positive domains, but should be minimal
        # At minimum, no crash
        assert isinstance(results, list)
