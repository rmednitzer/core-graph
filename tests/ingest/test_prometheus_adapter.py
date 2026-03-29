"""Tests for ingest.connectors.prometheus.adapter — AlertManager payload parsing."""

from __future__ import annotations

from ingest.connectors.prometheus.adapter import _extract_instance_ip, _map_alert


class TestExtractInstanceIP:
    def test_ip_with_port(self) -> None:
        assert _extract_instance_ip("10.0.0.5:9100") == "10.0.0.5"

    def test_ip_without_port(self) -> None:
        assert _extract_instance_ip("10.0.0.5") == "10.0.0.5"

    def test_hostname(self) -> None:
        assert _extract_instance_ip("myhost:9100") is None

    def test_empty_string(self) -> None:
        assert _extract_instance_ip("") is None

    def test_ipv4_full(self) -> None:
        assert _extract_instance_ip("192.168.1.100:3000") == "192.168.1.100"


class TestMapAlert:
    def test_firing_alert(self) -> None:
        alert = {
            "status": "firing",
            "labels": {
                "alertname": "HighCPUUsage",
                "instance": "10.0.0.5:9100",
                "severity": "critical",
            },
            "fingerprint": "abc123",
            "startsAt": "2026-03-29T12:00:00Z",
            "endsAt": "0001-01-01T00:00:00Z",
        }
        entity = _map_alert(alert)
        assert entity["label"] == "MonitoringAlert"
        props = entity["properties"]
        assert props["fingerprint"] == "abc123"
        assert props["alertname"] == "HighCPUUsage"
        assert props["severity"] == "critical"
        assert props["status"] == "firing"
        assert props["instance"] == "10.0.0.5:9100"
        assert props["starts_at"] == "2026-03-29T12:00:00Z"
        # Sentinel endsAt should be normalized to absent.
        assert "ends_at" not in props

    def test_resolved_alert(self) -> None:
        alert = {
            "status": "resolved",
            "labels": {
                "alertname": "DiskFull",
                "instance": "10.0.0.6:9100",
                "severity": "warning",
            },
            "fingerprint": "def456",
            "startsAt": "2026-03-29T10:00:00Z",
            "endsAt": "2026-03-29T12:00:00Z",
        }
        entity = _map_alert(alert)
        props = entity["properties"]
        assert props["status"] == "resolved"
        assert props["ends_at"] == "2026-03-29T12:00:00Z"

    def test_alert_missing_optional_labels(self) -> None:
        alert = {
            "status": "firing",
            "labels": {"alertname": "TestAlert"},
            "fingerprint": "ghi789",
            "startsAt": "2026-03-29T12:00:00Z",
            "endsAt": None,
        }
        entity = _map_alert(alert)
        props = entity["properties"]
        assert props["severity"] == "warning"  # default
        assert props["instance"] == ""
        # None endsAt should be normalized to absent.
        assert "ends_at" not in props

    def test_alert_tlp_is_green(self) -> None:
        alert = {
            "status": "firing",
            "labels": {"alertname": "Test"},
            "fingerprint": "x",
            "startsAt": "2026-03-29T12:00:00Z",
            "endsAt": None,
        }
        entity = _map_alert(alert)
        assert entity["properties"]["tlp"] == 1  # TLP:GREEN

    def test_sentinel_ends_at_normalized(self) -> None:
        """AlertManager sentinel 0001-01-01T00:00:00Z should become absent."""
        alert = {
            "status": "firing",
            "labels": {"alertname": "Test"},
            "fingerprint": "sentinel",
            "startsAt": "2026-03-29T12:00:00Z",
            "endsAt": "0001-01-01T00:00:00Z",
        }
        entity = _map_alert(alert)
        assert "ends_at" not in entity["properties"]
