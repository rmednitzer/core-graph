"""Tests for ingest.connectors.netbox.adapter — Netbox entity mapping."""

from __future__ import annotations

from ingest.connectors.netbox.adapter import (
    _extract_ip,
    _map_device,
    _map_interface,
    _map_prefix,
    _map_service,
    _map_site,
    _map_vm,
)


class TestExtractIP:
    def test_cidr_notation(self) -> None:
        assert _extract_ip({"address": "10.0.0.5/24"}) == "10.0.0.5"

    def test_bare_ip(self) -> None:
        assert _extract_ip({"address": "192.168.1.1"}) == "192.168.1.1"

    def test_none_input(self) -> None:
        assert _extract_ip(None) == ""

    def test_empty_address(self) -> None:
        assert _extract_ip({"address": ""}) == ""


class TestMapDevice:
    def test_basic_device(self) -> None:
        obj = {
            "id": 42,
            "name": "axiom",
            "platform": {"slug": "ubuntu-24.04"},
            "status": {"value": "active"},
            "site": {"slug": "homelab"},
            "primary_ip": {"address": "10.0.0.5/24"},
        }
        entity = _map_device(obj)
        assert entity["label"] == "Host"
        props = entity["properties"]
        assert props["name"] == "axiom"
        assert props["host_type"] == "device"
        assert props["platform"] == "ubuntu-24.04"
        assert props["status"] == "active"
        assert props["site"] == "homelab"
        assert props["primary_ip"] == "10.0.0.5"
        assert props["netbox_id"] == 42
        assert props["canonical_key"]  # non-empty hash

    def test_device_missing_optional_fields(self) -> None:
        obj = {
            "id": 1,
            "name": "minimal",
            "platform": None,
            "status": None,
            "site": None,
            "primary_ip": None,
        }
        entity = _map_device(obj)
        props = entity["properties"]
        assert props["platform"] == ""
        assert props["status"] == "active"
        assert props["site"] == ""
        assert props["primary_ip"] == ""


class TestMapVM:
    def test_basic_vm(self) -> None:
        obj = {
            "id": 10,
            "name": "test-vm",
            "platform": {"slug": "debian-12"},
            "status": {"value": "staged"},
            "site": {"slug": "dc-1"},
            "primary_ip": None,
        }
        entity = _map_vm(obj)
        assert entity["label"] == "Host"
        props = entity["properties"]
        assert props["host_type"] == "vm"
        assert props["name"] == "test-vm"
        assert props["status"] == "staged"

    def test_vm_canonical_key_differs_from_device(self) -> None:
        stub = {
            "id": 1,
            "name": "a",
            "platform": None,
            "status": None,
            "site": None,
            "primary_ip": None,
        }
        device = _map_device(stub)
        vm = _map_vm(stub)
        assert device["properties"]["canonical_key"] != vm["properties"]["canonical_key"]


class TestMapPrefix:
    def test_basic_prefix(self) -> None:
        obj = {
            "prefix": "10.0.0.0/24",
            "vlan": {"vid": 100},
            "site": {"slug": "homelab"},
            "description": "Management network",
        }
        entity = _map_prefix(obj)
        assert entity["label"] == "Network"
        props = entity["properties"]
        assert props["prefix"] == "10.0.0.0/24"
        assert props["vlan_id"] == 100
        assert props["description"] == "Management network"

    def test_prefix_no_vlan(self) -> None:
        obj = {"prefix": "192.168.0.0/16", "vlan": None, "site": None, "description": ""}
        entity = _map_prefix(obj)
        assert entity["properties"]["vlan_id"] is None


class TestMapSite:
    def test_basic_site(self) -> None:
        obj = {"name": "Homelab", "slug": "homelab", "region": {"slug": "eu-west"}}
        entity = _map_site(obj)
        assert entity["label"] == "Site"
        assert entity["properties"]["name"] == "Homelab"
        assert entity["properties"]["region"] == "eu-west"

    def test_site_no_region(self) -> None:
        obj = {"name": "Office", "slug": "office", "region": None}
        entity = _map_site(obj)
        assert entity["properties"]["region"] == ""


class TestMapInterface:
    def test_basic_interface(self) -> None:
        obj = {"id": 55, "name": "eth0", "mac_address": "AA:BB:CC:DD:EE:FF", "enabled": True}
        entity = _map_interface(obj)
        assert entity["label"] == "Interface"
        assert entity["properties"]["name"] == "eth0"
        assert entity["properties"]["mac_address"] == "AA:BB:CC:DD:EE:FF"

    def test_interface_no_mac(self) -> None:
        obj = {"id": 56, "name": "lo", "mac_address": None, "enabled": True}
        entity = _map_interface(obj)
        assert entity["properties"]["mac_address"] == ""


class TestMapService:
    def test_basic_service(self) -> None:
        obj = {
            "id": 7,
            "name": "ssh",
            "protocol": {"value": "tcp"},
            "ports": [22],
        }
        entity = _map_service(obj)
        assert entity["label"] == "Service"
        assert entity["properties"]["name"] == "ssh"
        assert entity["properties"]["protocol"] == "tcp"
        assert entity["properties"]["ports"] == [22]
