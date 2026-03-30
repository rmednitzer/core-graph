# Adapter Migration Guide

## AdapterBase

All new adapters must extend `ingest.connectors.base.AdapterBase`. Existing
adapters will be migrated incrementally. The Netbox adapter is the reference
implementation.

## Migration Steps

1. **Create an `AdapterConfig`** with name, NATS subject/stream, poll interval,
   default TLP, and delta_sync flag.

2. **Extend `AdapterBase`** and implement:
   - `fetch(since: str | None) -> list[dict]` — fetch raw data from the source
   - `map(raw: dict) -> dict | None` — transform one source record to a graph entity

3. **Override `run()`** only if needed (e.g., side-publishing extra entities,
   custom HTTP client lifecycle).

4. **Keep a backward-compatible `run()` function** at module level for existing
   callers.

## Metrics

All adapters using `AdapterBase` automatically emit:

- `cg_adapter_fetch_total{adapter, status}` — fetch success/error counts
- `cg_adapter_entities_total{adapter, label}` — published entity counts

## Migrated Adapters

- [x] Netbox (`ingest/connectors/netbox/adapter.py`)
- [x] Keycloak (`ingest/connectors/keycloak/adapter.py`)
- [ ] Prometheus
- [ ] Wazuh
- [ ] MISP
- [ ] OpenCTI
- [ ] OSINT
