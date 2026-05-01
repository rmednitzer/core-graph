"""Static safety scan for migration 023_memory_layer.sql."""

from __future__ import annotations

from pathlib import Path

MIGRATION_PATH = (
    Path(__file__).resolve().parent.parent
    / "schema"
    / "migrations"
    / "023_memory_layer.sql"
)


def _read() -> str:
    return MIGRATION_PATH.read_text()


def test_migration_present() -> None:
    assert MIGRATION_PATH.is_file()


def test_creates_layer_5_labels() -> None:
    text = _read()
    for vlabel in ("Session", "Episode", "ExtractedFact", "ConceptEntity"):
        assert vlabel in text
    for elabel in ("belongs_to", "extracted_from", "mentions", "supersedes"):
        assert elabel in text


def test_session_counter_table_with_pk() -> None:
    text = _read().lower()
    assert "create table if not exists memory_session_counters" in text
    assert "session_id        text primary key" in text


def test_extracted_fact_index_partial_active() -> None:
    text = _read().lower()
    assert "memory_extracted_fact_index" in text
    assert "where t_superseded is null" in text


def test_supersession_trigger_present() -> None:
    text = _read().lower()
    assert "memory_mark_supersession" in text
    assert "trg_memory_supersession" in text


def test_salience_recompute_function_signature() -> None:
    text = _read().lower()
    assert "memory_recompute_salience" in text
    # Parameters should match the api.config constants.
    for arg in (
        "p_recency_weight",
        "p_access_weight",
        "p_relevance_weight",
        "p_decay",
    ):
        assert arg in text


def test_cron_job_scheduled() -> None:
    text = _read().lower()
    assert "cron.schedule" in text
    assert "memory-salience-recompute" in text


def test_atomic_sequence_function() -> None:
    text = _read().lower()
    assert "memory_next_sequence" in text
    assert "on conflict (session_id) do update" in text
