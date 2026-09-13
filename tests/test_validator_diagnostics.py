"""Validation failures must not disclose file contents or report a clean scan."""

import builtins
from pathlib import Path

from scripts import validate


def test_secret_scan_omits_matched_value(tmp_path, monkeypatch, capsys):
    value = "A" * 24
    (tmp_path / "input.txt").write_text('api_key = "' + value + '"')
    monkeypatch.setattr(validate, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(validate, "EXIT_CODE", 0)
    validate.check_secrets()
    output = capsys.readouterr()
    assert validate.EXIT_CODE == 1
    assert value not in output.out + output.err
    assert "Potential secret" in output.err
    assert "No obvious secrets detected" not in output.out


def test_yaml_error_omits_source_excerpt(tmp_path, monkeypatch, capsys):
    policies = tmp_path / "policies"
    policies.mkdir()
    value = "sensitive-fixture-value"
    (policies / "invalid.yml").write_text("key: [" + value)
    monkeypatch.setattr(validate, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(validate, "EXIT_CODE", 0)
    validate.check_yaml_syntax()
    output = capsys.readouterr()
    assert validate.EXIT_CODE == 1
    assert value not in output.out + output.err
    assert "Invalid YAML" in output.err


def test_missing_yaml_dependency_fails(tmp_path, monkeypatch, capsys):
    policies = tmp_path / "policies"
    policies.mkdir()
    (policies / "valid.yml").write_text("key: value")
    monkeypatch.setattr(validate, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(validate, "EXIT_CODE", 0)
    original = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "yaml":
            raise ImportError("fixture")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    validate.check_yaml_syntax()
    assert validate.EXIT_CODE == 1
    assert "cannot run" in capsys.readouterr().err


def test_unreadable_file_fails_scan(tmp_path, monkeypatch, capsys):
    path = tmp_path / "unreadable.txt"
    path.write_text("fixture")
    monkeypatch.setattr(validate, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(validate, "EXIT_CODE", 0)
    original = Path.read_text

    def guarded_read(self, *args, **kwargs):
        if self == path:
            raise OSError("fixture")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read)
    validate.check_secrets()
    output = capsys.readouterr()
    assert validate.EXIT_CODE == 1
    assert "Cannot read" in output.err
    assert "No obvious secrets detected" not in output.out
