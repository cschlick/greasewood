"""
Unit tests for Directory cache-load resilience: a missing or corrupt cache file
must start empty rather than crash the daemon (the happy load/merge path is
covered by the integration suite).
"""
from greasewood.directory import Directory


def test_load_missing_file_returns_empty(tmp_path):
    d = Directory.load(tmp_path / "nope.json")
    assert d.all() == []


def test_load_corrupt_json_returns_empty(tmp_path):
    p = tmp_path / "dir.json"
    p.write_text("{ this is not valid json ]]]")
    d = Directory.load(p)  # must not raise
    assert d.all() == []


def test_load_valid_json_but_not_records_returns_empty(tmp_path):
    p = tmp_path / "dir.json"
    p.write_text('[{"garbage": true}]')  # parseable JSON, not NodeRecords
    d = Directory.load(p)
    assert d.all() == []
