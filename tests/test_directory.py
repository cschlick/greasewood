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


def test_one_corrupt_record_does_not_discard_the_cache(tmp_path):
    """A single malformed entry in directory.json must cost ONE peer, not the
    whole cache — the cache exists to keep running from last-known-good."""
    import json
    from greasewood.directory import Directory
    from greasewood.keys import CAKeys, NodeKeys, derive_addr
    from greasewood.wire import Credential, NodeRecord
    import datetime as dt
    ca = CAKeys.generate()
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)

    def good(name):
        k = NodeKeys.generate()
        cred = Credential(id_pub=k.id_pub_bytes, wg_pub=k.wg_pub_bytes,
                          addr=derive_addr(k.id_pub_bytes), hostname=name,
                          caps=["segment:mesh"], iat=now,
                          exp=now + dt.timedelta(hours=1)).sign(ca.ca_priv)
        return NodeRecord(id_pub=k.id_pub_bytes, seq=1, endpoints=[],
                          cred=cred).sign(k.id_priv).to_dict()

    raw = [good("db01"), {"garbage": True}, good("db02")]   # one corrupt in the middle
    (tmp_path / "directory.json").write_text(json.dumps(raw))
    d = Directory.load(tmp_path / "directory.json")
    names = {r.cred.hostname for r in d.all()}
    assert names == {"db01", "db02"}                        # both good ones survive
