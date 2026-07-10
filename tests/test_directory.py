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


# ---------------------------------------------------------------------------
# The fleet drop deadline (DROP_GRACE): records past exp + grace are shed from
# the directory with no delete-propagation protocol — merge() refuses stale
# incoming, prune_stale() evicts resident ones.
# ---------------------------------------------------------------------------

def _rec_exp(ca, name, exp, seq=1):
    """A signed NodeRecord whose credential expires at `exp` (may be past)."""
    import datetime as dt
    from greasewood.keys import NodeKeys, derive_addr
    from greasewood.wire import Credential, NodeRecord
    k = NodeKeys.generate()
    iat = exp - dt.timedelta(hours=24)
    cred = Credential(id_pub=k.id_pub_bytes, wg_pub=k.wg_pub_bytes,
                      addr=derive_addr(k.id_pub_bytes), hostname=name,
                      caps=["role:mesh"], iat=iat, exp=exp).sign(ca.ca_priv)
    return NodeRecord(id_pub=k.id_pub_bytes, seq=seq, endpoints=[],
                      cred=cred).sign(k.id_priv)


def test_prune_stale_drops_past_grace_keeps_recent_expiry():
    """A record expired longer than DROP_GRACE is pruned; one that expired only
    recently (still within the grace window) is kept — expiry ≠ drop."""
    import datetime as dt
    from greasewood.directory import Directory, DROP_GRACE
    from greasewood.keys import CAKeys
    ca = CAKeys.generate()
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)

    live = _rec_exp(ca, "live", now + dt.timedelta(hours=12))
    recent = _rec_exp(ca, "recent", now - dt.timedelta(days=1))          # expired, in grace
    dead = _rec_exp(ca, "dead", now - (DROP_GRACE + dt.timedelta(days=1)))  # past grace

    d = Directory()
    d.merge([live, recent, dead])
    # merge() itself refuses the already-past-grace record on the way in.
    assert {r.cred.hostname for r in d.all()} == {"live", "recent"}

    # prune_stale evicts anything that ages past grace while resident. Advance
    # time to just past 'recent's deadline (exp -1d + 7d = now+6d) but before
    # 'live's (exp +12h + 7d = now+7d12h): only 'recent' should fall.
    future = now + DROP_GRACE + dt.timedelta(hours=1)       # now + 7d1h
    removed = d.prune_stale(now=future)
    assert removed == 1                                     # 'recent' now past grace
    assert {r.cred.hostname for r in d.all()} == {"live"}   # only the live node remains


def test_merge_refuses_reinjected_dead_record():
    """A peer that hasn't pruned yet can't resurrect a dropped node: merge()
    rejects a record already past the drop deadline, so the fleet converges."""
    import datetime as dt
    from greasewood.directory import Directory, DROP_GRACE
    from greasewood.keys import CAKeys
    ca = CAKeys.generate()
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    dead = _rec_exp(ca, "dead", now - (DROP_GRACE + dt.timedelta(hours=1)), seq=99)
    d = Directory()
    assert d.merge([dead]) == 0                             # not accepted
    assert d.all() == []


def test_prune_stale_protects_own_record():
    """A node never prunes its own record from its own view, even if somehow
    past grace (it re-publishes with a fresh exp, but the guard is belt-and-braces)."""
    import datetime as dt
    from greasewood.directory import Directory, DROP_GRACE
    from greasewood.keys import CAKeys
    ca = CAKeys.generate()
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    mine = _rec_exp(ca, "me", now - (DROP_GRACE + dt.timedelta(days=1)))
    d = Directory()
    d.put(mine)                                             # put bypasses merge's filter
    removed = d.prune_stale(protect=mine.id_pub.hex())
    assert removed == 0 and len(d.all()) == 1
