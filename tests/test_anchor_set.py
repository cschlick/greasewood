"""
The ANCHOR SET: nodes discover every holder from the replicated directory and
fail over between them — sync, renewal, and leave all try each holder in
order, so one dead holder costs a timeout, never the operation.
"""
import datetime as dt
import types

from greasewood import cli
from greasewood.directory import Directory
from greasewood.keys import CAKeys, NodeKeys, derive_addr
from greasewood.renewal import RenewalLoop
from greasewood.wire import Credential, NodeRecord

_UTC = dt.timezone.utc


def _rec(ca, k, name, caps, ttl_h=24):
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    cred = Credential(id_pub=k.id_pub_bytes, wg_pub=k.wg_pub_bytes,
                      addr=derive_addr(k.id_pub_bytes), hostname=name,
                      caps=caps, iat=now,
                      exp=now + dt.timedelta(hours=ttl_h)).sign(ca.ca_priv)
    return NodeRecord(id_pub=k.id_pub_bytes, seq=1, endpoints=[],
                      cred=cred).sign(k.id_priv)


def _cfg(seeds=(), root=""):
    return types.SimpleNamespace(seeds=list(seeds), root_url=root,
                                 control_listen=":51902")


def test_anchor_urls_seeds_then_trusted_holders_self_excluded():
    ca = CAKeys.generate()
    h1, h2, me = NodeKeys.generate(), NodeKeys.generate(), NodeKeys.generate()
    d = Directory()
    d.put(_rec(ca, h1, "router", ["role:*", "role:admin"]))
    d.put(_rec(ca, h2, "panda", ["role:anchor", "role:node"]))
    d.put(_rec(ca, me, "gp2", ["role:anchor"]))          # me — a holder too
    d.put(_rec(ca, NodeKeys.generate(), "nas", ["role:node"]))   # not a holder

    urls = cli._anchor_urls(_cfg(seeds=["http://seed:51902"]), d,
                            own_addr=derive_addr(me.id_pub_bytes),
                            get_ca_pubs=lambda: [ca.ca_pub_bytes])
    assert urls[0] == "http://seed:51902"                # bootstrap first
    assert f"http://[{derive_addr(h1.id_pub_bytes)}]:51902" in urls
    assert f"http://[{derive_addr(h2.id_pub_bytes)}]:51902" in urls
    assert f"http://[{derive_addr(me.id_pub_bytes)}]:51902" not in urls
    assert len(urls) == 3


def test_anchor_urls_forged_holder_record_excluded():
    """A structurally-valid record whose cred no trusted CA signed must not
    steer control-plane traffic."""
    ca, evil = CAKeys.generate(), CAKeys.generate()
    fake = NodeKeys.generate()
    d = Directory()
    d.put(_rec(evil, fake, "root", ["role:*"]))
    urls = cli._anchor_urls(_cfg(root="http://real:51902"), d,
                            get_ca_pubs=lambda: [ca.ca_pub_bytes])
    assert urls == ["http://real:51902"]


def test_anchor_urls_expired_holder_still_listed():
    """Expiry is liveness, not death — an expired holder may well still serve
    (the expired-anchor incident's holder did); keep it dialable."""
    ca = CAKeys.generate()
    h = NodeKeys.generate()
    d = Directory()
    d.put(_rec(ca, h, "router", ["role:*"], ttl_h=-2))   # expired 2h ago
    urls = cli._anchor_urls(_cfg(), d, get_ca_pubs=lambda: [ca.ca_pub_bytes])
    assert urls == [f"http://[{derive_addr(h.id_pub_bytes)}]:51902"]


# ---------------------------------------------------------------------------
# renewal failover across the set
# ---------------------------------------------------------------------------

def _loop(tmp_path, urls, ca=None, get_ca_pubs=None):
    keys = NodeKeys.generate()
    ca = ca or CAKeys.generate()
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    cred = Credential(id_pub=keys.id_pub_bytes, wg_pub=keys.wg_pub_bytes,
                      addr=derive_addr(keys.id_pub_bytes), hostname="n1",
                      caps=[], iat=now,
                      exp=now + dt.timedelta(hours=24)).sign(ca.ca_priv)
    return keys, ca, RenewalLoop(keys, Directory(), lambda: urls, cred, "n1",
                                 [], tmp_path / "cache.json",
                                 get_ca_pubs=get_ca_pubs)


def test_renewal_fails_over_to_next_holder(tmp_path, monkeypatch):
    keys, ca, loop = _loop(tmp_path, ["http://dead:1", "http://live:1"])
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    fresh = Credential(id_pub=keys.id_pub_bytes, wg_pub=keys.wg_pub_bytes,
                       addr=derive_addr(keys.id_pub_bytes), hostname="n1",
                       caps=[], iat=now,
                       exp=now + dt.timedelta(hours=24)).sign(ca.ca_priv)
    tried, pushed = [], []

    def fake_renew(url, k, timeout=15.0):
        tried.append(url)
        if "dead" in url:
            raise RuntimeError("connection refused")
        return fresh

    from greasewood import renewal as rmod
    monkeypatch.setattr(rmod, "_do_renew", fake_renew)
    monkeypatch.setattr("greasewood.sync.push_record",
                        lambda url, rec, timeout=10.0: pushed.append(url))
    got = loop._renew_and_publish()
    assert got is fresh
    assert tried == ["http://dead:1", "http://live:1"]   # failover, in order
    assert pushed == ["http://live:1"]                   # pushed to the SERVER


def test_renewal_refuses_untrusted_credential(tmp_path, monkeypatch):
    """A holder handing back a credential no trusted CA signed must not be
    adopted — the fleet would reject the record it produces."""
    import pytest
    trusted = CAKeys.generate()
    rogue = CAKeys.generate()
    keys, _ca, loop = _loop(tmp_path, ["http://rogue:1"], ca=trusted,
                            get_ca_pubs=lambda: [trusted.ca_pub_bytes])
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    bad = Credential(id_pub=keys.id_pub_bytes, wg_pub=keys.wg_pub_bytes,
                     addr=derive_addr(keys.id_pub_bytes), hostname="n1",
                     caps=[], iat=now,
                     exp=now + dt.timedelta(hours=24)).sign(rogue.ca_priv)
    from greasewood import renewal as rmod
    monkeypatch.setattr(rmod, "_do_renew", lambda url, k, timeout=15.0: bad)
    with pytest.raises(ValueError):
        loop._renew_and_publish()


def test_single_url_string_still_works(tmp_path, monkeypatch):
    """Back-compat: a get_anchor_url returning one string behaves as before."""
    keys, ca, loop = _loop(tmp_path, "http://only:1")
    assert loop._anchor_urls() == ["http://only:1"]


# ---------------------------------------------------------------------------
# the fleet-renew hint gossips between holders (latest-wins)
# ---------------------------------------------------------------------------

def test_adopt_renew_after_latest_wins(tmp_path):
    cfg = types.SimpleNamespace(data_dir=tmp_path)
    t1 = dt.datetime(2026, 9, 21, 12, 0, tzinfo=_UTC)
    t2 = t1 + dt.timedelta(minutes=5)

    assert cli._adopt_renew_after(cfg, t1) is True       # nothing local → adopt
    assert (tmp_path / "renew_after").read_text().strip() == t1.isoformat()
    assert cli._adopt_renew_after(cfg, t1) is False      # equal → no-op
    assert cli._adopt_renew_after(cfg, t2) is True       # newer → advance
    assert (tmp_path / "renew_after").read_text().strip() == t2.isoformat()
    assert cli._adopt_renew_after(cfg, t1) is False      # older → keep t2
    assert (tmp_path / "renew_after").read_text().strip() == t2.isoformat()


def test_adopt_renew_after_replaces_own_older_hint(tmp_path):
    """A holder that ran its own `gw renew-all` last week still adopts a
    NEWER hint gossiped from another holder — the file is one latest-wins
    value, not per-holder state."""
    cfg = types.SimpleNamespace(data_dir=tmp_path)
    old = dt.datetime(2026, 9, 14, 8, 0, tzinfo=_UTC)
    (tmp_path / "renew_after").write_text(old.isoformat())
    newer = dt.datetime(2026, 9, 21, 9, 0, tzinfo=_UTC)
    assert cli._adopt_renew_after(cfg, newer) is True
    assert (tmp_path / "renew_after").read_text().strip() == newer.isoformat()
