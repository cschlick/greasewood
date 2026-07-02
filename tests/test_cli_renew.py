"""
Unit test for `gw renew` — force an immediate credential renewal.

The hub round-trip (renewal._do_renew) and the hub push (sync.push_record) are
stubbed; the test checks the *local* effects: the record is re-published with a
bumped seq and the fresh credential, and caps the hub changed (a set-caps /
set-segments) are adopted into the local config so the daemon's side of the
peering policy stays in sync.
"""
import datetime as dt
import os
import types

from greasewood import cli
from greasewood.config import load_config
from greasewood.directory import Directory
from greasewood.keys import CAKeys, NodeKeys, derive_addr
from greasewood.wire import Credential, NodeRecord

_UTC = dt.timezone.utc


def _cred(ca, node, caps, *, hours=24):
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    return Credential(
        id_pub=node.id_pub_bytes, wg_pub=node.wg_pub_bytes,
        addr=derive_addr(node.id_pub_bytes), hostname="n1", caps=list(caps),
        iat=now, exp=now + dt.timedelta(hours=hours),
    ).sign(ca.ca_priv)


def test_renew_bumps_record_and_adopts_caps(tmp_path, monkeypatch, capsys):
    ca = CAKeys.generate()
    me = NodeKeys.load_or_generate(tmp_path)
    (tmp_path / "gw.toml").write_text(f"""[node]
hostname = "n1"
data_dir = "{tmp_path}"
role = "node"
inbound = "yes"
caps = ["segment:mesh"]
[network]
interface = "gw-mesh"
seeds = []
root_url = "http://[fd8d:e5c1:db1a:7::1]:51902"
[ca]
trusted_pubs = ["{ca.ca_pub_hex}"]
""")
    cfg = load_config(tmp_path / "gw.toml")

    # An existing published record (seq 3) carrying the OLD caps.
    d = Directory()
    d.put(NodeRecord(
        id_pub=me.id_pub_bytes, seq=3, endpoints=["203.0.113.5:51900"],
        inbound="yes", cred=_cred(ca, me, ["segment:mesh"]),
    ).sign(me.id_priv))
    d.save(cfg.dir_cache_path)

    # The hub now issues a credential with an ADDED segment (a set-segments).
    new_cred = _cred(ca, me, ["segment:mesh", "segment:prod"])
    published = {}
    monkeypatch.setattr(os, "geteuid", lambda: 0)                    # pretend root
    monkeypatch.setattr("greasewood.renewal._do_renew",
                        lambda url, keys, **kw: new_cred)
    monkeypatch.setattr("greasewood.sync.push_record",
                        lambda url, rec, **kw: published.setdefault("rec", rec))

    rc = cli.cmd_renew(types.SimpleNamespace(config=str(tmp_path / "gw.toml")))
    assert rc == 0

    out = capsys.readouterr().out
    assert "renewed" in out and "caps updated by the hub" in out

    # config adopted the new segment
    assert "segment:prod" in (tmp_path / "gw.toml").read_text()

    # record re-published with bumped seq + fresh cred + preserved endpoints
    rec = Directory.load(cfg.dir_cache_path).get(me.id_pub_hex)
    assert rec.seq == 4
    assert "segment:prod" in rec.cred.caps
    assert rec.endpoints == ["203.0.113.5:51900"]
    assert published["rec"].seq == 4                                  # pushed to hub


def test_renew_without_config_exits(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    import pytest
    with pytest.raises(SystemExit):
        cli.cmd_renew(types.SimpleNamespace(config=str(tmp_path / "nope.toml")))
