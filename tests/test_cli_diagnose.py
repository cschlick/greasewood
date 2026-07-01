"""
Unit tests for `gw diagnose` per-peer classification — the tool's whole purpose
(explaining *why* a link fails). Builds a directory cache of crafted peer records
and asserts diagnose classifies each: untrusted CA, expired, revoked,
policy-denied. Live WireGuard state is stubbed empty.

Note: the step-3 (bad self-sig) and step-4 (forged addr) branches are NOT tested
here — they're unreachable for cache-sourced records, because directory.merge
runs verify_structural on ingest and drops any record failing those exact checks
(the same "shadowed by an earlier gate" situation as wire.verify_structural).
"""
import datetime as dt
import json
import types

from greasewood import cli
from greasewood.directory import Directory
from greasewood.keys import CAKeys, NodeKeys, derive_addr
from greasewood.wire import Credential, NodeRecord

_UTC = dt.timezone.utc


def _cred(node, ca, caps=("mesh",), ttl=3600):
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    return Credential(
        id_pub=node.id_pub_bytes, wg_pub=node.wg_pub_bytes,
        addr=derive_addr(node.id_pub_bytes), caps=list(caps),
        iat=now, exp=now + dt.timedelta(seconds=ttl),
    ).sign(ca.ca_priv)


def _record(node, cred, hostname):
    return NodeRecord(
        id_pub=node.id_pub_bytes, seq=1, endpoints=[], inbound="yes",
        hostname=hostname, cred=cred,
    ).sign(node.id_priv)


def _write_cfg(tmp_path, ca_hex):
    p = tmp_path / "gw.toml"
    p.write_text(f'''[node]
hostname = "self"
data_dir = "{tmp_path}"
role = "node"
caps = ["mesh"]
[network]
interface = "gw-mesh"
seeds = []
root_url = ""
[ca]
trusted_pubs = ["{ca_hex}"]
''')
    return p


def test_diagnose_classifies_rejections(tmp_path, capsys, monkeypatch):
    # No live WireGuard state (deterministic, no wg binary / interface needed).
    monkeypatch.setattr("greasewood.wg.get_peers", lambda iface: {})

    NodeKeys.load_or_generate(tmp_path)  # own identity → _own_identity works
    trusted = CAKeys.generate()
    evil = CAKeys.generate()
    cfg = _write_cfg(tmp_path, trusted.ca_pub_hex)

    directory = Directory()
    n1 = NodeKeys.generate()
    directory.put(_record(n1, _cred(n1, evil), "untrusted"))            # untrusted CA
    n2 = NodeKeys.generate()
    directory.put(_record(n2, _cred(n2, trusted, ttl=-10), "expired"))  # expired
    n3 = NodeKeys.generate()
    directory.put(_record(n3, _cred(n3, trusted), "revoked-node"))      # revoked
    (tmp_path / "revoked.json").write_text(
        json.dumps({"revoked": [n3.id_pub_hex]}))
    n4 = NodeKeys.generate()
    directory.put(_record(n4, _cred(n4, trusted, caps=("tls",)), "policy"))  # no mesh cap
    directory.save(tmp_path / "directory.json")

    args = types.SimpleNamespace(config=str(cfg), hostname=None)
    assert cli.cmd_diagnose(args) == 0

    out = capsys.readouterr().out
    assert "not from a trusted CA" in out
    assert "credential EXPIRED" in out
    assert "node is REVOKED" in out
    assert "policy denies" in out
    assert "rejected" in out and "policy-denied" in out  # summary line


def test_diagnose_targeted_single_peer(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("greasewood.wg.get_peers", lambda iface: {})
    NodeKeys.load_or_generate(tmp_path)
    trusted = CAKeys.generate()
    cfg = _write_cfg(tmp_path, trusted.ca_pub_hex)

    directory = Directory()
    keep = NodeKeys.generate()
    directory.put(_record(keep, _cred(keep, trusted, ttl=-10), "keep"))
    other = NodeKeys.generate()
    directory.put(_record(other, _cred(other, trusted, ttl=-10), "other"))
    directory.save(tmp_path / "directory.json")

    args = types.SimpleNamespace(config=str(cfg), hostname="keep")
    assert cli.cmd_diagnose(args) == 0
    out = capsys.readouterr().out
    assert "keep" in out
    assert "other" not in out.split("summary")[0]  # only the targeted peer shown
