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


def _cred(node, ca, hostname, caps=("role:mesh",), ttl=3600):
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    return Credential(
        id_pub=node.id_pub_bytes, wg_pub=node.wg_pub_bytes,
        addr=derive_addr(node.id_pub_bytes), hostname=hostname, caps=list(caps),
        iat=now, exp=now + dt.timedelta(seconds=ttl),
    ).sign(ca.ca_priv)


def _record(node, cred):
    return NodeRecord(
        id_pub=node.id_pub_bytes, seq=1, endpoints=[], inbound="yes",
        cred=cred,
    ).sign(node.id_priv)


def _write_cfg(tmp_path, ca_hex):
    p = tmp_path / "gw.toml"
    p.write_text(f'''[node]
hostname = "self"
data_dir = "{tmp_path}"
role = "node"
caps = ["role:mesh"]
[network]
interface = "gw-mesh"
seeds = []
root_url = ""
[ca]
trusted_pubs = ["{ca_hex}"]
''')
    return p


def test_diagnose_credential_column_flags_bad_creds(tmp_path, capsys, monkeypatch):
    """The credential row surfaces the rejection reason for each named node:
    untrusted CA and expired (revoked covered separately)."""
    monkeypatch.setattr("greasewood.wg.get_peers", lambda iface: {})
    NodeKeys.load_or_generate(tmp_path)
    trusted = CAKeys.generate()
    evil = CAKeys.generate()
    cfg = _write_cfg(tmp_path, trusted.ca_pub_hex)

    directory = Directory()
    n1 = NodeKeys.generate()
    directory.put(_record(n1, _cred(n1, evil, "untrusted")))            # untrusted CA
    n2 = NodeKeys.generate()
    directory.put(_record(n2, _cred(n2, trusted, "expired", ttl=-10)))  # expired
    directory.save(tmp_path / "directory.json")

    args = types.SimpleNamespace(config=str(cfg), nodes=["untrusted", "expired"])
    assert cli.cmd_diagnose(args) == 0
    out = capsys.readouterr().out
    assert "untrusted CA" in out
    assert "EXPIRED" in out


def test_diagnose_revoked_and_missing(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("greasewood.wg.get_peers", lambda iface: {})
    NodeKeys.load_or_generate(tmp_path)
    trusted = CAKeys.generate()
    cfg = _write_cfg(tmp_path, trusted.ca_pub_hex)
    directory = Directory()
    n3 = NodeKeys.generate()
    directory.put(_record(n3, _cred(n3, trusted, "banned")))
    (tmp_path / "revoked.json").write_text(json.dumps({"revoked": [n3.id_pub_hex]}))
    directory.save(tmp_path / "directory.json")

    assert cli.cmd_diagnose(types.SimpleNamespace(config=str(cfg),
                                                  nodes=["banned"])) == 0
    assert "REVOKED" in capsys.readouterr().out
    # An unknown name exits with a clear error, not a crash.
    import pytest
    with pytest.raises(SystemExit) as e:
        cli.cmd_diagnose(types.SimpleNamespace(config=str(cfg), nodes=["ghost"]))
    assert "no node named 'ghost'" in str(e.value)


def test_diagnose_pairwise_no_grant(tmp_path, capsys, monkeypatch):
    """Under a grant table with no grant connecting the pair, the pairwise
    verdict says the POLICY blocks it (not a firewall/reachability problem)."""
    import json as _json
    monkeypatch.setattr("greasewood.wg.get_peers", lambda iface: {})
    NodeKeys.load_or_generate(tmp_path)
    trusted = CAKeys.generate()
    cfg = _write_cfg(tmp_path, trusted.ca_pub_hex)
    directory = Directory()
    a = NodeKeys.generate()
    directory.put(_record(a, _cred(a, trusted, "web", caps=("role:web",))))
    b = NodeKeys.generate()
    directory.put(_record(b, _cred(b, trusted, "db", caps=("role:db",))))
    directory.save(tmp_path / "directory.json")
    # a policy that grants web↔web only — nothing connects web and db
    (tmp_path / "policy.json").write_text(_json.dumps({
        "seq": 1, "ca_sig": "",
        "grants": [{"from": ["web"], "to": ["web"], "ports": ["*"]}]}))

    assert cli.cmd_diagnose(types.SimpleNamespace(config=str(cfg),
                                                  nodes=["web", "db"])) == 0
    out = capsys.readouterr().out
    assert "web ↔ db" in out
    assert "no grant connects their roles" in out


def test_diagnose_targeted_single_peer(tmp_path, capsys, monkeypatch):
    """`diagnose keep` compares self ↔ keep only — an unrelated peer isn't
    dragged in."""
    monkeypatch.setattr("greasewood.wg.get_peers", lambda iface: {})
    NodeKeys.load_or_generate(tmp_path)
    trusted = CAKeys.generate()
    cfg = _write_cfg(tmp_path, trusted.ca_pub_hex)

    directory = Directory()
    keep = NodeKeys.generate()
    directory.put(_record(keep, _cred(keep, trusted, "keep")))
    other = NodeKeys.generate()
    directory.put(_record(other, _cred(other, trusted, "other")))
    directory.save(tmp_path / "directory.json")

    assert cli.cmd_diagnose(types.SimpleNamespace(config=str(cfg),
                                                  nodes=["keep"])) == 0
    out = capsys.readouterr().out
    assert "keep" in out
    assert "other" not in out
