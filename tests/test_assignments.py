"""
Declarative role assignments — the [assign] table in grants.toml.

The invariants under test:
  * [assign] is optional: absent → None (imperative mode, today's behavior)
  * validation is strict: DNS-safe hosts, no reserved roles, no ':' names
  * rewrite_assignment is surgical — comments and everything else survive
  * apply_assignments reconciles the registry (role: caps swapped, others
    kept), idempotently; unknown hosts are reported, never invented
  * `gw policy apply` previews role diffs + folds them into the tunnel
    delta, reconciles after confirm, and sends ONE fleet renew hint
  * a listed host refuses imperative `gw set-roles` (no silent drift)
  * the watch role editor writes the FILE when [assign] exists
"""
import datetime as dt
import json
import types

import pytest

from greasewood import cli, policy
from greasewood.ca import CA
from greasewood.directory import Directory
from greasewood.keys import CAKeys, NodeKeys, derive_addr
from greasewood.wire import Credential, NodeRecord

_UTC = dt.timezone.utc


# --- parsing / validation ---------------------------------------------------

def test_parse_assignments_absent_is_none_present_is_sorted():
    assert policy.parse_assignments('[[grant]]\nfrom=["a"]\nto=["b"]\n') is None
    got = policy.parse_assignments('[assign]\nnas = ["web", "db", "web"]\n')
    assert got == {"nas": ["db", "web"]}                # deduped + sorted


@pytest.mark.parametrize("body,msg", [
    ('[assign]\n"Bad_Host!" = ["web"]', "DNS-safe"),
    ('[assign]\nnas = ["*"]', "reserved"),
    ('[assign]\nnas = ["anchor"]', "reserved"),
    ('[assign]\nnas = ["host:bb"]', "can't contain"),
    ('[assign]\nnas = "web"', "list of"),
])
def test_parse_assignments_rejects_malformed(body, msg):
    with pytest.raises(ValueError, match=msg):
        policy.parse_assignments(body)


def test_grants_parser_tolerates_assign_table():
    text = '[[grant]]\nfrom=["a"]\nto=["b"]\n[assign]\nnas=["web"]\n'
    assert policy.parse_grants_toml(text)[0]["from"] == ["a"]


# --- surgical file rewrite --------------------------------------------------

def test_rewrite_assignment_replaces_appends_and_creates():
    text = ('# why: the app tier\n[[grant]]\nfrom = ["web"]\nto = ["api"]\n'
            'ports = ["tcp/8000"]\n\n[assign]\n# fleet roles\nnas = ["db"]\n')
    out = policy.rewrite_assignment(text, "nas", ["nfs_srv"])
    assert 'nas = ["nfs_srv"]' in out and '["db"]' not in out
    assert "# why: the app tier" in out and "# fleet roles" in out  # comments live
    out2 = policy.rewrite_assignment(out, "bb", ["web"])
    assert 'bb = ["web"]' in out2 and 'nas = ["nfs_srv"]' in out2   # appended
    out3 = policy.rewrite_assignment('[[grant]]\nfrom=["a"]\nto=["b"]\n',
                                     "gp2", ["nfs_usr"])
    assert "[assign]" in out3 and 'gp2 = ["nfs_usr"]' in out3       # section made
    # every result stays parseable, and round-trips
    assert policy.parse_assignments(out2)["bb"] == ["web"]
    assert policy.parse_assignments(out3) == {"gp2": ["nfs_usr"]}


# --- registry reconciliation -------------------------------------------------

def _registry(tmp_path, *nodes):
    """A real CA registry with the given (hostname, roles) nodes enrolled."""
    keys = CAKeys.generate()
    ca = CA(keys, tmp_path)
    out = {}
    for host, roles in nodes:
        k = NodeKeys.generate()
        ca.issue(k.id_pub_bytes, k.wg_pub_bytes, host,
                 [f"role:{r}" for r in roles] + ["tls"])
        out[host] = k
    return keys, ca, out


def test_apply_assignments_reconciles_and_is_idempotent(tmp_path):
    _, ca, ks = _registry(tmp_path, ("nas", ["node"]), ("bb", ["web"]))
    changed, missing = policy.apply_assignments(
        {"nas": ["nfs_srv"], "bb": ["web"], "ghost": ["db"]}, ca)
    assert changed == [("nas", ["node"], ["nfs_srv"])]  # bb already matched
    assert missing == ["ghost"]
    _, caps = ca.node_info(ks["nas"].id_pub_bytes)
    assert "role:nfs_srv" in caps and "tls" in caps and "role:node" not in caps
    # second run: nothing to do
    changed2, _ = policy.apply_assignments({"nas": ["nfs_srv"]}, ca)
    assert changed2 == []


def test_tunnel_delta_caps_override_previews_role_changes():
    ca = CAKeys.generate()

    def rec(name, roles):
        k = NodeKeys.generate()
        now = dt.datetime.now(_UTC).replace(microsecond=0)
        cred = Credential(id_pub=k.id_pub_bytes, wg_pub=k.wg_pub_bytes,
                          addr=derive_addr(k.id_pub_bytes), hostname=name,
                          caps=[f"role:{r}" for r in roles], iat=now,
                          exp=now + dt.timedelta(hours=1)).sign(ca.ca_priv)
        return NodeRecord(id_pub=k.id_pub_bytes, seq=1, endpoints=[],
                          cred=cred).sign(k.id_priv)

    a, b = rec("a1", ["node"]), rec("api1", ["api"])
    grants = [{"from": ["web"], "to": ["api"], "ports": ["*"]}]
    assert policy.tunnel_delta([a, b], grants, grants) == ([], [])
    created, _ = policy.tunnel_delta(
        [a, b], grants, grants,
        caps_override={a.id_pub.hex(): ["role:web"]})
    assert created == [("a1", "api1")]                  # the role change shows


# --- the full anchor flow ----------------------------------------------------

def _anchor_env(tmp_path):
    """A working anchor dir: config, CA key, registry, directory, grants.toml."""
    keys = CAKeys.generate()
    kf = tmp_path / "ca.key"
    keys.save(kf)
    ca = CA(keys, tmp_path)
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    d = Directory()
    nodekeys = {}
    for host, roles in (("nas", ["node"]), ("gp2", ["nfs_usr"])):
        k = NodeKeys.generate()
        cred = ca.issue(k.id_pub_bytes, k.wg_pub_bytes, host,
                        [f"role:{r}" for r in roles] + ["tls"])
        d.put(NodeRecord(id_pub=k.id_pub_bytes, seq=1, endpoints=[],
                         cred=cred).sign(k.id_priv))
        nodekeys[host] = k
    cfg_path = tmp_path / "gw.toml"
    cfg_path.write_text(
        f'[node]\nhostname = "anchor"\ndata_dir = "{tmp_path}"\nrole = "anchor"\n'
        f'[network]\nmesh_domain = "pm.internal"\n[ca]\ntrusted_pubs = []\n'
        f'[anchor]\ncontrol_listen = ":51902"\ndoor_port = 51901\n'
        f'ca_key_file = "{kf}"\n')
    from greasewood.config import load_config
    d.save(load_config(cfg_path).dir_cache_path)
    return cfg_path, keys, nodekeys


def test_policy_apply_reconciles_assignments(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    cfg_path, keys, ks = _anchor_env(tmp_path)
    text = ('[[grant]]\nfrom = ["nfs_usr"]\nto = ["nfs_srv"]\nports = ["tcp/2049"]\n'
            '[assign]\nnas = ["nfs_srv"]\nghost = ["db"]\n')
    (tmp_path / "grants.toml").write_text(text)
    # seed the SAME grants as the applied v1 policy, so the preview's "before"
    # is the grant table (not the flat mesh) and the delta isolates the re-role
    from greasewood.wire import GrantTable
    v1 = GrantTable(seq=1, grants=policy.parse_grants_toml(text)).sign(keys.ca_priv)
    (tmp_path / "policy.json").write_text(json.dumps(v1.to_dict()))
    rc = cli.cmd_policy(types.SimpleNamespace(action="apply",
                                              config=str(cfg_path),
                                              file=None, yes=True))
    assert rc == 0
    out = capsys.readouterr().out
    assert "~ roles  nas: node → nfs_srv" in out        # previewed
    assert "no current member" in out                   # ghost warned
    tun = next(l for l in out.splitlines() if "+ tunnel" in l)
    assert "gp2" in tun and "nas" in tun                # delta includes the re-role
    assert "NO current node holds role:nfs_srv" not in out  # assigned ≠ typo
    _, caps = CA(keys, tmp_path).node_info(ks["nas"].id_pub_bytes)
    assert "role:nfs_srv" in caps and "tls" in caps     # reconciled
    assert (tmp_path / "renew_after").exists()          # one fleet renew hint


def test_set_roles_refused_for_declared_host(tmp_path, monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    cfg_path, _, _ = _anchor_env(tmp_path)
    (tmp_path / "grants.toml").write_text('[assign]\nnas = ["nfs_srv"]\n')
    with pytest.raises(SystemExit, match="DECLARED in"):
        cli.cmd_set_roles(types.SimpleNamespace(config=str(cfg_path),
                                                node="nas", roles="web",
                                                now=False))
    # an UNLISTED host still takes the imperative path
    rc = cli.cmd_set_roles(types.SimpleNamespace(config=str(cfg_path),
                                                 node="gp2", roles="web",
                                                 now=False))
    assert rc == 0


def test_watch_editor_writes_the_file_in_declarative_mode(tmp_path):
    from greasewood.status import _make_role_applier
    from greasewood.config import load_config
    cfg_path, keys, ks = _anchor_env(tmp_path)
    (tmp_path / "grants.toml").write_text('[assign]\ngp2 = ["nfs_usr"]\n')
    cfg = load_config(cfg_path)
    apply = _make_role_applier(cfg)
    msg = apply({"id": ks["nas"].id_pub_bytes.hex(), "hostname": "nas"},
                ["nfs_srv"])
    assert "grants.toml" in msg                          # declared, not bypassed
    assert policy.parse_assignments(
        (tmp_path / "grants.toml").read_text()) == \
        {"gp2": ["nfs_usr"], "nas": ["nfs_srv"]}
    _, caps = CA(keys, tmp_path).node_info(ks["nas"].id_pub_bytes)
    assert "role:nfs_srv" in caps                        # and reconciled
    assert (tmp_path / "renew_after").exists()


def test_watch_editor_stays_imperative_without_assign_section(tmp_path):
    from greasewood.status import _make_role_applier
    from greasewood.config import load_config
    cfg_path, keys, ks = _anchor_env(tmp_path)
    (tmp_path / "grants.toml").write_text('[[grant]]\nfrom=["a"]\nto=["b"]\n')
    apply = _make_role_applier(load_config(cfg_path))
    msg = apply({"id": ks["nas"].id_pub_bytes.hex(), "hostname": "nas"}, ["web"])
    assert msg.startswith("✓") and "grants.toml" not in msg
    assert policy.parse_assignments(
        (tmp_path / "grants.toml").read_text()) is None  # file untouched
    _, caps = CA(keys, tmp_path).node_info(ks["nas"].id_pub_bytes)
    assert "role:web" in caps
