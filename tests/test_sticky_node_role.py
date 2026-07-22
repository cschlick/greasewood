"""
role:node is sticky. It's the default membership role and fleet grants (the
shipped admin -> node SSH) target it, so no assignment path may drop it
SILENTLY: `set-roles` keeps it unless --exact, `invite --roles` adds it unless
--exact, and the watch role editor warns on the review screen. The field bug
this pins down: `set-roles gp2 admin,nfs_usr` sealed gp2 out of admin SSH with
no signal, surfacing later as a firewall mystery.
"""
import types

import pytest

from greasewood import cli
from greasewood.ca import CA
from greasewood.keys import CAKeys, NodeKeys


def _anchor_cfg(tmp_path):
    """A minimal on-disk anchor with a real CA key (same shape as
    test_reserved_roles')."""
    CAKeys.generate().save(tmp_path / "ca.key")
    cfg = tmp_path / "gw.toml"
    cfg.write_text(
        f'[node]\nhostname = "a"\ndata_dir = "{tmp_path}"\nrole = "anchor"\n'
        f'caps = ["role:*", "role:anchor", "role:admin"]\n'
        f'[network]\nmesh_domain = "pm.internal"\n'
        f'[ca]\ntrusted_pubs = []\n'
        f'[anchor]\ncontrol_listen = ":51902"\ndoor_port = 51901\n'
        f'ca_key_file = "{tmp_path}/ca.key"\n')
    return cfg


def _enroll(tmp_path, name, caps):
    ca = CA(CAKeys.load(tmp_path / "ca.key"), tmp_path)
    nk = NodeKeys.generate()
    ca.issue(nk.id_pub_bytes, nk.wg_pub_bytes, name, caps)
    return ca, nk


def _roles_of(ca, nk):
    _, caps = ca.node_info(nk.id_pub_bytes)
    return sorted(c[len("role:"):] for c in caps if c.startswith("role:"))


def _args(cfg, **kw):
    kw.setdefault("exact", False)
    return types.SimpleNamespace(config=str(cfg), now=False, **kw)


def test_set_roles_keeps_node_when_unlisted(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_require_root", lambda *a, **k: None)
    cfg = _anchor_cfg(tmp_path)
    ca, nk = _enroll(tmp_path, "gp2", ["role:node"])
    cli.cmd_set_roles(_args(cfg, node="gp2", roles="admin,nfs_usr"))
    assert _roles_of(ca, nk) == ["admin", "nfs_usr", "node"]
    assert "kept role:node" in capsys.readouterr().out


def test_set_roles_exact_drops_node_with_warning(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_require_root", lambda *a, **k: None)
    cfg = _anchor_cfg(tmp_path)
    ca, nk = _enroll(tmp_path, "gp2", ["role:node"])
    cli.cmd_set_roles(_args(cfg, node="gp2", roles="admin,nfs_usr", exact=True))
    assert _roles_of(ca, nk) == ["admin", "nfs_usr"]
    assert "leaves role:node" in capsys.readouterr().out


def test_set_roles_does_not_resurrect_node(tmp_path, monkeypatch):
    """Sticky means PRESERVED, not forced: a host already sealed (no node)
    stays sealed unless node is listed explicitly."""
    monkeypatch.setattr(cli, "_require_root", lambda *a, **k: None)
    cfg = _anchor_cfg(tmp_path)
    ca, nk = _enroll(tmp_path, "nas", ["role:nfs_srv"])
    cli.cmd_set_roles(_args(cfg, node="nas", roles="nfs_srv,backup"))
    assert _roles_of(ca, nk) == ["backup", "nfs_srv"]


def test_set_roles_keeps_non_role_caps(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "_require_root", lambda *a, **k: None)
    cfg = _anchor_cfg(tmp_path)
    ca, nk = _enroll(tmp_path, "gp2", ["role:node", "tls"])
    cli.cmd_set_roles(_args(cfg, node="gp2", roles="admin"))
    _, caps = ca.node_info(nk.id_pub_bytes)
    assert "tls" in caps
    assert _roles_of(ca, nk) == ["admin", "node"]


def test_editor_review_warns_on_dropping_node():
    from greasewood.status import _role_editor_lines
    r = {"node": {"hostname": "gp2", "roles": ["node", "admin"]},
         "sel": {"admin"}, "vocab": ["admin", "node"], "cur": 0,
         "confirm": {"added": [], "removed": []}, "result": None}
    text = "\n".join(_role_editor_lines(r))
    assert "leaves role:node" in text


def test_editor_review_quiet_when_node_kept():
    from greasewood.status import _role_editor_lines
    r = {"node": {"hostname": "gp2", "roles": ["node"]},
         "sel": {"node", "admin"}, "vocab": ["admin", "node"], "cur": 0,
         "confirm": {"added": [], "removed": []}, "result": None}
    text = "\n".join(_role_editor_lines(r))
    assert "leaves role:node" not in text
