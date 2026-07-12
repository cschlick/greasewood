"""
Reserved roles: '*' (reach-all) and 'anchor' (single-member) are self-assigned
by the anchor at `gw create` and NEVER assignable to anyone else. Enforcing that
on every assignment path is what keeps `anchor` a single-member role — only the
create-time anchor ever holds it — and keeps a joiner from grabbing reach-all.
"""
import types

import pytest

from greasewood import cli, policy


def test_reserved_set():
    assert set(policy.RESERVED_ROLES) == {"*", "anchor"}


@pytest.mark.parametrize("bad", ["anchor", "*"])
def test_helper_rejects_reserved(bad):
    with pytest.raises(SystemExit, match="reserved for the anchor"):
        cli._reject_reserved_roles([bad], "--roles")


@pytest.mark.parametrize("ok", [["node"], ["web", "db"], ["admin"], []])
def test_helper_allows_ordinary_roles(ok):
    cli._reject_reserved_roles(ok, "--roles")        # must not raise


# --- the assignment CLI paths reject reserved roles ---

def _anchor_cfg(tmp_path):
    """A minimal on-disk anchor with a real CA key, enough for set-caps/roles."""
    from greasewood.keys import CAKeys
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


def test_set_roles_refuses_anchor(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "_require_root", lambda *a, **k: None)
    cfg = _anchor_cfg(tmp_path)
    # enroll a real node so _resolve_node finds it
    from greasewood.ca import CA
    from greasewood.keys import CAKeys, NodeKeys
    ca = CA(CAKeys.load(tmp_path / "ca.key"), tmp_path)
    nk = NodeKeys.generate()
    ca.issue(nk.id_pub_bytes, nk.wg_pub_bytes, "n1", ["role:node"])
    args = types.SimpleNamespace(config=str(cfg), node="n1", roles="anchor", now=False)
    with pytest.raises(SystemExit, match="reserved for the anchor"):
        cli.cmd_set_roles(args)


def test_set_caps_refuses_role_star(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "_require_root", lambda *a, **k: None)
    cfg = _anchor_cfg(tmp_path)
    from greasewood.ca import CA
    from greasewood.keys import CAKeys, NodeKeys
    ca = CA(CAKeys.load(tmp_path / "ca.key"), tmp_path)
    nk = NodeKeys.generate()
    ca.issue(nk.id_pub_bytes, nk.wg_pub_bytes, "n1", ["role:node"])
    args = types.SimpleNamespace(config=str(cfg), node="n1", caps="role:*,tls")
    with pytest.raises(SystemExit, match="reserved for the anchor"):
        cli.cmd_set_caps(args)


def test_anchor_bootstraps_admin_and_anchor_roles(tmp_path, monkeypatch):
    """`gw create` gives the anchor role:admin (so default-closed SSH works out
    of the box) and role:anchor (its single-member name), alongside role:*."""
    monkeypatch.setattr(cli, "_require_root", lambda *a, **k: None)
    data_dir = tmp_path / "var"
    cfg_path = tmp_path / "gw.toml"
    ns = types.SimpleNamespace(
        name="prod", config=str(cfg_path), data_dir=str(data_dir),
        hostname="anchor", endpoint=None, interface=None, listen_port=None,
        control_port=51902, door_port=51901, credential_ttl="24h",
        hosts_sync=True, no_service=True, caps="", mesh_domain=None,
        overlay_prefix="fd8d:e5c1:db1a:7::", force=False)
    assert cli.cmd_create(ns) == 0
    from greasewood.config import load_config
    caps = load_config(cfg_path).caps
    assert "role:*" in caps and "role:anchor" in caps and "role:admin" in caps
