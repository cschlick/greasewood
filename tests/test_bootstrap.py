"""
Underlay bootstrap: read-only server + `gw bootstrap` recovery command.

A node whose directory cache has lost the anchor record cannot build an overlay
tunnel to the anchor, so it cannot sync normally. The bootstrap port serves a
signed directory/revoked/policy snapshot on the underlay; the CLI fetches it,
verifies it, and replaces the local cache.
"""
import datetime as dt
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from greasewood.ca import CA
from greasewood.config import load_config, membership_key
from greasewood.directory import Directory
from greasewood.keys import CAKeys, NodeKeys
from greasewood.policy import POLICY_BASENAME
from greasewood.server import BootstrapServer
from greasewood.sync import pull_directory, pull_revoked
from greasewood import cli
from greasewood import wire as W

_UTC = dt.timezone.utc


def _overlay_prefix(addr: str) -> str:
    """/64 prefix for a generated overlay address."""
    return ":".join(addr.split(":")[:4]) + "::"


def _set_prefix_for(addr: str) -> None:
    from greasewood.keys import set_overlay_prefix, parse_overlay_prefix
    set_overlay_prefix(parse_overlay_prefix(_overlay_prefix(addr)))


def _bootstrap_url(srv) -> str:
    """The underlay URL to talk to a test BootstrapServer."""
    addr = srv._server.server_address
    return f"http://[{addr[0]}]:{addr[1]}"


def _anchor_setup(tmp_path):
    """Return (ca_keys, node_keys, record, directory) for a tiny anchor mesh."""
    from greasewood.keys import set_overlay_prefix, parse_overlay_prefix
    set_overlay_prefix(parse_overlay_prefix("fd8d:e5c1:db1a:7::"))
    ca_keys = CAKeys.generate()
    node_keys = NodeKeys.generate()
    ca = CA(ca_keys, tmp_path, dt.timedelta(hours=24))
    cred = ca.issue(node_keys.id_pub_bytes, node_keys.wg_pub_bytes,
                    hostname="anchor", caps=["role:anchor", "role:admin"])
    record = W.NodeRecord.sign(
        W.NodeRecord(
            id_pub=node_keys.id_pub_bytes,
            seq=1,
            endpoints=["[::1]:51900"],
            cred=cred,
        ),
        node_keys.id_priv)
    directory = Directory()
    directory.merge([record])
    return ca_keys, node_keys, record, directory


def test_bootstrap_server_serves_directory_and_rejects_post(tmp_path):
    ca_keys, _node, record, directory = _anchor_setup(tmp_path)

    srv = BootstrapServer(
        listen="[::1]:0",
        directory=directory,
        get_revoked=lambda: set(),
        mesh_domain="test.internal")
    srv.start()
    try:
        url = _bootstrap_url(srv)
        records, *_ = pull_directory(url)
        assert len(records) == 1
        assert records[0].hostname == "anchor"

        # POST must be rejected, even with a valid body.
        import urllib.request
        req = urllib.request.Request(
            f"{url}/directory",
            data=b"{}",
            method="POST",
            headers={"Content-Type": "application/json"})
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(req)
        assert exc.value.code == 405
    finally:
        srv.stop()


def test_bootstrap_server_serves_revoked(tmp_path):
    ca_keys, _node, record, directory = _anchor_setup(tmp_path)
    # We don't need a real record for the revoke list; just a set of hex ids.
    bad_hex = NodeKeys.generate().id_pub_hex
    srv = BootstrapServer(
        listen="[::1]:0",
        directory=directory,
        get_revoked=lambda: {bad_hex},
        mesh_domain="test.internal")
    srv.start()
    try:
        revoked = pull_revoked(_bootstrap_url(srv))
        assert revoked == {bad_hex}
    finally:
        srv.stop()


def test_bootstrap_cli_replaces_stale_directory(tmp_path, monkeypatch):
    ca_keys, node_keys, record, directory = _anchor_setup(tmp_path)

    # Set up a stale local config+keys on a second node.
    data_dir = tmp_path / "broken-node"
    data_dir.mkdir()
    cfg_path = data_dir / "greasewood.toml"
    cfg_path.write_text(f"""[node]
hostname = "broken"
data_dir = "{data_dir}"
role = "node"
caps = ["role:node"]

[network]
interface = "gw-home"
listen_port = 51900
overlay_prefix = "{_overlay_prefix(record.cred.addr)}"
seeds = []
root_url = ""
hosts_sync = false
enforce_ports = false
mesh_domain = "test.internal"

[ca]
trusted_pubs = ["{ca_keys.ca_pub_bytes.hex()}"]
""")
    # Enroll the broken node under the same CA so it has id_priv/wg keys.
    broken_keys = NodeKeys.generate()
    broken_keys.save(data_dir)

    # Pre-create an empty directory so the daemon would have nothing to peer with.
    (data_dir / "directory.json").write_text("[]")

    # Start a bootstrap server for the CLI to talk to.
    srv = BootstrapServer(
        listen="[::1]:0",
        directory=directory,
        get_revoked=lambda: set(),
        mesh_domain="test.internal")
    srv.start()
    try:
        url = _bootstrap_url(srv)

        with patch.object(cli, "_require_root", lambda x: None), \
             patch.object(cli, "_service_restart", return_value=True), \
             patch.object(cli.os, "geteuid", lambda: 0):
            args = type("Args", (), {
                "config": str(cfg_path),
                "seed": url,
                "yes": True,
            })()
            assert cli.cmd_bootstrap(args) == 0

        # Directory should now contain the anchor.
        local_dir = Directory.load(data_dir / "directory.json")
        assert any(r.hostname == "anchor" for r in local_dir.all())
    finally:
        srv.stop()


def test_bootstrap_cli_refuses_wrong_ca(tmp_path):
    """If the fetched directory is signed by a different CA, bootstrap fails."""
    from greasewood.keys import set_overlay_prefix, parse_overlay_prefix
    set_overlay_prefix(parse_overlay_prefix("fd8d:e5c1:db1a:7::"))
    good_ca = CAKeys.generate()
    other_ca = CAKeys.generate()
    other_node = NodeKeys.generate()
    other = CA(other_ca, tmp_path, dt.timedelta(hours=24))
    cred = other.issue(other_node.id_pub_bytes, other_node.wg_pub_bytes,
                       hostname="anchor", caps=["role:anchor"])
    record = W.NodeRecord.sign(
        W.NodeRecord(
            id_pub=other_node.id_pub_bytes,
            seq=1,
            endpoints=["[::1]:51900"],
            cred=cred),
        other_node.id_priv)
    directory = Directory()
    directory.merge([record])

    data_dir = tmp_path / "broken-node2"
    data_dir.mkdir()
    cfg_path = data_dir / "greasewood.toml"
    cfg_path.write_text(f"""[node]
hostname = "broken"
data_dir = "{data_dir}"
role = "node"
caps = ["role:node"]

[network]
interface = "gw-home"
listen_port = 51900
overlay_prefix = "{_overlay_prefix(cred.addr)}"
seeds = []
root_url = ""
hosts_sync = false
enforce_ports = false
mesh_domain = "test.internal"

[ca]
trusted_pubs = ["{good_ca.ca_pub_bytes.hex()}"]
""")
    NodeKeys.generate().save(data_dir)
    (data_dir / "directory.json").write_text("[]")

    srv = BootstrapServer(
        listen="[::1]:0",
        directory=directory,
        get_revoked=lambda: set(),
        mesh_domain="test.internal")
    srv.start()
    try:
        url = _bootstrap_url(srv)

        with patch.object(cli, "_require_root", lambda x: None), \
             patch.object(cli, "_service_restart", return_value=True), \
             patch.object(cli.os, "geteuid", lambda: 0):
            args = type("Args", (), {
                "config": str(cfg_path),
                "seed": url,
                "yes": True,
            })()
            with pytest.raises(SystemExit):
                cli.cmd_bootstrap(args)
    finally:
        srv.stop()
