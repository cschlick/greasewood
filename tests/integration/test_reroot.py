"""
Integration: graceful re-root (hub A → hub B) on real containers.

Exercises the end-to-end flow the README/RUNBOOK describe: B is enrolled as an
ordinary node, promoted to a hub with its own CA (still trusting A), the fleet is
repointed to trust A+B and renew against B, and `gw renew-all` pulls everyone over.
The nodes migrate to B-signed credentials WITHOUT copying A's nodes/ registry —
via the directory-record renewal fallback — and the mesh stays fully linked
throughout (two hubs run simultaneously with no collision).
"""
import time

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: F401
from greasewood.wire import Credential

from .conftest import bring_up_node, make_hub
from .helpers import directory_records, pexec, podman, wait_for_peer_count

pytestmark = pytest.mark.integration


def _restart_daemon(cid: str) -> None:
    # [g]w keeps pkill from matching its own cmdline (see test_reboot_survival).
    pexec(cid, "pkill", "-f", "[g]w.*run", check=False)
    time.sleep(1)
    podman("exec", "-d", cid, "sh", "-c", "gw -v run >> /tmp/gw.log 2>&1")


def _repoint_to_b(cid: str, a_ca: str, b_ca: str, b_ctrl: str) -> None:
    """Rewrite the node's config to trust A+B and use B as hub+seed (Ansible's job
    in production). We know both CA pubkeys, so we just set the list outright."""
    # Replace whole single-line entries (all templates write these on one line).
    # A content regex like \[.*?\] would mis-stop at the ']' inside a v6 URL.
    script = (
        "import re,pathlib\n"
        "p=pathlib.Path('/etc/greasewood.toml'); t=p.read_text()\n"
        f"t=re.sub(r'(?m)^trusted_pubs\\s*=.*$', 'trusted_pubs = [\"{a_ca}\", \"{b_ca}\"]', t)\n"
        f"t=re.sub(r'(?m)^root_url\\s*=.*$', 'root_url = \"{b_ctrl}\"', t)\n"
        f"t=re.sub(r'(?m)^seeds\\s*=.*$', 'seeds = [\"{b_ctrl}\"]', t)\n"
        "p.write_text(t)\n"
    )
    pexec(cid, "python3", "-c", script)


def _all_signed_by(hub_cid: str, ca_hex: str, hostnames) -> bool:
    """True once every named host's directory record is signed by ca_hex."""
    ca = bytes.fromhex(ca_hex)
    by_host = {r["cred"]["hostname"]: r for r in directory_records(hub_cid)}
    for h in hostnames:
        rec = by_host.get(h)
        if rec is None:
            return False
        try:
            Credential.from_dict(rec["cred"]).verify([ca])
        except Exception:
            return False
    return True


def test_graceful_reroot_a_to_b(gw_image, gw_network):
    cids = []
    try:
        # Hub A + a node, then B enrolled as an ordinary node in A's mesh.
        a = make_hub(gw_image, gw_network, hostname="huba")
        cids.append(a["cid"])
        n1 = bring_up_node(gw_image, gw_network, a, hostname="noden1")
        cids.append(n1["cid"])
        b = bring_up_node(gw_image, gw_network, a, hostname="hubb")
        cids.append(b["cid"])

        # 3-node mesh: everyone peered with everyone.
        for c in (a["cid"], n1["cid"], b["cid"]):
            assert wait_for_peer_count(c, 2) == 2, "initial mesh didn't form"

        # Promote B — it generates its own CA (keeps trusting A) and becomes a hub.
        promo = pexec(b["cid"], "gw", "hub-promote")
        b_ca = None
        for line in promo.stdout.splitlines():
            if "CA pub key" in line:
                b_ca = line.split(":")[-1].strip()
        assert b_ca and len(b_ca) == 64, f"no B CA pubkey in:\n{promo.stdout}"
        _restart_daemon(b["cid"])            # B now serves the control plane

        b_ctrl = f"http://[{b['overlay']}]:51902"

        # Repoint the migrating nodes to trust A+B and renew against B, then
        # restart their daemons. (A stays as-is; it's the outgoing hub.)
        for c in (n1["cid"], b["cid"]):
            _repoint_to_b(c, a["ca_pub"], b_ca, b_ctrl)
            _restart_daemon(c)

        # Mesh must not drop while both hubs run + configs flip.
        for c in (a["cid"], n1["cid"], b["cid"]):
            assert wait_for_peer_count(c, 2) == 2, "mesh dropped during re-root"

        # Ask B to pull the fleet onto its CA now.
        pexec(b["cid"], "gw", "renew-all")

        # n1 and B should migrate to B-signed credentials via the directory-record
        # fallback (no nodes/ copy), within a poll interval + jitter + renewal.
        deadline = time.time() + 150
        migrated = False
        while time.time() < deadline:
            if _all_signed_by(b["cid"], b_ca, ["noden1", "hubb"]):
                migrated = True
                break
            time.sleep(3)
        assert migrated, "nodes did not re-issue under B's CA"

        # ...and the mesh is still fully linked afterward.
        for c in (a["cid"], n1["cid"], b["cid"]):
            assert wait_for_peer_count(c, 2) == 2, "mesh not linked after re-root"
    finally:
        for c in cids:
            podman("rm", "-f", c, check=False)
