"""
Integration test: one host is a NODE on two independent greasewood meshes at
once (hub-in-two is explicitly out of scope).

Fleet A uses the default overlay prefix; fleet B a custom one. A single node
container joins both — distinct config, data dir, interface, port, and mesh
domain per membership — runs both daemons, and reaches both hubs' overlays.
This exercises configurable overlay prefixes, prefix-agnostic verification, and
per-interface isolation.
"""
import time

import pytest

from .conftest import _ENROLL_LOCK, _extract_token, overlay_addr_from_id_pub
from .helpers import container_ipv6, pexec, podman, wait_for_ping

pytestmark = pytest.mark.integration

PREFIX_B = "fdde:cafc:ffe:e::"   # fleet B's overlay /64 (canonical form, distinct from default)


def _run_container(gw_image, gw_network):
    cid = podman("run", "-d", "--privileged", "--network", gw_network,
                 "--sysctl", "net.ipv6.conf.all.disable_ipv6=0",
                 gw_image, "sleep", "infinity").stdout.strip()
    time.sleep(1)
    return cid


def _bring_up_hub(cid, ipv6, hostname, prefix, mesh_name=None):
    pexec(cid, "gw", "create", mesh_name or f"{hostname}mesh",
          "--hostname", hostname,
          "--endpoint", f"[{ipv6}]:51900", "--overlay-prefix", prefix)
    overlay = overlay_addr_from_id_pub(
        pexec(cid, "sh", "-c", "cat /var/lib/greasewood_*/id_pub.hex").stdout.strip(), prefix)
    podman("exec", "-d", cid, "sh", "-c", "gw run >> /tmp/gw.log 2>&1")
    return overlay


def _join(hub_cid, hub_ipv6, node_cid, node_ipv6, *, cfg, data_dir, iface,
          port):
    """Invite on the hub, join on the node into a distinct local instance."""
    with _ENROLL_LOCK:
        res = pexec(hub_cid, "gw", "invite", "--endpoint", hub_ipv6)
        token = _extract_token(res.stdout + "\n" + res.stderr)
        # Config path is the global -c, before the subcommand.
        r = pexec(node_cid, "gw", "-c", cfg, "join", token,
                  "--data-dir", data_dir, "--interface", iface,
                  "--listen-port", str(port),
                  "--endpoint", f"[{node_ipv6}]:{port}", check=False)
        assert r.returncode == 0, f"join failed:\n{r.stdout}\n{r.stderr}"
        # let the hub tear its door down before the next invite
        for _ in range(20):
            if pexec(hub_cid, "ip", "link", "show", "gw-door",
                     check=False).returncode != 0:
                break
            time.sleep(0.5)


def test_node_on_two_meshes(gw_hub, gw_image, gw_network):
    hub_b = node = None
    try:
        # Fleet A = the default gw_hub fixture. Fleet B = a fresh hub with a
        # custom overlay prefix.
        hub_b = _run_container(gw_image, gw_network)
        hub_b_ipv6 = container_ipv6(hub_b, gw_network)
        overlay_b = _bring_up_hub(hub_b, hub_b_ipv6, "hubb", PREFIX_B)

        node = _run_container(gw_image, gw_network)
        node_ipv6 = container_ipv6(node, gw_network)

        # Join both meshes as separate local instances.
        _join(gw_hub["cid"], gw_hub["ipv6"], node, node_ipv6,
              cfg="/etc/gw-a.toml", data_dir="/var/lib/gw-a", iface="gwa",
              port=51900)
        _join(hub_b, hub_b_ipv6, node, node_ipv6,
              cfg="/etc/gw-b.toml", data_dir="/var/lib/gw-b", iface="gwb",
              port=51910)

        # Configs carry different overlay prefixes.
        cfg_a = pexec(node, "cat", "/etc/gw-a.toml").stdout
        cfg_b = pexec(node, "cat", "/etc/gw-b.toml").stdout
        assert 'overlay_prefix = "fd8d:e5c1:db1a:7::"' in cfg_a
        assert f'overlay_prefix = "{PREFIX_B}"' in cfg_b
        assert 'interface = "gwa"' in cfg_a and 'interface = "gwb"' in cfg_b

        # Run both daemons.
        podman("exec", "-d", node, "sh", "-c", "gw -c /etc/gw-a.toml run >> /tmp/a.log 2>&1")
        podman("exec", "-d", node, "sh", "-c", "gw -c /etc/gw-b.toml run >> /tmp/b.log 2>&1")

        # The node reaches BOTH hubs' overlays — on different prefixes.
        assert wait_for_ping(node, gw_hub["overlay"], timeout=45), \
            "node could not reach fleet A hub"
        assert wait_for_ping(node, overlay_b, timeout=45), \
            "node could not reach fleet B hub"

        # Both mesh interfaces are up with addresses on their own prefix.
        links = pexec(node, "ip", "-6", "addr").stdout
        assert "gwa" in links and "gwb" in links
    finally:
        for cid in (hub_b, node):
            if cid:
                podman("rm", "-f", cid, check=False)


PREFIX_C = "fdde:cafc:ffe:f::"   # distinct overlay /64 for the auto-slot fleet


def test_second_mesh_auto_slots(gw_hub, gw_image, gw_network):
    """`gw join <token>` with NO location flags: the first mesh lands in the
    default slot; a token from a second mesh auto-provisions slot 2 —
    /etc/greasewood_<name>.toml, /var/lib/greasewood_<name>, gw_<name>, names
    under gw2.internal — and a repeat join with the same mesh's token routes
    back to slot 2 (refresh) instead of allocating slot 3."""
    hub_c = hub_d = node = None
    try:
        hub_c = _run_container(gw_image, gw_network)
        hub_c_ipv6 = container_ipv6(hub_c, gw_network)
        overlay_c = _bring_up_hub(hub_c, hub_c_ipv6, "hubc", PREFIX_C)

        node = _run_container(gw_image, gw_network)
        node_ipv6 = container_ipv6(node, gw_network)

        with _ENROLL_LOCK:
            # Mesh A: plain join, all defaults → the unsuffixed slot 1.
            res = pexec(gw_hub["cid"], "gw", "invite", "--endpoint", gw_hub["ipv6"])
            tok_a = _extract_token(res.stdout + "\n" + res.stderr)
            r = pexec(node, "gw", "join", tok_a,
                      "--endpoint", f"[{node_ipv6}]:51900", check=False)
            assert r.returncode == 0, f"mesh A join failed:\n{r.stdout}\n{r.stderr}"
            for _ in range(20):
                if pexec(gw_hub["cid"], "ip", "link", "show", "gw-door",
                         check=False).returncode != 0:
                    break
                time.sleep(0.5)

            # Mesh C: ALSO a plain join — the unknown CA auto-provisions slot 2.
            res = pexec(hub_c, "gw", "invite", "--endpoint", hub_c_ipv6)
            tok_c = _extract_token(res.stdout + "\n" + res.stderr)
            r = pexec(node, "gw", "join", tok_c,
                      "--endpoint", f"[{node_ipv6}]:51910", check=False)
            assert r.returncode == 0, f"auto-slot join failed:\n{r.stdout}\n{r.stderr}"
            assert "provisioning membership" in (r.stdout + r.stderr)

        # Slot 2 got the derived names + the mesh's OWN domain (carried in the
        # token — a mesh has ONE domain everywhere; no local aliasing exists).
        cfg2 = pexec(node, "cat", "/etc/greasewood_hubcmesh.toml").stdout
        assert 'interface = "gw_hubcmesh"' in cfg2
        assert "listen_port = 51910" in cfg2
        assert 'mesh_domain = "hubcmesh.internal"' in cfg2
        assert f'overlay_prefix = "{PREFIX_C}"' in cfg2
        assert 'data_dir = "/var/lib/greasewood_hubcmesh"' in cfg2
        cfg1 = pexec(node, "cat", "/etc/greasewood_testmesh.toml").stdout
        assert 'interface = "gw_testmesh"' in cfg1 and "listen_port = 51900" in cfg1
        assert 'mesh_domain = "testmesh.internal"' in cfg1        # adopted from token

        # Both daemons up; both overlays reachable.
        podman("exec", "-d", node, "sh", "-c", "gw run >> /tmp/a.log 2>&1")
        podman("exec", "-d", node, "sh", "-c",
               "gw -c /etc/greasewood_hubcmesh.toml run >> /tmp/c.log 2>&1")
        assert wait_for_ping(node, gw_hub["overlay"], timeout=45), \
            "node could not reach mesh A's hub"
        assert wait_for_ping(node, overlay_c, timeout=45), \
            "node could not reach the auto-slotted mesh's hub"

        # Re-join mesh C with a fresh token, still no flags: routes to slot 2
        # (same identity — "re-enrolling"), never allocates slot 3.
        with _ENROLL_LOCK:
            res = pexec(hub_c, "gw", "invite", "--endpoint", hub_c_ipv6)
            tok_c2 = _extract_token(res.stdout + "\n" + res.stderr)
            r = pexec(node, "gw", "join", tok_c2,
                      "--endpoint", f"[{node_ipv6}]:51910", check=False)
            assert r.returncode == 0, f"slot-2 refresh failed:\n{r.stdout}\n{r.stderr}"
            assert "refreshing it" in (r.stdout + r.stderr)
        n_cfgs = pexec(node, "sh", "-c",
                       "ls /etc/greasewood_*.toml | wc -l").stdout.strip()
        assert n_cfgs == "2", f"refresh wrongly made a third membership ({n_cfgs})"

        # HARD-NO collision: a third mesh whose name collides with membership
        # #1 ("testmesh") is refused BEFORE the door dance — no alias, no new
        # slot, and the token is NOT consumed (hub_d's window stays open).
        hub_d = _run_container(gw_image, gw_network)
        hub_d_ipv6 = container_ipv6(hub_d, gw_network)
        _bring_up_hub(hub_d, hub_d_ipv6, "hubd", "fdde:cafc:ffe:d::",
                      mesh_name="testmesh")
        with _ENROLL_LOCK:
            res = pexec(hub_d, "gw", "invite", "--endpoint", hub_d_ipv6)
            tok_d = _extract_token(res.stdout + "\n" + res.stderr)
            r = pexec(node, "gw", "join", tok_d,
                      "--endpoint", f"[{node_ipv6}]:51920", check=False)
            assert r.returncode != 0, "same-domain join was NOT refused!"
            out = r.stdout + r.stderr
            assert "cannot bridge two meshes with the same domain" in out
            assert "set-domain" in out and "NOT consumed" in out
            n_cfgs = pexec(node, "sh", "-c",
                           "ls /etc/greasewood_*.toml | wc -l").stdout.strip()
            assert n_cfgs == "2", "refusal still made a membership"
            # Token unburned: hub_d's door window is still open.
            assert pexec(hub_d, "test", "-e",
                         "/var/lib/greasewood_testmesh/door_window.json").returncode == 0
            pexec(hub_d, "sh", "-c", "rm -f /var/lib/greasewood_*/door_window.json",
                  check=False)
    finally:
        for cid in (hub_c, hub_d, node):
            if cid:
                podman("rm", "-f", cid, check=False)
