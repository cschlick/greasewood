"""
Standing door integration: one token, many enrollments, deliberate revocation.

The full lifecycle on real containers:
  * `gw invite --standing` issues ONE token;
  * two nodes join sequentially on that same token (each still a full one-node
    ceremony: fresh identity, CA-signed credential) and the door STAYS open;
  * `gw status` shows the standing door with its enrollment count;
  * a plain `gw invite` refuses to silently supersede the standing door;
  * `gw close-door` permanently invalidates the token — a third node's join
    with it must fail (nothing left to handshake against).
"""
import time
import uuid

import pytest

from .conftest import _ENROLL_LOCK, _extract_token, _wait_iface_gone, container_addr
from .helpers import pexec, podman, wait_for_hostname

pytestmark = pytest.mark.integration


def _fresh_container(gw_image, gw_network) -> tuple:
    r = podman("run", "-d", "--privileged", "--network", gw_network,
               "--sysctl", "net.ipv6.conf.all.disable_ipv6=0",
               gw_image, "sleep", "infinity")
    cid = r.stdout.strip()
    time.sleep(1)
    return cid, container_addr(cid, gw_network)


def test_standing_door_lifecycle(gw_image, gw_network, gw_anchor):
    anchor = gw_anchor["cid"]
    cids = []
    try:
        with _ENROLL_LOCK:
            # One standing token for everyone.
            res = pexec(anchor, "gw", "invite", "--standing",
                        "--endpoint", gw_anchor["ipv6"], "-q")
            token = _extract_token(res.stdout + "\n" + res.stderr)

            # Two nodes enroll on the SAME token, one after the other.
            names = []
            for i in range(2):
                cid, ipv6 = _fresh_container(gw_image, gw_network)
                cids.append(cid)
                name = f"baked-{uuid.uuid4().hex[:6]}"
                names.append(name)
                j = pexec(cid, "gw", "join", token,
                          "--endpoint", f"[{ipv6}]:51900", "--hostname", name,
                          check=False)
                assert j.returncode == 0, (
                    f"join #{i + 1} on the standing token failed "
                    f"(rc={j.returncode}):\n{j.stdout}\n{j.stderr}")
                assert wait_for_hostname(anchor, name, timeout=20), \
                    f"{name} missing from anchor directory after standing enroll"

            # The door is STILL open after successful enrollments.
            r = pexec(anchor, "ip", "link", "show", "gw-door", check=False)
            assert r.returncode == 0, "standing door interface went down after enrollments"
            status = pexec(anchor, "gw", "status").stdout
            assert "OPEN (standing)" in status
            assert "2 enrolled" in status

            # A plain invite must refuse to silently supersede it.
            r = pexec(anchor, "gw", "invite", "--endpoint", gw_anchor["ipv6"], check=False)
            assert r.returncode != 0
            assert "STANDING door is open" in (r.stdout + r.stderr)

            # Revoke: close-door kills the token everywhere, permanently.
            out = pexec(anchor, "gw", "close-door").stdout
            assert "permanently invalid" in out
            assert _wait_iface_gone(anchor, "gw-door"), \
                "gw-door still up after close-door"

            # A third machine holding the old (baked) token gets nothing:
            # the guest key no longer exists on the anchor, so the door handshake
            # never completes and join gives up.
            cid, ipv6 = _fresh_container(gw_image, gw_network)
            cids.append(cid)
            j = pexec(cid, "gw", "join", token,
                      "--endpoint", f"[{ipv6}]:51900", "--hostname", "too-late",
                      check=False)
            assert j.returncode != 0, "revoked standing token still enrolled a node!"
            assert not wait_for_hostname(anchor, "too-late", timeout=3)

        # Both legitimately-enrolled nodes still verify against the anchor
        # (their credentials come from the CA, not the door).
        for name in names:
            assert wait_for_hostname(anchor, name, timeout=5)
    finally:
        for cid in cids:
            podman("rm", "-f", cid, check=False)
        # Leave the shared anchor pristine for the other tests.
        pexec(anchor, "sh", "-c", "rm -f /var/lib/greasewood_*/door_window.json", check=False)
        _wait_iface_gone(anchor, "gw-door")
