"""
Integration test for hub / CA succession (§11).

Exercises the real migration on live containers: promote a second node to a
hub, have the current hub endorse it, then retire the original CA — and verify,
by resolving trust on a node that never changed its config, that:

  * after the endorsement, a node rooted only at A trusts BOTH A and B
    (transitive trust propagated through the synced bundle), and
  * the new hub issues credentials under its own CA (B-signed), proving the
    hub/CA role actually moved, and
  * after retiring A, the same node trusts B but NOT A — the old CA leaves the
    fleet with no config edit on any node.

This is the zero-downtime "hand the hub to another node" path; transitivity is
what lets it repeat indefinitely (A -> B -> C -> ...).
"""
import json
import time

import pytest

from .conftest import bring_up_node, door_enroll_via
from .helpers import container_ipv6, pexec, podman

pytestmark = pytest.mark.integration


# A node resolves its own live trusted-CA set exactly as the daemon does.
_TRUST_SNIPPET = (
    "import json;"
    "from pathlib import Path;"
    "from greasewood.config import load_config;"
    "from greasewood.trust import CABundle, resolve_trust;"
    "cfg=load_config(Path('/etc/greasewood.toml'));"
    "roots={bytes.fromhex(h) for h in cfg.ca_pubs};"
    "b=CABundle.load(cfg.ca_bundle_path);"
    "print(json.dumps(sorted(p.hex() for p in resolve_trust(roots,b))))"
)

# Which CA signed this node's own credential.
_SIGNER_SNIPPET = (
    "import sys,json;"
    "from pathlib import Path;"
    "from greasewood.config import load_config;"
    "from greasewood.keys import NodeKeys;"
    "from greasewood.directory import Directory;"
    "cfg=load_config(Path('/etc/greasewood.toml'));"
    "k=NodeKeys.load(cfg.data_dir);"
    "cred=Directory.load(cfg.dir_cache_path).get(k.id_pub_hex).cred;"
    "out={};"
    "\nfor name,h in (('a',sys.argv[1]),('b',sys.argv[2])):\n"
    "    try:\n        cred.verify([bytes.fromhex(h)]); out[name]=True\n"
    "    except Exception:\n        out[name]=False\n"
    "print(json.dumps(out))"
)


_BUNDLE_SNIPPET = (
    "import json;from pathlib import Path;"
    "from greasewood.config import load_config;"
    "from greasewood.trust import CABundle;"
    "cfg=load_config(Path('/etc/greasewood.toml'));"
    "b=CABundle.load(cfg.ca_bundle_path);"
    "print(json.dumps([[s.kind,s.by_pub.hex()[:8],s.subject_pub.hex()[:8]] "
    "for s in b.statements]))"
)

def _trusted_set(cid) -> set[str]:
    r = pexec(cid, "python3", "-c", _TRUST_SNIPPET)
    return set(json.loads(r.stdout))


_TRUST_AT_SNIPPET = (
    "import sys,json,datetime as dt;"
    "from pathlib import Path;"
    "from greasewood.config import load_config;"
    "from greasewood.trust import CABundle, resolve_trust;"
    "cfg=load_config(Path('/etc/greasewood.toml'));"
    "roots={bytes.fromhex(h) for h in cfg.ca_pubs};"
    "b=CABundle.load(cfg.ca_bundle_path);"
    "now=dt.datetime.now(dt.timezone.utc)+dt.timedelta(seconds=int(sys.argv[1]));"
    "print(json.dumps(sorted(p.hex() for p in resolve_trust(roots,b,now))))"
)


def _bundle_summary(cid) -> list:
    return json.loads(pexec(cid, "python3", "-c", _BUNDLE_SNIPPET).stdout)


def _trusted_at(cid, offset_secs) -> set[str]:
    """N's trusted set as it would resolve `offset_secs` from now (to peek past
    a scheduled retirement's grace without waiting it out)."""
    r = pexec(cid, "python3", "-c", _TRUST_AT_SNIPPET, str(offset_secs))
    return set(json.loads(r.stdout))


def _wait_retire(cid, by8, subj8, timeout=120) -> bool:
    """Block until cid's bundle contains a retire(subj) by `by8` (statement
    present — independent of whether its grace has elapsed yet)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        for s in _bundle_summary(cid):
            if s == ["retire", by8, subj8]:
                return True
        time.sleep(3)
    return False


def _wait_trust(cid, *, contains=(), excludes=(), timeout=90) -> set[str]:
    deadline = time.time() + timeout
    ts: set[str] = set()
    while time.time() < deadline:
        ts = _trusted_set(cid)
        if all(c in ts for c in contains) and all(e not in ts for e in excludes):
            return ts
        time.sleep(3)
    return ts


def _ca_pub_hex(cid) -> str:
    return pexec(cid, "cat", "/var/lib/greasewood/ca.pub").stdout.strip()


def test_ca_and_hub_succession(gw_root, gw_image, gw_network):
    extra_cids = []
    try:
        a_cid = gw_root["cid"]
        a_pub = _ca_pub_hex(a_cid)

        # N: an ordinary node, enrolled under A and rooted at A. It never has
        # its config touched again — our witness for trust propagation.
        n = bring_up_node(gw_image, gw_network, gw_root, hostname="oldnode")
        extra_cids.append(n["cid"])
        assert a_pub in _trusted_set(n["cid"]), "node should start trusting A"

        # B: another node under A, which we promote to a successor hub.
        b = bring_up_node(gw_image, gw_network, gw_root, hostname="newhub")
        extra_cids.append(b["cid"])
        b_ipv6 = container_ipv6(b["cid"], gw_network)

        # Promote B (mint its own CA key, flip config to role=hub).
        pexec(b["cid"], "gw", "hub-promote", "--control-port", "51902")
        b_pub = _ca_pub_hex(b["cid"])
        b_endpoint = f"http://[{b['overlay']}]:51902"
        assert b_pub != a_pub

        # Restart B's daemon so it serves as a hub (control plane + door + bundle).
        pexec(b["cid"], "pkill", "-f", "bin/gw", check=False)
        time.sleep(2)
        podman("exec", "-d", b["cid"], "sh", "-c", "gw -v run >> /tmp/gw.log 2>&1")
        time.sleep(3)

        # A endorses B as its successor and advertises B's endpoint.
        pexec(a_cid, "gw", "hub-endorse", "--ca-pub", b_pub, "--endpoint", b_endpoint)

        # --- Property 1: the endorsement propagates; N (rooted at A) now trusts
        #     BOTH A and B, purely from the synced bundle. ---
        ts = _wait_trust(n["cid"], contains={a_pub, b_pub})
        assert a_pub in ts and b_pub in ts, \
            f"N should trust both A and B after endorsement; got {ts}"

        # --- Property 2: B is really the CA/hub now — a node enrolled via B gets
        #     a B-signed credential. ---
        m_cid = podman(
            "run", "-d", "--privileged", "--network", gw_network,
            "--sysctl", "net.ipv6.conf.all.disable_ipv6=0",
            gw_image, "sleep", "infinity",
        ).stdout.strip()
        extra_cids.append(m_cid)
        time.sleep(1)
        m_ipv6 = container_ipv6(m_cid, gw_network)
        door_enroll_via(b["cid"], b_ipv6, m_cid, m_ipv6, hostname="viaB")
        signer = json.loads(
            pexec(m_cid, "python3", "-c", _SIGNER_SNIPPET, a_pub, b_pub).stdout
        )
        assert signer == {"a": False, "b": True}, \
            f"node enrolled via B should have a B-signed credential; got {signer}"

        # --- Property 3: A is retired with a grace (the one-TTL overlap), so it
        #     stays trusted long enough to propagate and for nodes to migrate —
        #     no node is cut off mid-handover. Use a short grace so the test can
        #     observe the scheduled transition. ---
        pexec(b["cid"], "gw", "hub-retire", "--ca-pub", a_pub, "--grace", "2m")

        # N must RECEIVE the retirement while still connected to B; if the grace
        # were not honored, B would have already dropped N and N could never
        # learn it. This is the regression guard for the propagation deadlock.
        assert _wait_retire(n["cid"], b_pub[:8], a_pub[:8], timeout=110), \
            "N never received the retirement statement (cut off during overlap?)"

        # During the grace, trust is intact (non-disruptive): N still trusts A.
        now_trust = _trusted_at(n["cid"], 0)
        assert a_pub in now_trust and b_pub in now_trust, \
            f"during grace N should still trust A and B; got {now_trust}"

        # Past the grace, the same statement drops A fleet-wide — no config edit
        # on any node. Peek 10 minutes ahead rather than waiting it out.
        later = _trusted_at(n["cid"], 600)
        assert b_pub in later and a_pub not in later, \
            f"after the grace, N should trust only B; got {later}"
    finally:
        for cid in extra_cids:
            podman("rm", "-f", cid, check=False)
