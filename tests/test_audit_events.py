"""
Domain-event trail: `audit.event(...)` writes one durable logfmt line per MESH
state TRANSITION — a topology change (reconcile installs/removes a peer) or a
policy-version adoption. The layer above the per-command trail: the so-what a
point-in-time snapshot can't show. `grep event=` reads the mesh's history.
"""
import datetime as dt
import logging

from greasewood import audit, policy, reconcile
from greasewood.directory import Directory
from greasewood.keys import CAKeys, NodeKeys, derive_addr
from greasewood.wire import Credential, GrantTable, NodeRecord

_UTC = dt.timezone.utc


def _cred(ca, n, host, roles=("node",), secs=3600):
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    return Credential(
        id_pub=n.id_pub_bytes, wg_pub=n.wg_pub_bytes,
        addr=derive_addr(n.id_pub_bytes), hostname=host,
        caps=["role:" + r for r in roles], iat=now,
        exp=now + dt.timedelta(seconds=secs)).sign(ca.ca_priv)


def _rec(n, cred):
    return NodeRecord(id_pub=n.id_pub_bytes, seq=1, endpoints=[], cred=cred).sign(n.id_priv)


class _FakeWg:
    """In-memory wg stand-in: install/remove mutate an in-memory peer set."""
    def __init__(self):
        self.peers = {}

    def get_peers(self, iface):
        return dict(self.peers)

    def set_peer(self, iface, pub, ip, endpoint=None, keepalive=25):
        from greasewood.wg import LivePeer
        self.peers[pub] = LivePeer(wg_pub_b64=pub, endpoint=endpoint or "",
                                   allowed_ips=f"{ip}/128", keepalive=keepalive)

    def remove_peer(self, iface, pub, ip=None):
        self.peers.pop(pub, None)


def _events(caplog, kind=""):
    return [r.getMessage() for r in caplog.records
            if r.name == "greasewood.audit"
            and r.getMessage().startswith(f"event={kind}")]


def test_event_logfmt_and_quoting(caplog):
    with caplog.at_level(logging.INFO, logger="greasewood.audit"):
        audit.event("topology", added=2, removed=1, peers=7)
        audit.event("policy", prev="none", seq=3, grants=2)
        audit.event("note", msg="two words")          # a value with a space quotes
    ev = _events(caplog)
    assert "event=topology added=2 removed=1 peers=7" in ev
    assert "event=policy prev=none seq=3 grants=2" in ev
    assert 'event=note msg="two words"' in ev


def test_policy_offer_emits_version_event(caplog):
    ca = CAKeys.generate()
    gp = policy.GrantPolicy(cache_path=None, get_ca_pubs=lambda: [ca.ca_pub_bytes])
    t1 = GrantTable(seq=1, grants=[{"from": ["*"], "to": ["*"], "ports": ["*"]}]).sign(ca.ca_priv)
    t2 = GrantTable(seq=2, grants=[{"from": ["web"], "to": ["api"],
                                    "ports": ["tcp/8000"]}]).sign(ca.ca_priv)
    with caplog.at_level(logging.INFO, logger="greasewood.audit"):
        assert gp.offer(t1.to_dict()) is True
        assert gp.offer(t2.to_dict()) is True
        assert gp.offer(t1.to_dict()) is False        # stale seq → no adoption
    ev = _events(caplog, "policy")
    assert "event=policy prev=none seq=1 grants=1" in ev
    assert "event=policy prev=1 seq=2 grants=1" in ev
    assert len(ev) == 2                               # the stale offer emitted nothing


def test_reconcile_emits_topology_only_on_membership_change(monkeypatch, caplog):
    ca = CAKeys.generate()
    local, peer = NodeKeys.generate(), NodeKeys.generate()
    directory = Directory()
    directory.put(_rec(local, _cred(ca, local, "local")))
    directory.put(_rec(peer, _cred(ca, peer, "peer1")))
    monkeypatch.setattr(reconcile, "wgmod", _FakeWg())

    def _run(revoked):
        reconcile.reconcile_once("gw-test", directory, local.id_pub_bytes,
                                 ["role:node"], [ca.ca_pub_bytes], revoked)

    with caplog.at_level(logging.INFO, logger="greasewood.audit"):
        _run(set())                                   # +peer1
    assert "event=topology added=1 removed=0 peers=1" in _events(caplog, "topology")

    caplog.clear()
    with caplog.at_level(logging.INFO, logger="greasewood.audit"):
        _run(set())                                   # steady state → silent
    assert _events(caplog, "topology") == []

    caplog.clear()
    with caplog.at_level(logging.INFO, logger="greasewood.audit"):
        _run({peer.id_pub_hex})                       # revoked → -peer1
    assert "event=topology added=0 removed=1 peers=0" in _events(caplog, "topology")
