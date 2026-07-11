"""
Unit tests for reconcile.default_policy — the authorization gate. Peering is
decided purely by **shared segments** (`segment:<name>` tags); every node is in
`segment:mesh` by default, and `segment:*` is the reach-all wildcard (the anchor).
These branches aren't all reachable in integration (every node is in a segment),
so they're covered here.

Also covers the reconcile trust gate: everything derived from the directory —
WireGuard peers AND the /etc/hosts name block — must pass FULL verification
(CA sig + expiry + revocation), not just the structural check that admits
records into the cache. A revoked node loses its tunnel; its name must not
keep resolving either.
"""
import datetime as dt

from greasewood import reconcile
from greasewood.directory import Directory
from greasewood.keys import CAKeys, NodeKeys
from greasewood.reconcile import ReconcileLoop, default_policy, reconcile_once
from greasewood.wire import Credential, NodeRecord

_UTC = dt.timezone.utc


def test_no_policy_is_flat_mesh():
    # Without a grant table, every verified member peers (implicit * -> * : *);
    # role tags are inert until a policy exists.
    assert default_policy(["role:mesh"], ["role:mesh"]) is True
    assert default_policy(["role:prod"], ["role:dev"]) is True
    assert default_policy([], []) is True
    assert default_policy(["tls"], []) is True


def test_wildcard_role_reaches_everyone():
    # The anchor carries role:* — hardwired beneath any policy.
    from greasewood.policy import peers_allowed
    assert peers_allowed(["role:*"], ["role:prod"], []) is True
    assert peers_allowed(["role:prod"], ["role:*"], []) is True


def test_isolation_comes_from_the_grant_table():
    # Under a policy, tunnels derive from grants: prod↔prod granted, dev is
    # isolated from prod, and a node with no role reaches only the anchor.
    from greasewood.policy import peers_allowed
    grants = [{"from": ["prod"], "to": ["prod"], "ports": ["*"]}]
    assert peers_allowed(["role:prod"], ["role:prod"], grants) is True
    assert peers_allowed(["role:prod"], ["role:dev"], grants) is False
    assert peers_allowed([], ["role:prod"], grants) is False


def test_bridge_role_reaches_multiple_groups():
    # A node holding several roles links wherever a grant names one of them
    # (A=web, B=web+db, C=db; grants web↔web and db↔db → A-B and B-C, not A-C).
    from greasewood.policy import peers_allowed
    grants = [{"from": ["web"], "to": ["web"], "ports": ["*"]},
              {"from": ["db"], "to": ["db"], "ports": ["*"]}]
    a, b, c = ["role:web"], ["role:web", "role:db"], ["role:db"]
    assert peers_allowed(a, b, grants) is True
    assert peers_allowed(b, c, grants) is True
    assert peers_allowed(a, c, grants) is False


def test_capabilities_do_not_affect_peering():
    # Ability/marker tags (tls, hostname-pinned) are not roles: they neither
    # create nor block a link under a policy.
    from greasewood.policy import peers_allowed
    grants = [{"from": ["mesh"], "to": ["mesh"], "ports": ["*"]}]
    assert peers_allowed(["tls"], ["tls"], grants) is False
    assert peers_allowed(["role:mesh", "tls", "hostname-pinned"],
                         ["role:mesh"], grants) is True


# ---------------------------------------------------------------------------
# Endpoint auto-fallback: rotate to a peer's next advertised endpoint when the
# current one produces no handshake (the dual-stack "v6 advertised but broken,
# v4 also available" case). Stays direct-or-fail — only endpoints the PEER
# advertised are ever tried, never a relay.
# ---------------------------------------------------------------------------

class TestEndpointTracker:
    V6, V4 = "[fd8d::1]:51900", "1.2.3.4:51900"

    def test_new_peer_gets_first_candidate(self):
        t = reconcile._EndpointTracker(dwell=20)
        assert t.choose("p", [self.V6, self.V4], hs=0, now=1000) == self.V6

    def test_healthy_peer_sticks(self):
        t = reconcile._EndpointTracker(dwell=20)
        t.choose("p", [self.V6, self.V4], hs=0, now=1000)
        # A live tunnel keeps handshaking (~every 2 min); as long as the last one
        # is within the healthy window, never rotate away — even long-term.
        assert t.choose("p", [self.V6, self.V4], hs=1000, now=1005) == self.V6
        assert t.choose("p", [self.V6, self.V4], hs=1100, now=1200) == self.V6
        assert t.choose("p", [self.V6, self.V4], hs=1900, now=2000) == self.V6

    def test_rotates_after_dwell_without_handshake(self):
        t = reconcile._EndpointTracker(dwell=20)
        assert t.choose("p", [self.V6, self.V4], hs=0, now=1000) == self.V6
        assert t.choose("p", [self.V6, self.V4], hs=0, now=1010) == self.V6  # dwell not up
        assert t.choose("p", [self.V6, self.V4], hs=0, now=1025) == self.V4  # rotated
        assert t.choose("p", [self.V6, self.V4], hs=0, now=1050) == self.V6  # round-robin

    def test_handshake_on_fallback_stops_rotation(self):
        t = reconcile._EndpointTracker(dwell=20)
        t.choose("p", [self.V6, self.V4], hs=0, now=0)
        assert t.choose("p", [self.V6, self.V4], hs=0, now=30) == self.V4  # rotated to v4
        # v4 now handshakes → stay on v4
        assert t.choose("p", [self.V6, self.V4], hs=30, now=35) == self.V4
        assert t.choose("p", [self.V6, self.V4], hs=30, now=200) == self.V4

    def test_single_candidate_never_rotates(self):
        t = reconcile._EndpointTracker(dwell=20)
        assert t.choose("p", [self.V6], hs=0, now=0) == self.V6
        assert t.choose("p", [self.V6], hs=0, now=1000) == self.V6

    def test_no_candidates_is_none(self):
        t = reconcile._EndpointTracker(dwell=20)
        assert t.choose("p", [], hs=0, now=0) is None

    def test_readvertised_endpoints_reset_to_new_first(self):
        t = reconcile._EndpointTracker(dwell=20)
        assert t.choose("p", [self.V6, self.V4], hs=0, now=0) == self.V6
        # peer now advertises a set that doesn't include the current endpoint
        assert t.choose("p", ["9.9.9.9:51900"], hs=0, now=5) == "9.9.9.9:51900"


class TestReconcileEndpointFallback:
    def _mesh_with_dead_endpoint(self):
        ca = CAKeys.generate()
        local, peer = NodeKeys.generate(), NodeKeys.generate()
        directory = Directory()
        directory.put(_make_record(local, _make_cred(local, ca, "local")))
        # Peer advertises v6-first then v4; the v6 path will never handshake.
        rec = _make_record(peer, _make_cred(peer, ca, "peer"),
                           endpoints=["[fd8d::9]:51900", "5.6.7.8:51900"])
        directory.put(rec)
        return ca, local, peer, directory, rec

    def test_reconcile_rotates_endpoint_when_no_handshake(self, monkeypatch):
        import base64
        ca, local, peer, directory, rec = self._mesh_with_dead_endpoint()
        fake = _FakeWg()
        monkeypatch.setattr(reconcile, "wgmod", fake)
        pub = base64.b64encode(peer.wg_pub_bytes).decode()
        tracker = reconcile._EndpointTracker(dwell=0)  # rotate as soon as stale

        def run():
            reconcile_once("gw-test", directory, local.id_pub_bytes,
                           ["segment:mesh"], [ca.ca_pub_bytes], set(),
                           local_families={4, 6}, endpoint_tracker=tracker)

        run()                                   # installs peer on v6 (first)
        assert fake.peers[pub].endpoint == "[fd8d::9]:51900"
        run()                                   # still no handshake → rotate to v4
        assert fake.peers[pub].endpoint == "5.6.7.8:51900"


# ---------------------------------------------------------------------------
# Trust gate: reconcile output (peers + hosts records) is fully verified
# ---------------------------------------------------------------------------

def _make_cred(node: NodeKeys, ca: CAKeys, hostname: str,
               ttl: int = 3600) -> Credential:
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    return Credential(
        id_pub=node.id_pub_bytes,
        wg_pub=node.wg_pub_bytes,
        addr=node.addr,
        hostname=hostname,
        caps=["segment:mesh"],
        iat=now,
        exp=now + dt.timedelta(seconds=ttl),
    ).sign(ca.ca_priv)


def _make_record(node: NodeKeys, cred: Credential, seq: int = 1,
                 endpoints: "list[str] | None" = None) -> NodeRecord:
    return NodeRecord(
        id_pub=node.id_pub_bytes,
        seq=seq,
        endpoints=["[2001:db8::1]:51900"] if endpoints is None else endpoints,
        cred=cred,
    ).sign(node.id_priv)


class _FakeWg:
    """In-memory stand-in for the wg module: records set/remove calls."""

    def __init__(self):
        self.peers: dict[str, object] = {}
        self.set_calls = 0
        self.remove_calls = 0

    def get_peers(self, iface):
        return dict(self.peers)

    def set_peer(self, iface, wg_pub_b64, allowed_ip, endpoint=None, keepalive=25):
        from greasewood.wg import LivePeer
        self.set_calls += 1
        self.peers[wg_pub_b64] = LivePeer(
            wg_pub_b64=wg_pub_b64, endpoint=endpoint or "",
            allowed_ips=f"{allowed_ip}/128", keepalive=keepalive,
        )

    def remove_peer(self, iface, wg_pub_b64, allowed_ip=None):
        self.remove_calls += 1
        self.peers.pop(wg_pub_b64, None)


class TestReconcileTrustGate:
    def _mesh(self):
        """A local node plus three peers: valid, revoked, and expired."""
        ca = CAKeys.generate()
        local = NodeKeys.generate()
        good, bad, stale = (NodeKeys.generate() for _ in range(3))
        directory = Directory()
        directory.put(_make_record(local, _make_cred(local, ca, "local")))
        directory.put(_make_record(good, _make_cred(good, ca, "good")))
        directory.put(_make_record(bad, _make_cred(bad, ca, "bad")))
        directory.put(_make_record(stale, _make_cred(stale, ca, "stale", ttl=-1)))
        revoked = {bad.id_pub_hex}
        return ca, local, good, directory, revoked

    def test_returns_only_fully_verified_records(self, monkeypatch):
        ca, local, good, directory, revoked = self._mesh()
        fake = _FakeWg()
        monkeypatch.setattr(reconcile, "wgmod", fake)

        trusted, _ = reconcile_once(
            "gw-test", directory, local.id_pub_bytes, ["segment:mesh"],
            [ca.ca_pub_bytes], revoked,
        )

        names = {r.hostname for r in trusted}
        assert "good" in names
        assert "local" in names          # own record stays resolvable
        assert "bad" not in names        # revoked → gone from every output
        assert "stale" not in names      # expired → gone from every output

        # Peers installed: only the valid remote node; never self.
        import base64
        assert set(fake.peers) == {base64.b64encode(good.wg_pub_bytes).decode()}

    def test_anchor_admits_expired_but_not_revoked_for_recert(self, monkeypatch):
        """The ANCHOR (role:*) admits an expired-but-not-revoked node so it can
        renew over the anchor's tunnel — expiry means 'must re-check-in', not
        'dead'. A revoked node stays out even for the anchor, and a regular node
        (previous test) still rejects the expired peer."""
        import base64
        ca, local, good, directory, revoked = self._mesh()   # 'stale' expired, 'bad' revoked
        fake = _FakeWg()
        monkeypatch.setattr(reconcile, "wgmod", fake)

        trusted, _ = reconcile_once(
            "gw-test", directory, local.id_pub_bytes, ["role:*"],   # local IS the anchor
            [ca.ca_pub_bytes], revoked,
        )
        names = {r.hostname for r in trusted}
        assert "stale" in names          # expired but NOT revoked → anchor admits it
        assert "bad" not in names        # revoked → rejected even by the anchor
        assert "good" in names
        # the expired node is actually installed as a peer, so a tunnel can form
        # for it to renew over
        stale_key = next(r for r in directory.all() if r.hostname == "stale")
        assert base64.b64encode(stale_key.cred.wg_pub).decode() in fake.peers

    def test_hosts_sync_receives_trusted_records_only(self, monkeypatch):
        """The ReconcileLoop's /etc/hosts block must be built from the same
        fully-verified set as the WG peer list — a revoked or expired node's
        name must stop resolving, not linger in /etc/hosts forever."""
        ca, local, good, directory, revoked = self._mesh()
        monkeypatch.setattr(reconcile, "wgmod", _FakeWg())
        captured = {}

        def fake_sync(records, domain, path=None):
            captured["names"] = {r.hostname for r in records}
            return True

        from greasewood import hosts
        monkeypatch.setattr(hosts, "sync", fake_sync)

        loop = ReconcileLoop(
            iface="gw-test",
            directory=directory,
            local_id_pub=local.id_pub_bytes,
            local_caps=["segment:mesh"],
            get_ca_pubs=lambda: [ca.ca_pub_bytes],
            get_revoked=lambda: revoked,
            hosts_domain="internal",
        )
        loop._tick()

        assert captured["names"] == {"local", "good"}

    def test_peer_that_stops_advertising_keeps_live_endpoint(self, monkeypatch):
        """A peer that stops advertising an endpoint (e.g. went outbound-only)
        keeps whatever endpoint the kernel already has. This is deliberate:
        WireGuard roams endpoints on any authenticated packet, and clearing one
        would require remove+re-add, tearing down a live session for no gain.
        Pinned here so the behavior stays a decision, not an accident."""
        import base64
        from greasewood.wg import LivePeer

        ca = CAKeys.generate()
        local, peer = NodeKeys.generate(), NodeKeys.generate()
        directory = Directory()
        directory.put(_make_record(local, _make_cred(local, ca, "local")))
        # The peer's current record advertises NO endpoints.
        rec = _make_record(peer, _make_cred(peer, ca, "peer"), endpoints=[])
        directory.put(rec)

        fake = _FakeWg()
        pub = base64.b64encode(peer.wg_pub_bytes).decode()
        fake.peers[pub] = LivePeer(          # kernel still has the old endpoint
            wg_pub_b64=pub, endpoint="[2001:db8::9]:51900",
            allowed_ips=f"{rec.cred.addr}/128", keepalive=25,
        )
        monkeypatch.setattr(reconcile, "wgmod", fake)

        reconcile_once(
            "gw-test", directory, local.id_pub_bytes, ["segment:mesh"],
            [ca.ca_pub_bytes], set(),
        )

        assert fake.set_calls == 0 and fake.remove_calls == 0   # no churn
        assert fake.peers[pub].endpoint == "[2001:db8::9]:51900"


class TestInterfaceSelfHeal:
    """The daemon creates the mesh interface at startup, but it can vanish
    underneath a running daemon (purge/re-create on the host, manual ip link
    del) — after which every peer install fails, door enrollments included,
    until a restart. With the ensure_iface hook the loop re-checks each cycle
    and recreates it."""

    def _loop(self, ensure):
        return ReconcileLoop(
            iface="gw-test", directory=Directory(), local_id_pub=b"\x01" * 32,
            local_caps=["segment:mesh"], get_ca_pubs=lambda: [],
            get_revoked=set, ensure_iface=ensure)

    def test_missing_interface_is_recreated_then_cycle_proceeds(self, monkeypatch):
        calls = {"ensure": 0, "reconcile": 0}
        monkeypatch.setattr(reconcile.wgmod, "interface_exists",
                            lambda iface: calls["ensure"] > 0, raising=False)
        monkeypatch.setattr(reconcile, "reconcile_once",
                            lambda *a, **k: calls.__setitem__("reconcile", calls["reconcile"] + 1) or [])
        loop = self._loop(lambda: calls.__setitem__("ensure", calls["ensure"] + 1))
        loop._tick()
        assert calls == {"ensure": 1, "reconcile": 1}   # healed, then reconciled

    def test_present_interface_is_not_touched(self, monkeypatch):
        calls = {"ensure": 0}
        monkeypatch.setattr(reconcile.wgmod, "interface_exists",
                            lambda iface: True, raising=False)
        monkeypatch.setattr(reconcile, "reconcile_once", lambda *a, **k: ([], []))
        loop = self._loop(lambda: calls.__setitem__("ensure", 1))
        loop._tick()
        assert calls["ensure"] == 0

    def test_failed_heal_skips_cycle_and_retries_next(self, monkeypatch):
        ran = {"reconcile": 0}
        monkeypatch.setattr(reconcile.wgmod, "interface_exists",
                            lambda iface: False, raising=False)
        monkeypatch.setattr(reconcile, "reconcile_once",
                            lambda *a, **k: ran.__setitem__("reconcile", 1) or ([], []))
        def boom():
            raise RuntimeError("ip link add failed")
        loop = self._loop(boom)
        loop._tick()                       # must not raise
        assert ran["reconcile"] == 0        # no reconcile against a dead iface

    def test_no_hook_means_no_check(self, monkeypatch):
        # Backward-compat: without the hook, _cycle never asks about the iface.
        def explode(iface):
            raise AssertionError("should not be called")
        monkeypatch.setattr(reconcile.wgmod, "interface_exists", explode, raising=False)
        monkeypatch.setattr(reconcile, "reconcile_once", lambda *a, **k: ([], []))
        loop = self._loop(None)
        loop._tick()


class TestEndpointBackoff:
    """A dead endpoint gets keepalive dropped to 0 (stop the futile 25s poke),
    stays pinned for automatic recovery, and restores keepalive on a handshake."""

    def test_tracker_marks_dead_after_dwell_single_endpoint(self):
        from greasewood.reconcile import _EndpointTracker
        t = _EndpointTracker(dwell=20.0, healthy=180.0)
        eps = ["[2001:db8::9]:51900"]
        assert t.choose("p", eps, hs=0, now=0.0) == eps[0]
        assert not t.is_backoff("p")                       # fresh, still probing
        t.choose("p", eps, hs=0, now=10.0)                 # 10s, no handshake
        assert not t.is_backoff("p")                       # within dwell
        t.choose("p", eps, hs=0, now=25.0)                 # past dwell, still dead
        assert t.is_backoff("p")                           # → backoff

    def test_tracker_backoff_clears_on_handshake(self):
        from greasewood.reconcile import _EndpointTracker
        t = _EndpointTracker(dwell=20.0, healthy=180.0)
        eps = ["[2001:db8::9]:51900"]
        t.choose("p", eps, hs=0, now=0.0)
        t.choose("p", eps, hs=0, now=25.0)
        assert t.is_backoff("p")
        t.choose("p", eps, hs=1000, now=1010.0)            # handshake 10s ago
        assert not t.is_backoff("p")                       # recovered

    def test_tracker_two_endpoints_dead_after_full_cycle(self):
        from greasewood.reconcile import _EndpointTracker
        t = _EndpointTracker(dwell=20.0, healthy=180.0)
        eps = ["[2001:db8::9]:51900", "203.0.113.7:51900"]
        t.choose("p", eps, hs=0, now=0.0)
        t.choose("p", eps, hs=0, now=25.0)                 # rotated to #2; 1 dwell in
        assert not t.is_backoff("p")                       # still probing #2
        t.choose("p", eps, hs=0, now=45.0)                 # 2 dwells → whole set dead
        assert t.is_backoff("p")

    def test_reconcile_drops_keepalive_on_dead_endpoint(self, monkeypatch):
        """End to end: a peer whose endpoint never handshakes is re-set with
        keepalive=0, endpoint still pinned."""
        import base64
        import time as _time
        from greasewood import reconcile as rmod
        from greasewood.reconcile import reconcile_once, _EndpointTracker
        from greasewood.wg import LivePeer

        ca = CAKeys.generate()
        local, peer = NodeKeys.generate(), NodeKeys.generate()
        directory = Directory()
        directory.put(_make_record(local, _make_cred(local, ca, "local")))
        rec = _make_record(peer, _make_cred(peer, ca, "peer"),
                           endpoints=["[2001:db8::9]:51900"])
        directory.put(rec)

        fake = _FakeWg()
        pub = base64.b64encode(peer.wg_pub_bytes).decode()
        # Kernel already has the peer with the pinned endpoint, keepalive 25,
        # and NO handshake (dead).
        fake.peers[pub] = LivePeer(wg_pub_b64=pub, endpoint="[2001:db8::9]:51900",
                                   allowed_ips=f"{rec.cred.addr}/128",
                                   latest_handshake=0, keepalive=25)
        monkeypatch.setattr(rmod, "wgmod", fake)
        # Tracker already past dwell for this peer (unhealthy since t=0).
        tracker = _EndpointTracker(dwell=20.0)
        tracker._state[pub] = rmod._PeerEndpoint(
            current="[2001:db8::9]:51900", since=0.0, unhealthy_since=0.0)
        monkeypatch.setattr(_time, "time", lambda: 1000.0)

        reconcile_once("gw-test", directory, local.id_pub_bytes, ["segment:mesh"],
                       [ca.ca_pub_bytes], set(), endpoint_tracker=tracker)

        assert fake.set_calls == 1                          # re-set for keepalive
        assert fake.peers[pub].keepalive == 0               # futile poke stopped
        assert fake.peers[pub].endpoint == "[2001:db8::9]:51900"  # still pinned


class TestReachablePublish:
    """reconcile_once reports the live-link set; ReconcileLoop publishes it
    (rate-limited) so it rides the directory to the fleet."""

    def test_reconcile_reports_live_links(self, monkeypatch):
        import base64
        import time as _time
        from greasewood import reconcile as rmod
        from greasewood.reconcile import reconcile_once
        from greasewood.wg import LivePeer
        ca = CAKeys.generate()
        local, up, down = NodeKeys.generate(), NodeKeys.generate(), NodeKeys.generate()
        directory = Directory()
        directory.put(_make_record(local, _make_cred(local, ca, "local")))
        rup = _make_record(up, _make_cred(up, ca, "up"), endpoints=["1.1.1.1:51900"])
        rdn = _make_record(down, _make_cred(down, ca, "down"), endpoints=["2.2.2.2:51900"])
        directory.put(rup)
        directory.put(rdn)
        fake = _FakeWg()
        pu = base64.b64encode(up.wg_pub_bytes).decode()
        pd = base64.b64encode(down.wg_pub_bytes).decode()
        fake.peers[pu] = LivePeer(wg_pub_b64=pu, endpoint="1.1.1.1:51900",
                                  allowed_ips=f"{rup.cred.addr}/128",
                                  latest_handshake=int(_time.time()) - 5)  # live
        fake.peers[pd] = LivePeer(wg_pub_b64=pd, endpoint="2.2.2.2:51900",
                                  allowed_ips=f"{rdn.cred.addr}/128",
                                  latest_handshake=0)                       # never
        monkeypatch.setattr(rmod, "wgmod", fake)
        _trusted, reachable = reconcile_once(
            "gw-test", directory, local.id_pub_bytes, ["segment:mesh"],
            [ca.ca_pub_bytes], set())
        assert reachable == [rup.cred.addr]           # only the handshaking peer

    def test_loop_publishes_on_change_rate_limited(self):
        from greasewood.reconcile import ReconcileLoop
        published = []
        loop = ReconcileLoop(
            iface="gw-x", directory=Directory(), local_id_pub=b"x" * 32,
            local_caps=[], get_ca_pubs=lambda: [], get_revoked=lambda: set(),
            on_reachable=published.append, reachable_min_interval=30.0)
        loop._maybe_publish_reachable(["a"])
        assert published == [["a"]]                    # first change fires
        loop._maybe_publish_reachable(["a"])
        assert len(published) == 1                     # unchanged → no fire
        loop._maybe_publish_reachable(["a", "b"])
        assert len(published) == 1                     # changed but < min interval
        loop._last_reachable_pub -= 31                 # pretend interval elapsed
        loop._maybe_publish_reachable(["a", "b"])
        assert published[-1] == ["a", "b"]             # now it fires


class TestLoopResilience:
    """The reconcile thread must survive an exception escaping the tick — a dead
    reconcile loop is a frozen data plane under a healthy-looking daemon. (The
    old bare run() died on the first such exception; the sibling loops already
    guarded theirs.)"""

    def test_run_survives_cycle_exception(self):
        import threading
        from greasewood.reconcile import ReconcileLoop
        loop = ReconcileLoop(iface="gw-x", directory=Directory(),
                             local_id_pub=b"x" * 32, local_caps=[],
                             get_ca_pubs=lambda: [], get_revoked=lambda: set(),
                             interval=0.01)
        calls = {"n": 0}
        fired = threading.Event()

        def boom():
            calls["n"] += 1
            if calls["n"] >= 3:
                fired.set()
            raise RuntimeError("cycle exploded")
        loop._tick = boom
        t = loop.start()
        assert fired.wait(timeout=5), "loop died after the first exception"
        loop.stop()
        t.join(timeout=2)
        assert calls["n"] >= 3                # kept cycling THROUGH the raises

    def test_cycle_mock_shape_matches_contract(self, monkeypatch):
        """Guard against the mock rot this class fixes: a full tick with the
        REAL reconcile_once return shape must reach the post-reconcile steps
        (reachable publish) — proving the tests above exercise the success
        path, not a swallowed unpack error."""
        from greasewood.reconcile import ReconcileLoop
        monkeypatch.setattr(reconcile.wgmod, "interface_exists",
                            lambda iface: True, raising=False)
        monkeypatch.setattr(reconcile, "reconcile_once",
                            lambda *a, **k: ([], ["fd8d::1"]))
        published = []
        loop = ReconcileLoop(iface="gw-x", directory=Directory(),
                             local_id_pub=b"x" * 32, local_caps=[],
                             get_ca_pubs=lambda: [], get_revoked=lambda: set(),
                             on_reachable=published.append)
        loop._tick()
        assert published == [["fd8d::1"]]     # the success path actually ran

    def test_local_families_reresolved_each_cycle(self, monkeypatch):
        """REGRESSION: a node that loses IPv6 mid-run (v4-only network) must
        re-detect its families each cycle and fall back to peers' v4 endpoints —
        NOT stay stranded dialing a dead v6. The loop must call get_local_families
        every tick, not capture it once."""
        from greasewood.reconcile import ReconcileLoop
        monkeypatch.setattr(reconcile.wgmod, "interface_exists",
                            lambda iface: True, raising=False)
        seen = []
        monkeypatch.setattr(reconcile, "reconcile_once",
                            lambda *a, **k: (seen.append(a[7]), ([], []))[1])
        fams = {"v": {4, 6}}                   # start dual-stack
        loop = ReconcileLoop(iface="gw-x", directory=Directory(),
                             local_id_pub=b"x" * 32, local_caps=[],
                             get_ca_pubs=lambda: [], get_revoked=lambda: set(),
                             get_local_families=lambda: fams["v"])
        loop._tick()
        fams["v"] = {4}                        # IPv6 goes away between ticks
        loop._tick()
        assert seen == [{4, 6}, {4}]           # each cycle used the CURRENT families


class TestUnreadableLiveState:
    """A transient `wg show dump` failure (get_peers → None) must NOT be acted on
    as 'no peers' — that would skip every removal and re-add everything. The
    cycle is skipped and retried next tick."""

    def test_get_peers_none_skips_the_diff(self, monkeypatch):
        from greasewood.reconcile import reconcile_once
        monkeypatch.setattr(reconcile.wgmod, "get_peers", lambda iface: None)
        set_peer_calls = []
        monkeypatch.setattr(reconcile.wgmod, "set_peer",
                            lambda *a, **k: set_peer_calls.append(a))
        monkeypatch.setattr(reconcile.wgmod, "remove_peer",
                            lambda *a, **k: set_peer_calls.append(("rm",) + a))
        result = reconcile_once("gw-x", Directory(), b"x" * 32, ["segment:mesh"],
                                [], set())
        assert result == ([], [])                # nothing derived
        assert set_peer_calls == []              # no kernel mutation on a misread


def test_reconcile_set_local_caps_updates_peering_view():
    """set_local_caps swaps the role set the loop peers with — the mechanism the
    daemon uses to adopt an anchor-side role change after renewal, no restart."""
    from greasewood import reconcile
    loop = reconcile.ReconcileLoop.__new__(reconcile.ReconcileLoop)
    loop._local_caps = ["role:mesh"]
    loop.set_local_caps(["role:web", "role:db", "tls"])
    assert loop._local_caps == ["role:web", "role:db", "tls"]


# --- daemon death breadcrumb ----------------------------------------------

def test_daemon_fatal_round_trips_and_clears(tmp_path):
    # The startup-fatal breadcrumb: write the reason, read it back, clear it.
    assert reconcile.read_daemon_fatal(tmp_path) is None      # nothing yet
    reconcile.write_daemon_fatal(tmp_path, "port 51900 in use")
    got = reconcile.read_daemon_fatal(tmp_path)
    assert got["reason"] == "port 51900 in use" and "ts" in got
    reconcile.clear_daemon_fatal(tmp_path)
    assert reconcile.read_daemon_fatal(tmp_path) is None       # forgotten on success


def test_read_daemon_fatal_tolerates_garbage(tmp_path):
    # A corrupt/truncated breadcrumb must degrade to None, never raise into watch.
    reconcile.daemon_fatal_path(tmp_path).write_text("{not json")
    assert reconcile.read_daemon_fatal(tmp_path) is None
    reconcile.clear_daemon_fatal(tmp_path)   # idempotent even when absent already
