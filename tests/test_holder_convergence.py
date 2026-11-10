"""
Active/active holders must CONVERGE: each holder mints decisions only it has,
so a holder's sync must pull EVERY source per cycle — first-success failover
there is the two-holders-that-never-converged bug (the original anchor's own
root_url is loopback, a self-pull always "succeeds", and the second holder's
statements never landed anywhere). Plain nodes keep failover. The holder's
own loopback deliberately STAYS a source: pulling it is how a holder's
daemon hears its own CLI's renew-all hint and upgrade-all announcement
(the graceful-reroot regression: with self excluded, `gw renew-all` on the
new anchor never made the new anchor itself renew).
"""
import datetime as dt

from greasewood import sync as syncmod
from greasewood.directory import Directory
from greasewood.keys import CAKeys, NodeKeys
from greasewood.server import ControlServer
from greasewood.statements import StatementLog
from greasewood.sync import SyncLoop
from greasewood.wire import AnchorStatement

_UTC = dt.timezone.utc


def _now():
    return dt.datetime.now(_UTC).replace(microsecond=0)


def _stmt(ca, kind, node, hostname=""):
    return AnchorStatement(kind=kind, id_pub=node.id_pub_bytes, ts=_now(),
                           hostname=hostname).sign(ca.ca_priv)


def _holder(ca, stmts, renew_after=None):
    srv = ControlServer(
        listen="[::1]:0", directory=Directory(),
        get_ca_pubs=lambda: [ca.ca_pub_bytes], get_revoked=set,
        statements=stmts, get_renew_after=lambda: renew_after,
    )
    srv.start()
    return srv, f"http://[::1]:{srv._server.server_address[1]}"


def _two_holders_each_with_own_decision():
    """Holder A knows only A's revoke; holder B only B's — the exact state of
    two holders that have each minted locally and not yet converged."""
    ca = CAKeys.generate()
    va, vb = NodeKeys.generate(), NodeKeys.generate()
    sa, sb = StatementLog(), StatementLog()
    sa.add(_stmt(ca, "revoke", va))
    sb.add(_stmt(ca, "revoke", vb))
    srv_a, url_a = _holder(ca, sa)
    srv_b, url_b = _holder(ca, sb)
    return ca, va, vb, srv_a, url_a, srv_b, url_b


def _loop(tmp_path, ca, urls, pull_all=None):
    me = NodeKeys.generate()
    local = StatementLog()
    loop = SyncLoop(Directory(), lambda: list(urls),
                    tmp_path / "directory.json",
                    statements=local,
                    get_ca_pubs=lambda: [ca.ca_pub_bytes],
                    own_id_hex=me.id_pub_hex,
                    pull_all=pull_all)
    return local, loop


def test_holder_pulls_every_source_and_converges(tmp_path):
    ca, va, vb, srv_a, url_a, srv_b, url_b = _two_holders_each_with_own_decision()
    local, loop = _loop(tmp_path, ca, [url_a, url_b],
                        pull_all=lambda: True)
    try:
        loop._pull_once()
    finally:
        srv_a.stop(); srv_b.stop()
    # BOTH holders' decisions landed, even though the first source succeeded.
    assert local.revoked_ids() == {va.id_pub_hex, vb.id_pub_hex}


def test_plain_node_keeps_first_success_failover(tmp_path):
    """A plain node stops at the first live holder — fleet load stays ~one
    pull per node, and (post-convergence-fix) any one holder suffices."""
    ca, va, vb, srv_a, url_a, srv_b, url_b = _two_holders_each_with_own_decision()
    local, loop = _loop(tmp_path, ca, [url_a, url_b])     # no pull_all
    try:
        loop._pull_once()
    finally:
        srv_a.stop(); srv_b.stop()
    assert local.revoked_ids() == {va.id_pub_hex}


def test_holder_failover_still_works_past_a_dead_source(tmp_path):
    """pull_all is additive, not a trade: a dead source costs a warning,
    the live ones still merge."""
    ca, va, vb, srv_a, url_a, srv_b, url_b = _two_holders_each_with_own_decision()
    srv_a.stop()                                           # A is down
    local, loop = _loop(tmp_path, ca, [url_a, url_b],
                        pull_all=lambda: True)
    try:
        loop._pull_once()
    finally:
        srv_b.stop()
    assert local.revoked_ids() == {vb.id_pub_hex}


def test_sole_holder_with_no_sources_stamps_freshness(tmp_path):
    """A sole holder (exclude_self leaves it zero sources) is not stale —
    its own log IS the mesh's current view; watch must not cry wolf."""
    ca = CAKeys.generate()
    local, loop = _loop(tmp_path, ca, [], pull_all=lambda: True)
    loop._pull_once()
    age = syncmod.seconds_since_sync(tmp_path)
    assert age is not None and age < 5


def test_plain_node_with_no_sources_stays_unstamped(tmp_path):
    """A plain node with nothing to pull genuinely has no view — stale is
    the truth there."""
    ca = CAKeys.generate()
    local, loop = _loop(tmp_path, ca, [])
    loop._pull_once()
    assert syncmod.seconds_since_sync(tmp_path) is None


# ---------------------------------------------------------------------------
# the self-pull is a FEATURE under pull_all: a holder's own loopback root_url
# stays a source, because pulling it is how the daemon hears its own CLI
# ---------------------------------------------------------------------------

def test_holder_hears_its_own_renew_hint_through_the_self_pull(tmp_path):
    """The graceful-reroot regression: `gw renew-all` on a holder writes the
    hint its own control plane serves — the daemon only acts on it via a
    pull. A holder whose first source is itself must BOTH fire the hint
    AND still converge with the other holder behind it (first-success here
    was the original never-converged bug)."""
    ca = CAKeys.generate()
    victim = NodeKeys.generate()
    hint = _now().isoformat()
    srv_self, url_self = _holder(ca, StatementLog(), renew_after=hint)
    other_stmts = StatementLog()
    other_stmts.add(_stmt(ca, "revoke", victim))
    srv_other, url_other = _holder(ca, other_stmts)

    me = NodeKeys.generate()
    local = StatementLog()
    hints = []
    loop = SyncLoop(Directory(), lambda: [url_self, url_other],
                    tmp_path / "directory.json",
                    statements=local,
                    get_ca_pubs=lambda: [ca.ca_pub_bytes],
                    own_id_hex=me.id_pub_hex,
                    on_renew_after=hints.append,
                    pull_all=lambda: True)
    try:
        loop._pull_once()
    finally:
        srv_self.stop(); srv_other.stop()
    assert hints and hints[0].isoformat() == hint      # own hint delivered
    assert local.revoked_ids() == {victim.id_pub_hex}  # ...and still converged
