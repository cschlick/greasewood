"""
Active/active holders must CONVERGE: each holder mints decisions only it has,
so a holder's sync must pull EVERY other holder per cycle — first-success
failover there is the two-holders-that-never-converged bug (the original
anchor's own root_url is loopback, a self-pull always "succeeds", and the
second holder's statements never landed anywhere). Plain nodes keep failover.
"""
import datetime as dt
import types

from greasewood import cli
from greasewood import sync as syncmod
from greasewood.directory import Directory
from greasewood.keys import CAKeys, NodeKeys, derive_addr
from greasewood.server import ControlServer
from greasewood.statements import StatementLog
from greasewood.sync import SyncLoop
from greasewood.wire import AnchorStatement, Credential, NodeRecord

_UTC = dt.timezone.utc


def _now():
    return dt.datetime.now(_UTC).replace(microsecond=0)


def _stmt(ca, kind, node, hostname=""):
    return AnchorStatement(kind=kind, id_pub=node.id_pub_bytes, ts=_now(),
                           hostname=hostname).sign(ca.ca_priv)


def _holder(ca, stmts):
    srv = ControlServer(
        listen="[::1]:0", directory=Directory(),
        get_ca_pubs=lambda: [ca.ca_pub_bytes], get_revoked=set,
        statements=stmts,
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
# the sync-source list: a node must never count ITSELF as a source
# ---------------------------------------------------------------------------

def _rec(ca, k, name, caps):
    now = _now()
    cred = Credential(id_pub=k.id_pub_bytes, wg_pub=k.wg_pub_bytes,
                      addr=derive_addr(k.id_pub_bytes), hostname=name,
                      caps=caps, iat=now,
                      exp=now + dt.timedelta(hours=24)).sign(ca.ca_priv)
    return NodeRecord(id_pub=k.id_pub_bytes, seq=1, endpoints=[],
                      cred=cred).sign(k.id_priv)


def _cfg(seeds=(), root=""):
    return types.SimpleNamespace(seeds=list(seeds), root_url=root,
                                 control_listen=":51902")


def test_exclude_self_drops_loopback_and_own_configured_urls():
    """THE create-anchor regression: its config has root_url=http://[::1],
    first in the anchor set, and a self-pull always succeeds — so with
    failover it synced with itself forever and never pulled the second
    holder. exclude_self strips loopback and own-address URLs."""
    ca = CAKeys.generate()
    me, other = NodeKeys.generate(), NodeKeys.generate()
    my_addr = derive_addr(me.id_pub_bytes)
    d = Directory()
    d.put(_rec(ca, me, "router", ["role:*"]))
    d.put(_rec(ca, other, "melvin", ["role:anchor"]))
    cfg = _cfg(seeds=["http://localhost:51902", "http://127.0.0.1:51902",
                      f"http://[{my_addr}]:51902"],
               root="http://[::1]:51902")
    urls = cli._anchor_urls(cfg, d, own_addr=my_addr,
                            get_ca_pubs=lambda: [ca.ca_pub_bytes],
                            exclude_self=True)
    assert urls == [f"http://[{derive_addr(other.id_pub_bytes)}]:51902"]


def test_without_exclude_self_loopback_stays():
    """Default semantics unchanged: renewal/attest/leave deliberately keep a
    holder's loopback (it serves itself first; a sole holder must not depend
    on a root_url pointing elsewhere)."""
    cfg = _cfg(root="http://[::1]:51902")
    urls = cli._anchor_urls(cfg, Directory())
    assert urls == ["http://[::1]:51902"]
