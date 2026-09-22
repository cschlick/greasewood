"""
Statement transport: /directory carries the log, /revoked folds it in, and a
node's SyncLoop merges what a holder decided — including the tombstone drop
that makes a leave/sweep visible fleet-wide without waiting out the TTL.
"""
import datetime as dt
import json
import urllib.request

from greasewood.directory import Directory
from greasewood.keys import CAKeys, NodeKeys, derive_addr
from greasewood.server import ControlServer
from greasewood.statements import StatementLog, statements_path
from greasewood.sync import SyncLoop, pull_directory
from greasewood.wire import AnchorStatement, Credential, NodeRecord

_UTC = dt.timezone.utc


def _now():
    return dt.datetime.now(_UTC).replace(microsecond=0)


def _rec(ca, node, hostname, iat=None):
    iat = iat or _now()
    cred = Credential(id_pub=node.id_pub_bytes, wg_pub=node.wg_pub_bytes,
                      addr=derive_addr(node.id_pub_bytes), hostname=hostname,
                      caps=["role:node"], iat=iat,
                      exp=iat + dt.timedelta(hours=24)).sign(ca.ca_priv)
    return NodeRecord(id_pub=node.id_pub_bytes, seq=1, endpoints=[],
                      cred=cred).sign(node.id_priv)


def _stmt(ca, kind, node, hostname=""):
    return AnchorStatement(kind=kind, id_pub=node.id_pub_bytes, ts=_now(),
                           hostname=hostname).sign(ca.ca_priv)


def _holder(directory, stmts, ca):
    srv = ControlServer(
        listen="[::1]:0", directory=directory,
        get_ca_pubs=lambda: [ca.ca_pub_bytes], get_revoked=set,
        statements=stmts,
    )
    srv.start()
    return srv, srv._server.server_address[1]


def test_directory_serves_statements_and_revoked_merges_them():
    ca, victim = CAKeys.generate(), NodeKeys.generate()
    stmts = StatementLog()
    stmts.add(_stmt(ca, "revoke", victim, hostname="mole"))
    srv, port = _holder(Directory(), stmts, ca)
    try:
        (_r, _ra, _now_, _dom, _pol, pulled,
         _attns) = pull_directory(f"http://[::1]:{port}")
        assert [s.kind for s in pulled] == ["revoke"]
        pulled[0].verify([ca.ca_pub_bytes])           # signature survives transport
        with urllib.request.urlopen(f"http://[::1]:{port}/revoked", timeout=5) as resp:
            revoked = json.loads(resp.read())["revoked"]
        assert victim.id_pub_hex in revoked           # folded into the legacy endpoint
    finally:
        srv.stop()


def test_sync_merges_statements_and_applies_tombstone(tmp_path):
    """A holder tombstones a departed node; a plain node's next pull drops
    that record from its own view and persists both stores."""
    ca = CAKeys.generate()
    departed, me = NodeKeys.generate(), NodeKeys.generate()

    holder_dir = Directory()
    holder_stmts = StatementLog()
    holder_stmts.add(_stmt(ca, "tombstone", departed, hostname="bb"))
    srv, port = _holder(holder_dir, holder_stmts, ca)

    node_dir = Directory()
    node_dir.put(_rec(ca, departed, "bb",
                      iat=_now() - dt.timedelta(hours=1)))   # predates tombstone
    node_stmts = StatementLog()
    cache = tmp_path / "directory.json"
    loop = SyncLoop(node_dir, lambda: [f"http://[::1]:{port}"], cache,
                    statements=node_stmts,
                    get_ca_pubs=lambda: [ca.ca_pub_bytes],
                    own_id_hex=me.id_pub_hex)
    try:
        loop._pull_once()
    finally:
        srv.stop()

    assert node_dir.get(departed.id_pub_hex) is None          # dropped now, not at TTL
    assert node_stmts.tombstone_ts(departed.id_pub_hex) is not None
    assert statements_path(tmp_path).exists()                 # persisted


def test_sync_never_tombstones_own_record(tmp_path):
    """Self-protection: even a tombstone naming THIS node must not make it
    erase its own record (that resets its seq and wedges renewal publishing).
    The rest of the fleet still drops it — this only guards the local view."""
    ca, me = CAKeys.generate(), NodeKeys.generate()
    holder_stmts = StatementLog()
    holder_stmts.add(_stmt(ca, "tombstone", me))
    srv, port = _holder(Directory(), holder_stmts, ca)

    node_dir = Directory()
    node_dir.put(_rec(ca, me, "me", iat=_now() - dt.timedelta(hours=1)))
    loop = SyncLoop(node_dir, lambda: [f"http://[::1]:{port}"],
                    tmp_path / "directory.json",
                    statements=StatementLog(),
                    get_ca_pubs=lambda: [ca.ca_pub_bytes],
                    own_id_hex=me.id_pub_hex)
    try:
        loop._pull_once()
    finally:
        srv.stop()
    assert node_dir.get(me.id_pub_hex) is not None


def test_untrusted_statements_do_not_land(tmp_path):
    ca, evil, victim, me = (CAKeys.generate(), CAKeys.generate(),
                            NodeKeys.generate(), NodeKeys.generate())
    holder_stmts = StatementLog()
    holder_stmts.add(_stmt(evil, "revoke", victim))   # forged upstream
    srv, port = _holder(Directory(), holder_stmts, ca)
    node_stmts = StatementLog()
    loop = SyncLoop(Directory(), lambda: [f"http://[::1]:{port}"],
                    tmp_path / "directory.json",
                    statements=node_stmts,
                    get_ca_pubs=lambda: [ca.ca_pub_bytes],   # we trust only ca
                    own_id_hex=me.id_pub_hex)
    try:
        loop._pull_once()
    finally:
        srv.stop()
    assert node_stmts.revoked_ids() == set()
