"""
StaleSweep — the holder's periodic GC tick. With the registry gone, one prune
does the whole job: dropping the aged-out record ends both the node's
visibility AND its ability to renew (renewal re-issues from the record), then
persists so peers converge.
"""
import datetime as dt

from greasewood.ca import CA, UnknownNodeError
from greasewood.directory import Directory, DROP_GRACE
from greasewood.keys import CAKeys, NodeKeys, derive_addr
from greasewood.statements import StatementLog
from greasewood.sweep import StaleSweep
from greasewood.wire import Credential, NodeRecord

_UTC = dt.timezone.utc


def _rec(ca_keys, k, name, exp):
    iat = exp - dt.timedelta(hours=24)
    cred = Credential(id_pub=k.id_pub_bytes, wg_pub=k.wg_pub_bytes,
                      addr=derive_addr(k.id_pub_bytes), hostname=name,
                      caps=["role:mesh"], iat=iat, exp=exp).sign(ca_keys.ca_priv)
    return NodeRecord(id_pub=k.id_pub_bytes, seq=1, endpoints=[],
                      cred=cred).sign(k.id_priv)


def test_sweep_tick_prunes_aged_records_and_persists(tmp_path):
    ca_keys = CAKeys.generate()
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    live, dead = NodeKeys.generate(), NodeKeys.generate()

    directory = Directory()
    directory.put(_rec(ca_keys, live, "live", now + dt.timedelta(hours=12)))
    directory.put(_rec(ca_keys, dead, "dead",
                       now - (DROP_GRACE + dt.timedelta(days=2))))
    cache = tmp_path / "directory.json"

    StaleSweep(directory, cache, statements=StatementLog())._tick()

    # The record is gone from the view AND from the persisted cache.
    assert {r.cred.hostname for r in directory.all()} == {"live"}
    assert cache.exists()
    reloaded = Directory.load(cache)
    assert {r.cred.hostname for r in reloaded.all()} == {"live"}

    # And the authorization consequence: with no record, renewal has nothing
    # to re-issue from — the node must re-enroll through the door.
    ca = CA(ca_keys, tmp_path, directory=directory, statements=StatementLog())
    assert ca.node_info(dead.id_pub_bytes) is None
    assert ca.node_info(live.id_pub_bytes) is not None


def test_sweep_tick_noop_when_nothing_stale(tmp_path):
    ca_keys = CAKeys.generate()
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    k = NodeKeys.generate()
    directory = Directory()
    directory.put(_rec(ca_keys, k, "live", now + dt.timedelta(hours=12)))
    cache = tmp_path / "directory.json"
    StaleSweep(directory, cache, statements=StatementLog())._tick()
    assert directory.size() == 1
    assert not cache.exists()          # nothing pruned → nothing rewritten


def test_sweep_never_reaps_the_protected_holder(tmp_path):
    """The holder passes its own id as `protect`: even when its credential is
    long past drop grace (a stalled self-renewal — field incident: a renewal
    loop that slept through a boot-time clock step), the sweep must not prune
    the record the fleet's path to the control plane hangs on. An
    equally-stale ordinary node is still reaped."""
    ca_keys = CAKeys.generate()
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    stale_exp = now - (DROP_GRACE + dt.timedelta(days=2))
    holder, dead = NodeKeys.generate(), NodeKeys.generate()

    directory = Directory()
    directory.put(_rec(ca_keys, holder, "anchor", stale_exp))
    directory.put(_rec(ca_keys, dead, "dead", stale_exp))
    cache = tmp_path / "directory.json"

    StaleSweep(directory, cache, statements=StatementLog(),
               protect=holder.id_pub_hex)._tick()

    assert {r.cred.hostname for r in directory.all()} == {"anchor"}
