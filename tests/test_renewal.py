"""
Unit test for RenewalLoop's retry/backoff — the resilience guarantee that keeps
the mesh from tearing down on a transient hub failure. Integration only ever
exercises successful renewals; this drives the failure path deterministically
(no real sleeps: _stop.wait is stubbed).
"""
import datetime as dt

from greasewood.directory import Directory
from greasewood.keys import CAKeys, NodeKeys
from greasewood.renewal import RenewalLoop
from greasewood.wire import Credential

_UTC = dt.timezone.utc


def _cred(node, ca):
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    return Credential(
        id_pub=node.id_pub_bytes, wg_pub=node.wg_pub_bytes, addr=node.addr,
        hostname="n1", caps=["mesh"], iat=now, exp=now + dt.timedelta(hours=1),
    ).sign(ca.ca_priv)


def test_renewal_retries_with_exponential_backoff_then_stops(tmp_path, monkeypatch):
    node = NodeKeys.generate()
    ca = CAKeys.generate()
    loop = RenewalLoop(
        node_keys=node,
        directory=Directory(),
        get_root_url=lambda: "http://[::1]:0",
        current_cred=_cred(node, ca),
        inbound="yes",
        hostname="n1",
        endpoints=[],
        cache_path=tmp_path / "dir.json",
    )

    attempts = {"n": 0}

    def boom():
        attempts["n"] += 1
        raise RuntimeError("hub down")

    monkeypatch.setattr(loop, "_renew_and_publish", boom)
    monkeypatch.setattr(loop, "_next_delay", lambda: 0.0)

    waits = []

    def fake_wait(t):
        waits.append(t)
        return len(waits) >= 3  # let the stop event fire during the 2nd backoff

    monkeypatch.setattr(loop._stop, "wait", fake_wait)

    loop.run()

    # waits[0] is the outer _next_delay(0.0); then exponential backoffs 30, 60.
    assert waits[0] == 0.0
    assert waits[1] == 30
    assert waits[2] == 60
    assert attempts["n"] == 2  # two failed attempts before the stop fired
