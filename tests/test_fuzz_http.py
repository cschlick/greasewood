"""
No-500s fuzz: the control plane's error contract is that malformed or
malicious input yields a clean 4xx — never an unhandled exception / 5xx.
(The naive-timestamp bug fixed in the 2026-07 audit was exactly this class:
parsed fine, blew up later as a TypeError.)

Strategy: mutate structurally-valid /publish, /renew, and /cert payloads
(drop a key / swap a value for typed garbage) and also throw entirely
arbitrary JSON and non-JSON bodies, asserting every response is < 500 and
the server stays healthy afterward.
"""
import datetime as dt
import json
import secrets
import urllib.error
import urllib.request

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from greasewood.ca import CA
from greasewood.directory import Directory
from greasewood.keys import CAKeys, NodeKeys
from greasewood.server import ControlServer
from greasewood.wire import CertRequest, NodeRecord, RenewRequest

_UTC = dt.timezone.utc

ENDPOINTS = ["/publish", "/renew", "/cert"]

# Typed garbage that historically hides parser bugs: wrong types, bad base64,
# naive timestamps, huge ints, empty containers.
GARBAGE = [
    None, True, 0, -1, 2**70, 1.5, "", "x", "not-b64!!!", "AAAA",
    "2026-07-01T12:00:00",          # naive ts (the fixed bug's shape)
    "9999-99-99T99:99:99Z", [], {}, ["a", 1], {"k": "v"}, "\x00￿",
]


@pytest.fixture(scope="module")
def fuzz_server(tmp_path_factory):
    """One hub-mode server (CA active so /renew and /cert are live) shared by
    all examples — module-scoped so hypothesis may reuse it."""
    tmp = tmp_path_factory.mktemp("fuzz-hub")
    ca_keys = CAKeys.generate()
    ca = CA(ca_keys, tmp)
    node = NodeKeys.generate()
    ca.issue(node.id_pub_bytes, node.wg_pub_bytes, "fuzz-node",
             ["segment:mesh", "tls"])
    srv = ControlServer(
        listen="[::1]:0", directory=Directory(),
        get_ca_pubs=lambda: [ca_keys.ca_pub_bytes], get_revoked=set,
        ca=ca, mesh_domain="internal",
    )
    port = srv._server.server_address[1]
    srv.start()

    now = dt.datetime.now(_UTC).replace(microsecond=0)
    cred = ca.issue(node.id_pub_bytes, node.wg_pub_bytes, "fuzz-node",
                    ["segment:mesh", "tls"])
    baselines = {
        "/publish": NodeRecord(
            id_pub=node.id_pub_bytes, seq=1, endpoints=[], inbound="yes",
            cred=cred,
        ).sign(node.id_priv).to_dict(),
        "/renew": RenewRequest(
            id_pub=node.id_pub_bytes, wg_pub=node.wg_pub_bytes,
            nonce=secrets.token_hex(8), ts=now,
        ).sign(node.id_priv).to_dict(),
        "/cert": CertRequest(
            id_pub=node.id_pub_bytes, leaf_pub=bytes(32), cn="",
            dns=[], ips=[], nonce=secrets.token_hex(8), ts=now,
        ).sign(node.id_priv).to_dict(),
    }
    yield port, baselines
    srv.stop()


def _post_raw(port: int, path: str, body: bytes) -> int:
    req = urllib.request.Request(
        f"http://[::1]:{port}{path}", data=body,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code


def _healthy(port: int) -> bool:
    with urllib.request.urlopen(f"http://[::1]:{port}/health", timeout=10) as r:
        return json.loads(r.read())["status"] == "ok"


json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=20),
    lambda children: st.lists(children, max_size=4)
    | st.dictionaries(st.text(max_size=10), children, max_size=4),
    max_leaves=10,
)


@settings(deadline=None, max_examples=60,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(endpoint=st.sampled_from(ENDPOINTS), data=st.data())
def test_mutated_valid_payloads_never_500(fuzz_server, endpoint, data):
    """Take a fully valid signed payload and break exactly one thing —
    the mutations most likely to slip past the first parse and explode
    somewhere deeper."""
    port, baselines = fuzz_server
    body = dict(baselines[endpoint])
    key = data.draw(st.sampled_from(sorted(body)))
    if data.draw(st.booleans()):
        del body[key]
    else:
        body[key] = data.draw(st.sampled_from(GARBAGE))
    status = _post_raw(port, endpoint, json.dumps(body).encode())
    assert status < 500, f"{endpoint} 5xx on mutated key {key!r}: {status}"


@settings(deadline=None, max_examples=40,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(endpoint=st.sampled_from(ENDPOINTS), payload=json_values)
def test_arbitrary_json_never_500(fuzz_server, endpoint, payload):
    port, _ = fuzz_server
    status = _post_raw(port, endpoint, json.dumps(payload).encode())
    assert status < 500, f"{endpoint} 5xx on {payload!r}"


@settings(deadline=None, max_examples=30,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(endpoint=st.sampled_from(ENDPOINTS), body=st.binary(max_size=200))
def test_non_json_bodies_never_500(fuzz_server, endpoint, body):
    port, _ = fuzz_server
    status = _post_raw(port, endpoint, body)
    assert status < 500, f"{endpoint} 5xx on raw bytes"


def test_server_still_healthy_after_fuzzing(fuzz_server):
    """Runs after the fuzz cases (file order): the barrage must not have
    wedged or killed the server."""
    port, _ = fuzz_server
    assert _healthy(port)
