"""
CA concurrency (finding F1, second review). The control plane is now a
ThreadingHTTPServer, so the CA is called from multiple request threads at once.
Two of its operations are unsynchronized:

  * issue() enforces hostname uniqueness by check-then-act (_hostname_owner then
    _save_node_caps) — a TOCTOU that lets two identities claim one name; and
  * _atomic_write_text uses a FIXED temp path, so two writers to the same file
    race on that temp and one can hit FileNotFoundError at the rename.

These tests drive the races with a barrier (all threads fire together) and must
pass once the CA takes a lock across the check-then-act region and writes via a
unique temp name.
"""
import json
import threading

from greasewood.ca import CA, _atomic_write_text
from greasewood.keys import CAKeys, NodeKeys


def _run_barrier(n, fn):
    """Start n threads that all block on a barrier, then call fn(i) together."""
    barrier = threading.Barrier(n)
    results = [None] * n

    def worker(i):
        barrier.wait()
        try:
            results[i] = ("ok", fn(i))
        except Exception as e:  # noqa: BLE001
            results[i] = ("err", e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def test_concurrent_same_hostname_issue_yields_one_owner(tmp_path):
    """N different identities racing to claim the SAME hostname: exactly one may
    win; the rest must be refused. Without a lock the check-then-act interleaves
    and several persist the same name."""
    ca = CA(CAKeys.generate(), tmp_path)
    nodes = [NodeKeys.generate() for _ in range(16)]

    def claim(i):
        return ca.issue(nodes[i].id_pub_bytes, nodes[i].wg_pub_bytes,
                        "dbmaster", ["segment:mesh"])

    results = _run_barrier(len(nodes), claim)
    ok = [r for r in results if r[0] == "ok"]

    # The authoritative check: exactly one registry file claims the name.
    owners = []
    for p in (tmp_path / "nodes").glob("*.json"):
        if json.loads(p.read_text()).get("hostname") == "dbmaster":
            owners.append(p.stem)
    assert len(owners) == 1, f"{len(owners)} nodes claimed 'dbmaster' (want 1)"
    assert len(ok) == 1, f"{len(ok)} issue() calls succeeded (want 1)"


def test_atomic_write_survives_concurrent_writers(tmp_path):
    """Many threads writing DIFFERENT content to the same path at once must all
    succeed and leave valid, self-consistent content — never a crash on the
    rename or a truncated/mixed file."""
    target = tmp_path / "nodes" / "same.json"
    target.parent.mkdir(parents=True)
    payloads = [json.dumps({"n": i, "pad": "x" * 500}) for i in range(24)]

    def write(i):
        _atomic_write_text(target, payloads[i])

    # A few rounds to make the race reliable.
    for _ in range(5):
        results = _run_barrier(len(payloads), write)
        errs = [r[1] for r in results if r[0] == "err"]
        assert not errs, f"writer raised under contention: {errs[:3]}"
        # Whatever won, the file must be exactly one writer's payload.
        text = target.read_text()
        assert text in payloads, "file content is not any single writer's payload"


def test_concurrent_ca_cert_pem_generates_one_cert(tmp_path):
    """Concurrent first-issuance of the x509 CA cert must produce exactly ONE
    cert, not a different one per thread (a check-then-create race). Every
    caller must see identical bytes."""
    ca = CA(CAKeys.generate(), tmp_path)
    results = _run_barrier(16, lambda i: ca.ca_cert_pem())
    pems = {r[1] for r in results if r[0] == "ok"}
    assert len(pems) == 1, f"{len(pems)} distinct CA certs generated (want 1)"
