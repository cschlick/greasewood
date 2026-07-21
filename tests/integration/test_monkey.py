"""
Monkey / chaos test: a live many-container greasewood mesh under a seeded,
randomized storm of disruptions — killed daemons, deleted interfaces,
revocations, role churn, policy rewrites, new nodes — with the full topology +
port-filter oracle asserted after every step, and real service traffic
(ssh/http/postgres/nfs/… ports) exercising the port filter throughout.

The point is brutal robustness: does the mesh always converge to exactly what
the policy declares, no matter what order the chaos arrives in? A pure model
(chaos/model.py, itself unit-tested and cross-checked against greasewood's
policy engine in tests/test_chaos_model.py) predicts the answer; the driver
throws the chaos and the verifier confirms reality matches.

Gated behind GW_MONKEY=1 (spins up many privileged containers, minutes to run).
Deterministic: the same GW_MONKEY_SEED replays the exact sequence.

  GW_MONKEY=1 pytest tests/integration/test_monkey.py -v -s

Tunables:
  GW_MONKEY_SEED    RNG seed                        (default 0 = time-derived)
  GW_MONKEY_STEPS   chaos operations to run         (default 20)
  GW_MONKEY_NODES   initial non-anchor node count   (default 4)
  GW_MONKEY_CONVERGE  per-step convergence timeout   (default 150s)
"""
import os
import time

import pytest

from .chaos.driver import Fleet, pick_op
from .chaos.verify import verify, wait_converge

pytestmark = [pytest.mark.integration, pytest.mark.monkey]

if not os.environ.get("GW_MONKEY"):
    pytest.skip("monkey test is gated — set GW_MONKEY=1 to run",
                allow_module_level=True)

SEED = int(os.environ.get("GW_MONKEY_SEED", "0")) or int(time.time())
STEPS = int(os.environ.get("GW_MONKEY_STEPS", "20"))
NODES = int(os.environ.get("GW_MONKEY_NODES", "4"))
CONVERGE = int(os.environ.get("GW_MONKEY_CONVERGE", "150"))


def test_mesh_survives_chaos(gw_image, gw_network):
    import random
    rng = random.Random(SEED)
    timeline = []

    def log(msg):
        line = f"[{time.strftime('%H:%M:%S')}] {msg}"
        timeline.append(line)
        print(line, flush=True)

    log(f"=== monkey test · seed={SEED} · {NODES} nodes · {STEPS} steps ===")
    log(f"    replay with GW_MONKEY_SEED={SEED}")
    fleet = Fleet(gw_image, gw_network, rng, log)
    try:
        fleet.bootstrap(NODES)
        # An initial random policy + services, then a clean baseline check.
        fleet.randomize_grants()
        fleet.deploy_services()

        def checkpoint(label):
            converged = wait_converge(fleet, timeout=CONVERGE)
            problems = verify(fleet)
            if not converged and not problems:
                # converge timed out but the oracle is satisfied — a slow
                # settle, not a fault; record it and move on.
                log(f"    {label}: slow converge (oracle OK)")
            if problems:
                dump = "\n".join(f"      {p}" for p in problems)
                tl = "\n".join(timeline[-40:])
                pytest.fail(
                    f"\nORACLE DIVERGENCE after {label} (seed={SEED}):\n{dump}\n"
                    f"\n--- recent timeline ---\n{tl}\n"
                    f"\nreplay: GW_MONKEY_SEED={SEED} GW_MONKEY_STEPS={STEPS} "
                    f"GW_MONKEY_NODES={NODES} GW_MONKEY=1 pytest "
                    f"tests/integration/test_monkey.py -v -s")
            log(f"    {label}: ✓ oracle satisfied "
                f"({len(fleet._nonanchor())} live nodes)")

        checkpoint("baseline")

        for step in range(1, STEPS + 1):
            op = pick_op(rng)
            log(f"step {step}/{STEPS}: {op.__name__}")
            detail = op(fleet)
            log(f"    {detail}")
            checkpoint(f"step {step} ({op.__name__})")

        log(f"=== survived {STEPS} chaos steps · seed={SEED} ===")
    finally:
        fleet.teardown()
