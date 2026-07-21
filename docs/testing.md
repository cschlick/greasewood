# Testing

```bash
pip install -e '.[test]'   # or: pip install pytest
python -m pytest           # unit tests (fast, no privileges)
```

Integration and stress tests run real WireGuard inside privileged Podman
containers and are skipped by the default run. They need Podman 4+ and the
WireGuard kernel module:

```bash
# Functional tests: mesh connectivity, re-enrollment, rename, TLS, reboot
# survival, and a full anchor re-root A→B (two live anchors, fleet migrates to B's CA) —
# all on real containers, under tests/integration/
python -m pytest tests/integration/

# Scale tests — grow the mesh to many nodes and verify full convergence.
# Gated behind GW_STRESS; knobs: GW_STRESS_N / _WAVES / _WORKERS.
GW_STRESS=1 GW_STRESS_N=8 python -m pytest tests/integration/test_stress.py -v -s

# Soak — hold a mesh up across many renewal cycles, sampling continuously.
GW_SOAK=1 python -m pytest tests/integration/test_soak.py -v -s

# Monkey / chaos — a many-container mesh under a seeded storm of disruptions,
# with a topology + port-filter ORACLE asserted after every step and real
# service traffic (ssh/http/postgres/nfs ports) exercising the filter.
# Deterministic: the same seed replays the exact sequence, and a divergence
# prints the seed + a model-vs-reality diff.
GW_MONKEY=1 GW_MONKEY_STEPS=20 python -m pytest tests/integration/test_monkey.py -v -s
```

**The monkey test's oracle** (`tests/integration/chaos/model.py`) is a pure,
*independent* reimplementation of greasewood's topology + port rules — not a
call into `greasewood.policy`, so a bug there is caught, not mirrored. It's
unit-tested and cross-checked against the real policy engine on 300 fuzzed
meshes in `tests/test_chaos_model.py` (which runs in the fast suite), so the
judge is proven correct before it judges. It models network reality too, not
just policy: an injected **underlay partition** makes the oracle expect exactly
that one tunnel to drop (direct-or-fail) while the rest stay up.

The chaos vocabulary is weighted toward what actually broke the real fleet — a
killed daemon (the `killall python` incident), a deleted interface, an
`nft flush ruleset` wiping the port table — and adds partitions with heal,
anchor kill (offline tolerance: the data plane must survive), corrupt-cache
cold restarts, revoke/rejoin, role churn, and full policy rewrites. Each op
mutates the live containers and the model identically, so a single missed
tunnel or leaked port anywhere fails the step with a replayable seed.

**Deep property tests** (`tests/deep/`, marker `deep`) are the exhaustive
Hypothesis tier, kept out of the default run so it stays ~30s. They drive
state machines and adversarial inputs against the security-critical invariants:
credential/record tamper resistance (the wire format signs *canonical
semantics* — equivalent encodings verify, changed semantics never do), the CA
registry's hostname-uniqueness/revocation/rollback rules under arbitrary
operation interleavings, directory merge monotonicity, the audit→narrate logfmt
round trip (including control-character injection via wire-supplied hostnames),
and `/etc/hosts` never damaging user content. Their first run found two real
bugs the fast suite had missed — an audit-log injection via control characters
in hostnames, and a unicode-line-boundary corruption in hosts-file rewrites —
which is the tier's job.

```bash
# Quick sanity pass of the deep tier: stock example counts, a few seconds.
python -m pytest tests/deep -m deep

# THE NIGHTLY: 10,000 examples per property, ~9 minutes. Point cron or a CI
# schedule at this. Extra args pass through to pytest (-k, -x, ...).
scripts/deep-tests.sh

# Same thing spelled out (the script just sets the Hypothesis profile):
HYPOTHESIS_PROFILE=deep python -m pytest tests/deep -m deep -q
```

When the nightly fails, Hypothesis prints the shrunken falsifying example plus
a `@reproduce_failure(...)` blob — paste that decorator onto the failing test
to replay the exact case in a normal fast run. Failing examples are also cached
in `.hypothesis/` (gitignored), so a plain re-run of `tests/deep` retries them
first even without the blob.
