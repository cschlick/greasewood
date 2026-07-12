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
```

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
