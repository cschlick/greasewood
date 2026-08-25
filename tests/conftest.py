"""
Hypothesis profiles: fast by default, exhaustive for the nightly deep run.

The regular suite must stay fast, so the default profile keeps Hypothesis's
stock example counts (and the fast property tests additionally pin small
max_examples inline). The `deep` profile is for the nightly run of
tests/deep/ — thousands of examples per property, no deadlines, longer
stateful sequences:

    HYPOTHESIS_PROFILE=deep python -m pytest tests/deep -m deep -q

(or scripts/deep-tests.sh). Deep tests deliberately do NOT set max_examples
inline, so the profile alone decides how hard they hammer — under the default
profile they run at stock counts, which is what makes a quick sanity pass of
tests/deep/ cheap.
"""
import os

from hypothesis import HealthCheck, settings

settings.register_profile("default", settings())
# Sized from measurement: 1k examples ≈ 55s for the whole tier, so 10k ≈ 9min —
# squarely nightly-shaped, with room to grow the tier before it matters.
settings.register_profile("deep", settings(
    max_examples=10_000,
    deadline=None,
    stateful_step_count=50,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large,
                           HealthCheck.filter_too_much],
    print_blob=True,      # failures print a reproduction blob for the fast suite
))
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))


import pytest


@pytest.fixture(autouse=True)
def _pin_linux_platform(monkeypatch):
    """Pin the platform seam to Linux for every test. The suite's fixtures and
    assertions speak the Linux data plane (`ip` argv, nftables, systemd paths),
    and must pass identically on a macOS dev box and the Linux CI — the OS the
    suite happens to run on must never leak into what it asserts. Darwin-path
    tests opt in explicitly by re-setting IS_MACOS/IS_LINUX themselves (their
    monkeypatch runs after this autouse fixture)."""
    from greasewood import platform as gwplat
    monkeypatch.setattr(gwplat, "IS_LINUX", True)
    monkeypatch.setattr(gwplat, "IS_MACOS", False)
