#!/usr/bin/env bash
# Nightly deep property-test run — exhaustive Hypothesis pass over tests/deep/.
#
# Kept out of the regular suite (marker `deep`, deselected by default) so day-
# to-day unit runs stay ~30s. This run is sized for a nightly: thousands of
# examples per property, long stateful sequences, no deadlines.
#
#   scripts/deep-tests.sh              # the nightly run
#   pytest tests/deep -m deep -q       # quick sanity pass (stock example counts)
#
# Failures print a `@reproduce_failure` blob — paste it onto the failing test
# to replay the exact case in a normal fast run. Hypothesis also caches failing
# examples in .hypothesis/, so a later plain run of tests/deep retries them
# first.
set -euo pipefail
cd "$(dirname "$0")/.."
export HYPOTHESIS_PROFILE=deep
exec python -m pytest tests/deep -m deep -q "$@"
