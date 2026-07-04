"""
DEEP: CA registry state machine.

Drives arbitrary interleavings of issue / re-issue / rename / forget / revoke
against a real on-disk registry, mirroring them in a plain-dict model, and
checks the invariants that this week's field incident showed matter:

  * live sanitized hostnames are UNIQUE, and hostname_owner agrees with the
    model about who owns each;
  * a revoked id can never (re-)enroll;
  * forget frees the name for a different identity (the enrollment-rollback
    guarantee);
  * a node re-issuing under its own id keeps/renames its record without
    tripping the uniqueness check.
"""
import json
from pathlib import Path

import pytest
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, rule

from greasewood.ca import CA
from greasewood.hosts import sanitize
from greasewood.keys import CAKeys

pytestmark = pytest.mark.deep

# A small name pool with deliberate sanitize-collisions ("db" vs "DB!" vs "db-")
# so uniqueness is exercised on the sanitized form, not the raw string.
NAMES = st.sampled_from(
    ["db", "DB!", "db-", "web1", "web_1", "nats01", "Nats01", "x" * 63, "ops@node"])


class RegistryMachine(RuleBasedStateMachine):
    def __init__(self):
        super().__init__()
        self._n = 0

    @initialize(tmp=st.nothing().map(lambda _: None) | st.none())
    def setup(self, tmp):
        import tempfile
        self.dir = Path(tempfile.mkdtemp())
        self.ca = CA(CAKeys.generate(), self.dir)
        self.model: dict[bytes, str] = {}     # id_pub -> raw hostname
        self.revoked: set[bytes] = set()

    def teardown(self):
        # 10k nightly runs would otherwise litter /tmp with registry dirs.
        import shutil
        if hasattr(self, "dir"):
            shutil.rmtree(self.dir, ignore_errors=True)

    # -- helpers -------------------------------------------------------------
    def _new_id(self) -> bytes:
        self._n += 1
        return self._n.to_bytes(32, "big")

    def _owner_in_model(self, name: str, but: "bytes | None" = None):
        want = sanitize(name)
        for i, h in self.model.items():
            if i != but and sanitize(h) == want:
                return i
        return None

    def _write_revoked(self):
        (self.dir / "revoked.json").write_text(
            json.dumps({"revoked": [i.hex() for i in self.revoked]}))

    # -- rules ---------------------------------------------------------------
    @rule(name=NAMES)
    def issue_new(self, name):
        id_pub = self._new_id()
        taken = self._owner_in_model(name) is not None
        if taken:
            with pytest.raises(ValueError):
                self.ca.issue(id_pub, b"\x02" * 32, name, ["segment:mesh"])
        else:
            self.ca.issue(id_pub, b"\x02" * 32, name, ["segment:mesh"])
            self.model[id_pub] = name

    @rule(name=NAMES, data=st.data())
    def reissue_or_rename(self, name, data):
        if not self.model:
            return
        id_pub = data.draw(st.sampled_from(sorted(self.model)), label="which")
        taken_by_other = self._owner_in_model(name, but=id_pub) is not None
        if id_pub in self.revoked or taken_by_other:
            # A revoked id can never re-enroll; a taken name refuses anyone else.
            with pytest.raises(ValueError):
                self.ca.issue(id_pub, b"\x02" * 32, name, ["segment:mesh"])
        else:
            # Same id may keep its name or rename to a free one.
            self.ca.issue(id_pub, b"\x02" * 32, name, ["segment:mesh"])
            self.model[id_pub] = name

    @rule(data=st.data())
    def forget(self, data):
        if not self.model:
            return
        id_pub = data.draw(st.sampled_from(sorted(self.model)), label="which")
        assert self.ca.forget_node(id_pub) is True
        del self.model[id_pub]

    @rule(data=st.data())
    def revoke_then_issue_refused(self, data):
        if not self.model:
            return
        id_pub = data.draw(st.sampled_from(sorted(self.model)), label="which")
        self.revoked.add(id_pub)
        self._write_revoked()
        with pytest.raises(ValueError):
            self.ca.issue(id_pub, b"\x02" * 32, "fresh-name-for-revoked",
                          ["segment:mesh"])

    @rule(data=st.data(), caps=st.lists(
        st.sampled_from(["segment:mesh", "segment:prod", "tls"]), min_size=1, max_size=3))
    def set_caps_keeps_name(self, data, caps):
        if not self.model:
            return
        id_pub = data.draw(st.sampled_from(sorted(self.model)), label="which")
        self.ca.set_caps(id_pub, caps)
        hostname, got = self.ca.node_info(id_pub)
        assert sanitize(hostname) == sanitize(self.model[id_pub])
        assert got == caps

    # -- invariants ----------------------------------------------------------
    @invariant()
    def registry_matches_model(self):
        if not hasattr(self, "model"):
            return
        for id_pub, hostname in self.model.items():
            assert self.ca.hostname_owner(hostname) == id_pub.hex()
            info = self.ca.node_info(id_pub)
            assert info is not None and sanitize(info[0]) == sanitize(hostname)
        # A name nobody in the model holds must be free.
        assert self.ca.hostname_owner("definitely-free-name") is None

    @invariant()
    def sanitized_names_unique(self):
        if not hasattr(self, "model"):
            return
        seen = [sanitize(h) for h in self.model.values()]
        assert len(seen) == len(set(seen))


TestRegistryMachine = RegistryMachine.TestCase
