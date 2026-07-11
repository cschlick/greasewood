"""
DEEP: directory merge state machine.

The directory is last-writer-wins by strictly-greater seq, gated by structural
verification (self-sig + addr derivation + id/cred consistency). Properties:

  * the stored record for each id always carries the highest seq ever accepted
    (no downgrade, no resurrection of older records);
  * merge is idempotent (replaying anything already merged accepts 0);
  * a tampered record NEVER enters, whatever its seq;
  * save/load round-trips the exact record set.

A fixed pool of signed identities is built once; Hypothesis drives who
publishes what seq in what order.
"""
import datetime as dt
from pathlib import Path

import pytest
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, rule

from greasewood.directory import Directory
from greasewood.keys import CAKeys, NodeKeys
from greasewood.wire import Credential, NodeRecord

pytestmark = pytest.mark.deep

_UTC = dt.timezone.utc
_CA = CAKeys.generate()
_NOW = dt.datetime.now(_UTC).replace(microsecond=0)


def _identity(name: str):
    k = NodeKeys.generate()
    cred = Credential(id_pub=k.id_pub_bytes, wg_pub=k.wg_pub_bytes, addr=k.addr,
                      hostname=name, caps=["segment:mesh"],
                      iat=_NOW, exp=_NOW + dt.timedelta(days=365)).sign(_CA.ca_priv)
    return k, cred


POOL = [_identity(f"node{i}") for i in range(5)]


def _record(idx: int, seq: int, endpoints: list) -> NodeRecord:
    k, cred = POOL[idx]
    return NodeRecord(id_pub=k.id_pub_bytes, seq=seq, endpoints=endpoints,
                      cred=cred).sign(k.id_priv)


class DirectoryMachine(RuleBasedStateMachine):
    @initialize()
    def setup(self):
        import tempfile
        self.d = Directory()
        self.model: dict[str, int] = {}     # id_pub hex -> highest accepted seq
        self.tmp = Path(tempfile.mkdtemp())
        self._saves = 0

    def teardown(self):
        import shutil
        if hasattr(self, "tmp"):
            shutil.rmtree(self.tmp, ignore_errors=True)

    @rule(idx=st.integers(0, len(POOL) - 1), seq=st.integers(0, 40),
          eps=st.lists(st.sampled_from(
              ["203.0.113.7:51900", "[2001:db8::9]:51900"]), max_size=2))
    def publish(self, idx, seq, eps):
        rec = _record(idx, seq, eps)
        accepted = self.d.merge([rec])
        key = rec.id_pub.hex()
        prev = self.model.get(key)
        if prev is None or seq > prev:
            assert accepted == 1
            self.model[key] = seq
        else:
            assert accepted == 0            # equal or lower seq never downgrades

    @rule(idx=st.integers(0, len(POOL) - 1), seq=st.integers(0, 40))
    def tampered_record_never_enters(self, idx, seq):
        rec = _record(idx, seq, [])
        d = rec.to_dict()
        d["endpoints"] = list(d["endpoints"]) + ["[2001:db8::dead]:51820"]  # break self-sig
        forged = NodeRecord.from_dict(d)
        assert self.d.merge([forged]) == 0
        got = self.d.get(rec.id_pub.hex())
        assert got is None or got.seq == self.model.get(rec.id_pub.hex())

    @rule()
    def merge_is_idempotent(self):
        current = self.d.all()
        assert self.d.merge(current) == 0

    @rule()
    def save_load_roundtrip(self):
        self._saves += 1
        p = self.tmp / f"directory-{self._saves}.json"
        self.d.save(p)
        again = Directory.load(p)
        assert {r.id_pub.hex(): r.seq for r in again.all()} == self.model

    @invariant()
    def stored_seqs_match_model(self):
        if not hasattr(self, "d"):
            return
        assert {r.id_pub.hex(): r.seq for r in self.d.all()} == self.model


TestDirectoryMachine = DirectoryMachine.TestCase
