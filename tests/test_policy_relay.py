"""
Relay is granted, not inferred.

Relay is decrypt-and-forward: the anchor terminates both tunnels and can read
what passes between the pair. So it takes two independent yeses — the anchor
offering relay at all (`gw relay on`), and a grant naming THIS pair as
relayable (`relay = true`). Neither implies the other, and a pair that merely
fails to connect gets nothing.
"""
import pytest

from greasewood.policy import parse_grants_toml, peers_allowed, relay_allowed


def _grants(text):
    return parse_grants_toml(text)


class TestRelayGrantSchema:
    def test_relay_defaults_to_absent(self):
        g = _grants('[[grant]]\nfrom=["a"]\nto=["b"]\nports=["*"]\n')
        # Omitted rather than false: a table opting nobody in stays byte-identical
        # to one written before the key existed, so old nodes still verify it.
        assert "relay" not in g[0]

    def test_relay_true_is_carried(self):
        g = _grants('[[grant]]\nfrom=["a"]\nto=["b"]\nports=["*"]\nrelay=true\n')
        assert g[0]["relay"] is True

    def test_relay_must_be_a_bool(self):
        with pytest.raises(ValueError, match="relay must be true or false"):
            _grants('[[grant]]\nfrom=["a"]\nto=["b"]\nrelay="yes"\n')

    def test_a_typo_is_still_a_hard_error(self):
        with pytest.raises(ValueError, match="unknown key"):
            _grants('[[grant]]\nfrom=["a"]\nto=["b"]\nrelayy=true\n')


class TestRelayAllowed:
    A, B = ["role:a"], ["role:b"]

    def test_a_plain_grant_does_not_authorize_relay(self):
        g = _grants('[[grant]]\nfrom=["a"]\nto=["b"]\nports=["*"]\n')
        assert peers_allowed(self.A, self.B, g) is True      # they may peer…
        assert relay_allowed(self.A, self.B, g) is False     # …but not via the anchor

    def test_relay_true_authorizes_the_pair(self):
        g = _grants('[[grant]]\nfrom=["a"]\nto=["b"]\nports=["*"]\nrelay=true\n')
        assert relay_allowed(self.A, self.B, g) is True
        assert relay_allowed(self.B, self.A, g) is True      # either direction

    def test_relay_is_scoped_to_the_granted_pair(self):
        g = _grants('[[grant]]\nfrom=["a"]\nto=["b"]\nports=["*"]\nrelay=true\n')
        assert relay_allowed(self.A, ["role:c"], g) is False

    def test_no_table_means_no_relay(self):
        # Unlike peers_allowed, a flat mesh does NOT get relay — there is no
        # grant to carry the opt-in, and silently relaying everything is
        # precisely what this is meant to prevent.
        assert peers_allowed(self.A, self.B, None) is True
        assert relay_allowed(self.A, self.B, None) is False

    def test_the_anchor_wildcard_does_not_imply_relay(self):
        # role:* peers with everyone (hardwired), but that must not smuggle in
        # a relay permission nobody wrote down.
        g = _grants('[[grant]]\nfrom=["a"]\nto=["b"]\nports=["*"]\n')
        assert peers_allowed(["role:*"], self.B, g) is True
        assert relay_allowed(["role:*"], self.B, g) is False

    def test_host_grants_work_for_relay_too(self):
        g = _grants('[[grant]]\nfrom=["host:melvin"]\nto=["host:nas"]\n'
                    'ports=["*"]\nrelay=true\n')
        assert relay_allowed(["role:node"], ["role:node"], g,
                             "melvin", "nas") is True
        assert relay_allowed(["role:node"], ["role:node"], g,
                             "melvin", "bb") is False
