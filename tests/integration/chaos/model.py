"""
The chaos test's oracle: a pure model of what a greasewood mesh SHOULD do,
reimplemented INDEPENDENTLY of greasewood's own policy engine.

This is deliberate. If the oracle called greasewood.policy.peers_allowed, a bug
in that function would be mirrored in the expectation and the test would pass on
its own defect. So the topology + port derivation here is written from the
README's stated rules, from scratch — greasewood and this model must agree by
each being correct, not by sharing code.

The model tracks the declared state (members, their roles, the grant table) and
answers three questions the driver checks against the live containers:

  tunnel(a, b)          should a WireGuard peer link exist between them?
  reachable(c, s, port) should a fresh TCP connection c -> s:port succeed?
  port_blocked(c, s, p) a tunnel exists but this specific port is ungranted

Everything here is plain data + pure functions — unit-tested in the normal
suite (tests/test_chaos_model.py), no containers involved.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace


# A service is just a well-known TCP port with a familiar name. The chaos test
# runs a trivial TCP listener on each — the point is exercising greasewood's
# PORT FILTER across many ports and roles, not the services' own behavior.
SERVICE_PORTS = {
    "ssh": 22,
    "http": 80,
    "https": 443,
    "postgres": 5432,
    "nfs": 2049,
    "redis": 6379,
    "app": 8000,
}

# Roles never assignable to a node (the anchor's own).
RESERVED = {"*", "anchor"}


@dataclass(frozen=True)
class Node:
    hostname: str
    roles: tuple = ()               # role names (no 'role:' prefix, no reserved)
    is_anchor: bool = False
    alive: bool = True              # daemon running?
    revoked: bool = False           # revoked at the anchor?

    def tags(self) -> set:
        """The grant-matchable tags: roles + the derived host:<name>, plus '*'
        for the anchor. Mirrors greasewood.policy.node_tags, independently."""
        t = {f"host:{self.hostname}"} | set(self.roles)
        if self.is_anchor:
            t.add("*")
        return t


@dataclass(frozen=True)
class Grant:
    src: tuple                      # from-tags
    dst: tuple                      # to-tags
    ports: tuple                    # 'tcp/22' | 'udp/53' | '*'


@dataclass
class MeshModel:
    """The declared state of the mesh and the oracle over it."""
    nodes: dict = field(default_factory=dict)      # hostname -> Node
    grants: "list | None" = None                   # None => flat mesh (no policy)
    # Underlay partitions: unordered {a, b} pairs whose UNDERLAY path is blocked
    # (an injected network fault, not a policy decision). Direct-or-fail means a
    # partitioned pair cannot form a tunnel even when policy allows it — so the
    # oracle must know about them or it would flag the (correct) missing tunnel
    # as a bug. Modeling network reality, not just policy, is what lets the
    # chaos test inject real partitions.
    partitions: set = field(default_factory=set)   # of frozenset({a, b})

    # -- mutation (the chaos ops call these to keep the model in step) --

    def add(self, node: Node) -> None:
        self.nodes[node.hostname] = node

    def set_roles(self, hostname: str, roles) -> None:
        self.nodes[hostname] = replace(self.nodes[hostname],
                                       roles=tuple(sorted(set(roles))))

    def set_alive(self, hostname: str, alive: bool) -> None:
        self.nodes[hostname] = replace(self.nodes[hostname], alive=alive)

    def revoke(self, hostname: str) -> None:
        self.nodes[hostname] = replace(self.nodes[hostname], revoked=True,
                                       alive=False)
        self._forget_partitions(hostname)

    def drop(self, hostname: str) -> None:
        self.nodes.pop(hostname, None)
        self._forget_partitions(hostname)

    def partition(self, a: str, b: str) -> None:
        self.partitions.add(frozenset((a, b)))

    def heal(self, a: str, b: str) -> None:
        self.partitions.discard(frozenset((a, b)))

    def _forget_partitions(self, hostname: str) -> None:
        self.partitions = {p for p in self.partitions if hostname not in p}

    def is_partitioned(self, a: str, b: str) -> bool:
        return frozenset((a, b)) in self.partitions

    # -- the membership the data plane can actually act on --

    def effective(self) -> list:
        """Nodes that can currently participate: alive and not revoked. A
        revoked or dead node forms no tunnels (the peer evicts it / it isn't
        running), so the oracle excludes it from every expectation."""
        return [n for n in self.nodes.values() if n.alive and not n.revoked]

    # -- the oracle --

    @staticmethod
    def _grant_connects(g: Grant, a_tags: set, b_tags: set) -> bool:
        src = "*" in g.src or bool(a_tags & set(g.src))
        dst = "*" in g.dst or bool(b_tags & set(g.dst))
        return src and dst

    def tunnel(self, a: str, b: str) -> bool:
        """Should a WireGuard peer link exist between a and b? Independent
        reimplementation of the direct-or-fail topology rule:
          - a node always peers with the anchor ('*' on either side)
          - no grant table -> flat mesh (every effective member peers)
          - else a link exists iff some grant connects their tags either way
        """
        if a == b:
            return False
        na, nb = self.nodes.get(a), self.nodes.get(b)
        if na is None or nb is None:
            return False
        if not (na.alive and not na.revoked and nb.alive and not nb.revoked):
            return False
        if self.is_partitioned(a, b):
            return False                           # direct-or-fail: blocked underlay
        ta, tb = na.tags(), nb.tags()
        if "*" in ta or "*" in tb:
            return True
        if self.grants is None:
            return True
        return any(self._grant_connects(g, ta, tb) or self._grant_connects(g, tb, ta)
                   for g in self.grants)

    def _port_open(self, c: str, s: str, port: int) -> bool:
        """Server s accepts a fresh connection from client c on `port`?
        Inbound enforcement on the server side: some grant c -> s covering the
        port (or a fully-open policy). The anchor's control/door ports are
        hardwired but no SERVICE port is, so this covers the service catalog
        cleanly."""
        if self.grants is None:
            return True                            # flat mesh, no port filter
        sn, cn = self.nodes[s], self.nodes[c]
        s_tags, c_tags = sn.tags(), cn.tags()
        for g in self.grants:
            src = "*" in g.src or bool(c_tags & set(g.src))
            dst = "*" in g.dst or bool(s_tags & set(g.dst))
            if src and dst and self._ports_cover(g.ports, port):
                return True
        return False

    @staticmethod
    def _ports_cover(spec: tuple, port: int) -> bool:
        for p in spec:
            if p == "*":
                return True
            proto, _, num = p.partition("/")
            if num.isdigit() and int(num) == port:
                return True
        return False

    def reachable(self, c: str, s: str, port: int) -> bool:
        """A fresh TCP connection c -> s:port should succeed iff a tunnel
        exists AND the port is granted (both are necessary; the port filter
        can't pass traffic on a tunnel that doesn't exist)."""
        return self.tunnel(c, s) and self._port_open(c, s, port)

    def port_blocked(self, c: str, s: str, port: int) -> bool:
        """A tunnel exists but THIS port is ungranted — the port filter's job.
        The sharpest test: same tunnel, one port open and another closed."""
        return self.tunnel(c, s) and not self._port_open(c, s, port)

    # -- convenient views for the driver --

    def expected_peer_count(self, hostname: str) -> int:
        others = [n.hostname for n in self.effective() if n.hostname != hostname]
        return sum(1 for o in others if self.tunnel(hostname, o))

    def all_pairs(self) -> list:
        eff = [n.hostname for n in self.effective()]
        return [(eff[i], eff[j]) for i in range(len(eff))
                for j in range(i + 1, len(eff))]
