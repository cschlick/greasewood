"""
The chaos engine: keep a live many-container mesh and the pure MeshModel in
lockstep while a seeded RNG throws a randomized sequence of disruptions at it,
asserting the full oracle after every step. Any divergence fails with the seed
(deterministic replay) and a model-vs-reality diff.

The chaos vocabulary is deliberately weighted toward what actually broke this
project's real fleet — a killed daemon (the `killall python` incident), a
deleted interface, stale/rejoined state, plus policy churn (grants, roles,
revocation) and topology churn (new nodes) that the oracle must track exactly.
"""
from __future__ import annotations

import time

from .model import RESERVED, Grant, MeshModel, Node
from .services import probe, roles_to_ports, start_services
from ..conftest import bring_up_node, make_anchor
from ..helpers import (pexec, podman, wait_for_control_plane, wait_for_peer_count)


ROLE_POOL = ["web", "http", "api", "app", "db", "postgres", "worker",
             "cache", "redis", "ssh", "nfs", "metrics"]


class Fleet:
    """Live containers + their model, kept in step. Owns cleanup."""

    def __init__(self, gw_image, gw_network, rng, log):
        self.image = gw_image
        self.network = gw_network
        self.rng = rng
        self.log = log
        self.model = MeshModel(grants=None)
        self.cids = {}                  # hostname -> container id
        self.overlays = {}              # hostname -> overlay addr
        self.anchor = None
        self._n = 0

    # -- lifecycle --

    def bootstrap(self, n_nodes: int) -> None:
        self.anchor = make_anchor(self.image, self.network, ttl="2m",
                                  hostname="chaosanchor", open_policy=False)
        self.model.add(Node("chaosanchor", is_anchor=True))
        self.cids["chaosanchor"] = self.anchor["cid"]
        self.overlays["chaosanchor"] = self.anchor["overlay"]
        for _ in range(n_nodes):
            self.spawn()

    def spawn(self) -> "str | None":
        self._n += 1
        host = f"cn{self._n}"
        roles = self._rand_roles()
        try:
            node = bring_up_node(self.image, self.network, self.anchor,
                                 hostname=host, roles=",".join(roles) or None)
        except AssertionError as e:
            self.log(f"  spawn {host} failed to enroll: {e}")
            self._n -= 1
            return None
        self.cids[host] = node["cid"]
        self.overlays[host] = node["overlay"]
        self.model.add(Node(host, tuple(sorted(roles))))
        self.log(f"  + node {host} roles={roles or ['(none)']}")
        return host

    def teardown(self) -> None:
        for cid in self.cids.values():
            podman("rm", "-f", cid, check=False)

    def _rand_roles(self) -> list:
        k = self.rng.randint(0, 3)
        return sorted(set(self.rng.sample(ROLE_POOL, k))) if k else []

    def _nonanchor(self) -> list:
        return [h for h in self.model.nodes
                if not self.model.nodes[h].is_anchor
                and self.model.nodes[h].alive
                and not self.model.nodes[h].revoked]

    # -- policy authoring (writes grants.toml + [assign], applies on the anchor) --

    def _write_and_apply_policy(self) -> None:
        lines = []
        for g in (self.model.grants or []):
            lines.append("[[grant]]")
            lines.append(f"from = {list(g.src)}".replace("'", '"'))
            lines.append(f"to = {list(g.dst)}".replace("'", '"'))
            lines.append(f"ports = {list(g.ports)}".replace("'", '"'))
        text = "\n".join(lines) + "\n"
        pexec(self.anchor["cid"], "sh", "-c",
              f'cat > "$(ls -d /var/lib/greasewood_*)"/grants.toml <<"EOF"\n{text}\nEOF')
        r = pexec(self.anchor["cid"], "gw", "policy", "apply", "-y", check=False)
        self.log(f"  policy apply rc={r.returncode}")

    def randomize_grants(self) -> None:
        """A fresh random grant table over the current roles + some host: and
        wildcard grants across the service catalog's ports."""
        from .model import SERVICE_PORTS
        hosts = self._nonanchor()
        roletags = list({r for h in hosts for r in self.model.nodes[h].roles})
        pool = roletags + [f"host:{h}" for h in hosts]
        grants = []
        for _ in range(self.rng.randint(1, 5)):
            if not pool:
                break
            src = tuple(self.rng.sample(pool, min(len(pool), self.rng.randint(1, 2))))
            dst = tuple(self.rng.sample(pool, min(len(pool), self.rng.randint(1, 2))))
            if self.rng.random() < 0.3:
                ports = ("*",)
            else:
                svc = self.rng.sample(sorted(SERVICE_PORTS.values()),
                                      self.rng.randint(1, 3))
                ports = tuple(f"tcp/{p}" for p in svc)
            grants.append(Grant(src, dst, ports))
        self.model.grants = grants
        self._write_and_apply_policy()

    # -- the live services follow each node's roles --

    def deploy_services(self) -> None:
        for h in self._nonanchor():
            start_services(self.cids[h], self.overlays[h],
                           roles_to_ports(self.model.nodes[h].roles))

    # -- daemon control in containers (no systemd; gw run backgrounded) --

    def _kill(self, host: str) -> None:
        pexec(self.cids[host], "pkill", "-f", "[g]w.*run", check=False)

    def _start(self, host: str) -> None:
        podman("exec", "-d", self.cids[host], "sh", "-c",
               "gw -v run >> /tmp/gw.log 2>&1")


# ---------------------------------------------------------------------------
# chaos operations — each mutates the live mesh AND the model identically
# ---------------------------------------------------------------------------

def op_kill_and_restart(fleet: Fleet) -> str:
    """The `killall python` incident, on purpose: stop a random daemon, let it
    sit briefly, restart it. The model stays unchanged (the node recovers) —
    the invariant is that it re-forms every tunnel it should."""
    hosts = fleet._nonanchor()
    if not hosts:
        return "kill: no eligible node"
    h = fleet.rng.choice(hosts)
    fleet._kill(h)
    time.sleep(fleet.rng.uniform(1, 4))
    fleet._start(h)
    return f"kill+restart {h}"


def op_delete_interface(fleet: Fleet) -> str:
    """Delete a node's mesh interface under the running daemon — reconcile's
    ensure_iface must recreate it. Model unchanged; the node must recover."""
    hosts = fleet._nonanchor()
    if not hosts:
        return "deliface: no eligible node"
    h = fleet.rng.choice(hosts)
    iface = pexec(fleet.cids[h], "sh", "-c",
                  "wg show interfaces | tr ' ' '\\n' | grep -v door | head -1"
                  ).stdout.strip() or "gw-chaosanchormesh"
    pexec(fleet.cids[h], "ip", "link", "del", iface, check=False)
    return f"del iface {iface} on {h}"


def op_revoke(fleet: Fleet) -> str:
    """Revoke a random node. The model marks it gone; the oracle then expects
    every peer to evict it and its tunnels to vanish."""
    hosts = fleet._nonanchor()
    if len(hosts) <= 1:
        return "revoke: too few nodes"
    h = fleet.rng.choice(hosts)
    pexec(fleet.anchor["cid"], "gw", "revoke", h, check=False)
    fleet.model.revoke(h)
    return f"revoke {h}"


def op_change_roles(fleet: Fleet) -> str:
    """Re-role a random node via set-roles + a forced renew so it adopts live.
    The model swaps its roles; topology + service ports must follow."""
    hosts = fleet._nonanchor()
    if not hosts:
        return "reroles: no node"
    h = fleet.rng.choice(hosts)
    roles = fleet._rand_roles()
    pexec(fleet.anchor["cid"], "gw", "set-roles", h, ",".join(roles) or "node",
          check=False)
    pexec(fleet.cids[h], "gw", "renew", check=False)     # adopt immediately
    fleet.model.set_roles(h, roles)
    start_services(fleet.cids[h], fleet.overlays[h], roles_to_ports(roles))
    return f"reroles {h} -> {roles or ['(none)']}"


def op_randomize_policy(fleet: Fleet) -> str:
    fleet.randomize_grants()
    fleet.deploy_services()
    return f"policy -> {len(fleet.model.grants)} grant(s)"


def op_add_node(fleet: Fleet) -> str:
    if len(fleet._nonanchor()) >= fleet.rng.randint(6, 10):
        return "add: at soft cap"
    h = fleet.spawn()
    if h:
        start_services(fleet.cids[h], fleet.overlays[h],
                       roles_to_ports(fleet.model.nodes[h].roles))
    return f"add node {h}"


# weighted so the field-incident ops (kill, iface) fire often, and the
# expensive ones (policy, add) less so.
CHAOS_OPS = [
    (op_kill_and_restart, 4),
    (op_delete_interface, 3),
    (op_change_roles, 3),
    (op_randomize_policy, 2),
    (op_revoke, 2),
    (op_add_node, 2),
]


def pick_op(rng):
    ops = [o for o, w in CHAOS_OPS for _ in range(w)]
    return rng.choice(ops)
