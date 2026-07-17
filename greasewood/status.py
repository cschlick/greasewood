"""
greasewood.status — everything `gw` PRINTS about the mesh.

The read-only presentation layer: the split roster, the live watch dashboard
(throughput/latency), per-segment connectivity (partitions + down edges), the
self/health and door blocks, and the pairwise `gw diagnose`. Pure consumers of
the directory cache + live WireGuard state — nothing here mutates the mesh, so
an auditor can skip this file entirely when tracing what greasewood *does* to
a system (that story lives in wg.py/reconcile.py, recorded by audit.py).
"""
from __future__ import annotations

import base64
import contextlib
import datetime as dt
import ipaddress
import itertools
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from .config import membership_key
from .keys import _key_file_warnings, _own_identity, _secret_key_paths

_UTC = dt.timezone.utc
log = logging.getLogger("greasewood")


def _version() -> str:
    try:
        from importlib.metadata import version
        return version("greasewood")
    except Exception:
        return "0.0.0+unknown"


def _underlay_addrs(endpoints: list[str]) -> tuple[str, str]:
    """(v6_host, v4_host) from a node's advertised underlay endpoints, '-' if it
    advertises none of that family. Endpoints are formatted 'host:port' /
    '[v6]:port'; the port is dropped for the table."""
    v6 = v4 = "-"
    for ep in endpoints:
        if ep.startswith("["):                 # [v6]:port
            v6 = ep[1:].split("]")[0]
        elif ep:                               # host:port (v4)
            v4 = ep.rsplit(":", 1)[0]
    return v6, v4


_CGNAT4 = ipaddress.ip_network("100.64.0.0/10")   # RFC 6598 carrier-grade NAT


def _endpoint_scope_note(v6: str, v4: str) -> str:
    """A warning if EVERY advertised underlay host is non-globally-reachable.
    Advertising a CGNAT or private address doesn't make a node dialable — a real
    source of "it's listed, why won't it connect?" confusion. '' when at least
    one host is plausibly reachable (or unparseable — a hostname; don't guess),
    or when none is advertised (outbound-only, reported elsewhere). The explicit
    CGNAT test is version-independent: 100.64/10 is not is_private, and its
    is_global was only corrected in CPython 3.11.9 / 3.12.4."""
    note = ""
    for h in (v6, v4):
        if h == "-":
            continue
        try:
            addr = ipaddress.ip_address(h)
        except ValueError:
            return ""                              # a hostname → can't classify
        if addr.is_global and not (addr.version == 4 and addr in _CGNAT4):
            return ""                              # a reachable endpoint exists
        note = note or ("CGNAT (100.64/10, not globally reachable)"
                        if addr.version == 4 and addr in _CGNAT4
                        else "not globally reachable")
    return note


def _record_roles(r) -> list[str]:
    """The roles a record holds (from its `role:` caps)."""
    return [c[len("role:"):] for c in r.cred.caps if c.startswith("role:")]


# A link counts as "up" if it handshaked within this window — the same ~180s
# WireGuard-refresh window reconcile uses for its `reachable` set.
_LINK_FRESH_SECS = 180


def _wg_key(record) -> str:
    """A record's WireGuard public key as the base64 string live-peer dicts are
    keyed by."""
    return base64.b64encode(record.cred.wg_pub).decode()


def _handshake_fresh(live_peer, now_epoch: int) -> bool:
    """True if this live peer handshaked recently enough to count as a live link
    (the single definition of 'up' the roster, live view, and diagnose share)."""
    return bool(live_peer and live_peer.latest_handshake
                and (now_epoch - live_peer.latest_handshake) <= _LINK_FRESH_SECS)


def _parse_iso(iso: str) -> "dt.datetime | None":
    """Parse an RFC-3339 'Z' timestamp, or None if it's absent/malformed."""
    try:
        return dt.datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _fmt_bytes(n) -> str:
    """Human byte size: 4200000 → '4.0M'."""
    x = float(n)
    for unit in ("B", "K", "M", "G"):
        if x < 1024:
            return f"{int(x)}{unit}" if unit == "B" else f"{x:.1f}{unit}"
        x /= 1024
    return f"{x:.1f}T"


def _fmt_handshake_age(age_s: float) -> str:
    """Compact age for a handshake: 12→'12s', 90→'1m', 7200→'2h', bigger→'Nd'."""
    if age_s < 60:
        return f"{int(age_s)}s"
    if age_s < 3600:
        return f"{int(age_s // 60)}m"
    if age_s < 86400:
        return f"{int(age_s // 3600)}h"
    return f"{int(age_s // 86400)}d"


def _load_policy_grants(cfg) -> "list | None":
    """The active grant table's grants for DISPLAY (roster peer decisions,
    diagnose verdicts, health expectations), from the policy.json cache the
    daemon maintains. None = no policy (flat mesh). Display-only read; the
    daemon verifies signatures on adoption."""
    from .policy import POLICY_BASENAME
    from .wire import GrantTable
    try:
        return GrantTable.from_dict(
            json.loads((cfg.data_dir / POLICY_BASENAME).read_text())).grants
    except FileNotFoundError:
        return None
    except (OSError, ValueError, KeyError):
        return None


def _live_and_hidden(records, now, show_all):
    """`gw watch` shows only the LIVE mesh: records whose credential hasn't
    expired (now < cred.exp) — the same predicate peers use to accept a node, so
    the roster matches who's actually in the mesh. Expired records (a node that
    lapsed but may still recertify, or one aging toward its true drop) are hidden
    unless --all. Returns (shown, hidden_count)."""
    if show_all:
        return records, 0
    live = [r for r in records if now < r.cred.exp]
    return live, len(records) - len(live)


# Reserved widths for the roster cells whose render CHANGES WIDTH over time —
# so a rescaling rate/traffic, a filling-in latency, a counting-down exp, or a
# flipping link state never shifts the table. Sizing these to the live value
# (the old behavior) jittered the whole layout every refresh. Each is the widest
# string its formatter can produce; a value is always <= it, so the column is
# rock-solid. (Static columns — name/addr/roles — still size to the fleet: they
# only reflow when membership actually changes, which is a real event.)
_W_EXP     = len("EXPIRED")                   # widest exp token
_W_LINK    = len("● up, 999d ago")            # widest link string
_W_LAT     = len("1000ms")                    # ping -W1 deadline caps RTT ~1s
_W_TRAFFIC = len("↓1023.9G ↑1023.9G")         # widest cumulative ↓rx ↑tx
_W_RATE    = len("↓1023.9K/s ↑1023.9K/s")     # widest per-second ↓ ↑


def _roster_lines(records, cfg, now, own_id, live_peers, is_root,
                  latency=None, rates=None, grants=None, show_total=False) -> list:
    """Thin wrapper: build the per-node model (the same dicts `--json` emits) from
    the records, then render. Kept so the live view and existing callers/tests
    pass records; the actual rendering lives in _render_roster, which only ever
    touches the JSON-native model — so the text roster and --json cannot diverge."""
    own_rec = next((r for r in records if r.id_pub.hex() == own_id), None)
    own_caps = list(own_rec.cred.caps) if own_rec else list(cfg.caps)
    now_epoch = int(now.timestamp())
    nodes = [_node_view(r, cfg, now, now_epoch, own_id, own_caps, live_peers, grants)
             for r in records]
    return _render_roster(nodes, cfg, live_peers is not None, is_root,
                          latency=latency, rates=rates, show_total=show_total)


def _render_roster(nodes, cfg, have_live, is_root,
                   latency=None, rates=None, show_total=False) -> list:
    """The split roster as a list of lines, rendered PURELY from the per-node
    model dicts (`_node_view` / the `--json` `nodes`): LEFT is the mesh
    (fleet-wide — name, addr, roles, credential); RIGHT is THIS node's view.
    Without live data (no root) the right side is just the policy 'would I peer'
    answer; with it, the live link + cumulative traffic; in LIVE mode (latency
    supplied) link + per-second RATE + an async latency column. It reaches for no
    NodeRecord — every value it shows came through the model, so a column can't
    exist that the JSON doesn't."""
    from .hosts import mesh_name

    is_live = latency is not None

    def _exp(n):
        left = n["ttl_remaining_s"]
        if left < 0:
            return "EXPIRED"
        if left < 3600:
            return "<1h!"
        h = int(left // 3600)
        return f"{h // 24}d" if h >= 48 else f"{h}h"

    def _right(n):
        is_self, peers, live = n["is_self"], n["peer_expected"], n.get("live")
        installed = bool(live and live.get("installed"))
        up = bool(live and live.get("up"))
        if is_live:                             # link · rate · latency
            if is_self:
                return ("(self)", "", latency.get(n["addr"], "…"))
            if not peers:
                return ("— not a peer", "", "")
            if not installed:
                return ("not installed", "", "")
            if up:
                # middle column: cumulative traffic (steady) or per-second rate.
                middle = (f"↓{_fmt_bytes(live['rx_bytes'])} ↑{_fmt_bytes(live['tx_bytes'])}"
                          if show_total else (rates or {}).get(n["addr"], ""))
                return (f"● up, {_fmt_handshake_age(live['handshake_age_s'])}",
                        middle,
                        latency.get(n["addr"], "…"))   # … = ping in flight
            return ("○ no handshake", "", "—")
        if not have_live:                       # policy only (no root)
            return ("self" if is_self else ("yes" if peers else "no"),)
        if is_self:
            return ("(self)", "")
        if not peers:
            return ("— not a peer", "")
        if not installed:
            return ("not installed", "")
        if up:
            return (f"● up, {_fmt_handshake_age(live['handshake_age_s'])} ago",
                    f"↓{_fmt_bytes(live['rx_bytes'])} ↑{_fmt_bytes(live['tx_bytes'])}")
        return ("○ no handshake", "")

    left_hdr = ("name", "addr", "roles", "exp")
    if is_live:
        right_hdr = ("link", "traffic" if show_total else "rate", "latency")
    elif have_live:
        right_hdr = ("link", "traffic")
    else:
        right_hdr = ("peer?",)

    left_rows, right_rows = [], []
    for n in nodes:
        left_rows.append((
            mesh_name(n["hostname"], cfg.mesh_domain), n["addr"],
            ",".join(n["roles"]) or "-", _exp(n),
        ))
        right_rows.append(_right(n))

    # A per-column reserved floor for the width-changing cells (0 = size to
    # data). left: only `exp` is dynamic. right depends on mode.
    left_reserve = (0, 0, 0, _W_EXP)              # name, addr, roles, exp
    if is_live:
        right_reserve = (_W_LINK, _W_TRAFFIC if show_total else _W_RATE, _W_LAT)
    elif have_live:
        right_reserve = (_W_LINK, _W_TRAFFIC)
    else:
        right_reserve = (0,)                      # peer? — small + static

    def _col_width(header, i, rows, reserve):
        # max with the live values too, so an under-estimate degrades to today's
        # reflow rather than overflowing a column (alignment stays intact).
        cur = max((len(row[i]) for row in rows), default=0)
        return max(len(header), cur, reserve)
    left_widths = [_col_width(left_hdr[i], i, left_rows, left_reserve[i])
                   for i in range(len(left_hdr))]
    right_widths = [_col_width(right_hdr[i], i, right_rows, right_reserve[i])
                    for i in range(len(right_hdr))]

    def _fmt_left(cells):   # name right-justified, the rest left-justified
        return " ".join([f"{cells[0]:>{left_widths[0]}}"]
                        + [f"{cells[i]:<{left_widths[i]}}" for i in range(1, len(cells))])

    def _fmt_right(cells):
        return " ".join(f"{cells[i]:<{right_widths[i]}}" for i in range(len(cells)))

    left_width = len(_fmt_left(left_hdr))
    out = [f"{'mesh — the fleet (same on every node)':<{left_width}} │ this node",
           _fmt_left(left_hdr) + " │ " + _fmt_right(right_hdr),
           "-" * left_width + "-+-" + "-" * max(len(_fmt_right(right_hdr)), 9)]
    out += [_fmt_left(lrow) + " │ " + _fmt_right(rrow)
            for lrow, rrow in zip(left_rows, right_rows)]
    if not have_live and not is_live:
        note = ("run 'sudo gw watch' for live data links + traffic" if not is_root
                else "no live WireGuard state — is the daemon running?")
        out.append(f"({note})")
    return out


def _segment_analysis(members, grants=None):
    """Connectivity within a group, from each node's self-reported `reachable`
    set (synced in the directory — no root or live wg needed). Returns
    (components, missing_edges). An edge is UP if EITHER end reports the other
    (a session is bidirectional, so one end suffices — robust to one-sided
    staleness). An edge is EXPECTED (so its absence is a fault) only when the
    POLICY says the pair should tunnel (peers_allowed under the active grant
    table — under a derived topology, two group-mates without a grant are
    correctly unlinked, not a fault) AND a dialable direction exists (at least
    one end advertises an endpoint)."""
    from .policy import peers_allowed

    def linked(a, b):
        return b.cred.addr in a.reachable or a.cred.addr in b.reachable
    parent = {r.cred.addr: r.cred.addr for r in members}

    def find(x):
        root = x
        while parent[root] != root:
            root = parent[root]
        while parent[x] != root:               # path-compress
            parent[x], x = root, parent[x]
        return root

    missing = []
    for i, a in enumerate(members):
        for b in members[i + 1:]:
            if linked(a, b):
                parent[find(a.cred.addr)] = find(b.cred.addr)
            elif peers_allowed(a.cred.caps, b.cred.caps, grants,
                               a.cred.hostname, b.cred.hostname) \
                    and (a.endpoints or b.endpoints):
                missing.append((a, b))         # possible + authorized, but absent
    comps = {}
    for r in members:
        comps.setdefault(find(r.cred.addr), []).append(r)
    return list(comps.values()), missing


def _edge_down_hint(a, b, cfg) -> str:
    """A directional hint for a down edge, derived from who advertises an
    endpoint (the dialable direction) — the discovery-vs-firewall first question."""
    from .hosts import mesh_name
    na = mesh_name(a.hostname, cfg.mesh_domain)
    nb = mesh_name(b.hostname, cfg.mesh_domain)
    ea, eb = bool(a.endpoints), bool(b.endpoints)
    if ea and eb:
        return f"{na} ✗ {nb}  (both advertise endpoints — check firewalls at both ends)"
    if ea:                                      # only a is dialable → b must reach it
        return f"{na} ✗ {nb}  ({nb} can't reach {na} at {a.endpoints[0]} — {na}'s firewall/NAT?)"
    return f"{na} ✗ {nb}  ({na} can't reach {nb} at {b.endpoints[0]} — {nb}'s firewall/NAT?)"


def _print_segment_health(members, cfg, grants=None) -> None:
    """Under a group's roster: fully-connected, or the partition/down-edge
    breakdown (the EMERGENT segments — the connected structure the grant graph
    produces). Uses only the synced `reachable` sets, so it works non-root."""
    from .hosts import mesh_name
    if len(members) < 2:
        return
    comps, missing = _segment_analysis(members, grants)
    if len(comps) <= 1 and not missing:
        print("  ✓ fully connected")
        return
    if len(comps) > 1:
        print(f"  ⚠ PARTITIONED — {len(comps)} islands that can't reach each other:")
        for c in sorted(comps, key=len, reverse=True):
            names = ", ".join(sorted(mesh_name(r.hostname, cfg.mesh_domain) for r in c))
            tail = "   ← isolated" if len(c) == 1 else ""
            print(f"      {{ {names} }}{tail}")
    if missing:
        n = len(missing)
        print(f"  ⚠ {n} expected link{'' if n == 1 else 's'} down:")
        for a, b in missing:
            print(f"      {_edge_down_hint(a, b, cfg)}")


def _fmt_rate(bytes_per_s: float) -> str:
    return f"{_fmt_bytes(max(0.0, bytes_per_s))}/s"


def _ping_rtt(addr: str) -> str:
    """Round-trip time to an overlay address via one ICMPv6 echo, as 'Nms', or
    '—' on timeout/unreachable. Numeric only (-n), 1s deadline (-W1)."""
    try:
        r = subprocess.run(["ping", "-6", "-n", "-c", "1", "-W", "1", addr],
                           capture_output=True, text=True, timeout=3)
    except Exception:
        return "—"
    if r.returncode != 0:
        return "—"
    m = re.search(r"time=([\d.]+)\s*ms", r.stdout)
    return f"{float(m.group(1)):.0f}ms" if m else "—"


class _LatencyProber:
    """Background prober for `gw watch`: round-robins ICMP pings over the
    current linked peers and publishes results in `self.results` ({addr: 'Nms'|
    '—'}). The display reads it non-blocking, so latency fills in over the first
    few seconds instead of stalling the first frame — and pings run ONLY while
    someone is watching the live view (the caller stops it on exit)."""

    def __init__(self) -> None:
        self.results: dict = {}
        self._targets: list = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, name="latency", daemon=True)

    def set_targets(self, addrs) -> None:
        with self._lock:
            self._targets = list(addrs)

    def _run(self) -> None:
        while not self._stop.is_set():
            with self._lock:
                tgts = list(self._targets)
            if not tgts:
                self._stop.wait(0.5)
                continue
            for addr in tgts:
                if self._stop.is_set():
                    break
                self.results[addr] = _ping_rtt(addr)

    def start(self) -> None:
        self._t.start()

    def stop(self) -> None:
        self._stop.set()


def _watch_header(cfg, directory, own_id, own_addr) -> list:
    """The header block shown at the top of BOTH `gw watch` (live) and
    `gw watch --snapshot` — role/hostname/addr/sync freshness, the self/health
    facts, and (on the anchor) the enrollment door's state. Shared so the two
    views are identical above the roster."""
    lines = [
        f"role     : {cfg.role}",
        f"hostname : {cfg.hostname}",
        f"addr     : {own_addr or '(keys not generated)'}",
    ]
    fresh = _sync_freshness(cfg)
    if fresh:
        lines.append(f"synced   : {fresh}")
    recon = _reconcile_freshness(cfg)              # daemon-liveness heartbeat (all roles)
    if recon:
        lines.append(f"daemon   : {recon}")
    from . import reconcile as _rec                 # port enforcement degraded? (H2)
    degraded = _rec.read_enforce_degraded(cfg.data_dir)
    if degraded:
        lines.append(f"enforce  : ⚠ port enforcement DOWN — running UNFILTERED "
                     f"(enforce_ports=true but nftables unusable: {degraded['reason']})")
    # Where to look when the daemon line above is unhappy: the journal (what the
    # daemon logged) and the audit file (every ip/wg/nft command it ran).
    lines.append(f"logs     : journalctl -eu greasewood@{membership_key(cfg.mesh_domain)}")
    if getattr(cfg, "audit_log", None):
        lines.append(f"audit    : {cfg.audit_log}  (ip/wg/nft commands + "
                     f"'grep event=' for topology/policy changes)")
    lines += _self_health_lines(cfg, directory, own_id)
    if cfg.role == "anchor":                       # the door only exists here
        lines += _door_status_lines(cfg)
    return lines


def _nft_table_lines(cfg) -> list:
    """The greasewood nftables table shown verbatim in `gw watch`: the literal
    `nft list table` command, then its raw output. No summary — what the kernel
    holds, exactly as `nft` prints it (we run without sudo since watch is already
    root; the displayed command keeps sudo so it's copy-pasteable elsewhere)."""
    from .portfilter import table_name
    from .config import membership_key
    tbl = table_name(membership_key(cfg.mesh_domain))
    cmd = [f"$ sudo nft list table inet {tbl}"]

    if not getattr(cfg, "enforce_ports", True):
        return cmd + ["  (port enforcement off — enforce_ports=false; no table)"]
    try:
        r = subprocess.run(["nft", "list", "table", "inet", tbl],
                           capture_output=True, text=True)
    except FileNotFoundError:
        return cmd + ["  (nft not installed)"]
    if r.returncode == 0:
        return cmd + r.stdout.rstrip("\n").splitlines()
    if os.geteuid() != 0:
        return cmd + ["  (run as root to read the table)"]
    # nft's "no such table" error is THREE lines (message + a command echo + a
    # caret) — collapsing it to one keeps it from bleeding into the roster. The
    # usual cause is the daemon not running yet (it installs the table each
    # reconcile), so say that rather than echo nft's raw diagnostic.
    return cmd + ["  (table not present — the daemon isn't running yet, or "
                  "hasn't applied enforcement; it's (re)installed on reconcile)"]


def _cfg_control_port(cfg) -> int:
    """The anchor control port from cfg.control_listen (':51902' → 51902)."""
    try:
        return int(getattr(cfg, "control_listen", ":51902").rsplit(":", 1)[1])
    except (ValueError, IndexError, AttributeError):
        return 51902


def _strip_gw_table(lines: list, gw_table: str) -> list:
    """Drop greasewood's own `table inet <gw_table> { … }` block from raw
    `nft list ruleset` output, so a HOST-firewall view doesn't display
    greasewood's overlay rules (gw-<mesh>/gw-door/51902 — which also match a
    'gw-' grep) as if the operator had written them. The table's closing brace is
    the only `}` at column 0; sub-blocks (set/chain) close indented."""
    out, skip = [], False
    for ln in lines:
        if not skip and ln.startswith(f"table inet {gw_table} "):
            skip = True
            continue
        if skip:
            if ln.rstrip() == "}":            # column-0 close = end of the table
                skip = False
            continue
        out.append(ln)
    return out


def _main_firewall_lines(cfg) -> list:
    """The operator's OWN firewall vs the greasewood underlay port(s), surfaced
    in `gw watch` so a blocked port is visible at a glance — greasewood NEVER
    edits these rules. Line 0 is the verdict (the only line kept when the section
    is collapsed with `f`); the rest is the command + the matching HOST rules.

    Omitted entirely when nft isn't installed — that host isn't firewalling with
    nftables, so there's nothing to check. Per role: a plain node needs only the
    mesh WireGuard UDP port; an anchor also needs the enrollment-door port. LOUD
    when a default-drop firewall doesn't accept a needed port (the daemon is then
    likely unreachable inbound). greasewood's OWN table is excluded from the shown
    rules (its overlay rules match a 'gw-' grep and would masquerade as the
    operator's) — it's shown verbatim in its own section below."""
    from . import firewall as fw
    if shutil.which("nft") is None:
        return []

    iface = cfg.wg_interface
    if getattr(cfg, "role", "node") == "anchor":
        rules = fw.anchor_rules(cfg.listen_port, _cfg_control_port(cfg),
                                iface, getattr(cfg, "enforce_ports", True))
    else:
        rules = fw.node_rules(cfg.listen_port)
    ports = sorted({r.port for r in rules})
    # The mesh needs BOTH: the underlay UDP port(s), AND the overlay coarsely
    # admitted (`iifname "gw-*" accept`) so greasewood's own table can filter it
    # — a default-drop host drops gw-* before our table ever sees it.
    portlist = ", ".join(f"{r.proto}/{r.port}" for r in rules)
    need = f"{portlist} + gw-* overlay"
    from .portfilter import table_name
    from .config import membership_key
    gw_table = table_name(membership_key(cfg.mesh_domain))
    # The shown command strips greasewood's own table too, so it reproduces
    # exactly what's displayed (only the operator's rules).
    cmd = (f"  $ sudo nft list ruleset | sed '/^table inet {gw_table} /,/^}}/d' "
           "| grep -E '" + "|".join(str(p) for p in ports) + "|gw-'")

    ruleset = fw._load_ruleset()
    if ruleset is None:
        return [f"main firewall : need {need} reachable "
                "(run `sudo gw watch` to read the ruleset)", cmd]

    try:
        full = subprocess.run(["nft", "list", "ruleset"], capture_output=True,
                              text=True).stdout.splitlines()
    except FileNotFoundError:
        full = []
    raw = [ln.strip() for ln in _strip_gw_table(full, gw_table)
           if any(str(p) in ln for p in ports) or "gw-" in ln]

    drop = fw.default_drop(ruleset)
    if not drop:
        # An accept policy admits everything — ports and overlay both fine.
        lines = [f"main firewall : input policy ACCEPT — {need} not blocked ✓", cmd]
        return lines + (["    " + ln for ln in raw] or ["    (no matching rule)"])

    missing = [r for r in rules
               if r.port in {m.port for m in fw.missing_rules(ruleset, rules)}]
    overlay_ok = fw.admits_iface(ruleset, iface)

    # LOUD when blocked — and the complaint carries the exact nft rule(s) to fix
    # it, since that's the whole point of surfacing this.
    fixes = [f"{r.nft_match()} accept   # {r.why}" for r in missing]
    if not overlay_ok:
        fixes.append('iifname "gw-*" accept   # admit the overlay so greasewood '
                     "can filter it")

    if not missing and overlay_ok:
        verdict = f"main firewall : {need} allowed ✓ (default-drop + accept)"
    else:
        blocked = [f"{r.proto}/{r.port}" for r in missing]
        if not overlay_ok:
            blocked.append("gw-* overlay")
        verdict = (f"main firewall : ⚠ {', '.join(blocked)} BLOCKED by default-drop "
                   "— daemon likely UNREACHABLE inbound")

    lines = [verdict, cmd]
    lines += ["    " + ln for ln in raw] or ["    (no matching rule)"]
    if fixes:
        lines.append("  add these to your nftables config (greasewood never will):")
        lines += ["      " + f for f in fixes]
    return lines


# ---------------------------------------------------------------------------
# gw watch — interactive live view (scrollable; groundwork for a TUI)
# ---------------------------------------------------------------------------

def _scroll_clamp(off: int, total: int, view_h: int) -> int:
    """Keep a scroll offset within [0, total - view_h] so the viewport never
    runs past the content (or before the start)."""
    return max(0, min(off, max(0, total - view_h)))


def _scroll_key(action: str, off: int, total: int, view_h: int) -> int:
    """Apply a scroll action to the offset, clamped. Pure: the input layer maps
    keypresses to these action names, and the view math lives here so it's
    testable without a terminal."""
    if action == "top":
        off = 0
    elif action == "bottom":
        off = total
    else:
        off += {"up": -1, "down": 1,
                "pgup": -view_h, "pgdown": view_h}.get(action, 0)
    return _scroll_clamp(off, total, view_h)


_BAR_TRACK, _BAR_THUMB = "░", "█"


def _scrollbar_column(off: int, total: int, view_h: int) -> list:
    """A `view_h`-tall vertical scrollbar as a list of glyphs (one per visible
    row): a track with a thumb whose SIZE reflects how much of the content is on
    screen (view_h/total) and whose POSITION reflects the scroll offset. Pure, so
    the geometry is testable without a terminal. Blank when everything fits."""
    if view_h <= 0:
        return []
    if total <= view_h:
        return [" "] * view_h                          # all visible → no bar
    thumb = min(view_h, max(1, round(view_h * view_h / total)))
    max_off = total - view_h
    pos = round(off * (view_h - thumb) / max_off) if max_off else 0
    pos = max(0, min(pos, view_h - thumb))
    return [_BAR_THUMB if pos <= i < pos + thumb else _BAR_TRACK
            for i in range(view_h)]


# Keypress bytes → action. Single keys plus the common escape sequences (arrows,
# PgUp/PgDn, Home/End). This table is the seam where future interactive ops
# (sort, filter, select a peer and act on it) attach.
_KEY_ACTIONS = {
    b"j": "down",   b"\x1b[B": "down",
    b"k": "up",     b"\x1b[A": "up",
    b" ": "pgdown", b"\x1b[6~": "pgdown",
    b"b": "pgup",   b"\x1b[5~": "pgup",
    b"g": "top",    b"\x1b[H": "top",
    b"G": "bottom", b"\x1b[F": "bottom",
    b"f": "toggle_nft",
    b"t": "toggle_total",
    b"q": "quit",   b"\x03": "quit",  b"\x1b": "quit",
}


@contextlib.contextmanager
def _cbreak_terminal():
    """Put the tty in cbreak mode (keys a char at a time, no echo) with the
    cursor hidden, restoring both on exit — even on exception. cbreak (not raw)
    keeps signals, so Ctrl-C still raises KeyboardInterrupt, and output newline
    translation stays on. Linux-only, like the rest of greasewood. Yields the
    stdin fd for the key reader."""
    import termios
    import tty
    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd)
    tty.setcbreak(fd)
    sys.stdout.write("\x1b[?25l")                 # hide cursor
    sys.stdout.flush()
    try:
        yield fd
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)
        sys.stdout.write("\x1b[?25h\x1b[0m\n")    # show cursor, reset attrs, newline
        sys.stdout.flush()


def _read_action(fd: int, timeout: float) -> "str | None":
    """Block up to `timeout` for a keypress; return its action name, None on
    timeout, or "" for an unmapped key. One os.read grabs a whole escape
    sequence, so arrow keys arrive intact."""
    import select
    if not select.select([fd], [], [], timeout)[0]:
        return None
    data = os.read(fd, 16)
    if not data:
        return "quit"                             # EOF on stdin
    return _KEY_ACTIONS.get(data, "")


class _WatchApp:
    """Interactive `gw watch`: a scrollable dashboard over the mesh roster.
    Fixed header + enforcement block on top, a scrollable peer viewport in the
    middle, a status/keys footer pinned to the bottom.

    Built as an app (state + fetch + compose + input) rather than a print loop,
    so richer interaction — sort, filter, select a peer and act on it — can grow
    here without reworking the render path. Data refreshes every `interval`;
    scrolling responds immediately in between."""

    def __init__(self, cfg, own_id, own_addr, prober, interval: float,
                 show_all: bool = False, show_total: bool = False) -> None:
        self._cfg = cfg
        self._own_id = own_id
        self._own_addr = own_addr
        self._prober = prober
        self._interval = interval
        self._show_all = show_all        # --all: include expired records
        self._show_total = show_total    # t toggles rate ↔ cumulative traffic
        self._off = 0                    # scroll offset into the peer rows
        self._prev: dict = {}            # wg key → (rx, tx, mono) for rate deltas
        self._show_nft = True            # f toggles the firewall area (both blocks)
        # Pinned-top pieces, kept separate so `f` collapses the firewall area
        # instantly without a re-fetch.
        self._header: list = []          # role/addr/door/...
        self._fw_lines: list = []        # host-firewall port check (line 0 = verdict)
        self._nft_lines: list = []       # the raw `nft list table` block
        self._chrome: list = []          # roster title/column-header/separator
        self._rows: list = []            # scrollable: one line per peer
        self._up = 0                     # live-link count (for the footer)
        self._hidden = 0                 # expired records hidden (for the footer)

    def _fetch(self) -> None:
        """Refresh the data snapshot (directory + live WireGuard state) and
        rebuild the pinned header and scrollable peer rows. The I/O-heavy work,
        run every `interval` — not on every keypress."""
        from .directory import Directory
        from . import wg as wgmod
        directory = Directory.load(self._cfg.dir_cache_path)
        now = dt.datetime.now(_UTC)
        records = sorted(directory.all(), key=lambda r: r.hostname)
        records, self._hidden = _live_and_hidden(records, now, self._show_all)
        try:
            live = wgmod.get_peers(self._cfg.wg_interface) or {}
        except Exception:
            live = {}
        now_epoch = int(now.timestamp())
        mono = time.monotonic()

        rates, targets = {}, []
        for r in records:
            if r.id_pub.hex() == self._own_id:
                targets.append(r.cred.addr)   # ping self (~0ms) so its row shows too
                continue
            key = _wg_key(r)
            lp = live.get(key)
            if not lp:
                continue
            if _handshake_fresh(lp, now_epoch):
                targets.append(r.cred.addr)
                p = self._prev.get(key)
                if p and mono > p[2]:
                    dts = mono - p[2]
                    rates[r.cred.addr] = (
                        f"↓{_fmt_rate((lp.rx_bytes - p[0]) / dts)} "
                        f"↑{_fmt_rate((lp.tx_bytes - p[1]) / dts)}")
            self._prev[key] = (lp.rx_bytes, lp.tx_bytes, mono)
        self._prober.set_targets(targets)
        self._up = len(targets)

        grants = _load_policy_grants(self._cfg)
        roster = _roster_lines(records, self._cfg, now, self._own_id, live, True,
                               latency=self._prober.results, rates=rates,
                               grants=grants, show_total=self._show_total)
        # Roster chrome (title, column header, separator) pins with the header;
        # the per-peer rows below the separator are what scrolls.
        sep = next((i for i, ln in enumerate(roster) if "-+-" in ln), 2)
        self._header = _watch_header(self._cfg, directory, self._own_id, self._own_addr)
        self._fw_lines = _main_firewall_lines(self._cfg)
        self._nft_lines = _nft_table_lines(self._cfg)
        self._chrome = roster[:sep + 1]
        self._rows = roster[sep + 1:]

    def _top_lines(self) -> list:
        """The pinned block above the scrollable roster: header, the firewall
        area (the host-firewall port check + greasewood's own table), a blank,
        then the roster's column header. `f` collapses the firewall area to each
        block's line 0 — the host-firewall VERDICT (so a blocked port stays loud
        even collapsed) and the gw-table command. Recomputed each render, so `f`
        toggles instantly."""
        fw, nft = self._fw_lines, self._nft_lines
        if self._show_nft:
            area = fw + ([""] if fw and nft else []) + nft
        else:
            area = ([fw[0] + "   (f to expand)"] if fw else []) \
                 + ([nft[0] + "   (f to expand)"] if nft else [])
        return self._header + area + [""] + self._chrome

    def _footer(self, view_h: int) -> str:
        now = dt.datetime.now(_UTC)
        total = len(self._rows)
        if total <= view_h:
            pos = f"all {total}"
        else:
            off = _scroll_clamp(self._off, total, view_h)
            pos = f"peers {off + 1}–{min(off + view_h, total)} of {total}"
        hidden = f" · {self._hidden} expired hidden" if self._hidden else ""
        tkey = "t rate" if self._show_total else "t total"
        return (f"{now:%H:%M:%S}Z · {self._up} link"
                f"{'' if self._up == 1 else 's'} up · {pos}{hidden} · "
                f"↑↓/PgUp/PgDn/g/G scroll · f firewall · {tkey} · q quit")

    def _compose(self, cols: int, term_h: int) -> list:
        """The full frame as a list of exactly term_h lines: pinned top, the
        scrolled peer window (padded so the footer stays at the bottom), footer.
        Pure — no terminal I/O — so the scroll windowing is unit-testable."""
        top = self._top_lines()
        view_h = max(1, term_h - len(top) - 1)            # 1 row for the footer
        self._off = _scroll_clamp(self._off, len(self._rows), view_h)
        visible = self._rows[self._off:self._off + view_h]
        body = visible + [""] * (view_h - len(visible))
        # When the peer list overflows the viewport, pin a 1-col scrollbar rail
        # to the right edge of the scrollable rows (only that region scrolls, so
        # only it gets a bar). Pad/truncate each row to cols-1, then the glyph.
        if len(self._rows) > view_h and cols > 1:
            bar = _scrollbar_column(self._off, len(self._rows), view_h)
            w = cols - 1
            body = [f"{ln:<{w}.{w}}{bar[i]}" for i, ln in enumerate(body)]
        return top + body + [self._footer(view_h)]

    def _view_h(self, term_h: int) -> int:
        return max(1, term_h - len(self._top_lines()) - 1)

    def _render(self) -> None:
        cols, term_h = shutil.get_terminal_size((80, 24))
        sys.stdout.write(self._frame(self._compose(cols, term_h), cols))
        sys.stdout.flush()

    @staticmethod
    def _frame(lines: list, cols: int) -> str:
        """Assemble the redraw string. Clear each line to EOL BEFORE writing it
        (not after): nft output is tab-indented, and a tab moves the cursor over
        columns without erasing them, so a trailing clear leaves stale content
        in the indent. Tabs are expanded first so truncation counts real
        columns. \\x1b[J at the end wipes anything below a now-shorter frame."""
        body = "\r\n".join("\x1b[K" + ln.expandtabs()[:cols] for ln in lines)
        return "\x1b[H" + body + "\x1b[J"

    def run(self, fd: int) -> None:
        last = -1e9
        while True:
            if time.monotonic() - last >= self._interval:
                self._fetch()
                last = time.monotonic()
            self._render()
            action = _read_action(fd, min(0.25, self._interval))
            if action == "quit":
                return
            if action == "toggle_nft":
                self._show_nft = not self._show_nft     # instant, next render shows it
            elif action == "toggle_total":
                # rate↔cumulative lives in the peer ROWS (built in _fetch), so
                # rebuild them now for instant feedback rather than waiting a tick.
                self._show_total = not self._show_total
                self._fetch()
            elif action:
                _, term_h = shutil.get_terminal_size((80, 24))
                self._off = _scroll_key(action, self._off, len(self._rows),
                                        self._view_h(term_h))


def _watch_live(cfg, own_id, own_addr, interval: float = 2.0,
                show_all: bool = False, show_total: bool = False) -> int:
    """Live, scrollable `gw watch`: link state + per-second throughput + an
    async latency column, in a viewport that scrolls when there are more peers
    than screen rows. See _WatchApp. Root + a terminal required."""
    if not sys.stdout.isatty():
        sys.exit("gw watch needs a terminal to redraw into; "
                 "use 'gw watch --snapshot' for piped/one-shot output")
    if os.geteuid() != 0:
        # Root is for `wg show` (live link state) — the same gate the static
        # right-side columns have. Pinging itself is unprivileged on Linux.
        sys.exit("gw watch needs root — it reads live WireGuard state "
                 "(wg show). Try: sudo gw watch  (or gw watch --snapshot "
                 "for a no-root static view)")
    prober = _LatencyProber()
    prober.start()
    app = _WatchApp(cfg, own_id, own_addr, prober, max(0.5, interval),
                    show_all, show_total)
    try:
        with _cbreak_terminal() as fd:
            app.run(fd)
    except KeyboardInterrupt:
        pass
    finally:
        prober.stop()
    return 0


def _reconcile_freshness(cfg) -> "str | None":
    """Last completed reconcile pass — the 'is the daemon alive and working'
    heartbeat, shown in `gw watch` for EVERY role (the anchor never syncs, so
    this is its only freshness signal). None if the marker isn't there yet."""
    from . import reconcile as rmod
    last = rmod.read_last_reconcile(cfg.data_dir)
    if last is not None:
        last_dt = _parse_iso(last)
        age = (dt.datetime.now(_UTC) - last_dt).total_seconds() if last_dt else 0.0
        if age <= 30:                 # reconcile runs every ~5s → alive right now
            return f"reconciled {_fmt_ago(last)}"
    # Not fresh (or never reconciled). If the daemon died on an unrecoverable
    # STARTUP condition it left a breadcrumb — show WHY it's down, not just that
    # it is. This is the visible end of the restart-loop fix: the reason lands
    # right here in the header the operator already reads.
    fatal = rmod.read_daemon_fatal(cfg.data_dir)
    if fatal:
        return (f"⚠ daemon FAILED to start: {fatal['reason']} "
                f"({_fmt_ago(fatal['ts'])}) — see logs below")
    if last is None:
        return "never reconciled — is the daemon running? (sudo gw run)"
    return (f"⚠ last reconcile {_fmt_ago(last)} — daemon stalled or stopped? "
            f"(should be seconds)")


def _sync_freshness(cfg) -> "str | None":
    """How fresh the local directory is — shown at the TOP of `gw watch` so the
    roster/segment view's staleness is obvious (it's only as current as the last
    sync). None on the anchor (it's the source of truth)."""
    if cfg.role == "anchor":
        return None
    from . import sync as syncmod
    last = syncmod.read_last_sync(cfg.data_dir)
    if last is None:
        return "never synced (is the daemon running / reaching the anchor?)"
    last_dt = _parse_iso(last)
    age = (dt.datetime.now(_UTC) - last_dt).total_seconds() if last_dt else 0.0
    if age > 120:
        return (f"⚠ directory synced {_fmt_ago(last)} — anchor unreachable? "
                f"this view may be stale")
    return f"directory synced {_fmt_ago(last)}"


def _fmt_ago(iso: str) -> str:
    """A coarse 'time since' for a timestamp: seconds, then minutes, then >1h."""
    t = _parse_iso(iso)
    if t is None:
        return "?"
    s = (dt.datetime.now(_UTC) - t).total_seconds()
    if s < 0:
        return "just now"
    if s < 60:
        return f"{int(s)}s ago"
    if s < 3600:
        return f"{int(s // 60)}m ago"
    return ">1h ago"


def _fmt_until(iso: str) -> str:
    """Minutes until a future timestamp (for the open door's close time)."""
    t = _parse_iso(iso)
    if t is None:
        return "?"
    s = (t - dt.datetime.now(_UTC)).total_seconds()
    if s <= 0:
        return "now"
    if s < 60:
        return "<1m"
    return f"{int(s // 60) + (1 if s % 60 else 0)}m"


def _door_status_lines(cfg) -> list:
    """The `door:` block for `gw watch` — anchor only. Shows whether the
    enrollment door is open (and time-to-close) or closed (and how long ago),
    plus failed attempts + source IPs and the last enrollment."""
    from . import door
    try:
        st = door.read_door_status(cfg.data_dir)
    except PermissionError:
        # door_status.json is 0600 root (it holds attempt source IPs). Degrade
        # honestly rather than dying — status is a no-root command.
        return ["door     : (state readable only with root — sudo gw watch)"]
    if st is None:
        return ["door     : closed (never opened)"]

    lines = []
    attempts = st.get("attempts") or []

    def _attempt_summary(prefix: str):
        if not attempts:
            return
        ips = ", ".join(f"{a.get('ip','?')} ({a.get('reason','?')})" for a in attempts)
        n = len(attempts)
        lines.append(f"           {prefix}{n} failed attempt{'s' if n != 1 else ''}: {ips}")

    if st.get("state") == "open" and st.get("standing"):
        n = int(st.get("enroll_count") or 0)
        head = f"door     : OPEN (standing) — {n} enrolled"
        enr = st.get("enrolled")
        if enr:
            head += f", last: {enr.get('hostname','?')} ({_fmt_ago(enr.get('ts',''))})"
        if st.get("opened_at"):
            head += f" (opened {_fmt_ago(st['opened_at'])})"
        lines.append(head)
        grants = ", ".join(st.get("caps") or []) or "(default)"
        lines.append(f"           grants: {grants} · closes only via: gw close-door")
        # The standing token, re-retrievable for baking into new images without
        # re-issuing. From the 0600-root window file — and this whole door block
        # only renders for a root `gw watch` (door_status.json is 0600 too), so
        # the token (which IS the enrollment credential) never shows non-root.
        w = door.read_window(cfg.data_dir)
        if w and w.get("token"):
            lines.append(f"           token: {w['token']}")
        _attempt_summary("")
    elif st.get("state") == "open":
        head = f"door     : OPEN — closes in {_fmt_until(st.get('expires',''))}"
        if st.get("opened_at"):
            head += f" (opened {_fmt_ago(st['opened_at'])})"
        lines.append(head)
        grants = ", ".join(st.get("caps") or []) or "(default)"
        pin = st.get("pinned_hostname")
        lines.append(f"           grants: {grants}"
                     + (f"; hostname pinned to {pin!r}" if pin else ""))
        _attempt_summary("")
        left = max(0, int(st.get("max_attempts", 3)) - len(attempts))
        lines.append(f"           {left} attempt{'s' if left != 1 else ''} remaining")
    else:
        reason = st.get("close_reason") or "closed"
        enr = st.get("enrolled")
        if reason == "enrolled" and enr:
            phrase = f"enrolled {enr.get('hostname','?')} from {enr.get('ip','?')}"
        else:
            phrase = {"expired": "window expired with no enrollment",
                      "attempts_exhausted": "too many failed attempts",
                      "superseded": "replaced by a newer invite / daemon stop",
                      }.get(reason, reason)
        when = _fmt_ago(st["closed_at"]) if st.get("closed_at") else "?"
        lines.append(f"door     : closed — last closed {when} ({phrase})")
        _attempt_summary("last window: ")
    return lines


def _dur_short(seconds: float) -> str:
    """Compact future-duration: '45m', '18h', '2d 3h'."""
    s = int(seconds)
    if s < 3600:
        return f"{s // 60}m"
    if s < 86400:
        return f"{s // 3600}h"
    d, h = s // 86400, (s % 86400) // 3600
    return f"{d}d {h}h" if h else f"{d}d"


def _self_health_lines(cfg, directory, own_id) -> list:
    """The self/health block for `gw watch` — local facts about THIS node
    (version, own credential, reachability posture, trust anchors, and — for a
    plain node — how fresh the directory cache is). All local: no root, no
    network, so `status` stays instant. Live/reach-out checks (clock skew, live
    links) stay in `gw diagnose`."""
    from . import sync as syncmod
    lines = []
    lines.append(f"{'version':<9}: {_version()}")

    self_rec = directory.get(own_id) if own_id else None
    if self_rec is not None:
        left = (self_rec.cred.exp - dt.datetime.now(_UTC)).total_seconds()
        if left < 0:
            cred = f"⚠ EXPIRED {int(-left // 60)}m ago — renewal isn't keeping up"
        else:
            cred = (f"expires {self_rec.cred.exp:%Y-%m-%d %H:%M UTC} "
                    f"(in {_dur_short(left)})")
        lines.append(f"{'cred':<9}: {cred}")
    elif own_id:
        lines.append(f"{'cred':<9}: no self record yet (has the daemon published?)")

    reach = ("advertises an endpoint (dialable)" if cfg.endpoints
             else "no endpoint (outbound-only — you dial peers)")
    lines.append(f"{'reach':<9}: {reach}")

    n = len(cfg.ca_pubs_hex)
    lines.append(f"{'trust':<9}: {n} trusted CA{'' if n == 1 else 's'} · "
                 f"anchor {cfg.root_url or '(none configured)'}")

    # (Sync freshness is shown prominently at the top of `gw watch` instead —
    # see _sync_freshness — so the segment/roster view's staleness is obvious.)

    # A pending mesh rename the daemon detected from the anchor — persisted so it
    # doesn't scroll past in the log. Needs an operator action, so it's loud.
    pend = cfg.data_dir / "pending_rename.json"
    if pend.exists():
        try:
            d = json.loads(pend.read_text())
            newk = membership_key(d["new_domain"])
            lines.append(f"{'rename':<9}: ⚠ the anchor renamed this mesh "
                         f"{d.get('old_domain','?')} → {d['new_domain']}. "
                         f"Migrate: sudo gw rename-mesh {newk}")
        except Exception:
            pass
    return lines


_SNAPSHOT_SCHEMA = "gw.watch/v1"


def _iso_z(t) -> "str | None":
    """A dt → 'YYYY-MM-DDTHH:MM:SSZ' (UTC, second precision), or None."""
    if t is None:
        return None
    return t.astimezone(_UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _node_view(r, cfg, now, now_epoch, own_id, own_caps, live_peers, grants) -> dict:
    """One directory record as the JSON-native per-node dict — the SINGLE model
    both `--json` and the text roster render from, so a per-node column can't
    exist in one without the other. Everything the roster shows is derived HERE
    (roles, expiry countdown, the policy peering verdict, live link stats), so
    the renderer only ever formats these primitives — never reaches back into a
    NodeRecord. `live` is present only when wg state was readable (root)."""
    from .policy import peers_allowed
    caps = list(r.cred.caps)
    entry = {
        "id": r.id_pub.hex(),
        "hostname": r.hostname,
        "addr": r.cred.addr,
        "roles": [c[len("role:"):] for c in caps if c.startswith("role:")],
        "caps": [c for c in caps if not c.startswith("role:")],
        "endpoints": list(r.endpoints),
        "iat": _iso_z(r.cred.iat),
        "exp": _iso_z(r.cred.exp),
        "expired": now >= r.cred.exp,
        "ttl_remaining_s": int((r.cred.exp - now).total_seconds()),
        "is_self": r.id_pub.hex() == own_id,
        "peer_expected": peers_allowed(own_caps, caps, grants,
                                       cfg.hostname, r.cred.hostname),
        "reachable": sorted(r.reachable) if r.reachable else [],
    }
    if live_peers is not None:
        lp = live_peers.get(base64.b64encode(r.cred.wg_pub).decode())
        if lp:
            entry["live"] = {
                "installed": True,
                "up": _handshake_fresh(lp, now_epoch),
                "last_handshake": (_iso_z(dt.datetime.fromtimestamp(
                    lp.latest_handshake, _UTC)) if lp.latest_handshake else None),
                "handshake_age_s": ((now_epoch - lp.latest_handshake)
                                    if lp.latest_handshake else None),
                "rx_bytes": lp.rx_bytes,
                "tx_bytes": lp.tx_bytes,
            }
        else:
            entry["live"] = {"installed": False}
    return entry


def _watch_snapshot_dict(cfg, own_id, own_addr) -> dict:
    """Structured, machine-readable state for `gw watch --snapshot --json`.

    Same underlying data as the text snapshot — identity, mesh + enforcement,
    daemon/sync freshness, the signed policy summary, and one entry per directory
    record (roles, caps, endpoints, expiry, the policy peering verdict from THIS
    node, the node's advertised `reachable` set, and live WireGuard stats when run
    as root) — as a STABLE contract (the `schema` field is versioned) so monitors
    and jq pipelines don't scrape the human view. Expired records are INCLUDED and
    flagged (`expired: true`); tooling filters as it sees fit."""
    from .directory import Directory
    from .policy import peers_allowed, POLICY_BASENAME
    from .wire import GrantTable
    from . import reconcile as rmod
    from . import sync as syncmod

    now = dt.datetime.now(_UTC)
    now_epoch = int(now.timestamp())
    directory = Directory.load(cfg.dir_cache_path)
    grants = _load_policy_grants(cfg)

    policy = None
    ppath = cfg.data_dir / POLICY_BASENAME
    if ppath.exists():
        try:
            t = GrantTable.from_dict(json.loads(ppath.read_text()))
            policy = {"seq": t.seq, "grants": len(t.grants)}
        except Exception:
            policy = None

    records = sorted(directory.all(), key=lambda r: r.hostname)
    own_rec = next((r for r in records if r.id_pub.hex() == own_id), None)
    own_caps = list(own_rec.cred.caps) if own_rec else list(cfg.caps)

    # Live data plane (root only, wg readable) — else each entry omits `live`.
    live_peers = None
    if os.geteuid() == 0:
        try:
            from . import wg as wgmod
            live_peers = wgmod.get_peers(cfg.wg_interface)
        except Exception:
            live_peers = None

    nodes = [_node_view(r, cfg, now, now_epoch, own_id, own_caps, live_peers, grants)
             for r in records]
    live_n = sum(1 for n in nodes if not n["expired"])
    expired_n = len(nodes) - live_n

    last_recon = rmod.read_last_reconcile(cfg.data_dir)
    recon_dt = _parse_iso(last_recon) if last_recon else None
    recon_age = (now - recon_dt).total_seconds() if recon_dt else None
    fatal = rmod.read_daemon_fatal(cfg.data_dir)
    last_sync = None if cfg.role == "anchor" else syncmod.read_last_sync(cfg.data_dir)
    sync_dt = _parse_iso(last_sync) if last_sync else None

    return {
        "schema": _SNAPSHOT_SCHEMA,
        "generated_at": _iso_z(now),
        "self": {
            "id": own_id,
            "hostname": cfg.hostname,
            "addr": own_addr,
            "role": cfg.role,
            "roles": [c[len("role:"):] for c in own_caps if c.startswith("role:")],
            "is_anchor": "*" in [c[len("role:"):] for c in own_caps
                                 if c.startswith("role:")],
        },
        "mesh": {
            "domain": cfg.mesh_domain,
            "interface": cfg.wg_interface,
            "enforce_ports": bool(getattr(cfg, "enforce_ports", True)),
            # True = enforce_ports is on but nftables is unusable, so the daemon
            # is running UNFILTERED (see gw watch). (H2)
            "enforcement_degraded": rmod.read_enforce_degraded(cfg.data_dir) is not None,
        },
        "policy": policy,
        "daemon": {
            "last_reconcile": _iso_z(recon_dt),
            "reconcile_age_s": round(recon_age, 1) if recon_age is not None else None,
            "healthy": recon_age is not None and recon_age <= 30,
            "fatal": {"reason": fatal["reason"], "ts": fatal["ts"]} if fatal else None,
        },
        "sync": {
            "last": _iso_z(sync_dt),
            "age_s": round((now - sync_dt).total_seconds(), 1) if sync_dt else None,
        },
        "has_live_data": live_peers is not None,
        "counts": {"total": len(nodes), "live": live_n, "expired": expired_n},
        "nodes": nodes,
    }


def cmd_watch(args) -> int:
    from .config import load_config
    from .directory import Directory

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        print("not configured (no config file at %s)" % cfg_path)
        return 0

    cfg = load_config(cfg_path)

    # The snapshot (static) view is a no-root command: it reads only the public
    # files (id_pub.hex, directory.json). But on a legacy install with a 0700
    # data dir, those reads fail invisibly (exists() → False, Directory.load →
    # empty) and it would lie ("keys not generated", "directory is empty"). Say
    # the truth instead.
    if (cfg.data_dir.exists() and not os.access(cfg.data_dir, os.X_OK)) or (
            cfg.dir_cache_path.exists() and not os.access(cfg.dir_cache_path, os.R_OK)):
        sys.exit(f"can't read the public state under {cfg.data_dir} (a legacy "
                 f"install with a 0700 data dir?). Either run: sudo gw watch, "
                 f"or open the public files up: sudo chmod 755 {cfg.data_dir}")
    own_id, own_addr = _own_identity(cfg.data_dir)

    # --json is a one-shot machine snapshot (implies --snapshot): a stable,
    # versioned schema for monitors/jq, so nothing has to scrape the human view.
    if getattr(args, "json", False):
        print(json.dumps(_watch_snapshot_dict(cfg, own_id, own_addr), indent=2))
        return 0

    # Live is the default; a static one-shot is --snapshot (for piping/logging),
    # and we auto-fall-back to it when there's no terminal to redraw into.
    if not getattr(args, "snapshot", False) and sys.stdout.isatty():
        # Redraw-in-place live view: link state + per-second throughput + an
        # async latency column (pings run only while you're watching). Needs
        # root for live WireGuard state — that's why the default wants sudo.
        return _watch_live(cfg, own_id, own_addr,
                            interval=max(1.0, getattr(args, "interval", 2.0) or 2.0),
                            show_all=getattr(args, "all", False),
                            show_total=getattr(args, "total", False))

    directory = Directory.load(cfg.dir_cache_path)
    grants = _load_policy_grants(cfg)

    for line in _watch_header(cfg, directory, own_id, own_addr):
        print(line)
    for line in _main_firewall_lines(cfg):         # host firewall vs the mesh port(s)
        print(line)
    for line in _nft_table_lines(cfg):             # greasewood's own nftables table, verbatim
        print(line)
    print()

    now = dt.datetime.now(_UTC)
    all_records = sorted(directory.all(), key=lambda r: r.hostname)

    if not all_records:
        print("directory is empty — run 'gw join <token>' then 'gw run'")
        return 0

    # Live mesh only, unless --all: expired records are hidden (a lapsed node is
    # not in the mesh — peers have evicted it — so it doesn't belong in the view).
    show_all = getattr(args, "all", False)
    records, hidden = _live_and_hidden(all_records, now, show_all)
    if not records:
        print(f"no live nodes — {hidden} expired record(s) hidden "
              f"(gw watch --all to show them)")
        return 0

    is_root = os.geteuid() == 0

    # DOGFOOD: the roster is rendered from the EXACT snapshot `gw watch --json`
    # emits, round-tripped through serialization — so the human view can only
    # ever show what the machine contract carries (drop or rename a field and it
    # breaks BOTH, not just the JSON). `nodes` is that model; the header/firewall
    # /nft chrome above and the segment-health below stay on records (they aren't
    # per-node columns, and raw nft dumps don't belong in a machine contract).
    snap = json.loads(json.dumps(_watch_snapshot_dict(cfg, own_id, own_addr)))
    has_live = snap["has_live_data"]
    node_by_id = {n["id"]: n for n in snap["nodes"]}

    def _nodes_for(recs):                        # the model rows for these records
        return [node_by_id[r.id_pub.hex()] for r in recs if r.id_pub.hex() in node_by_id]

    if getattr(args, "by_role", False):
        # One table per named role. A node appears under every role it holds,
        # and the anchor (role:*) appears under ALL of them — so many nodes
        # show up in more than one table. Health under each group flags only
        # policy-EXPECTED links that are down (the emergent-segment view).
        named = sorted({t for r in records for t in _record_roles(r) if t != "*"})
        shown: set[str] = set()
        for tag in named:
            members = [r for r in records
                       if tag in _record_roles(r) or "*" in _record_roles(r)]
            shown.update(r.id_pub.hex() for r in members)
            print(f"role: {tag}  ({len(members)} node{'' if len(members) == 1 else 's'})")
            for line in _render_roster(_nodes_for(members), cfg, has_live, is_root):
                print(line)
            _print_segment_health(members, cfg, grants)
            print()
        # Anything not shown above — nodes with no role. They still peer on a
        # flat mesh (no policy); under a policy they reach only the anchor.
        leftover = [r for r in records if r.id_pub.hex() not in shown]
        if leftover:
            print(f"(no role)  ({len(leftover)} node{'' if len(leftover) == 1 else 's'}) "
                  f"— hold no role: tag; under a grant table they reach only the anchor")
            for line in _render_roster(_nodes_for(leftover), cfg, has_live, is_root):
                print(line)
            print()
    else:
        for line in _render_roster(_nodes_for(records), cfg, has_live, is_root):
            print(line)
        print()

    if hidden:
        print(f"{len(records)} live · {hidden} expired hidden (gw watch --all to show)")
    else:
        print(f"{len(records)} record(s) in local directory cache")
    return 0


# ---------------------------------------------------------------------------
# diagnose — pairwise link diagnosis (up to two nodes + the anchor)
# ---------------------------------------------------------------------------

def _anchor_clock_skew(root_url: str, timeout: float = 3.0) -> "float | None":
    """Local-minus-anchor clock difference in seconds via /health's 'now' stamp,
    or None if the anchor is unreachable or doesn't send one (older anchor)."""
    import urllib.request
    try:
        with urllib.request.urlopen(f"{root_url.rstrip('/')}/health",
                                    timeout=timeout) as resp:
            raw = json.loads(resp.read()).get("now")
        if not raw:
            return None
        anchor_now = _parse_iso(raw)
        if anchor_now is None:
            return None
        return (dt.datetime.now(_UTC) - anchor_now).total_seconds()
    except Exception:
        return None


# IPv6 header (40) + ICMPv6 echo header (8): the fixed overhead an ICMP echo
# adds on top of its -s payload, so payload = iface_mtu - 48 fills exactly one
# interface-MTU packet.
_ICMP6_OVERHEAD = 48


def _iface_mtu(iface: str) -> "int | None":
    """The MTU of the WireGuard interface, or None if it can't be read."""
    r = subprocess.run(["ip", "-o", "link", "show", iface],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return None
    parts = r.stdout.split()
    for i, tok in enumerate(parts):
        if tok == "mtu" and i + 1 < len(parts):
            try:
                return int(parts[i + 1])
            except ValueError:
                return None
    return None


def _ping6_df(addr: str, payload: int, timeout: int = 1) -> "bool | None":
    """Send one DF (don't-fragment) ICMPv6 echo of `payload` bytes across the
    overlay. True if a reply came back, False if not, None if ping is missing.
    -M do forbids fragmentation, so an oversized packet is dropped rather than
    split — which is exactly what a full-size tunnel packet does over a
    too-small underlay path."""
    ping = shutil.which("ping")
    if not ping:
        return None
    r = subprocess.run(
        [ping, "-6", "-M", "do", "-c", "1", "-W", str(timeout),
         "-s", str(payload), addr],
        capture_output=True, text=True)
    return r.returncode == 0


def _mtu_probe(iface: str, addr: str, iface_mtu: "int | None") -> "str | None":
    """Detect a path-MTU blackhole to a linked peer: a small DF ping succeeds
    but a full-interface-MTU one is dropped. Returns a warning string, or None
    if the path is clean, ping is unavailable, or the result is inconclusive
    (small ping already failing means the link is just down, not an MTU issue)."""
    if iface_mtu is None:
        return None
    small = _ping6_df(addr, 100)
    if not small:  # None (no ping) or False (link down) → don't cry wolf
        return None
    payload = iface_mtu - _ICMP6_OVERHEAD
    if _ping6_df(addr, payload):
        return None  # full-size packets pass → no blackhole
    return (f"PATH MTU BLACKHOLE: {payload}-byte (full {iface_mtu}-MTU) packets "
            f"to {addr} are dropped though small ones pass — TLS handshakes and "
            f"other large transfers will hang. Lower the tunnel MTU "
            f"(ip link set {iface} mtu 1280) or fix the underlay path MTU.")


def _self_firewall_verdict(port: int) -> str:
    """This host's own nftables verdict for a UDP port: 'OPEN', 'CLOSED' (a
    default-drop policy with no accept rule), 'open (no default-drop)', or
    '??? (nft unreadable)'. Only the local host is knowable — every other node's
    firewall is inferred from observed connectivity or left ???."""
    from . import firewall as fw
    rs = fw._load_ruleset()
    if rs is None:
        return "??? (nft unreadable)"
    if not fw.default_drop(rs):
        return "open (no default-drop)"
    missing = fw.missing_rules(rs, [fw.Rule("udp", port, None, "mesh")])
    return "CLOSED — blocked!" if missing else "OPEN"


def _diag_anchor_record(directory, cfg, own_rec):
    """The anchor's directory record. If this host IS the anchor, that's our own
    record; otherwise the node at the control-plane URL (root_url) address.
    None if unresolvable / not yet in cache."""
    if cfg.role == "anchor":
        return own_rec
    # root_url is an overlay (IPv6) control-plane URL in practice, but parse it
    # with the stdlib rather than a hand-rolled bracket regex: urlparse unbrackets
    # v6, strips the port, and stays correct if a bare host ever appears.
    from urllib.parse import urlparse
    host = urlparse(cfg.root_url or "").hostname
    if not host:
        return None
    for record in directory.all():
        if record.cred.addr == host:
            return record
    return None


@dataclass
class _DiagnoseColumn:
    """One column of the diagnose comparison — a node's resolved facts."""
    label: str
    is_self: bool
    rec: object                            # NodeRecord | None (None: not in cache)
    addr: str = "?"
    underlay_v6: str = "-"
    underlay_v4: str = "-"
    caps: list = field(default_factory=list)
    roles: str = ""                        # comma-joined role names
    credential: str = ""                   # human verdict, e.g. "valid · 23h"
    has_endpoint: bool = False             # dialable iff it advertises an endpoint
    endpoint: str = "—"                    # the endpoint to dial, or "—"
    scope_note: str = ""                   # set iff the endpoint isn't globally reachable
    handshake_age: "int | None" = None     # secs since last handshake, or None
    firewall: str = ""                     # this-host verdict / inferred / "???"


def _resolve_diag_columns(args, cfg, directory, own_id_bytes, own_rec) -> list:
    """The up-to-three nodes to compare, as (label, rec, is_self): the requested
    pair (or self↔anchor with no args, self↔A with one), plus the anchor as a
    reference. Deduped by overlay address, capped at three, order preserved."""
    from .hosts import sanitize

    def find(name):
        # Accept the full mesh name too (the roster prints bastion.pm.internal,
        # so that's what people copy into diagnose) — strip the domain suffix.
        want = sanitize(name)
        dom = sanitize("x." + cfg.mesh_domain)[1:]     # ".pm.internal", sanitized
        if want.endswith(dom):
            want = want[:-len(dom)]
        return next((r for r in directory.all() if sanitize(r.hostname) == want), None)

    requested = [n for n in (getattr(args, "nodes", None) or []) if n]
    picks = []                                  # list of (label, rec|None, is_self)
    for name in requested:
        rec = find(name)
        if rec is None:
            sys.exit(f"no node named {name!r} in the directory cache (see gw watch)")
        picks.append((rec.hostname, rec, rec.id_pub == own_id_bytes))

    if not requested:                           # 0 args: self ↔ anchor
        picks.append((cfg.hostname, own_rec, True))
    elif len(requested) == 1:                   # 1 arg: self ↔ A
        picks.insert(0, (cfg.hostname, own_rec, True))

    anchor_rec = _diag_anchor_record(directory, cfg, own_rec)  # anchor as reference
    if anchor_rec is not None:
        picks.append((anchor_rec.hostname, anchor_rec,
                      anchor_rec.id_pub == own_id_bytes))

    columns, seen = [], set()
    for label, rec, is_self in picks:
        key = rec.cred.addr if rec is not None else ("self" if is_self else label)
        if key not in seen:
            seen.add(key)
            columns.append((label, rec, is_self))
    return columns[:3]


def _build_diag_facts(columns, cfg, own_addr, ca_pubs, revoked,
                      live_peers, now, now_epoch, port) -> list:
    """Turn (label, rec, is_self) columns into _DiagnoseColumn facts — the
    credential verdict, underlay families, reachability, live handshake age, and
    the firewall verdict (directly known for THIS host, inferred OPEN from an
    observed handshake for a peer, else ???)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from .wire import _canonical

    def signed_by_trusted_ca(rec) -> bool:
        body = _canonical(rec.cred._body_dict())
        for raw_pub in ca_pubs:
            try:
                Ed25519PublicKey.from_public_bytes(raw_pub).verify(rec.cred.ca_sig, body)
                return True
            except InvalidSignature:
                continue
        return False

    def credential_verdict(rec) -> str:
        if rec is None:
            return "(not in cache)"
        if not signed_by_trusted_ca(rec):
            return "✗ untrusted CA"
        if rec.id_pub.hex() in revoked:
            return "✗ REVOKED"
        left = (rec.cred.exp - now).total_seconds()
        if left < 0:
            return f"✗ EXPIRED {int(-left // 60)}m ago"
        return f"valid · {_dur_short(left)}"

    def handshake_age(rec) -> "int | None":
        if rec is None:
            return None
        live_peer = live_peers.get(_wg_key(rec))
        if live_peer and live_peer.latest_handshake:
            age = now_epoch - live_peer.latest_handshake
            return age if age <= _LINK_FRESH_SECS else None
        return None

    facts = []
    for label, rec, is_self in columns:
        v6, v4 = _underlay_addrs(rec.endpoints if rec else cfg.endpoints)
        has_endpoint = v6 != "-" or v4 != "-"
        age = handshake_age(rec)
        if is_self:
            firewall = _self_firewall_verdict(port)
        elif not has_endpoint:
            firewall = "n/a (outbound-only)"
        elif age is not None:
            firewall = "OPEN (inferred: handshake)"
        else:
            firewall = "??? unconfirmed"
        facts.append(_DiagnoseColumn(
            label=label, is_self=is_self, rec=rec,
            addr=rec.cred.addr if rec else (own_addr or "?"),
            underlay_v6=v6, underlay_v4=v4,
            caps=list(rec.cred.caps) if rec else list(cfg.caps),
            roles=(",".join(_record_roles(rec)) if rec else
                   ",".join(s[len("role:"):] for s in cfg.caps
                            if s.startswith("role:"))),
            credential=credential_verdict(rec),
            has_endpoint=has_endpoint,
            endpoint=v6 if v6 != "-" else (v4 if v4 != "-" else "—"),
            scope_note=_endpoint_scope_note(v6, v4),
            handshake_age=age, firewall=firewall))
    return facts


def _print_diag_header(cfg, own_addr, port, ca_pubs) -> None:
    print(f"diagnose · this host: {cfg.hostname} ({own_addr}) · "
          f"iface {cfg.wg_interface} · mesh UDP {port}")
    if not ca_pubs:
        print("  ⚠ no trusted CA keys — nothing will verify (check [ca] trusted_pubs)")
    if cfg.root_url:
        skew = _anchor_clock_skew(cfg.root_url)
        if skew is None:
            print("  clock: anchor unreachable — skew check skipped")
        elif abs(skew) >= 60:
            print(f"  ⚠ clock {skew:+.0f}s off the anchor — FIX NTP (past ±300s "
                  f"renewals refused; expiry checks misfire earlier)")
    if os.geteuid() != 0:
        print("  ⚠ not root — no live WireGuard state; link status & firewall "
              "inference unavailable (re-run with sudo)")
    print()


def _print_diag_table(facts, port) -> None:
    """The comparison table: one column per node, one row per fact."""
    heads = [f"{col.label}{' (self)' if col.is_self else ''}" for col in facts]
    rows = [("overlay", [col.addr for col in facts]),
            ("underlay v6", [col.underlay_v6 for col in facts]),
            ("underlay v4", [col.underlay_v4 for col in facts]),
            ("reachable", ["no (outbound-only)" if not col.has_endpoint
                           else f"yes, but {col.scope_note}" if col.scope_note
                           else "yes (advertises endpoint)" for col in facts]),
            ("roles", [col.roles or "-" for col in facts]),
            ("credential", [col.credential for col in facts]),
            (f"firewall udp/{port}", [col.firewall for col in facts])]
    label_w = max([len(r[0]) for r in rows] + [0])
    col_w = [max(len(heads[i]), *(len(r[1][i]) for r in rows))
             for i in range(len(facts))]
    print(" " * label_w + "  " +
          "  ".join(f"{heads[i]:<{col_w[i]}}" for i in range(len(facts))))
    for name, cells in rows:
        print(f"{name:<{label_w}}  " +
              "  ".join(f"{cells[i]:<{col_w[i]}}" for i in range(len(cells))))
    print()


def _print_pair_verdict(col_a, col_b, cfg, port, grants=None) -> None:
    """Whether col_a and col_b can form a tunnel, and if not, which factor blocks
    it: policy (the grant table) → a dialable direction → live handshake,
    localizing a failure to this host's firewall vs an upstream router/NAT when
    possible."""
    from .policy import peers_allowed

    def _hn(col):
        return col.rec.cred.hostname if col.rec is not None else None

    print(f"  {col_a.label} ↔ {col_b.label}")
    if not peers_allowed(col_a.caps, col_b.caps, grants, _hn(col_a), _hn(col_b)):
        print("    ✗ policy: no grant connects their roles or host names — no "
              "tunnel by design (add a grant to grants.toml and `gw policy "
              "apply` to change this)")
        return
    if "*" in col_a.roles or "*" in col_b.roles:
        why = "anchor is reach-all (hardwired beneath the policy)"
    elif grants is None:
        why = "no policy — flat mesh, every verified member tunnels"
    else:
        why = "a grant connects their roles"
    print(f"    policy: ✓ {why}")

    a_dials_b = col_b.has_endpoint     # a can dial b iff b listens with an endpoint
    b_dials_a = col_a.has_endpoint

    def _dir(src, dst):
        if not dst.has_endpoint:
            return f"can't — {dst.label} is outbound-only / advertises no endpoint"
        # State the address class as a fact, no inference: a non-global endpoint
        # is reachable only from its own network (a same-LAN peer still can), so
        # don't claim it "won't work" — just name it so the operator can judge.
        if dst.scope_note:
            return f"dial {dst.endpoint}  ⚠ {dst.scope_note}"
        return f"dial {dst.endpoint}"
    print(f"    {col_a.label} → {col_b.label}: {_dir(col_a, col_b)}")
    print(f"    {col_b.label} → {col_a.label}: {_dir(col_b, col_a)}")
    if not (a_dials_b or b_dials_a):
        print("    ✗ no dialable direction — the link can't form "
              "(both outbound-only)")
        return

    this_host = col_a if col_a.is_self else (col_b if col_b.is_self else None)
    other = col_b if col_a.is_self else (col_a if col_b.is_self else None)
    if this_host is None:
        print("    live: (neither is this host) — should link per the "
              "directory; run 'gw diagnose' from either for live confirmation")
        return
    if other.handshake_age is not None:
        print(f"    live: ● LINKED (handshake {other.handshake_age}s ago) — path open; "
              f"{other.label}'s firewall/router inferred OPEN")
        # A LINKED peer can still silently blackhole full-size packets (a
        # WG-over-cloud MTU mismatch): small pings pass, TLS handshakes hang.
        if os.geteuid() == 0:
            warn = _mtu_probe(cfg.wg_interface, other.addr,
                              _iface_mtu(cfg.wg_interface))
            if warn:
                print(f"    ⚠ {warn}")
        return
    print("    live: ○ no handshake yet")
    self_fw = this_host.firewall
    if this_host.has_endpoint:
        if self_fw.startswith("OPEN") or self_fw.startswith("open"):
            print(f"    ⚠ our host firewall {self_fw} for udp/{port} — so the "
                  f"block is NOT this host. If {other.label} can't reach us, "
                  f"suspect an UPSTREAM router/NAT not forwarding udp/{port} to "
                  f"this host, or {other.label}'s outbound/daemon.")
        elif self_fw.startswith("CLOSED"):
            print(f"    ⚠ our host firewall {self_fw} for udp/{port} — OPEN it "
                  f"(create/join printed the exact rule).")
        else:
            print(f"    firewall udp/{port} here: {self_fw}")
    if other.has_endpoint:
        print(f"    ⚠ we can dial {other.label} at {other.endpoint} but it isn't "
              f"answering — check {other.label}'s host firewall + any upstream "
              f"port-forward for udp/{port}, and that its daemon is up "
              f"('gw diagnose' on {other.label} shows its host firewall).")


def cmd_diagnose(args) -> int:
    """
    Pairwise link diagnosis. `gw diagnose [A [B]]` lays up to two named nodes
    plus the anchor side by side and explains, per pair, whether a WireGuard tunnel
    can form — and if not, WHICH factor blocks it, with the firewall/reachability
    directionality that's usually the real question.

      gw diagnose            this node ↔ the anchor
      gw diagnose A          this node ↔ A            (+ anchor as reference)
      gw diagnose A B        A ↔ B                    (+ anchor as reference)

    Only THIS host's firewall is directly knowable; a peer's is inferred OPEN
    from an observed handshake (packets flowing prove its whole inbound path —
    host firewall + any router/NAT + daemon) and otherwise shown ???. When the
    pair involves this host, the verdict localizes a failure: e.g. "our host
    firewall allows the port, so a peer that still can't reach us points at an
    upstream router/NAT not forwarding it."
    """
    from .config import load_config
    from .directory import Directory
    from . import wg as wgmod

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        print(f"not configured (no config file at {cfg_path})")
        return 1
    cfg = load_config(cfg_path)
    port = cfg.listen_port

    own_id, own_addr = _own_identity(cfg.data_dir)
    if own_id is None:
        print("keys not generated yet — run 'gw join <token>' or 'gw create' first")
        return 1
    own_id_bytes = bytes.fromhex(own_id)

    for warning in _key_file_warnings(_secret_key_paths(cfg)):
        print(f"  ⚠ {warning}")

    ca_pubs = [bytes.fromhex(h) for h in cfg.ca_pubs_hex]
    revoked: set = set()
    rev_path = cfg.data_dir / "revoked.json"
    if rev_path.exists():
        try:
            revoked = set(json.loads(rev_path.read_text()).get("revoked", []))
        except Exception:
            pass

    try:
        live_peers = wgmod.get_peers(cfg.wg_interface) or {}
    except Exception:
        live_peers = {}
    directory = Directory.load(cfg.dir_cache_path)
    now = dt.datetime.now(_UTC)
    now_epoch = int(time.time())
    own_rec = directory.get(own_id)

    columns = _resolve_diag_columns(args, cfg, directory, own_id_bytes, own_rec)
    facts = _build_diag_facts(columns, cfg, own_addr, ca_pubs, revoked,
                              live_peers, now, now_epoch, port)

    _print_diag_header(cfg, own_addr, port, ca_pubs)
    _print_diag_table(facts, port)

    grants = _load_policy_grants(cfg)
    print("link viability  (direct-or-fail; ??? firewalls assumed open)")
    for col_a, col_b in itertools.combinations(facts, 2):
        _print_pair_verdict(col_a, col_b, cfg, port, grants)
    return 0


# ---------------------------------------------------------------------------
# renew  (force an immediate credential renewal for THIS node)
# ---------------------------------------------------------------------------
