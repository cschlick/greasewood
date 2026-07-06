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
import datetime as dt
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


def _record_segments(r) -> list[str]:
    """The segment names a record belongs to (from its `segment:` caps)."""
    return [c[len("segment:"):] for c in r.cred.caps if c.startswith("segment:")]


def _fmt_bytes(n) -> str:
    """Human byte size: 4200000 → '4.0M'."""
    x = float(n)
    for unit in ("B", "K", "M", "G"):
        if x < 1024:
            return f"{int(x)}{unit}" if unit == "B" else f"{x:.1f}{unit}"
        x /= 1024
    return f"{x:.1f}T"


def _fmt_hs_age(age_s: float) -> str:
    """Compact age for a handshake: 12→'12s', 90→'1m', 7200→'2h', bigger→'Nd'."""
    if age_s < 60:
        return f"{int(age_s)}s"
    if age_s < 3600:
        return f"{int(age_s // 60)}m"
    if age_s < 86400:
        return f"{int(age_s // 3600)}h"
    return f"{int(age_s // 86400)}d"


def _roster_lines(records, cfg, now, own_id, live_peers, is_root,
                  latency=None, rates=None) -> list:
    """The split roster as a list of lines: LEFT is the mesh (fleet-wide, same on
    every node — name, addr, reachable, segments, credential); RIGHT is THIS
    node's view. Without root the right side is just the policy 'would I peer'
    answer. With root it's the live link + cumulative traffic. In LIVE mode
    (latency dict supplied) the right side is link + per-second RATE + a latency
    column that fills in asynchronously (blank until each peer's ping returns)."""
    from .hosts import mesh_name
    from .reconcile import default_policy

    have_live = live_peers is not None
    is_live = latency is not None
    now_epoch = int(now.timestamp())

    def _exp(r):
        left = (r.cred.exp - now).total_seconds()
        if left < 0:
            return "EXPIRED"
        if left < 3600:
            return "<1h!"
        h = int(left // 3600)
        return f"{h // 24}d" if h >= 48 else f"{h}h"

    def _right(r, is_self, peers, lp):
        if is_live:                             # link · rate · latency
            if is_self:
                return ("(self)", "", latency.get(r.cred.addr, "…"))
            if not peers:
                return ("— not a peer", "", "")
            if lp is None:
                return ("not installed", "", "")
            if lp.latest_handshake and (now_epoch - lp.latest_handshake) <= 180:
                return (f"● up, {_fmt_hs_age(now_epoch - lp.latest_handshake)}",
                        (rates or {}).get(r.cred.addr, ""),
                        latency.get(r.cred.addr, "…"))   # … = ping in flight
            return ("○ no handshake", "", "—")
        if not have_live:                       # policy only (no root)
            return ("self" if is_self else ("yes" if peers else "no"),)
        if is_self:
            return ("(self)", "")
        if not peers:
            return ("— not a peer", "")
        if lp is None:
            return ("not installed", "")
        if lp.latest_handshake and (now_epoch - lp.latest_handshake) <= 180:
            return (f"● up, {_fmt_hs_age(now_epoch - lp.latest_handshake)} ago",
                    f"↓{_fmt_bytes(lp.rx_bytes)} ↑{_fmt_bytes(lp.tx_bytes)}")
        return ("○ no handshake", "")

    left_hdr = ("name", "addr", "in", "segments", "exp")
    if is_live:
        right_hdr = ("link", "rate", "latency")
    elif have_live:
        right_hdr = ("link", "traffic")
    else:
        right_hdr = ("peer?",)

    left_rows, right_rows = [], []
    for r in records:
        left_rows.append((
            mesh_name(r.hostname, cfg.mesh_domain), r.cred.addr,
            "yes" if r.endpoints else "no",
            ",".join(_record_segments(r)) or "-", _exp(r),
        ))
        lp = (live_peers or {}).get(base64.b64encode(r.cred.wg_pub).decode())
        right_rows.append(_right(r, r.id_pub.hex() == own_id,
                                 default_policy(cfg.caps, r.cred.caps), lp))

    def _w(hdr, i, rows):
        return max(len(hdr), *(len(row[i]) for row in rows)) if rows else len(hdr)
    lw = [_w(left_hdr[i], i, left_rows) for i in range(len(left_hdr))]
    rw = [_w(right_hdr[i], i, right_rows) for i in range(len(right_hdr))]

    def _fl(cells):     # left: name right-justified, rest left
        return " ".join([f"{cells[0]:>{lw[0]}}"]
                        + [f"{cells[i]:<{lw[i]}}" for i in range(1, len(cells))])
    def _fr(cells):
        return " ".join(f"{cells[i]:<{rw[i]}}" for i in range(len(cells)))

    lwidth = len(_fl(left_hdr))
    out = [f"{'mesh — the fleet (same on every node)':<{lwidth}} │ this node",
           _fl(left_hdr) + " │ " + _fr(right_hdr),
           "-" * lwidth + "-+-" + "-" * max(len(_fr(right_hdr)), 9)]
    out += [_fl(lr) + " │ " + _fr(rr) for lr, rr in zip(left_rows, right_rows)]
    if not have_live and not is_live:
        note = ("run 'sudo gw watch' for live data links + traffic" if not is_root
                else "no live WireGuard state — is the daemon running?")
        out.append(f"({note})")
    return out


def _print_node_table(records, cfg, now, own_id, live_peers, is_root) -> None:
    for line in _roster_lines(records, cfg, now, own_id, live_peers, is_root):
        print(line)


def _segment_analysis(members):
    """Fleet-wide connectivity within a segment, from each node's self-reported
    `reachable` set (synced in the directory — no root or live wg needed).
    Returns (components, missing_edges). An edge is UP if EITHER end reports the
    other (a session is bidirectional, so one end suffices — robust to one-sided
    staleness). An edge is EXPECTED (so its absence is a fault) when at least one
    end advertises an endpoint, i.e. a dialable direction exists."""
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
            elif a.endpoints or b.endpoints:   # a link was possible but is absent
                missing.append((a, b))
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


def _print_segment_health(members, cfg) -> None:
    """Under a segment's roster: fully-connected, or the partition/down-edge
    breakdown. Uses only the synced `reachable` sets, so it works non-root."""
    from .hosts import mesh_name
    if len(members) < 2:
        return
    comps, missing = _segment_analysis(members)
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


def _watch_live(cfg, own_id, interval: float = 2.0) -> int:
    """Live, redraw-in-place `gw watch`: link state + per-second throughput
    (from the sample delta between frames) + an async latency column. Root +
    a terminal required; Ctrl-C exits."""
    from .directory import Directory
    from . import wg as wgmod

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
    prev: dict = {}          # wg_pub_b64 -> (rx, tx, monotonic) for the rate delta
    sys.stdout.write("\033[?25l")   # hide cursor
    try:
        while True:
            records = sorted(Directory.load(cfg.dir_cache_path).all(),
                             key=lambda r: r.hostname)
            try:
                live = wgmod.get_peers(cfg.wg_interface) or {}
            except Exception:
                live = {}
            now = dt.datetime.now(_UTC)
            now_epoch = int(now.timestamp())
            mono = time.monotonic()

            rates, targets = {}, []
            for r in records:
                if r.id_pub.hex() == own_id:
                    # Ping our own overlay address (~0ms) so the self row shows a
                    # latency too — makes a peer with NO latency (broken) visually
                    # distinct from the healthy rows.
                    targets.append(r.cred.addr)
                    continue
                pub = base64.b64encode(r.cred.wg_pub).decode()
                lp = live.get(pub)
                if not lp:
                    continue
                if lp.latest_handshake and (now_epoch - lp.latest_handshake) <= 180:
                    targets.append(r.cred.addr)
                    p = prev.get(pub)
                    if p and mono > p[2]:
                        dts = mono - p[2]
                        rates[r.cred.addr] = (
                            f"↓{_fmt_rate((lp.rx_bytes - p[0]) / dts)} "
                            f"↑{_fmt_rate((lp.tx_bytes - p[1]) / dts)}")
                prev[pub] = (lp.rx_bytes, lp.tx_bytes, mono)
            prober.set_targets(targets)

            body = _roster_lines(records, cfg, now, own_id, live, True,
                                 latency=prober.results, rates=rates)
            up = len(targets)
            fresh = _sync_freshness(cfg)
            frame = ["\033[H\033[J",
                     f"gw watch · {cfg.hostname}.{cfg.mesh_domain} · "
                     f"{now:%H:%M:%S}Z · {up} link{'' if up == 1 else 's'} up"
                     + (f" · {fresh}" if fresh else ""), ""]
            frame += body
            frame += ["", "(latency pings fill in live · throughput is per-second "
                      "· Ctrl-C to exit)"]
            sys.stdout.write("\n".join(frame))
            sys.stdout.flush()
            time.sleep(interval)
    except KeyboardInterrupt:
        pass
    finally:
        prober.stop()
        sys.stdout.write("\033[?25h\n")   # restore cursor
        sys.stdout.flush()
    return 0


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
    try:
        age = (dt.datetime.now(_UTC) - dt.datetime.fromisoformat(
            last.replace("Z", "+00:00"))).total_seconds()
    except (ValueError, AttributeError):
        age = 0.0
    if age > 120:
        return (f"⚠ directory synced {_fmt_ago(last)} — anchor unreachable? "
                f"this view may be stale")
    return f"directory synced {_fmt_ago(last)}"


def _fmt_ago(iso: str) -> str:
    """A coarse 'time since' for a timestamp: seconds, then minutes, then >1h."""
    try:
        t = dt.datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
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
    try:
        t = dt.datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
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

    n = len(cfg.ca_pubs)
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

    # Live is the default; a static one-shot is --snapshot (for piping/logging),
    # and we auto-fall-back to it when there's no terminal to redraw into.
    if not getattr(args, "snapshot", False) and sys.stdout.isatty():
        # Redraw-in-place live view: link state + per-second throughput + an
        # async latency column (pings run only while you're watching). Needs
        # root for live WireGuard state — that's why the default wants sudo.
        return _watch_live(cfg, own_id,
                            interval=max(1.0, getattr(args, "interval", 2.0) or 2.0))

    directory = Directory.load(cfg.dir_cache_path)

    print(f"role     : {cfg.role}")
    print(f"hostname : {cfg.hostname}")
    print(f"addr     : {own_addr or '(keys not generated)'}")
    fresh = _sync_freshness(cfg)
    if fresh:
        print(f"synced   : {fresh}")
    # Self/health — local facts about THIS node (fast, no root, no network).
    for line in _self_health_lines(cfg, directory, own_id):
        print(line)
    # The enrollment door only exists on the anchor — show its state there.
    if cfg.role == "anchor":
        for line in _door_status_lines(cfg):
            print(line)
    print()

    now = dt.datetime.now(_UTC)
    records = sorted(directory.all(), key=lambda r: r.hostname)

    if not records:
        print("directory is empty — run 'gw join <token>' then 'gw run'")
        return 0

    # Live data-plane state for the right-hand "this node" columns — only as
    # root (wg show needs it). None → the roster shows the policy 'peer?' answer
    # and a hint to re-run with sudo.
    is_root = os.geteuid() == 0
    live_peers = None
    if is_root:
        try:
            from . import wg as wgmod
            live_peers = wgmod.get_peers(cfg.wg_interface) or {}
        except Exception:
            live_peers = None

    if getattr(args, "by_segment", False):
        # One table per named segment. A node appears under every segment it's in,
        # and a reach-all (segment:*) node appears under ALL of them — so many
        # nodes show up in more than one table.
        named = sorted({s for r in records for s in _record_segments(r) if s != "*"})
        shown: set[str] = set()
        for s in named:
            members = [r for r in records
                       if s in _record_segments(r) or "*" in _record_segments(r)]
            shown.update(r.id_pub.hex() for r in members)
            print(f"segment: {s}  ({len(members)} node{'' if len(members) == 1 else 's'})")
            _print_node_table(members, cfg, now, own_id, live_peers, is_root)
            _print_segment_health(members, cfg)
            print()
        # Anything not shown above — unsegmented nodes (can't peer), or reach-all
        # nodes with no named segment to fall under — so the grouped view drops
        # nobody.
        leftover = [r for r in records if r.id_pub.hex() not in shown]
        if leftover:
            print(f"(no segment)  ({len(leftover)} node{'' if len(leftover) == 1 else 's'}) "
                  f"— unsegmented, can't peer until given a segment")
            _print_node_table(leftover, cfg, now, own_id, live_peers, is_root)
            print()
    else:
        _print_node_table(records, cfg, now, own_id, live_peers, is_root)
        print()

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
        anchor_now = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
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


def _self_firewall_port(port: int) -> str:
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


class _DiagCol:
    """One column of the diagnose comparison — a node's resolved facts."""
    __slots__ = ("label", "is_self", "rec", "addr", "u6", "u4",
                 "caps", "segments", "cred", "has_ep", "ep_str", "hs", "fw")


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
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from .config import load_config
    from .keys import derive_addr
    from .directory import Directory
    from .reconcile import default_policy
    from .wire import _canonical
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

    for w in _key_file_warnings(_secret_key_paths(cfg)):
        print(f"  ⚠ {w}")

    ca_pubs = [bytes.fromhex(h) for h in cfg.ca_pubs]
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

    # ---- resolve the requested nodes → up to three columns (pair + anchor) ------
    def _find(name):
        from .hosts import sanitize
        want = sanitize(name)
        for r in directory.all():
            if sanitize(r.hostname) == want:
                return r
        return None

    requested = [n for n in (getattr(args, "nodes", None) or []) if n]
    picks = []                                  # list of (label, rec|None, is_self)
    for name in requested:
        r = _find(name)
        if r is None:
            sys.exit(f"no node named {name!r} in the directory cache (see gw watch)")
        picks.append((r.hostname, r, r.id_pub == own_id_bytes))

    if not requested:                           # 0 args: self ↔ anchor
        picks.append((cfg.hostname, own_rec, True))
    elif len(requested) == 1:                   # 1 arg: self ↔ A
        picks.insert(0, (cfg.hostname, own_rec, True))

    anchor_rec = _diag_anchor_record(directory, cfg, own_rec)  # always add the anchor as reference
    if anchor_rec is not None:
        picks.append((anchor_rec.hostname, anchor_rec, anchor_rec.id_pub == own_id_bytes))

    # Dedup by overlay address, cap at three, keep order.
    cols, seen = [], set()
    for label, rec, is_self in picks:
        key = rec.cred.addr if rec is not None else ("self" if is_self else label)
        if key in seen:
            continue
        seen.add(key)
        cols.append((label, rec, is_self))
    cols = cols[:3]

    def _verify(rec) -> str:
        if rec is None:
            return "(not in cache)"
        ok = False
        body = _canonical(rec.cred._body_dict())
        for raw in ca_pubs:
            try:
                Ed25519PublicKey.from_public_bytes(raw).verify(rec.cred.ca_sig, body)
                ok = True
                break
            except InvalidSignature:
                continue
        if not ok:
            return "✗ untrusted CA"
        if rec.id_pub.hex() in revoked:
            return "✗ REVOKED"
        left = (rec.cred.exp - now).total_seconds()
        if left < 0:
            return f"✗ EXPIRED {int(-left // 60)}m ago"
        return f"valid · {_dur_short(left)}"

    def _hs_age(rec):
        if rec is None:
            return None
        lp = live_peers.get(base64.b64encode(rec.cred.wg_pub).decode())
        if lp and lp.latest_handshake:
            age = now_epoch - lp.latest_handshake
            return age if age <= 180 else None
        return None

    # Build a column of facts per node.
    facts = []
    for label, rec, is_self in cols:
        c = _DiagCol()
        c.label = label
        c.is_self = is_self
        c.rec = rec
        c.addr = rec.cred.addr if rec else (own_addr or "?")
        eps = rec.endpoints if rec else cfg.endpoints
        c.u6, c.u4 = _underlay_addrs(eps)
        c.caps = list(rec.cred.caps) if rec else list(cfg.caps)
        c.segments = ",".join(_record_segments(rec)) if rec else \
            ",".join(s[len("segment:"):] for s in cfg.caps if s.startswith("segment:"))
        c.cred = _verify(rec)
        # Reachability is emergent: a node is dialable iff it advertises an
        # endpoint. No inbound flag anymore.
        c.has_ep = (c.u6 != "-" or c.u4 != "-")
        c.ep_str = c.u6 if c.u6 != "-" else (c.u4 if c.u4 != "-" else "—")
        c.hs = _hs_age(rec)
        if is_self:
            c.fw = _self_firewall_port(port)
        elif not c.has_ep:
            c.fw = "n/a (outbound-only)"
        elif c.hs is not None:
            c.fw = "OPEN (inferred: handshake)"
        else:
            c.fw = "??? unconfirmed"
        facts.append(c)

    # ---- header -------------------------------------------------------------
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

    # ---- comparison table (nodes as columns) --------------------------------
    heads = [f"{c.label}{' (self)' if c.is_self else ''}" for c in facts]
    rows = [("overlay", [c.addr for c in facts]),
            ("underlay v6", [c.u6 for c in facts]),
            ("underlay v4", [c.u4 for c in facts]),
            ("reachable", ["yes (advertises endpoint)" if c.has_ep
                           else "no (outbound-only)" for c in facts]),
            ("segments", [c.segments or "-" for c in facts]),
            ("credential", [c.cred for c in facts]),
            (f"firewall udp/{port}", [c.fw for c in facts])]
    lblw = max([len(r[0]) for r in rows] + [0])
    colw = [max(len(heads[i]), *(len(r[1][i]) for r in rows)) for i in range(len(facts))]
    print(" " * lblw + "  " + "  ".join(f"{heads[i]:<{colw[i]}}" for i in range(len(facts))))
    for name, cells in rows:
        print(f"{name:<{lblw}}  " +
              "  ".join(f"{cells[i]:<{colw[i]}}" for i in range(len(cells))))
    print()

    # ---- pairwise verdicts --------------------------------------------------
    print(f"link viability  (direct-or-fail; ??? firewalls assumed open)")
    import itertools
    for x, y in itertools.combinations(facts, 2):
        print(f"  {x.label} ↔ {y.label}")
        if not default_policy(x.caps, y.caps):
            print("    ✗ no shared segment — they won't peer by design "
                  "(give them a common segment to change this)")
            continue
        seg = "anchor is reach-all *" if ("*" in x.segments or "*" in y.segments) \
            else "share " + repr(",".join(sorted(
                set(x.segments.split(",")) & set(y.segments.split(",")))) or "?")
        print(f"    segment: ✓ {seg}")

        x_dials_y = y.has_ep       # x can dial y iff y listens with an endpoint
        y_dials_x = x.has_ep
        print(f"    {x.label} → {y.label}: " + (f"dial {y.ep_str}" if x_dials_y
              else f"can't — {y.label} is outbound-only / advertises no endpoint"))
        print(f"    {y.label} → {x.label}: " + (f"dial {x.ep_str}" if y_dials_x
              else f"can't — {x.label} is outbound-only / advertises no endpoint"))
        if not (x_dials_y or y_dials_x):
            print("    ✗ no dialable direction — the link can't form "
                  "(both outbound-only)")
            continue

        self_col = x if x.is_self else (y if y.is_self else None)
        other = y if x.is_self else (x if y.is_self else None)
        if self_col is None:
            print("    live: (neither is this host) — should link per the "
                  "directory; run 'gw diagnose' from either for live confirmation")
            continue
        if other.hs is not None:
            print(f"    live: ● LINKED (handshake {other.hs}s ago) — path open; "
                  f"{other.label}'s firewall/router inferred OPEN")
            # A LINKED peer can still silently blackhole full-size packets (a
            # WG-over-cloud MTU mismatch): small pings pass, TLS handshakes hang.
            if os.geteuid() == 0:
                warn = _mtu_probe(cfg.wg_interface, other.addr,
                                  _iface_mtu(cfg.wg_interface))
                if warn:
                    print(f"    ⚠ {warn}")
            continue
        print("    live: ○ no handshake yet")
        self_fw = self_col.fw
        if self_col.has_ep:
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
        if other.has_ep:
            print(f"    ⚠ we can dial {other.label} at {other.ep_str} but it isn't "
                  f"answering — check {other.label}'s host firewall + any upstream "
                  f"port-forward for udp/{port}, and that its daemon is up "
                  f"('gw diagnose' on {other.label} shows its host firewall).")
    return 0


# ---------------------------------------------------------------------------
# renew  (force an immediate credential renewal for THIS node)
# ---------------------------------------------------------------------------
