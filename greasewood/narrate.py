"""
greasewood.narrate — turn the data-plane command trail into a story.

`gw narrate` reads the audit log (greasewood.audit's logfmt lines) and *translates*
it: instead of `wg set gw-mesh peer qa7IAQ… allowed-ips fd8d::a1/128 …`, you get

    ● 2026-07-02 22:53:45Z  Reconcile added a peer — db01 (segment prod) shares a
                            segment with this node, so a tunnel is authorized.
        ✓ Set up the WireGuard tunnel to peer qa7IAQ…: accept and route its
          overlay address fd8d::a1 (a /128 host route — one address per peer,
          derived from its identity key), dial it at 203.0.113.7:51900, and send
          a keepalive every 25s to hold the path open.                    (12ms)
        ✓ Route traffic for fd8d::a1 over gw-mesh — wg configures the peer but
          not the kernel route, so greasewood adds it explicitly.          (3ms)

So you can read the mesh's whole history as prose: what happened, when, why, and
whether it worked.
"""
from __future__ import annotations

import datetime as dt
import re
import shlex

# ── parsing ─────────────────────────────────────────────────────────────────

_FIELD = r'(?:^|\s){k}=("(?:[^"\\]|\\.)*"|\S+)'


class Entry:
    __slots__ = ("ts", "rc", "t_ms", "ctx", "argv", "stderr", "failed")

    def __init__(self, ts, rc, t_ms, ctx, argv, stderr, failed):
        self.ts, self.rc, self.t_ms = ts, rc, t_ms
        self.ctx, self.argv, self.stderr, self.failed = ctx, argv, stderr, failed


def _field(line: str, key: str) -> "str | None":
    m = re.search(_FIELD.format(k=re.escape(key)), line)
    if not m:
        return None
    v = m.group(1)
    if v.startswith('"'):
        # Invert the writer's escaping: any backslash-escaped char (\" and \\).
        v = re.sub(r"\\(.)", r"\1", v[1:-1])
    return v


def parse_line(line: str) -> "Entry | None":
    """Parse one audit line into an Entry, or None if it isn't a command line."""
    # One test suffices: every command line carries argv="..."; anything
    # without it (banners, tracebacks, other loggers) isn't a command line.
    argv_s = _field(line, "argv")
    if argv_s is None:
        return None
    ts = _field(line, "ts") or ""
    try:
        rc = int(_field(line, "rc") or "0")
    except ValueError:
        rc = 0
    t_ms = int(re.sub(r"\D", "", _field(line, "t") or "0") or 0)
    ctx = _field(line, "ctx") or ""
    if ctx == "-":
        ctx = ""
    stderr = _field(line, "stderr") or ""
    try:
        argv = shlex.split(argv_s)
    except ValueError:
        argv = argv_s.split()
    # A line is a failure if it carries stderr (only failures record it) — the
    # writer sets ERROR level, but the file has no level, so use stderr presence.
    failed = bool(stderr) or " ERROR " in f" {line} "
    return Entry(ts, rc, t_ms, ctx, argv, stderr, failed)


# ── translating a single command ────────────────────────────────────────────

def _short_key(k: str) -> str:
    return (k[:10] + "…") if len(k) > 12 else k


def _val(tokens, key: str) -> "str | None":
    for i, t in enumerate(tokens):
        if t == key and i + 1 < len(tokens):
            return tokens[i + 1]
    return None


def describe(argv) -> str:
    """Translate one ip/wg command into a plain-English sentence."""
    if not argv:
        return "(empty command)"
    if argv[0] == "wg":
        return _describe_wg(argv)
    if argv[0] == "ip":
        return _describe_ip(argv)
    return " ".join(argv)


def _describe_wg(a) -> str:
    if len(a) >= 3 and a[1] == "set":
        iface, rest = a[2], a[3:]
        if "private-key" in rest:
            port = _val(rest, "listen-port")
            return (f"Configure interface {iface}: load its WireGuard private key "
                    f"and start listening for tunnel traffic on UDP {port}.")
        if "peer" in rest:
            pub = _short_key(_val(rest, "peer") or "?")
            if "remove" in rest:
                return (f"Remove WireGuard peer {pub} from {iface} — drop its key "
                        f"and stop carrying its traffic.")
            ip = _val(rest, "allowed-ips")
            ep = _val(rest, "endpoint")
            ka = _val(rest, "persistent-keepalive")
            bits = []
            if ip:
                bits.append(f"accept and route its overlay address {ip.split('/')[0]} "
                            f"(a /128 host route — one address per peer, derived from "
                            f"its identity key)")
            bits.append(f"dial it at {ep}" if ep else
                        "it advertises no endpoint, so we wait for it to dial us")
            if "preshared-key" in rest:
                bits.append("using a pre-shared key (this is the transient door tunnel)")
            if ka:
                bits.append(f"send a keepalive every {ka}s to hold the path open")
            return f"Set up the WireGuard tunnel to peer {pub}: " + "; ".join(bits) + "."
    return "wg " + " ".join(a[1:])


def _describe_ip(a) -> str:
    toks = [t for t in a[1:] if t not in ("-6", "-4", "-o")]
    if len(toks) < 3:               # a bare/truncated line — nothing to translate
        return "ip " + " ".join(a[1:])
    two = toks[:2]
    dev = toks[-1]
    if two == ["link", "add"]:
        return f"Create the WireGuard interface {toks[2]}."
    if two == ["link", "set"] and toks[-1] == "up":
        return f"Bring interface {toks[2]} up."
    if two in (["link", "del"], ["link", "delete"]):
        return f"Destroy interface {toks[2]}."
    if two == ["addr", "add"]:
        return f"Assign the overlay address {toks[2].split('/')[0]} to {dev}."
    if two == ["route", "replace"]:
        return (f"Route traffic for {toks[2].split('/')[0]} over {dev} — wg configures "
                f"the peer but not the kernel route, so greasewood adds it explicitly.")
    if two == ["route", "del"]:
        return f"Remove the kernel route to {toks[2].split('/')[0]}."
    if two == ["route", "add"] and "blackhole" in toks:
        return (f"Blackhole everything in routing table {_val(toks, 'table')} — the "
                f"door's isolation, so a joining node can't reach the mesh even if IP "
                f"forwarding is on.")
    if two == ["rule", "add"]:
        return (f"Policy-route packets from {_val(toks, 'from')} into table "
                f"{_val(toks, 'lookup')} — funnels the door guest into the blackhole, "
                f"isolating it from the mesh.")
    if "show" in toks:
        return f"Query kernel state ({' '.join(a[1:])})."
    return "ip " + " ".join(a[1:])


# ── translating an operation (a run of commands sharing a context) ───────────

def describe_operation(ctx: str) -> "str | None":
    """One sentence about *why* an operation ran, from its context tag."""
    if not ctx:
        return None
    head, _, rest = ctx.partition(":")
    rest = rest.strip()
    if head == "reconcile":
        peer = rest[6:] if len(rest) > 6 else rest
        if rest.startswith("+peer"):
            return (f"Reconcile added a peer — {peer} shares a segment with this "
                    f"node, so a tunnel is authorized and greasewood brought it up.")
        if rest.startswith("-peer"):
            return (f"Reconcile removed a peer — {peer} is no longer authorized here "
                    f"(revoked, expired, or it left a shared segment), so greasewood "
                    f"tore the tunnel down.")
        if rest.startswith("~peer"):
            name = peer.split(" (")[0]
            why = ("its advertised endpoint changed" if "(endpoint)" in rest
                   else "a kernel route was missing")
            return (f"Reconcile repaired a peer — {name}: {why}, so greasewood "
                    f"re-applied its config.")
    if head == "enroll":
        return f"A new node enrolled through the door and was installed as a peer ({rest})."
    if head == "startup":
        return f"Daemon startup — {rest}."
    if head == "invite":
        return f"`gw invite` opened the enrollment door — {rest}."
    if head == "join":
        return f"`gw join` dialed the anchor's enrollment door — {rest}."
    if head == "door":
        return f"Door isolation setup — {rest}."
    return ctx


# ── rendering ────────────────────────────────────────────────────────────────

class _C:
    """ANSI colours, disabled when off."""
    def __init__(self, on):
        self.b = "\033[1m" if on else ""
        self.g = "\033[32m" if on else ""
        self.r = "\033[31m" if on else ""
        self.d = "\033[2m" if on else ""
        self.x = "\033[0m" if on else ""


def _fmt_ts(ts: str) -> str:
    return ts.replace("T", " ") if ts else "?"


def _wrap_plain(text: str, width: int) -> list:
    """Wrap into bare chunks (no indent), each ≤ width."""
    out, line = [], ""
    for word in text.split():
        if line and len(line) + 1 + len(word) > width:
            out.append(line)
            line = word
        else:
            line = f"{line} {word}".strip()
    if line:
        out.append(line)
    return out or [""]


def _hang(text: str, first_prefix: str, prefix_len: int, width: int) -> list:
    """Hanging-indent wrap: first line keeps `first_prefix`, the rest align under
    it (`prefix_len` visible columns)."""
    chunks = _wrap_plain(text, max(20, width - prefix_len))
    lines = [first_prefix + chunks[0]]
    lines += [" " * prefix_len + ch for ch in chunks[1:]]
    return lines


def _group(entries):
    """Yield operations: maximal runs of consecutive entries sharing a context."""
    cur = []
    for e in entries:
        if cur and e.ctx == cur[-1].ctx:
            cur.append(e)
        else:
            if cur:
                yield cur
            cur = [e]
    if cur:
        yield cur


def _cycle_period(op) -> int:
    """The smallest period p (1 ≤ p ≤ len/2) such that this operation is its
    first p commands repeated end-to-end — or 0 if it isn't a clean cycle.

    A crash-loop records the SAME short command sequence over and over under one
    context (e.g. `startup: ensure interface` → Configure, Bring-up, Configure,
    Bring-up, …). This detects that N-times repeat so the renderer can show the
    cycle once as `×N` instead of a wall of identical lines. p=1 covers a run of
    one identical command; p=2 covers the Configure/Bring-up pair; etc."""
    n = len(op)
    keys = [tuple(e.argv) for e in op]
    for p in range(1, n // 2 + 1):
        if n % p == 0 and all(keys[i] == keys[i - p] for i in range(p, n)):
            return p
    return 0


def narrate(entries, *, color=False, raw=False, width=88):
    """Yield the narrated lines for a sequence of Entries."""
    c = _C(color)
    for op in _group(entries):
        first = op[0]
        intro = describe_operation(first.ctx) or "greasewood ran data-plane commands."
        total = sum(e.t_ms for e in op)
        tsx = _fmt_ts(first.ts)
        plen = 2 + len(tsx) + 2                       # "● " + ts + "  "
        prefix = f"{c.b}●{c.x} {c.b}{tsx}{c.x}  "
        yield from _hang(intro, prefix, plen, width)

        # Collapse a repeated command cycle (a crash-loop's Configure/Bring-up
        # over and over) into the cycle shown once with ×N — so 177 restarts read
        # as two lines, not 354. Only when nothing failed (failures stay explicit)
        # and the cycle actually repeats a few times.
        period = _cycle_period(op) if not any(e.failed for e in op) else 0
        reps = (len(op) // period) if period else 1
        if period and reps >= 3:
            for i in range(period):
                e = op[i]
                cyc_ms = sum(op[i + k * period].t_ms for k in range(reps))
                body = _hang(describe(e.argv), f"    {c.g}✓{c.x} ", 6, width)
                body[-1] = f"{body[-1]}  {c.d}×{reps} ({cyc_ms}ms){c.x}"
                yield from body
                if raw:
                    yield f"        {c.d}$ {' '.join(e.argv)}{c.x}"
            yield (f"    {c.d}└─ {len(op)} commands "
                   f"({period}-command cycle ×{reps}), {total}ms{c.x}")
            yield ""
            continue

        for e in op:
            mark = f"{c.g}✓{c.x}" if not e.failed else f"{c.r}✗{c.x}"
            sentence = describe(e.argv)
            body = _hang(sentence, f"    {mark} ", 6, width)
            body[-1] = f"{body[-1]}  {c.d}({e.t_ms}ms){c.x}"
            yield from body
            if e.failed and e.stderr:
                yield f"        {c.r}→ {e.stderr}{c.x}"
            if raw:
                yield f"        {c.d}$ {' '.join(e.argv)}{c.x}"
        if len(op) > 1:
            yield f"    {c.d}└─ {len(op)} commands, {total}ms{c.x}"
        yield ""


def summarize(entries) -> str:
    """A one-block tally — counted by operation (a run of commands), not by raw
    command, so 'peers added' means peers, not the two commands each add takes."""
    kinds = {"added": 0, "removed": 0, "repaired": 0, "enrolled": 0}
    failures = sum(1 for e in entries if e.failed)
    peers = set()
    for op in _group(entries):
        h = op[0].ctx
        if h.startswith("reconcile: +peer"):
            kinds["added"] += 1
        elif h.startswith("reconcile: -peer"):
            kinds["removed"] += 1
        elif h.startswith("reconcile: ~peer"):
            kinds["repaired"] += 1
        elif h.startswith("enroll:"):
            kinds["enrolled"] += 1
        m = re.search(r"peer (\S+)", h)
        if m:
            peers.add(m.group(1))
    span = ""
    stamped = [e.ts for e in entries if e.ts]
    if stamped:
        span = f" from {_fmt_ts(stamped[0])} to {_fmt_ts(stamped[-1])}"
    return (f"{len(entries)} data-plane commands{span}: "
            f"{kinds['added']} peer(s) added, {kinds['removed']} removed, "
            f"{kinds['repaired']} repaired, {kinds['enrolled']} enrolled, "
            f"{failures} command(s) failed. {len(peers)} distinct peer(s) touched.")
