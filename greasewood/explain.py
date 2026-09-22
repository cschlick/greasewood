"""
greasewood.explain — the story of a node (or a pair), assembled from the
evidence this machine already holds.

The mesh keeps four kinds of memory, each answering a different question:

  the audit trail    what THIS machine did, when, and why (commands + events)
  the statement log  what the MESH decided about membership (replicated,
                     CA-signed: revoke / tombstone / setcaps — visible here
                     even when the decision was made on another holder)
  the directory      what each node currently claims (credential, endpoints)
  the attestations   what peers have recently PROVEN about reachability

`gw explain <node> [--since 24h]` merges them into one chronological
narrative and a current-state verdict, so "what happened to bb?" is a
command instead of four files and a reconstruction. Read-only, no root:
every source is a world-readable cache the daemon maintains (live handshake
detail appears when `wg show` happens to be permitted, and is simply omitted
otherwise).
"""
from __future__ import annotations

import datetime as dt
import logging

from . import narrate as N

log = logging.getLogger(__name__)

_UTC = dt.timezone.utc


def _parse_ts(s: str) -> "dt.datetime | None":
    try:
        t = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        return t if t.tzinfo else t.replace(tzinfo=_UTC)
    except (ValueError, AttributeError):
        return None


def _fmt(ts: "dt.datetime") -> str:
    return ts.astimezone(_UTC).strftime("%Y-%m-%d %H:%M:%SZ")


def _ago(now: "dt.datetime", ts: "dt.datetime") -> str:
    s = int((now - ts).total_seconds())
    if s < 0:
        return "in the future (clock skew?)"
    if s < 90:
        return f"{s}s ago"
    if s < 5400:
        return f"{s // 60}m ago"
    if s < 129600:
        return f"{s // 3600}h ago"
    return f"{s // 86400}d ago"


class Subject:
    """One node under explanation: its name plus every string the evidence
    might refer to it by (hostname, overlay addr, id prefixes)."""

    def __init__(self, hostname: str, id_hex: "str | None", record=None):
        self.hostname = hostname
        self.id_hex = id_hex
        self.record = record
        self.needles = {hostname.lower()}
        if record is not None:
            self.needles.add(record.cred.addr.lower())
        if id_hex:
            self.needles.add(id_hex[:12].lower())
            self.needles.add(id_hex[:16].lower())
            self.needles.add(id_hex.lower())

    def mentioned_in(self, text: str) -> bool:
        t = text.lower()
        return any(n in t for n in self.needles)


def resolve_subject(handle: str, directory, statements=None) -> Subject:
    """A hostname / mesh name / id-hex prefix → Subject. A departed node
    (tombstoned, record gone) still resolves by id prefix or — via the
    statement log's remembered hostnames — by name, so `gw explain bb` works
    AFTER bb left; that is half the point of an explain command."""
    from .hosts import sanitize
    want = sanitize(handle.split(".")[0])
    for r in (directory.all() if directory else []):
        if sanitize(r.cred.hostname) == want:
            return Subject(r.cred.hostname, r.id_pub.hex(), r)
    lowered = handle.strip().lower()
    if all(c in "0123456789abcdef" for c in lowered) and len(lowered) >= 8:
        for r in (directory.all() if directory else []):
            if r.id_pub.hex().startswith(lowered):
                return Subject(r.cred.hostname, r.id_pub.hex(), r)
        return Subject(handle[:12] + "…", lowered if len(lowered) == 64 else None)
    if statements is not None:
        for s in statements.all():
            if s.hostname and sanitize(s.hostname) == want:
                return Subject(s.hostname, s.id_pub.hex())
    return Subject(handle, None)


# ── assembling the timeline ─────────────────────────────────────────────────

def _timeline_from_audit(entries, subjects, since) -> list:
    """(ts, text) per audit OPERATION (narrate's grouping) or domain event
    that mentions a subject. Reuses narrate's translations so the story
    speaks the same language as `gw narrate`."""
    out = []
    for group in N._group(entries):
        first = group[0]
        ts = _parse_ts(first.ts)
        if ts is None or ts < since:
            continue
        if isinstance(first, N.EventEntry):
            hay = first.kind + " " + " ".join(
                f"{k}={v}" for k, v in first.fields.items())
            if not any(s.mentioned_in(hay) for s in subjects):
                continue
            out.append((ts, N.describe_event(first)))
            continue
        ctx = first.ctx
        if not ctx or not any(s.mentioned_in(ctx) for s in subjects):
            continue
        text = N.describe_operation(ctx) or ctx
        failed = any(getattr(e, "failed", False) for e in group)
        if failed:
            text += "  ✗ (a command in this operation FAILED — gw narrate has the detail)"
        out.append((ts, text))
    return out


def _timeline_from_statements(statements, subjects, since) -> list:
    """The mesh's replicated decisions about the subjects — visible here even
    when they were made on another holder, which is exactly why they belong
    in the story a plain node can tell."""
    if statements is None:
        return []
    kind_text = {
        "revoke": "the CA REVOKED this identity — permanent exclusion; peers "
                  "evict it as its credential expires",
        "tombstone": "membership ended (a leave, or the abandoned-node sweep) "
                     "— its records die, the hostname frees, a fresh "
                     "enrollment can return",
        "setcaps": None,   # rendered with its payload below
    }
    out = []
    for s in statements.all():
        subj = next((x for x in subjects
                     if x.id_hex and s.id_pub.hex() == x.id_hex), None)
        if subj is None or s.ts < since:
            continue
        if s.kind == "setcaps":
            roles = sorted(c[5:] for c in s.caps if c.startswith("role:"))
            text = (f"a holder changed its roles to "
                    f"{', '.join(roles) or '(none)'} (applied at its next "
                    f"renewal, by whichever holder serves it)")
        else:
            text = kind_text[s.kind]
        out.append((s.ts, f"{subj.hostname}: {text}"))
    return out


def _timeline_from_records(subjects, since) -> list:
    out = []
    for s in subjects:
        if s.record is None:
            continue
        iat = s.record.cred.iat
        if iat >= since:
            out.append((iat, f"{s.hostname}: credential issued/renewed — "
                             f"expires {_fmt(s.record.cred.exp)}"))
    return out


# ── the current-state verdict ───────────────────────────────────────────────

def _now_lines(subjects, directory, statements, attestations, live_peers,
               grants, own_id, now) -> list:
    lines = []
    id_to_name = {r.id_pub.hex(): r.cred.hostname
                  for r in (directory.all() if directory else [])}
    for s in subjects:
        bits = []
        if s.record is None:
            dead = statements is not None and s.id_hex is not None and \
                statements.tombstone_ts(s.id_hex) is not None
            bits.append("no record in this node's directory — "
                        + ("departed (tombstoned); re-enrollment would mint a "
                           "fresh credential" if dead else
                           "never seen here, or aged out past the drop grace"))
        else:
            left = (s.record.cred.exp - now).total_seconds()
            bits.append(f"credential {'EXPIRED ' + _ago(now, s.record.cred.exp) if left < 0 else 'valid for ' + str(int(left // 3600)) + 'h'}")
            if statements is not None and s.id_hex in (statements.revoked_ids() or set()):
                bits.append("REVOKED")
            eps = list(s.record.endpoints)
            if not eps:
                bits.append("advertises no endpoint (outbound-only)")
            elif attestations is not None and s.id_hex:
                conf = attestations.confirmations_for(s.id_hex, now=now)
                matched = {e: v for e, v in conf.items() if e in eps}
                if matched:
                    who = sorted({id_to_name.get(a, a[:8] + "…")
                                  for v in matched.values() for a in v})
                    bits.append(f"endpoint confirmed by {', '.join(who)}")
                elif conf:
                    bits.append(f"⚠ advertised endpoint UNCONFIRMED — peers "
                                f"reach it at {', '.join(sorted(conf))} instead")
                else:
                    bits.append("advertises an endpoint (no peer testimony yet)")
            if live_peers is not None:
                import base64
                lp = live_peers.get(
                    base64.b64encode(s.record.cred.wg_pub).decode())
                if lp is not None and lp.latest_handshake:
                    hs = dt.datetime.fromtimestamp(lp.latest_handshake, _UTC)
                    bits.append(f"tunnel from here: handshake {_ago(now, hs)}"
                                + (f" over {lp.endpoint}" if lp.endpoint else ""))
                elif s.id_hex != own_id:
                    bits.append("no tunnel from here right now")
        lines.append(f"  {s.hostname:<10} " + " · ".join(bits))

    # The pair verdict: does policy even allow these two to peer?
    if len(subjects) == 2 and all(x.record is not None for x in subjects):
        a, b = subjects
        try:
            from .policy import peers_allowed
            ok = peers_allowed(list(a.record.cred.caps),
                               list(b.record.cred.caps), grants or [])
            lines.append(f"  {'pair':<10} policy "
                         + ("allows this tunnel"
                            if ok else "DENIES this tunnel — no grant connects "
                                       "their roles (gw policy show)"))
        except Exception as e:  # noqa: BLE001 — verdicts must not crash the story
            log.debug("pair policy verdict unavailable: %s", e)
    return lines


# ── entry point ─────────────────────────────────────────────────────────────

def build_story(subjects, *, audit_entries=(), directory=None, statements=None,
                attestations=None, live_peers=None, grants=None,
                own_id=None, since=None,
                now: "dt.datetime | None" = None) -> str:
    now = now or dt.datetime.now(_UTC)
    since = since or (now - dt.timedelta(hours=24))
    timeline = (_timeline_from_audit(audit_entries, subjects, since)
                + _timeline_from_statements(statements, subjects, since)
                + _timeline_from_records(subjects, since))
    timeline.sort(key=lambda p: p[0])

    who = " ↔ ".join(s.hostname for s in subjects)
    span = _ago(now, since)
    head = f"── the story of {who} — since {_fmt(since)} ({span}) "
    out = [head + "─" * max(0, 88 - len(head))]
    if not timeline:
        out.append(f"  (no recorded events here in the last {span[:-4]} — "
                   f"the trail only knows what THIS machine witnessed plus "
                   f"the mesh's replicated decisions)")
    for ts, text in timeline:
        out.append(f"  {_fmt(ts)}  {text}")
    out.append("")
    out.append("now:")
    out += _now_lines(subjects, directory, statements, attestations,
                      live_peers, grants, own_id, now)
    return "\n".join(out)
