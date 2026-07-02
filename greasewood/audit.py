"""
greasewood.audit — the data-plane command trail.

Every `ip`/`wg` mutation greasewood makes goes through wg._run, which calls
record_command() here. That gives a complete, durable, greppable record of
exactly what touched the kernel's networking state, when, with what result —
and, via a contextvar, *why* (which reconcile decision, which enrollment).

Two sinks, both fed by the `greasewood.audit` logger at INFO (so commands are
always captured, never hidden behind -v):
  - the process's normal log stream (stderr → journal), and
  - a dedicated rotating file, <data_dir>/audit.log, attached by the daemon so
    the trail survives independent of journald retention.

Format is logfmt — one line per command, both human-greppable and parseable:

    ts=2026-07-02T10:15:03Z cmd rc=0 t=12ms ctx="reconcile: +peer db01 [fd8d::a1] seg=prod" \
        argv="wg set gw-mesh peer <pub> allowed-ips fd8d::a1/128 ..."

Safe by construction: argv carries only *public* keys and key-file *paths*
(never private key bytes — the wg CLI reads keys from files), so a command can
be logged verbatim without leaking secrets.
"""
from __future__ import annotations

import contextlib
import contextvars
import datetime as dt
import logging
import shlex
from logging.handlers import RotatingFileHandler
from pathlib import Path

log = logging.getLogger("greasewood.audit")

# The "why" attached to commands run inside a context() block. Per-thread via
# contextvars, so the reconcile / enroll / door threads don't cross-contaminate.
_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("gw_audit_ctx", default="")


@contextlib.contextmanager
def context(description: str):
    """Tag every ip/wg command issued in this block with `description`."""
    token = _ctx.set(description)
    try:
        yield
    finally:
        _ctx.reset(token)


def current_context() -> str:
    return _ctx.get()


def _q(s: str) -> str:
    """logfmt-quote a value only if it needs it."""
    return s if s and all(c not in s for c in ' "=\t\n') else '"' + s.replace('"', '\\"') + '"'


def record_command(argv, rc: int, elapsed_ms: int,
                   stdout: str = "", stderr: str = "") -> None:
    """Log one executed ip/wg (or other data-plane) command as a logfmt line."""
    ctx = _ctx.get()
    cmd = " ".join(shlex.quote(a) for a in argv)
    line = (f"cmd rc={rc} t={elapsed_ms}ms "
            f"ctx={_q(ctx or '-')} argv={_q(cmd)}")
    if rc != 0 and stderr:
        line += f" stderr={_q(stderr.strip())}"
    # rc!=0 is an ERROR so failures stand out; successes are INFO but always
    # present (the whole point is a complete trail, not just failures).
    log.log(logging.ERROR if rc != 0 else logging.INFO, line)


# ---------------------------------------------------------------------------
# Sinks
# ---------------------------------------------------------------------------

class _UTCFormatter(logging.Formatter):
    """ISO-8601 UTC timestamps — a command trail spanning days must be
    unambiguous (the default console format is time-only)."""
    def formatTime(self, record, datefmt=None):
        t = dt.datetime.fromtimestamp(record.created, dt.timezone.utc)
        return t.strftime("%Y-%m-%dT%H:%M:%SZ")


_FILE_FMT = _UTCFormatter("ts=%(asctime)s %(message)s")


def attach_file(path, max_mb: float = 8.0, keep: int = 12) -> "RotatingFileHandler | None":
    """Attach the durable rotating audit-file sink to the `greasewood.audit`
    logger. Idempotent per path; returns the handler (or None if it can't be
    opened — auditing must never stop the daemon)."""
    path = Path(path)
    for h in log.handlers:
        if isinstance(h, RotatingFileHandler) and getattr(h, "_gw_path", None) == str(path):
            return h  # already attached
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        h = RotatingFileHandler(path, maxBytes=int(max_mb * 1024 * 1024),
                                backupCount=keep, encoding="utf-8")
        h._gw_path = str(path)              # type: ignore[attr-defined]
        h.setLevel(logging.INFO)
        h.setFormatter(_FILE_FMT)
        try:
            import os
            os.chmod(path, 0o600)           # holds source IPs / topology
        except OSError:
            pass
        log.addHandler(h)
        log.setLevel(logging.INFO)          # always capture, regardless of -v
        return h
    except OSError as e:
        log.warning("could not open audit log %s: %s (continuing without it)", path, e)
        return None
