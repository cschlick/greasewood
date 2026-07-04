"""
DEEP: the audit-trail write/read seam.

`gw narrate` parses what greasewood.audit writes. Two kinds of property:

  * ROBUSTNESS — the narrator never raises, whatever bytes it is fed (audit
    logs can be truncated mid-line by rotation, or hand-edited);
  * ROUNDTRIP — a line rendered exactly the way audit renders it parses back
    to the same rc / timing / context / argv. This pins the logfmt quoting
    (_q) and the narrator's field regex + shlex split to each other.
"""
import pytest
from hypothesis import assume, given, strategies as st

from greasewood import audit, narrate

pytestmark = pytest.mark.deep

# Text without the characters that legitimately terminate/garble a LINE-based
# format (the writer emits one line per command; embedded newlines can't occur).
_line_text = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\n\r"),
    max_size=80)
# argv tokens as they reach audit: os-exec'able strings, no NULs/newlines.
_token = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",),
                           blacklist_characters="\n\r\x00"),
    min_size=1, max_size=24)
# The vocabulary real ip/wg argv is drawn from: iface names, base64 keys (with
# '=' padding and '+/'), v6 literals with brackets, paths, ints. The EXACT
# roundtrip is guaranteed for this alphabet; adversarial text (controls,
# quotes, backslashes) is guaranteed sanitized-single-line-parseable instead.
_cmd_token = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
             "+/=:.,[]_@-", min_size=1, max_size=24)


@given(st.text(max_size=300))
def test_parse_line_never_raises(line):
    e = narrate.parse_line(line)
    assert e is None or e.argv is not None


@given(st.lists(_token, max_size=12))
def test_describe_never_raises(argv):
    assert isinstance(narrate.describe(argv), str)


@given(_line_text)
def test_describe_operation_never_raises(ctx):
    r = narrate.describe_operation(ctx)
    assert r is None or isinstance(r, str)


@given(rc=st.integers(0, 255), t_ms=st.integers(0, 10**6),
       ctx=_line_text, argv=st.lists(_cmd_token, min_size=1, max_size=8))
def test_audit_line_roundtrips_through_narrate(rc, t_ms, ctx, argv):
    """Render a line exactly as audit's file formatter does, then parse it back:
    exact argv roundtrip for the real command vocabulary; ctx (which carries
    wire-supplied hostnames) comes back exactly as the sanitizer wrote it."""
    cmd = " ".join(argv)
    body = f"cmd rc={rc} t={t_ms}ms ctx={audit._q(ctx or '-')} argv={audit._q(cmd)}"
    line = f"ts=2026-07-04T12:00:00Z {body}"
    assert "\n" not in line and "\r" not in line        # injection-proof: one line
    e = narrate.parse_line(line)
    assert e is not None
    assert e.rc == rc and e.t_ms == t_ms
    assert e.ts == "2026-07-04T12:00:00Z"
    assert e.argv == argv                               # exact roundtrip
    want = audit._sanitize(ctx)
    if want and want != "-":
        assert e.ctx == want
    else:
        assert e.ctx == ""                              # '-' sentinel → no context


@given(rc=st.integers(0, 255), stderr=_line_text, argv=st.lists(_cmd_token, min_size=1, max_size=6))
def test_failed_line_roundtrip_marks_failure(rc, stderr, argv):
    assume(audit._sanitize(stderr).strip())      # empty stderr isn't written at all
    body = (f"cmd rc={rc} t=1ms ctx=- argv={audit._q(' '.join(argv))} "
            f"stderr={audit._q(stderr)}")
    e = narrate.parse_line(f"ts=2026-07-04T12:00:00Z {body}")
    assert e is not None and e.failed
    assert e.stderr == audit._sanitize(stderr)


@given(st.lists(st.text(max_size=120), max_size=30))
def test_narrate_render_never_raises_on_arbitrary_files(lines):
    entries = [e for e in map(narrate.parse_line, lines) if e]
    out = list(narrate.narrate(entries, color=False))
    assert isinstance(out, list)
    assert isinstance(narrate.summarize(entries), str)


@given(st.text(max_size=120))
def test_logfmt_quote_is_parseable_and_inverts(s):
    """_q's output must always be recoverable by the narrator's field regex,
    and unquoting must invert the escaping exactly — for ANY input, controls
    and quotes and backslashes included."""
    field = f"ctx={audit._q(s or '-')}"
    got = narrate._field(f"a=1 {field} b=2", "ctx")
    assert got == audit._sanitize(s or "-")
