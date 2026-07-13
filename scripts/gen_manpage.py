#!/usr/bin/env python3
"""Generate the gw(1) man page from the argparse parser.

Single source of truth with `gw --help`: the page is built from the SAME
`build_parser()` the CLI dispatches through, so `man gw` can never drift from
the tool. Pure stdlib on purpose — no argparse-manpage or other build-time
dependency; the whole tool is auditable pure Python, and so is its man page.

    python scripts/gen_manpage.py            # write man/gw.1
    python scripts/gen_manpage.py -          # write to stdout

Date is taken from SOURCE_DATE_EPOCH when set (reproducible builds), else today.
"""
import argparse
import datetime as dt
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from greasewood.cli import build_parser          # noqa: E402
from greasewood.status import _version           # noqa: E402


# Unicode punctuation the help text uses → portable roff. Applied AFTER the
# backslash/hyphen escaping so these escapes' own backslashes survive intact.
_ROFF = {
    "—": "\\(em",      # — em dash
    "→": "\\(->",      # → rightwards arrow
    "↔": "<\\->",      # ↔ left-right arrow (no portable glyph; render <->)
    "…": "...",        # … ellipsis
    "·": "\\(bu",      # · middle dot (used as a list separator) → bullet
}


def esc(s: str) -> str:
    """Escape text for roff: backslashes, hyphens (so `--flag` renders as a
    literal minus, not a hyphenation point), then map Unicode punctuation to
    portable roff escapes so the page stays clean ASCII."""
    if not s:
        return ""
    s = " ".join(s.split()).replace("\\", "\\\\").replace("-", "\\-")
    for uni, roff in _ROFF.items():
        s = s.replace(uni, roff)
    return s


def text_block(s: str) -> str:
    """A free-text paragraph, guarding any line that starts with a roff control
    char (`.`/`'`) with the zero-width `\\&`."""
    out = []
    for line in (s or "").splitlines():
        line = line.rstrip()
        if line[:1] in (".", "'"):
            line = "\\&" + line
        out.append(esc(line) if line else "")
    return "\n".join(out)


def _takes_arg(action) -> bool:
    return action.nargs != 0 and not isinstance(
        action, (argparse._StoreTrueAction, argparse._StoreFalseAction,
                 argparse._StoreConstAction, argparse._CountAction,
                 argparse._HelpAction, argparse._VersionAction))


def _metavar(action) -> str:
    if action.metavar:
        return action.metavar if isinstance(action.metavar, str) else action.metavar[0]
    if action.choices:
        return "{" + ",".join(map(str, action.choices)) + "}"
    return action.dest.upper()


def invocation(action) -> str:
    """The bold option header, e.g. `\\fB\\-c\\fR, \\fB\\-\\-config\\fR \\fIFILE\\fR`."""
    if not action.option_strings:                      # positional
        return f"\\fI{esc(_metavar(action))}\\fR"
    arg = f" \\fI{esc(_metavar(action))}\\fR" if _takes_arg(action) else ""
    flags = ", ".join(f"\\fB{esc(o)}\\fR" for o in action.option_strings)
    return flags + arg


def emit_actions(actions, out):
    for a in actions:
        if isinstance(a, argparse._SubParsersAction):
            continue                                   # handled separately
        if isinstance(a, argparse._HelpAction) and not a.option_strings:
            continue
        out.append(".TP")
        out.append(invocation(a))
        out.append(text_block(a.help or "") or "\\ ")


def render(parser) -> str:
    ver = _version()
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    when = (dt.datetime.fromtimestamp(int(epoch), dt.timezone.utc)
            if epoch else dt.datetime.now(dt.timezone.utc)).strftime("%Y-%m-%d")

    out = []
    out.append(f'.TH GW 1 "{when}" "greasewood {ver}" "User Commands"')
    out.append(".SH NAME")
    out.append(f"gw \\- {esc(parser.description)}")

    out.append(".SH SYNOPSIS")
    out.append(".B gw")
    out.append("[\\fIGLOBAL OPTIONS\\fR] \\fICOMMAND\\fR [\\fIARGS\\fR...]")

    out.append(".SH DESCRIPTION")
    out.append(text_block(
        "greasewood is a minimal, self-hosted WireGuard mesh overlay: "
        "direct-or-fail links, an IPv6-only overlay over a v4-or-v6 underlay, "
        "membership gated by a certificate authority. It manages the data plane "
        "by shelling out to wg(8), ip(8) and nft(8), and logs every command it "
        "runs. The " + "gw" + " command is the whole interface; the daemon it "
        "starts is a self-managed systemd service."))

    # Global options: everything on the top-level parser except the subparsers.
    out.append(".SH GLOBAL OPTIONS")
    emit_actions(parser._actions, out)

    # One .SS per subcommand, in definition order.
    subs = next(a for a in parser._actions
                if isinstance(a, argparse._SubParsersAction))
    out.append(".SH COMMANDS")
    # choices preserves insertion order (dict); _choices_actions carries help.
    help_by_name = {ca.dest: (ca.help or "") for ca in subs._choices_actions}
    for name, sp in subs.choices.items():
        out.append(f".SS gw {esc(name)}")
        usage = sp.format_usage().replace("usage: ", "", 1).strip()
        out.append(f"\\fBUsage:\\fR {esc(usage)}")
        summary = help_by_name.get(name, "")
        if summary:
            out.append(".PP")
            out.append(text_block(summary))
        real_opts = [a for a in sp._actions
                     if not (isinstance(a, argparse._HelpAction) and a.option_strings)]
        if real_opts:
            emit_actions(sp._actions, out)

    if parser.epilog:
        out.append(".SH EXAMPLES")
        out.append(".nf")                              # no-fill: keep the columns
        out.append(text_block(parser.epilog))
        out.append(".fi")

    out.append(".SH FILES")
    out.append(".TP")
    out.append("\\fB/etc/greasewood_\\fR\\fINAME\\fR\\fB.toml\\fR")
    out.append("Per-mesh membership config written by \\fBgw create\\fR / \\fBgw join\\fR.")
    out.append(".TP")
    out.append("\\fB/var/lib/greasewood_\\fR\\fINAME\\fR")
    out.append("Per-mesh state: keys, credentials, the directory, and the audit log.")

    out.append(".SH SEE ALSO")
    out.append("wg(8), wg\\-quick(8), ip(8), nft(8), systemctl(1)")
    out.append(".PP")
    out.append("Full documentation: \\fIhttps://github.com/cschlick/greasewood\\fR")

    out.append(".SH AUTHOR")
    out.append("cschlick")

    return "\n".join(out) + "\n"


def main() -> int:
    dest = sys.argv[1] if len(sys.argv) > 1 else "man/gw.1"
    page = render(build_parser())
    if dest == "-":
        sys.stdout.write(page)
        return 0
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), dest)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(page)
    sys.stderr.write(f"wrote {path}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
