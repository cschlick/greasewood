"""
The gw(1) man page is generated from the SAME argparse parser the CLI
dispatches through (build_parser), so `man gw` can't drift from `--help`.
These pin the generator: parser is reusable offline, output is clean portable
roff (no raw non-ASCII → no troff warnings), and every subcommand is documented.
"""
import argparse
import importlib.util
import os

import pytest

from greasewood.cli import build_parser

_GEN = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scripts", "gen_manpage.py")


def _load_gen():
    spec = importlib.util.spec_from_file_location("gen_manpage", _GEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_build_parser_is_reusable_and_complete():
    p = build_parser()
    assert isinstance(p, argparse.ArgumentParser) and p.prog == "gw"
    subs = next(a for a in p._actions if isinstance(a, argparse._SubParsersAction))
    assert len(subs.choices) >= 26            # all subcommands wired


def test_manpage_renders_clean_ascii():
    page = _load_gen().render(build_parser())
    # portable roff only — a stray Unicode punctuation char is a troff warning
    non_ascii = sorted({c for c in page if ord(c) > 127})
    assert non_ascii == [], f"non-ASCII leaked into man page: {non_ascii!r}"


def test_manpage_has_expected_structure():
    page = _load_gen().render(build_parser())
    assert page.startswith(".TH GW 1 ")
    for section in (".SH NAME", ".SH SYNOPSIS", ".SH COMMANDS",
                    ".SH FILES", ".SH SEE ALSO"):
        assert section in page
    # a representative subcommand shows up as its own subsection
    assert ".SS gw create" in page and ".SS gw join" in page


def test_committed_manpage_is_in_sync():
    """man/gw.1 must match what the generator produces now (minus the date
    line, which varies) — a CLI change that forgets to regenerate fails here."""
    committed = os.path.join(os.path.dirname(os.path.dirname(__file__)), "man", "gw.1")
    if not os.path.exists(committed):
        pytest.skip("man/gw.1 not present in this checkout")
    fresh = _load_gen().render(build_parser())

    def _strip_th(s):
        return "\n".join(l for l in s.splitlines() if not l.startswith(".TH "))

    assert _strip_th(open(committed).read()) == _strip_th(fresh), (
        "man/gw.1 is stale — regenerate: python scripts/gen_manpage.py")
