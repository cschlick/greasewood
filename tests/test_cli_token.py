"""
Unit tests for join-token extraction — `gw join -` (stdin) and tolerance of raw
`gw invite` output (so it works with or without `invite -q`).
"""
import pytest

from greasewood.cli import _extract_token


def test_clean_token_returned():
    assert _extract_token("gw1.TOKENDATA") == "gw1.TOKENDATA"


def test_surrounding_whitespace_stripped():
    assert _extract_token("  gw1.TOKENDATA \n") == "gw1.TOKENDATA"


def test_extracted_from_raw_invite_blob():
    blob = "an informational line\ngw1.TOKENDATA\na trailing note\n"
    assert _extract_token(blob) == "gw1.TOKENDATA"


def test_no_token_exits():
    with pytest.raises(SystemExit):
        _extract_token("nothing token-like here\n")
