"""
Guard: greasewood must read/write NOTHING in /tmp.

Confined hosts (AppArmor on modern Ubuntu, SELinux) restrict what binaries may
touch under /tmp — that's what broke `wg` reading a key file there and, in turn,
`gw join` (fixed by handing keys to wg on /dev/stdin; see wg._wg_set). To keep
that class of failure from creeping back, every temp file greasewood writes goes
in the TARGET's own directory (data_dir, /etc, …) via keys.atomic_write, which
passes dir=path.parent to mkstemp — never the default /tmp.

These tests scan the package source (AST, so comments don't count and docstrings
are excluded) and fail if:
  * a tempfile factory is called without an explicit dir= (would land in /tmp), or
  * a "/tmp" path literal appears in the code.
"""
import ast
import pathlib

import pytest

_PKG = pathlib.Path(__file__).parent.parent / "greasewood"

# tempfile factories that create a file/dir in $TMPDIR (→ /tmp) unless dir= given.
_TEMP_FACTORIES = {"mkstemp", "mkdtemp", "NamedTemporaryFile",
                   "TemporaryFile", "TemporaryDirectory", "SpooledTemporaryFile"}


def _py_files():
    return sorted(_PKG.rglob("*.py"))


def _docstring_constants(tree):
    """ids of the string-Constant nodes that are module/def/class docstrings —
    they're allowed to mention /tmp (they explain this very rule)."""
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            body = getattr(node, "body", [])
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                ids.add(id(body[0].value))
    return ids


def test_no_tempfile_factory_without_explicit_dir():
    offenders = []
    for f in _py_files():
        tree = ast.parse(f.read_text(), filename=str(f))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = (node.func.attr if isinstance(node.func, ast.Attribute)
                    else node.func.id if isinstance(node.func, ast.Name) else None)
            if name in _TEMP_FACTORIES and not any(kw.arg == "dir" for kw in node.keywords):
                offenders.append(f"{f.name}:{node.lineno}: {name}() with no dir=")
    assert not offenders, (
        "tempfile factory without dir= — would create the file in /tmp, which "
        "AppArmor/SELinux may deny (see the wg /dev/stdin fix). Pass "
        "dir=<target's own dir>:\n  " + "\n  ".join(offenders))


def test_no_tmp_path_literals():
    offenders = []
    for f in _py_files():
        tree = ast.parse(f.read_text(), filename=str(f))
        docs = _docstring_constants(tree)
        for node in ast.walk(tree):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and "/tmp" in node.value and id(node) not in docs):
                offenders.append(f"{f.name}:{node.lineno}: {node.value!r}")
    assert not offenders, (
        "'/tmp' path literal in the package — write under the mesh data_dir "
        "instead (AppArmor/SELinux-safe):\n  " + "\n  ".join(offenders))
