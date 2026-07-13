# Packaging

How greasewood is packaged for distros. Three channels, one release flow.

| Channel        | What it ships                                              | Built by |
|----------------|-----------------------------------------------------------|----------|
| **PyPI**       | sdist + wheel (`pip install greasewood`)                  | manual (see below) |
| **.deb / .rpm**| self-contained: a bundled relocatable Python + greasewood | `release.yml` on a `v*` tag |
| **AUR**        | native Arch package (system Python + `python-cryptography`)| `aur/PKGBUILD` |

## Why the .deb/.rpm bundle a Python

greasewood needs Python ≥ 3.11, and its self-managed systemd unit runs
`{sys.executable} -m greasewood` (see `cli._service_exec`). So the installed
`gw` must resolve to a Python that can import greasewood — a zipapp can't, and a
host-Python venv isn't portable across machines. `build-standalone.sh` therefore
bundles a [python-build-standalone](https://github.com/astral-sh/python-build-standalone)
interpreter at `/opt/greasewood/python` and pip-installs greasewood into it. The
package then depends on **no** system Python and works the same on Debian 12 or
Fedora 41. It mirrors `install.sh`'s fixed-prefix model, so the service's
`ExecStart` path never drifts.

The `install_only_stripped` pbs variant is used deliberately: it strips debug
symbols the safe way. Stripping libpython ourselves corrupts its dynamic-symbol
versioning (the interpreter then dies with *"no version information available"*).

## Cutting a release

1. Bump `version` in `pyproject.toml`; commit.
2. Regenerate the man page and confirm it's in sync:
   `python scripts/gen_manpage.py && git add man/gw.1`
3. **PyPI** (manual, keeps you in control):
   ```bash
   rm -rf dist && python -m build
   python -m twine check dist/*
   python -m twine upload dist/*
   ```
4. Tag and push — this fires `release.yml`:
   ```bash
   git tag -a vX.Y.Z -m "greasewood X.Y.Z" && git push origin vX.Y.Z
   ```
   The workflow builds the sdist/wheel and the amd64+arm64 `.deb`/`.rpm`, then
   creates the GitHub Release with all of them attached. (It does **not** touch
   PyPI — step 3 already did.)
5. **AUR:** in the `aur/` clone, bump `pkgver` (and `sha256sums` — take it from
   the PyPI JSON `digests.sha256`), regenerate `.SRCINFO`
   (`makepkg --printsrcinfo > .SRCINFO`), then `git push` to the AUR remote.

## Building the packages locally

```bash
python -m build                                        # produces dist/*.whl
DESTDIR=./stage GREASEWOOD_SPEC=dist/greasewood-*.whl ./packaging/build-standalone.sh
GREASEWOOD_VERSION=X.Y.Z PKG_ARCH=amd64 nfpm pkg -f packaging/nfpm.yaml -p deb -t dist/
GREASEWOOD_VERSION=X.Y.Z PKG_ARCH=amd64 nfpm pkg -f packaging/nfpm.yaml -p rpm -t dist/
```

Smoke-test the result: `dpkg-deb -x dist/greasewood_*.deb /tmp/r &&
/tmp/r/opt/greasewood/python/bin/python3 -m greasewood --version`.

## Future: PyPI Trusted Publishing

Step 3 can move into `release.yml` via PyPI Trusted Publishing (OIDC, no stored
token) — add a `pypi` job with `permissions: id-token: write` and
`pypa/gh-action-pypi-publish`. Left out for now so releases to PyPI stay a
deliberate manual act.
