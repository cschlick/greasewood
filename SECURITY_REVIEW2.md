# Security review 2

> **Multi-agent security review.** Follow-up to the review recorded in `SECURITY_REVIEW.md`.
>
> **Date:** 2026-07-13 · **Reviewed at commit:** `32f60ce8` · **Method:** focused subagent reviews of `certs.py`, enrollment/door, policy/port-filter/hosts, plus manual review of the remaining control-plane source (`server.py`, `reconcile.py`, `keys.py`, `audit.py`, `hosts.py`, `backup.py`, `config.py`, `sync.py`, `renewal.py`, `install.sh`).
>
> A point-in-time assessment, not a guarantee. See `SECURITY.md` for the intended threat model and `RUNBOOK.md` for operational response.
>
> **Post-review resolution (2026-07-13, commit `b534930`):** all seven actionable findings — **H2, M1, L1, L2, L3, L4, L5** — were fixed and are marked **RESOLVED** inline below. Remaining items are hygiene (**L6**), handshake-gated/negligible (**L7**), design-intent or positive (**I1–I8**), or macOS-only test issues (greasewood is Linux-only). Note: this review predates commit `2748593`, which had already added interface validation, the replay-guard hard cap, and `from_dict` key-length checks (the first Devin review's applicable items).

## Executive summary

The codebase is in good shape: the prior High-severity finding (H1) is correctly fixed, the CA/door cryptography is sound, and the design is default-closed. This review confirms the previous local-file fixes (H1, L6 standing-door, L10) and surfaces a few remaining issues:

- **One High-severity defect:** `enforce_ports=true` with an unusable `nft` silently runs the daemon **unenforced**.
- **One Medium-severity defect:** the control-plane port is accepted from **any** peer on **every** node, not just the anchor.
- **Several Low-severity local-privilege and consistency issues:** the single-use door window, audit log, and `/etc/hosts` writes have TOCTOU or symlink-race windows; `cmd_invite` can still issue reserved roles through `default_caps`/`default_caps`/`--caps`; the joiner hostname is not validated before the proof-of-possession check; and the `CA.cap_policy` hook is never actually used.
- **Two test failures** are environment-specific (macOS) and not security findings.

No Critical issues were found and no finding lets a remote, secret-less attacker gain anything.

## Scope & methodology

The review covered the greasewood control-plane implementation in Python and the installer:

- **Identity & crypto:** `wire.py`, `keys.py`, `tlsca.py`, `ca.py`.
- **Control plane:** `server.py`, `reconcile.py`, `directory.py`, `sync.py`, `renewal.py`.
- **Enrollment / door:** `enroll.py`, `door.py`, `cli.py` invite/join paths.
- **Policy enforcement:** `policy.py`, `portfilter.py`, `hosts.py`.
- **Local surface:** `certs.py`, `audit.py`, `backup.py`, `config.py`, `install.sh`.

Findings were verified by focused subagents and manual re-tracing of the cited code paths. Findings are reported at their verified severity. Statuses: *confirmed*, *resolved*, *design-intent* (deliberate; gap is documentation or hardening), *test-only*.

## Prior findings status

### H1 — Door enrollment proof-of-possession is resolved
`enroll.py:_validate_request` now requires `id_sig` over `enroll_pop_body(id_pub, wg_pub, hostname)`. Verification fails closed on any error. `test_security_review_fixes.py` covers the base case, the "enroll under a victim's id_pub" attack, and the "reuse a captured signature with a different wg_pub" attack. `cli.py:_enroll_over_door` and `wire.py:enroll_pop_body` share the same canonical body.

### L6 (standing door) — Resolved; single-use branch still open
The standing-door branch of `cmd_invite` now uses `keys.atomic_write(window_path, ..., mode=0o600)`. The single-use branch still uses `window_path.write_text(json.dumps(...))`, creating the file at the process umask and never chmoding it. This is the same TOCTOU class as the original L6, just on the non-standing path.

### L10 — TLS cert placement resists symlink races is resolved
`certs.py:place_cert_files` uses `tempfile.mkstemp` with a random name, fd-based `fchmod`/`fchown`, and `os.replace`. `tests/test_security_review_fixes.py` demonstrates that a pre-planted `server.crt.gwtmp` symlink is ignored and the victim file is untouched.

## Findings

### Critical

None.

### High

#### H2 — `enforce_ports=true` fails open when nftables is unavailable
**Component:** `greasewood/cli.py:408-435` (`_make_port_enforcer`). **Status:** confirmed — **RESOLVED (`b534930`).**

> **Resolution:** kept degrade-to-open (fail-closed would reintroduce the crash loop) but made it VISIBLE: `_make_port_enforcer` writes an `enforce_degraded` breadcrumb (`reconcile.write_enforce_degraded`) which `gw watch` surfaces as `⚠ port enforcement DOWN` and `--json` reports as `mesh.enforcement_degraded`. The `portfilter.ensure_available` docstring now describes the actual degrade-open-but-loud behaviour.

`_make_port_enforcer` catches `NftUnavailable` and returns `None` when `enforce_ports=true` but `nft` is not usable. The daemon starts with **no port enforcement**. The `portfilter.py` docstring still claims "fail closed" (`greasewood/portfilter.py:65-69`), but the caller explicitly degrades to open to avoid a systemd restart loop.

The risk is operational drift: a host whose `nft` breaks or is removed after enrollment reboots into a fully unfiltered mesh. The `gw create`/`join` paths write `enforce_ports=false` on hosts where `nft` is unavailable at setup time, so only post-join breakage is exposed.

**Recommendation:** make the degraded state either fail closed (refuse to start the daemon when `enforce_ports=true` and `nft` is unusable) or loudly visible fleet-wide (`gw watch`, the directory payload, the anchor's view). Update the `portfilter.py` docstring to match the actual degrade-to-open behavior.

### Medium

#### M1 — Control-plane port accepted from any mesh peer on every node
**Component:** `greasewood/portfilter.py:183-186` (`render_ruleset`). **Status:** confirmed — **RESOLVED (`b534930`).**

> **Resolution:** the control-port accept is now emitted ONLY on the anchor (`"*" in node_tags(local_caps)`); a plain node no longer opens 51902 to any peer (its replies to the anchor ride `ct established`).

The hardwired rule

```nft
iifname "<iface>" tcp dport <control_port> accept
```

has no `ip6 saddr` restriction, while every grant-derived rule does. It is installed on every node, not just the anchor. The control server runs only on the anchor, but if an ordinary node binds a service to `51902`, any mesh peer can reach it regardless of the grant table.

**Recommendation:** restrict the accept to the anchor's overlay address set (e.g. `ip6 saddr @anchor_set`) or emit the rule only on the anchor. Node-side replies to the anchor already ride `ct state established,related accept`.

### Low

#### L1 — Single-use door window written non-atomically at default umask
**Component:** `greasewood/cli.py:874-882` (`cmd_invite`, single-use branch). **Status:** confirmed — **RESOLVED (`b534930`).**

> **Resolution:** the single-use window now uses `keys.atomic_write(..., mode=0o600)` like the standing branch — no world-readable pre-chmod window.

The single-use door window is written with `window_path.write_text(json.dumps(...))`. It is never chmod'd, so it is created at the process umask and may be world-readable. The file contains `caps`, `allowed_roles`, `hostname`, and `expires`. This is the same class of issue as the prior L6; the standing-door fix should be applied to both branches.

**Recommendation:** `atomic_write(window_path, json.dumps(...), mode=0o600)` for the single-use branch as well.

#### L2 — Audit log created at default umask, then chmod'd (TOCTOU)
**Component:** `greasewood/audit.py:139-150` (`attach_file`). **Status:** confirmed — **RESOLVED (`b534930`).**

> **Resolution:** the audit log is pre-created `O_CREAT|0o600` before `RotatingFileHandler` opens it, closing the umask-create→chmod window.

`RotatingFileHandler` creates the audit log at the process umask, then `os.chmod(path, 0o600)` is applied. The file lives inside the 0755 data dir, so between creation and chmod it is world-readable. The audit log contains source IPs and topology information.

**Recommendation:** pre-create the file with `os.open(path, O_CREAT | O_WRONLY, 0o600)` before handing it to `RotatingFileHandler`, or temporarily set `umask(0o077)` around handler creation.

#### L3 — `/etc/hosts` temp file uses a predictable name and `write_text`
**Component:** `greasewood/hosts.py:183-199` (`_atomic_write`). **Status:** confirmed — **RESOLVED (`b534930`).**

> **Resolution:** the temp file is now `tempfile.mkstemp` (random name, `O_CREAT|O_EXCL`, 0600) in the target dir, so a pre-planted symlink can't be followed. (Already low: `/etc` is root-only writable.)

The temp file is `path.with_suffix(path.suffix + ".gw.tmp")` (e.g. `/etc/hosts.gw.tmp`), then `write_text` writes to it, then `os.replace` is used. If an attacker pre-plants a symlink at the predictable temp path, `write_text` follows the symlink and can overwrite an arbitrary target. The fallback `open(path, "w")` also follows symlinks.

**Recommendation:** use a randomized `tempfile.mkstemp` in the same directory and `os.replace` it, preserving `errors="surrogateescape"` as `keys.atomic_write` does.

#### L4 — `invite` reserved-role guard bypassed for `default_caps`/`default_roles`/`--caps`
**Component:** `greasewood/cli.py:790-802`, `greasewood/config.py:247-248`, `greasewood/ca.py:65-70`. **Status:** confirmed — **RESOLVED (`b534930`).**

> **Resolution:** `cmd_invite` now runs `_reject_reserved_roles` over the role: tags of the MERGED caps (covering `--caps`, `default_caps`, `default_roles`), so a reserved `role:*`/`role:anchor` can't be CA-signed through an invite. (`cap_policy` left as-is — I3.)

`_reject_reserved_roles` is applied to `--self-roles` and `--roles` but not to the final `caps` list, which also pulls from `cfg.default_roles` and `cfg.default_caps` (and raw `--caps`). `CA.cap_policy` defaults to the identity function and is never instantiated with a real policy, so nothing blocks a reserved role from being CA-signed on an invite. `cmd_set_caps` (`cli.py:1851-1859`) correctly checks this, but `cmd_invite` does not.

**Recommendation:** in `cmd_invite`, run `_reject_reserved_roles` over the `role:`-prefixed entries of the merged `caps` list, or validate `default_roles`/`default_caps` at config load. Also consider installing a real `cap_policy` in `CA` so the CA itself enforces the invariant, not just the CLI.

#### L5 — Joiner hostname not validated before the proof-of-possession check
**Component:** `greasewood/enroll.py:272-315`, `greasewood/ca.py:104-109`. **Status:** confirmed — **RESOLVED (`b534930`).**

> **Resolution:** `_validate_request` now rejects a non-string / >253-char / control-char hostname BEFORE the PoP check and `ca.issue`.

`enroll._validate_request` accepts `req["hostname"]` and uses it directly in the PoP verification and in the `ca.issue` path. `ca.hostname_owner` sanitizes it, but no length or format check happens before the signature is verified. A very long hostname can cause a confusing error, and the PoP signature is over the raw hostname while the issued credential ends up using the sanitized hostname, so the signed name is not the canonical name in the credential.

**Recommendation:** validate `hostname` length and format in `_validate_request` before the PoP check (e.g. `<= 255` chars, reject empty), and use the sanitized canonical hostname in the PoP body.

#### L6 — Public key files and config files written without explicit modes
**Component:** `greasewood/keys.py:160-166`, `greasewood/cli.py:530-535`, `greasewood/cli.py:1153-1157`, `greasewood/cli.py:554`. **Status:** confirmed.

Public key files and config files are created with `write_text` and then chmod'd (or not at all). Public key files are intentionally public, but the inconsistency with `atomic_write` for secrets is worth fixing. Config files contain topology and policy information; they live under `/etc/` (root-only in practice), but explicit modes are clearer. `grants.toml` is also written with `write_text` and no mode.

**Recommendation:** write config files with explicit mode `0o640` or `0o600` and public key files via `atomic_write` (or document the intentional behavior).

#### L7 — WireGuard peers installed before the first port-filter apply
**Component:** `greasewood/reconcile.py:442-463`. **Status:** confirmed.

`ReconcileLoop._tick` installs WireGuard peers via `reconcile_once` before calling `PortFilter.apply`. On the first tick of a fresh interface, peers exist before the nftables rules are installed. This is mitigated by WireGuard handshake gating, so the practical exposure is sub-second and unusable without a handshake.

**Recommendation:** consider applying the port filter before installing peers, or installing a temporary deny-all rule during the first reconcile. Low priority because of handshake gating.

### Info / design-intent / positive findings

- **I1 — No replay protection on enroll requests.** The door enroll RPC has no nonce/timestamp. The window is time-bounded and single-use, and the PoP signature binds `id_pub`/`wg_pub`/`hostname`, so the only replayable request is the legitimate one for the same identity. Design-intent under the documented threat model.
- **I2 — Standing door has no rate limit.** A standing token can be used to open many connections, but each connection requires the valid door seed. This is a trusted-provisioner concern. Consider per-source rate limits if the standing token is broadly distributed.
- **I3 — `cap_policy` hook is never used.** `CA` accepts a `cap_policy` callable but defaults to the identity function and is always instantiated without one. Fine today, but a future CA caller could bypass the CLI guard. Consider wiring in a real policy.
- **I4 — Config path expansion with `~` is not validated.** `expanduser()` is used for `ca_key_file`. Operators control the config, so this is not an external attack vector, but validating absolute paths would reduce operational foot-guns.
- **I5 — Backup restore path-traversal protection is correct.** `backup.restore_files` resolves `data_dir` and the destination and rejects any path outside `data_dir` (`greasewood/backup.py:165-177`).
- **I6 — Token encoding has safe field-length limits.** `door.encode_token` rejects host/domain/menu fields > 255 bytes (`greasewood/door.py:182-192`).
- **I7 — `keys.atomic_write` is a good primitive.** It uses `mkstemp` with `0o600`, fd-level operations, and `os.replace` (`greasewood/keys.py:91-120`).
- **I8 — Systemd unit is well-sandboxed.** `CapabilityBoundingSet=CAP_NET_ADMIN`, `NoNewPrivileges=yes`, `ProtectSystem=yes`, `ProtectHome=yes`, etc. (`greasewood/cli.py:91-117`).

## Test failures

Two tests failed during the verification pass. Both are environment-specific on macOS and are not security findings.

1. **`test_permission_error_as_root_names_the_ownership_fix`** (`tests/test_cli_service.py:136-148`)
   - `cli.main` calls `_require_supported_os()` before `args.fn()`, which exits with *"greasewood is a Linux-only tool (this host is Darwin)."* before the monkey-patched `cmd_watch` can raise `PermissionError`. The test is effectively Linux-only and should be skipped on non-Linux.

2. **`test_bounded_pool_sheds_load_at_capacity`** (`tests/test_server.py:572-615`)
   - The server correctly sheds the over-capacity connection, but on macOS the server-side `shutdown`/`close` produces a `RST` because the client still has unread data. The test asserts `recv(64) == b""` (EOF), so it fails with `ConnectionResetError`. The load-shedding behavior is correct; the test is too strict for macOS.

## Recommendations

1. **H2:** Decide the `enforce_ports=true` + broken `nft` behavior: fail closed or make the degraded state visible fleet-wide. Update `portfilter.py` docstrings.
2. **M1:** Restrict the control-plane nftables rule to the anchor's overlay address set or emit it only on the anchor.
3. **L4:** Close the reserved-role bypass in `cmd_invite` and consider a real `CA.cap_policy`.
4. **L1, L2, L3:** Fix the remaining TOCTOU writes (single-use door, audit log, `/etc/hosts`).
5. **L5:** Add hostname validation and canonicalization before the PoP check.
6. **L6:** Add explicit modes to config and public-key writes.
7. **Test failures:** skip the Linux-only root permission test on non-Linux and relax the load-shedding test on macOS.
8. **L7:** Optionally reorder reconcile to apply the port filter before installing peers.
