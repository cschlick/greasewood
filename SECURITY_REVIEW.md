# Security review

> **Multi-agent security review, conducted under Claude Opus 4.8.** This session was
> auto-routed from Fable 5 to Opus 4.8 by Anthropic's safeguards on security content,
> so although the review was requested under Fable 5, the analysis was performed by
> Opus 4.8 — this attribution reflects what actually ran.
>
> **Date:** 2026-07-13 · **Reviewed at commit:** `e629a8b` · **Method:** seven review
> dimensions (keys &amp; cryptography, trust gate, control-plane authorization,
> enrollment/door, policy enforcement, injection/parsing, privilege/multi-user)
> fanned out to independent agents over the control-plane source; every candidate
> finding was then adversarially verified by independent skeptics that re-traced the
> cited code (17 raw findings → 15 retained at their verified severity).
>
> A point-in-time assessment, not a guarantee. See [SECURITY.md](SECURITY.md) for the
> intended model and [RUNBOOK.md](RUNBOOK.md) for operational response.
>
> **Post-review resolution (2026-07-13, commit `34d82c9`):** the sole High
> finding (H1) and the two local-privilege file-mode findings (L6, L10) were fixed
> before publishing; each is marked **RESOLVED** inline below. The remaining Low/Info
> items are documentation drift or accepted-risk hardening notes, tracked but not
> yet actioned. Findings are reported at the severity they had *when reviewed*.

## Executive summary

greasewood's security architecture is sound and the code largely lives up to the model it advertises. The core trust primitives — self-certifying overlay addresses, CA-signed capabilities that a member cannot self-assert, expiry-as-revocation, a strictly default-closed grant table, and a control plane bound off the underlay by construction — are implemented as documented and hold up under adversarial scrutiny. The review surfaced **one High-severity defect**: the door enrollment path performs no proof-of-possession of the joining identity's private key, so a token holder can re-bind another node's public identity (routing and persisted caps). The remaining findings are **Low or Info**: a cluster of documentation-vs-code deviations in SECURITY.md (firewall interaction, `0700` data dir, TLS-leaf lifetime, anchor recert window), a few local-multiuser hardening gaps (a symlink race in cert placement, a world-readable TOCTOU window on the standing door, an unbounded joiner hostname), and several honest fail-open / consistency footguns in the nftables port layer. No Critical issues were found, and no finding lets a remote, secret-less attacker gain anything. The overall posture is that of a carefully-reasoned design whose main real gap is a missing ownership check at enrollment; the rest is drift and defense-in-depth.

## Scope & methodology

The review covered the greasewood control-plane implementation in pure Python:

- **Identity & crypto**: `wire.py` (canonical signing, `Credential`/`NodeRecord`/`RenewRequest`/`CertRequest`/`GrantTable`), `keys.py` (key generation, address derivation, atomic writes), `tlsca.py` (x509 leaf issuance), `ca.py` (issue/renew/revoke/set-caps registry).
- **Control plane**: `server.py` (`/renew`, `/cert`, `/publish`, `/directory`, re-root fallback), `reconcile.py` (the 7-step trust gate, hosts + port-filter derivation), `directory.py` (seq-merge cache).
- **Enrollment / door**: `enroll.py`, `door.py`, `cli.py` invite/join paths.
- **Policy enforcement**: `policy.py` (roles/grants, reserved roles), `portfilter.py` (nftables rendering), `hosts.py` (`/etc/hosts` block).
- **Local surface**: `certs.py` (profile cert placement), `audit.py`/`narrate` (audit trail), file-mode handling.

Each candidate was assessed across **seven dimensions**: keys & cryptography, trust-gate correctness, control-plane authorization, enrollment/door security, policy enforcement, injection/parsing, and privilege/multi-user isolation. Every finding below was then **adversarially verified by independent skeptics** who re-traced the cited code paths and attempted to refute the claim or recalibrate its severity. Findings whose exploit path or severity did not survive verification were downgraded (two Medium filings collapsed to Low, one Low to Info) and are reported at their verified level. Statuses are: *confirmed* (mechanism and impact reproduced), *plausible* (mechanism real, exploit/impact contested), *design-intent* (behavior deliberate; the gap is documentation).

## Findings

### Critical

None.

### High

#### H1 — Door enrollment has no proof-of-possession of `id_priv`; a token holder can re-bind another node's identity
**Component:** `enroll.py:296` (`_validate_request`) → `enroll.py:342`/`361` (`_issue_and_install`) → `ca.py:84` (`CA.issue`). **Status:** confirmed — **RESOLVED (`34d82c9`).**

> **Resolution:** the enroll request now carries an `id_sig` — a proof-of-possession signature by the joiner's `id_priv` over `enroll_pop_body(id_pub, wg_pub, hostname)` (`wire.py`). `_validate_request` verifies it against the presented `id_pub` and fails closed on any error, so a token holder cannot enroll under an `id_pub` it does not control, nor replay a captured signature with a different `wg_pub`. Brand-new and re-joining nodes alike hold their `id_priv` and sign.

The enroll request `{v, id_pub, wg_pub, hostname, roles}` (built at `cli.py:1328`) carries no signature, and `_validate_request` (`enroll.py:272-297`) verifies none — the door seed is the sole authorization. That is safe for a fresh, attacker-generated `id_pub`, but the code applies it to *any* caller-supplied `id_pub`. `id_pub` values are public (they appear in every `/directory` record and derive each node's overlay address). `_issue_and_install` computes `was_registered = node_info(id_pub) is not None` (`enroll.py:342`) only to decide rollback; it never rejects a re-bind. `CA.issue` then unconditionally rewrites `nodes/<id_pub>.json` via `_save_node_caps` (`ca.py:123`) — its only uniqueness guard is on *hostname* (`ca.py:104-109`), which the attacker satisfies by reusing the victim's own name or any free name — and the enroll path installs `set_peer(wg_iface, attacker_wg, derive_addr(victim_id))` (`enroll.py:361`).

**Attack scenario:** an adversary holding a valid, unexpired door token (the "join-token holder" in SECURITY.md, or a member who obtains a provisioning token) reads a victim's `id_pub` from `/directory` and sends an enroll request with `id_pub = victim`, `wg_pub = attacker`. Two effects follow. (1) *Persistent authorization tampering*: `nodes/<victim>.json` is overwritten with the token's caps/roles; because `CA.renew` reads caps straight from that registry (`ca.py:148-152, 167`), the victim adopts the attacker-chosen caps at its very next renewal (≤ one TTL), recoverable only by an operator `gw set-caps`. (2) *Transient interception*: the anchor now maps the victim's overlay `/128` to the attacker's WireGuard key, so anchor→victim overlay traffic is encrypted to the attacker until the next reconcile cycle reclaims the allowed-ip (`reconcile.py:283-310`). The attacker cannot exceed the token's own grant, but can corrupt an arbitrary *other* node's authorization and briefly hijack its routing — directly contradicting SECURITY.md's containment for the join-token holder ("Enrolls one node … no other node's", lines 21-22) and even the compromised-anchor row's claim that an existing node's overlay address cannot be taken over (line 24).

**Recommendation:** refuse door re-binding of an already-registered id. If `node_info(id_pub)` exists, reject the unsigned door enroll and force the signed `/renew` path (which already proves `id_priv` via `verify_self_sig`), unless the request carries a fresh self-signature over a nonce/timestamp by that `id_pub`. Brand-new ids need no signature (the seed authorizes creation); an already-registered id must prove ownership before its `wg_pub`/caps/hostname entry or its peer route can change.

*Note on severity:* one verifier argued Medium, since the precondition is a valid, time-boxed, single-slot, `gw watch`-visible token, the interception self-heals in one reconcile cycle, and both effects are bounded by the token's own grant and remediable via `gw set-caps`/`gw revoke`. The aggregate verdict is High because the attack achieves active cross-node interception plus persistent tampering against an explicitly-stated boundary. Even at Medium it is the review's most serious issue and the clearest candidate for a code fix.

### Medium

None. (Two findings initially filed at Medium — the re-root caps replay and the audit-trail Unicode forgery — were reduced to Low on verification; see L1 and L7.)

### Low

#### L1 — Re-root fallback re-issues caps from a node-replayable directory record, undoing a `set-caps` downgrade
**Component:** `server.py:232` (`_reroot_reissue`). **Status:** confirmed.

During a re-root, when the new anchor has no local registry entry for a node, `_reroot_reissue` (`server.py:223-232`) mints a fresh credential using `list(rec.cred.caps)` from whatever `NodeRecord` the directory currently holds — guarded only by `rec.cred.verify(get_ca_pubs())` (`server.py:227`), i.e. CA-signature + expiry (`wire.py:129-156`). Both are satisfied by any of the node's own still-unexpired old credentials during the CA-overlap window. Because `/publish` accepts any structurally-valid, CA-signed, non-revoked record and the directory merges purely by node-chosen `seq` (`directory.py:88`), a downgraded node can self-sign a high-`seq` record wrapping an *old, higher-cap* credential, publish it, then `/renew`; the new anchor falls into the fallback, reads the replayed record, and re-issues (and permanently persists) the escalated caps under the new CA.

**Attack scenario:** node X was issued `[tls, role:prod]`, later downgraded to `[role:node]` via `gw set-caps` (effective next renewal). Within one credential TTL the operator re-roots to a fresh anchor without restoring the `nodes/` registry (the exact case the fallback exists for). X publishes a high-`seq` record wrapping its still-valid pre-downgrade credential, then renews; the anchor re-issues `[tls, role:prod]` under the new CA and writes it to `nodes/<X>.json`, reviving production reachability and TLS issuance the operator had revoked. This contradicts SECURITY.md line 112 ("can't drift upward at renew"), which states no re-root caveat.

**Recommendation:** do not treat a node-published record as authoritative for caps in the re-root path. Either require the operator to restore the `nodes/` registry as part of re-root (dropping the record-caps fallback), or re-issue at a base cap set (`role:node`) requiring an explicit anchor action to restore elevated caps, or bind caps to the specific latest credential the anchor last issued. At minimum, document (RUNBOOK already nearly does, for revokes) that a re-root without registry restore resets the `set-caps` guarantee.

*Note:* filed Medium, verified Low. During the overlap the old CA is still trusted, so X's old credential already grants the caps to every peer regardless of re-root; the marginal harm is persistence past the overlap, in a rare operator-driven ceremony bounded by one TTL. The genuinely undocumented sharpening is that a node can *replay an old* credential, which the code does not guard.

#### L2 — Anchor's `allow_expired` admits expired records into the set that drives `/etc/hosts` and the port filter
**Component:** `reconcile.py:226` (`reconcile_once` / `ReconcileLoop._tick`). **Status:** confirmed.

When the local node is the anchor (`is_anchor`, `reconcile.py:222`), every record is verified with `allow_expired=True` (`reconcile.py:226`; `wire.py:153` shows this skips exactly the expiry check), so expired-but-not-revoked records are appended to `trusted` (`reconcile.py:235`). That same list feeds `port_enforcer.apply(trusted)` (`reconcile.py:463`) and `hosts.sync(trusted, …)` (`reconcile.py:469`), neither of which re-checks `cred.exp`. SECURITY.md lines 101-105 state resolution is built from records passing full verification "(CA signature, expiry, revocation)" and that "an expired credential drops out of resolution the same way" as a revoked one — false on the anchor, where a lapsed node's name keeps resolving and its address keeps passing the port filter until it is revoked or aged past drop-grace (default 7d, `config.py:183`).

**Attack scenario:** essentially none (no forged material, no cross-node escalation, no adversarial gain). An operator who decommissions a node by letting its credential lapse (without `gw revoke`) sees it drop from members within one TTL as promised, but on the anchor host its `<host>.<domain>` keeps resolving and its overlay address keeps passing the port filter for up to drop-grace. This is a deviation from the stated model, not an exploit.

**Recommendation:** build the anchor's hosts block and port-filter source set from the subset of `trusted` whose credential is currently unexpired (re-check `record.cred.exp` for the derivation even while the tunnel is kept for recert), or amend SECURITY.md and the stale comment at `reconcile.py:466-468` to carve out the anchor recert window explicitly.

#### L3 — `invite --caps` and `[anchor] default_roles`/`default_caps` bypass the `RESERVED_ROLES` guard
**Component:** `cli.py:799` (`cmd_invite`). **Status:** confirmed.

`policy.py:56-58` documents `RESERVED_ROLES` (`*`, `anchor`) as "Enforced on every assignment path," and `set-caps` deliberately screens raw `role:` caps (`cli.py:1846`) for exactly this reason. But `cmd_invite` applies `_reject_reserved_roles` only to `--self-roles`/`--roles` (`cli.py:790, 793`); it appends raw `--caps` (`cli.py:799-800`), `default_caps` (`cli.py:802`), and `default_roles` (`cli.py:797`, loaded unvalidated at `config.py:247`) with no screening. These flow verbatim into the enroll server (`enroll.py:317`) and are CA-signed by `ca.issue` (`cap_policy` is the identity function, `ca.py:70`; no caller installs a real one). Thus `gw invite --caps role:*` mints a reach-all joiner (`policy.py:181-182` returns True against every node) and `role:anchor` breaks the single-member invariant (`portfilter.py:118-119` matches every `to=["anchor"]` grant), with no post-hoc duplicate detection.

**Attack scenario:** not an escalation — the path requires root on the anchor, the same principal who could edit `grants.toml`. It is an invariant-consistency footgun: an operator typo (`--caps role:anchor` instead of `--roles admin`, or a stray `default_roles` edit) silently violates the reserved-role invariant the code enforces everywhere else.

**Recommendation:** in `cmd_invite`, run `_reject_reserved_roles` over the `role:`-prefixed entries of the merged caps list (after `cli.py:802`, mirroring `set-caps`), covering `--caps`, `default_caps`, and `default_roles` in one place. Consider validating `default_roles`/`default_caps` at config load.

#### L4 — Port enforcement fails **open** at daemon start when nftables is unusable
**Component:** `cli.py:428` (`_make_port_enforcer`). **Status:** confirmed.

`portfilter.ensure_available`'s contract is "the daemon refuses loudly rather than running with silently-absent enforcement (fail closed)" (`portfilter.py:66-69`), but the caller `_make_port_enforcer` catches `NftUnavailable` and returns `None`, running the daemon with **no** enforcement while `enforce_ports=true` (`cli.py:426-435`; a deliberate crash-loop-avoidance change in commit 671868e that left the docstrings stale). The nftables table is kernel state and does not survive a reboot, so a host whose nft breaks after join (package removed, module lost in an update) reboots into a fully unfiltered mesh — every port open inside every existing tunnel — with only a journal error. SECURITY.md line 22 promises a member "cannot reach anything the grant table doesn't allow (default-closed)"; the accepted-risks section (lines 122-139) never mentions this degradation. (Secondary: on a fresh interface's first tick, WireGuard peers are installed at `reconcile.py:443` before the first `port_enforcer.apply` at `reconcile.py:463` — a sub-second, handshake-gated window.)

**Attack scenario:** no remote trigger; operational drift. A default-closed host quietly degrades to tunnel-existence-only enforcement, and any peer holding a grant to it (so a tunnel exists) can then reach every port on it. `gw create`/`join` write `enforce_ports=false` on nft-less hosts (`cli.py:375-385`), so only post-join breakage is exposed.

**Recommendation:** make the degraded state fail closed or at least visible fleet-wide — e.g. refuse to install non-anchor peers (keep only the control-plane star) when `enforce_ports=true` and nft is unusable, or surface "enforcement DOWN" in `gw watch`/`status` and the anchor's view. Align the `portfilter.py` "fail closed / refuses loudly" docstrings with the caller's actual degrade-to-open behavior, and order the first filter apply before peer installation.

#### L5 — Port filter accepts the control port from **any** mesh peer on **every** node
**Component:** `portfilter.py:186` (`render_ruleset`). **Status:** confirmed.

The hardwired allowance is documented as "every node ↔ anchor, tcp/51902 — the control plane" (`policy.py:89-90`), but the rendered rule `iifname "<mesh>" tcp dport <control_port> accept` (`portfilter.py:186`) has no `saddr` restriction (every grant-derived rule does) and is installed on every member, ahead of the default `drop`. The control server runs only on the anchor (`server.py:2`; started only in the anchor branch, `cli.py:2586-2591`), so on ordinary nodes this normally accepts traffic to a closed port — but any operator service that binds 51902 on a node becomes reachable from every tunneled peer, silently exempt from the grant table, contradicting SECURITY.md line 22's default-closed claim.

**Attack scenario:** a malicious member sharing any tunnel with a victim (any grant links them symmetrically, `policy.py:185-186`) can open new TCP connections to the victim's 51902 despite holding no grant for it; this yields something only if the victim runs an unrelated service bound to that port on its overlay address or `::`.

**Recommendation:** restrict the accept to the anchor's overlay address as source, or emit the control-port accept only on the anchor — matching the documented node↔anchor hardwire exactly. (Node-side replies to the anchor already ride `ct state established,related accept`, `portfilter.py:184`, so no rule is needed on ordinary nodes.)

#### L6 — Standing door window (guest key + PSK + token) is written world-readable, then chmod'd 0600 (TOCTOU)
**Component:** `cli.py:858` (`cmd_invite`, standing-door branch). **Status:** confirmed — **RESOLVED (`34d82c9`).**

> **Resolution:** the standing-door window is now written via `keys.atomic_write(..., mode=0o600)` (`mkstemp`, 0600 from creation), eliminating the world-readable pre-`chmod` window — matching every other secret file.

For a standing door, `cli.py:858` writes `door_window.json` with `write_text(json.dumps({… "psk": …, "guest_pub": …, "token": token}))` and only afterward `os.chmod(window_path, 0o600)` at `cli.py:868`. `write_text` creates the file at the process umask (0644 for a root daemon under umask 022), so between create and chmod the secrets sit world-readable inside the 0755 data dir. Every other secret is written via `keys.atomic_write`, which uses `mkstemp` (0600 from creation) precisely to avoid this; this one site bypasses it.

**Attack scenario:** a local non-root co-tenant tight-looping on `door_window.json` during `gw invite --standing` can read the file in the sub-millisecond pre-chmod window. It captures the PSK and — as verification sharpened — the full standing `token` (`cli.py:866`), which carries the seed from which `guest_priv` is derived, i.e. complete door-enrollment material. The window is two adjacent syscalls with no intervening I/O; SECURITY.md line 182 already declares untrusted co-tenants outside the accepted posture, keeping this Low.

**Recommendation:** write the standing window via `keys.atomic_write` (0600 atomically at creation), matching every other secret file.

#### L7 — Audit `_sanitize` misses Unicode line separators that `gw narrate` honors
**Component:** `audit.py:60` (`_sanitize`) / `narrate.parse_line` (consumer, `cli.py:2900/2914`). **Status:** plausible.

`_sanitize` escapes only C0 controls (`c < 0x20`, `audit.py:55-60`), and its docstring promises an adversarial hostname "must not be able to forge extra log lines or bleed across fields." But `gw narrate` splits with `str.splitlines()`, which *also* breaks on U+0085/U+2028/U+2029 — none of which `_sanitize` escapes. The hostname is attacker-controlled and unvalidated (`enroll.py:296`, `ca.py:117`), flows into the audit `ctx` field at `reconcile.py:261`, and lands as one physical log line whose embedded separator `narrate` cuts into two, parsing the tail as a genuine `Entry`. The same hazard is already handled elsewhere: `hosts.py:104-105` deliberately uses `split("\n")` "not splitlines()" for exactly this reason.

**Attack scenario:** verification confirmed the mechanism but **refuted the filed proof-of-concept and Medium severity**. `_q()` quotes the whole `ctx` and escapes embedded `"`→`\"`, and `parse_line` gives `argv=` precedence over `event=` with `argv` always emitted after `ctx`, so the attacker cannot inject the clean spaced fields originally claimed. A working payload is limited to space-free dash-joined tokens (e.g. a visibly-mangled `argv=wg-set-peer-remove`), the durable log file stays one intact physical line for `grep`/`split("\n")`, and masking only affects the single line naming the attacker's own hostname. The result is a real log-rendering/forensic-deception nuisance, not a convincing forged peer-add/remove — hence Low.

**Recommendation:** make `_sanitize` escape every character `str.splitlines()` treats as a break (U+0085/U+2028/U+2029 and other format separators), which protects all consumers; and/or have `narrate` read with `split("\n")` as `hosts.py` does. Also validate the joiner hostname (see L8).

#### L8 — Joiner-supplied hostname is unbounded and unvalidated before it is CA-signed and persisted
**Component:** `enroll.py:296` (`_validate_request`) / `ca.py:104-123` (`CA.issue`). **Status:** confirmed.

`_validate_request` accepts `str(req["hostname"])` with no length or charset check, and `CA.issue` signs it into the credential (`ca.py:117`) and writes it to the registry verbatim (`ca.py:123`); uniqueness is checked only on the *sanitized* form (`ca.py:340/361`). The enroll bound is the door framing's 64 KiB (`door.py:47`), and verification found a second unmentioned path — rename-at-renew, where `RenewRequest` takes `hostname` unvalidated (`wire.py:356`) and `ca.renew` re-issues under it (`ca.py:153-167`) — so any enrolled member (not just a token holder) can set an arbitrary large/exotic name at every renewal unless pinned.

**Attack scenario:** a member enrolls (or renames) with a huge or exotic hostname; it is durably persisted and replicated fleet-wide in the signed credential and `NodeRecord`, bloating `directory.json` and every audit line. Downstream sinks mostly defang it (`hosts.sanitize` truncates to a 63-char DNS label, `audit._q` quotes it, TLS SANs authorize against the sanitized name), so impact is registry/directory bloat plus a couple of unescaped display sinks — the raw name is logged to the daemon log (`ca.py:124`) and written to `door_status.json` / printed by `gw watch` (`status.py`), permitting control-character / ANSI injection into a root terminal. No trust break.

**Recommendation:** reject hostnames that aren't a reasonable length (≤ 63) and DNS-label-shaped at enroll/issue time — covering both `enroll.py:296` and the `ca.py:153` rename path — rather than relying on each downstream consumer to defang them.

#### L9 — SECURITY.md claims a `0700` data dir, but the code deliberately sets `0755`
**Component:** `keys.py:140` (`NodeKeys.save`), `cli.py:508` (`cmd_create`), `cli.py:1587` (`cmd_join`). **Status:** confirmed.

SECURITY.md line 151-152 tells the operator secrets are "`0600` inside a `0700` data dir," presenting the `0700` dir as part of what stops a co-tenant reading secrets. The code does the opposite on purpose: all three paths `os.chmod(data_dir, 0o755)` so root-free commands (`gw watch --snapshot`) can read world-readable public files; no path ever sets `0700`. The confidentiality property still holds via per-file modes — `id_priv.pem`, `wg.key`, `ca.key` are each their own `0600` file via `atomic_write`/`mkstemp` (`keys.py:236-263`) with no mid-write exposure — so no key material leaks. Only the stated dir-level defense-in-depth is absent and the document is factually wrong.

**Attack scenario:** none against secrets. A co-tenant can enumerate the dir and read `directory.json` (0644) and `*.pub`, which SECURITY.md already treats as non-secret (line 147). The defect is that the "`0700` data dir" clause does not describe the shipped code.

**Recommendation:** correct SECURITY.md to state the data dir is `0755` by design with per-file `0600` secrets (matching the comment at `cli.py:503-508`), or, if the `0700` guarantee is wanted, keep the dir `0700` and grant the root-free readers access another way.

#### L10 — TLS cert placement uses a predictable temp name without `O_EXCL`/`O_NOFOLLOW` and then `chown`s it
**Component:** `certs.py:191` (`place_cert_files`). **Status:** confirmed — **RESOLVED (`34d82c9`).**

> **Resolution:** placement now uses `tempfile.mkstemp` (random name, `O_CREAT|O_EXCL`, 0600) in the target dir and operates on the file descriptor (`os.fchmod`/`os.fchown`), never a path — so a pre-planted `<name>.gwtmp` symlink can neither be opened nor followed, and `os.replace` renames the name rather than writing through a symlinked target.

`place_cert_files` runs as root and writes each profile file via `tmp = dest.with_name(dest.name + ".gwtmp")` (fixed, predictable) then `os.open(tmp, O_WRONLY|O_CREAT|O_TRUNC, mode)` (`certs.py:194`) with no `O_EXCL` and no `O_NOFOLLOW`, followed by `os.chmod` and `os.chown(tmp, …)` (`certs.py:199-201`, both `follow_symlinks=True`). It deliberately bypasses `keys.atomic_write`/`mkstemp`. If the destination directory is writable by a non-root account, that account can pre-plant `<name>.gwtmp` as a symlink; root follows it — `O_TRUNC`/write clobbers the target and `os.chown` transfers ownership of the target to the attacker's uid.

**Attack scenario:** the postgres profile (`profiles/postgres.toml`) places the key under `/var/lib/postgresql/17/main`, owned `postgres:postgres` mode 0700, and `place_cert_files`' `mkdir(exist_ok=True)` leaves it postgres-writable. The postgres account persistently plants `server.key.gwtmp` → a root-owned file (e.g. `/etc/passwd`); the next root-run renewal (`certs.py:337-345`) truncates and `chown`s that target to postgres — a clean local privilege escalation, no tight race needed since the name persists across the renewal interval. Verification confirmed the other shipped profiles (redis/nats/mosquitto/minio) target subdirs that root's `mkdir` creates root-owned, so only the postgres profile is exploitable among those shipped; hence Low (borderline Medium given the root outcome).

**Recommendation:** create the temp with `O_EXCL|O_NOFOLLOW` (or use `tempfile.mkstemp` in `dest.parent` as `keys.atomic_write` does) and open/chown the final path with `O_NOFOLLOW` / `follow_symlinks=False`, so a pre-planted symlink aborts placement instead of being followed.

### Info

#### I1 — No domain-separation tag across the five Ed25519 signing contexts
**Component:** `wire.py:54` (`_canonical`). **Status:** confirmed (defense-in-depth; no attack today).

The CA key signs both x509 TBSCertificates (DER, `tlsca.py:97/153`) and canonical-JSON `Credential`/`GrantTable` bodies (`wire.py:126/479`); a node's `id_priv` signs three JSON object types — `NodeRecord`, `RenewRequest`, `CertRequest` (`wire.py:220/333/394`). None carries a per-type context/domain prefix; each signature is taken directly over the object's canonical bytes. Cross-type confusion is not exploitable today because the encodings and key-sets are disjoint (DER begins `0x30`, JSON `0x7b`; the five JSON types have mutually disjoint top-level key sets, so canonical JSON is injective and no byte string verifies under two types). But that disjointness is incidental — no comment, test, or SECURITY.md clause pins it as an invariant.

**Recommendation:** prepend a short fixed context label to the bytes each signer covers (e.g. `b"gw/cred/v1"`, `b"gw/noderecord/v1"`, `b"gw/renew/v1"`, `b"gw/certreq/v1"`, `b"gw/grants/v1"`) so cross-context reuse is structurally impossible regardless of future encoding changes.

#### I2 — `/cert` issuance has no explicit revocation check; it relies on revoke atomically deleting the registry entry
**Component:** `server.py:262` (`_handle_cert`). **Status:** plausible.

The TLS-cert path authorizes solely on `node_info(id_pub) is not None` plus the `tls` cap (`server.py:262-269`); unlike `ca.renew`/`ca.issue` (`ca.py:101/145`), it never calls `is_revoked`. Revocation reaches `/cert` only because `add_revoke` unlinks `nodes/<id>.json` via `forget_node` under the same lock (`ca.py:243-247`). One verifier judged the coupling structurally sound (every registry writer is itself revocation-gated) and rated this Info; the other noted a narrow fail-open ordering — `add_revoke` writes `revoked.json` *before* the unlink, and `forget_node` swallows only `FileNotFoundError`, so a crash or `EROFS`/`PermissionError` between the two leaves `revoked=True` with the registry record present, in which state `/renew` refuses but `/cert` keeps issuing until `drop_stale` fires. Net verified severity: Info.

**Recommendation:** add an explicit `if self.ca.is_revoked(req.id_pub): 403` in `_handle_cert` alongside the existing checks (the handler already holds the live revoke reader used for `/publish`), so revocation is enforced on `/cert` directly rather than as an emergent property of registry deletion.

#### I3 — SECURITY.md says greasewood "never touches your firewall," but port enforcement installs nftables rules by default
**Component:** SECURITY.md line 158 vs `portfilter.py`. **Status:** confirmed (documentation drift).

SECURITY.md line 157-158 states "greasewood won't [enforce at the OS layer], by design — it never touches your firewall," and "What is enforced" (lines 56-120) describes only the 7-step reconcile check with no mention of the port layer. But `enforce_ports` defaults to true (`config.py:231`; written true at create/join when nft is usable, `cli.py:375-385`) and the daemon installs `table inet greasewood_<mesh>` with an input-hook chain (`portfilter.py:175-199`), applied every cycle (`reconcile.py:463`) and deliberately persisted after daemon stop (teardown only via `gw purge`, `portfilter.py:262-264`). The code's scoping is sound — drops match only mesh/door ifnames and non-mesh traffic is accepted non-terminally (`portfilter.py:183/192/196`), so it cannot affect a physical NIC — but the document both misstates the firewall interaction and omits an entire enforcement layer (grants-as-port-policy, fail-closed persistence, the `enforce_ports` opt-out and its nft-less degradation from L4). Verification split on Info vs Low; recorded here as Info as originally filed, with the security-relevance noted.

**Recommendation:** update SECURITY.md — reword the multi-user-hosts sentence to "never touches your underlay firewall or your own rule tables," and add the portfilter layer to "What is enforced" (scope guarantee, fail-closed persistence, and the `enforce_ports=false` / nft-less degradation).

#### I4 — Issued TLS leaf certs are not revocable and outlive the mesh credential TTL (design-intent)
**Component:** `server.py:277` / `tlsca.py` (`issue_tls`). **Status:** design-intent.

TLS leaves are minted with `tls_cert_ttl` (default 7d, `server.py:277`) signed by the same CA key, with no CRL/OCSP and no binding to the node's mesh credential (default 24h). A node revoked via `gw revoke` keeps a CA-valid, `verify-full`-trusted leaf for the remainder of its up-to-7-day TTL — ~7× the credential TTL the model advertises for containment. This is the documented passive-revocation design (SECURITY.md line 129 "Revocation is expiry-based on nodes (no CRL push)"; `tlsca.py:13`), and post-revoke re-issuance is blocked (`add_revoke` deletes the registry record, so `/cert` 403s). Exploiting the tail requires an off-mesh path, since the revoked holder loses WireGuard reachability within one credential TTL and addresses are self-certifying. The one real gap is documentation precision: SECURITY.md line 23 ("its certs … fleet-wide within one credential TTL") and lines 131-132 quantify revocation containment only in credential-TTL terms and never mention that `tls_cert_ttl` is a separate, longer window for already-issued leaves.

**Recommendation:** document the TLS-leaf lifetime as a distinct revocation-containment window in SECURITY.md, and/or default `tls_cert_ttl ≤ credential_ttl` (or to hours) so a revoked identity's service cert cannot outlive its mesh membership.

## Design strengths

The review found much to commend; the code implements its stated model faithfully in the areas that matter most.

- **Self-certifying addresses.** `addr == truncate64(blake2s(id_pub))` (reconcile step 4) means a node cannot claim an overlay address it did not derive, and address theft additionally requires the victim's `id_priv` — a `2^64`-plus-key barrier. This holds even against a compromised anchor (SECURITY.md line 24), and the review found no path around it.
- **Default-closed policy.** The grant table is deny-by-default: a peer is installed only if a grant links the two roles, and the port filter's terminal rule is `drop` (`portfilter.py:196`). The Low findings against the port layer are fail-open *degradations* and a wider-than-documented control-port exception — the default posture itself is closed.
- **Expiry-as-revocation with a clean structural basis.** Acceptance is credential-bound: a `wg_pub` is honored only while a live credential binds it, so revoke or key rotation drops a node fleet-wide within one TTL without any CRL machinery. Anchor-side revoke is immediate and atomic (`add_revoke` + `forget_node` under one lock).
- **Canonical signing over a stable encoding.** `_canonical` (`wire.py:54`) yields deterministic sorted-key JSON, and the five signing contexts happen to be byte-disjoint; the only gap (I1) is the absence of an explicit domain tag, a defense-in-depth nicety, not a live flaw.
- **Control plane isolated by construction.** `/renew`, `/cert`, `/publish` bind to the overlay address and loopback only, never `::` (SECURITY.md lines 49-51), so they are unreachable from the underlay independent of any firewall; the enrollment RPC runs inside a transient door tunnel. Requests are signature-authenticated and replay-bounded (nonce + ±300s skew).
- **Door isolation and single-slot enrollment.** The door listens only during a time-boxed window, admits one peer, and runs inside its own WireGuard tunnel; token seeds are 32-byte high-entropy. The H1 defect is a missing *ownership* check within an otherwise well-contained door, not a break of the door's isolation.
- **Reserved roles and the single-anchor invariant** are enforced on the primary assignment paths (`set-roles`, `set-caps`, `--roles`/`--self-roles`), with `role:*`/`role:anchor` screened; L3 is a consistency gap on `invite --caps` reachable only by the already-trusted root operator.
- **Structural verification on directory ingest** (self-signature, address-derivation, `id_pub`↔credential match) blocks high-`seq` cache-poisoning DoS before a record is cached, exactly as SECURITY.md lines 83-91 describe.
- **Upfront root/guard errors and safe atomic writes.** Root-requiring commands check `CAP_NET_ADMIN`/root before acting, fatal startup paths leave a `gw-watch` breadcrumb, and every secret file (except the two flagged sites, L6/L10) is written 0600-from-creation via `mkstemp` — the correct primitive is present and used almost everywhere.

## Conclusion

greasewood is a well-reasoned control plane whose cryptographic and trust-gate core is sound and matches its documented model. The single material defect is H1 — door enrollment omits proof-of-possession of the joining identity, letting a token holder re-bind another node's public identity for a transient interception and a persistent caps overwrite — and it warrants a code fix (reject door re-binding of a registered id, or require a self-signature). Everything else is Low or Info: a handful of local-multiuser hardening gaps (a symlink race and a TOCTOU secret window, both fixable by routing through the existing `atomic_write` primitive), a few honest fail-open/consistency footguns in the nftables layer, and a cluster of SECURITY.md deviations (firewall interaction, `0700` dir, TLS-leaf lifetime, anchor recert window) that should be corrected so the document once again describes the shipped code. No Critical issues exist, no remote secret-less attacker gains anything, and the design's marquee properties — self-certifying addresses, default-closed grants, expiry-based revocation, and a construction-isolated control plane — hold up under adversarial review. Fix H1, close the two file-mode races, and reconcile the documentation, and the posture is strong.