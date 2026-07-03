# Porting notes

Exploratory notes on what a **macOS port** would actually cost. greasewood is
[Linux-only by design](README.md#linux-only) and there is no port planned — this
document exists so the reasoning isn't lost, and so that if the day ever comes,
whoever picks it up starts from a clear-eyed estimate instead of a hunch.

The short version: the parts that *look* hard (naming, the audit trail) are
cheap, and the real cost lives in two subsystems — supervising a userspace
tunnel process, and re-expressing the door's isolation in `pf`. Everything else
is mechanical.

## The guiding principle: the grease *is* the auditability

greasewood manages the data plane by shelling out to `wg`/`ip` and recording
every command. That looks greasy — the "clean" way is netlink bindings — but the
grease is load-bearing: you cannot have [the command trail and `gw
narrate`](README.md#auditable) without shelling out to real, inspectable,
re-runnable commands. greasewood's "clean" is **legibility** (you can read every
command it runs), not **polish**.

That fixes the distribution decision before it's asked. A macOS port ships via
**pip / conda / brew** (in that order of preference) and runs in the
**root + subprocess** lane — the same shape as on Linux. It does **not** become a
Network Extension / packet-tunnel provider.

- A Network Extension is opaque by construction: signed, notarized, sandboxed,
  framework-mediated. You don't shell out to `route`/`pfctl` from inside a
  packet-tunnel provider — you call NE APIs and the framework does it. That
  throws away the exact property (transparent, audited subprocess commands) this
  project is built around. It would be "clean" the way a sealed appliance is
  clean, which is off-brand for greasewood.
- The brew/CLI lane also dodges the ceremony: **Gatekeeper gates downloaded
  `.app` bundles opened from Finder**, not a CLI a user `brew install`s and runs
  as root from a terminal. So no notarization, no entitlements, no Apple in the
  loop.
- The audience doesn't change either. greasewood is for people who'd run it as
  root and know what `pf` is — the same person the Linux version already targets.
  The NE path would chase the "don't make me think" crowd greasewood
  deliberately doesn't serve.

**Consequence for this whole document:** because we stay in the subprocess lane,
the [audit trail](README.md#auditable) and `gw narrate` port intact — every
`route`/`ifconfig`/`pfctl`/`wg` call is a real subprocess through the same
audited `wg._run`. That's the cheapest, most portable part of the codebase.

## Scorecard

| Element | Cost | Why |
|---|---|---|
| **Audit + narrator infrastructure** | ~free | Platform-neutral: records "argv, rc, timing, why." Only the narrator's command→English *dictionary* grows (add macOS verbs). |
| **Interface naming** | small | The mesh interface name is already config-driven (multi-mesh forced it). utun constrains the *shape* to `utunN`, and one constant (`DOOR_IFACE`) is still hardcoded. |
| **Routing verbs/semantics** | small–medium | `ip` → `route`/`ifconfig`; no atomic `route replace`; utun is point-to-point. |
| **Interface *lifecycle*** | **real** | The interface is a supervised userspace process (`wireguard-go`), not a kernel object. |
| **Door isolation** | **real, security-critical** | Linux policy routing (blackhole table + `ip rule`) has no macOS equivalent; it becomes a `pf` anchor. |
| **Service + packaging tail** | medium | launchd instead of systemd; a fresh integration-test harness; resolver-cache quirks. |

## The cheap parts

### Audit and narrator — carry across verbatim

`audit.record_command`, the contextvars, the file/journal sinks, and the logfmt
format don't care whether the argv is `ip` or `route`. The narrator's *framework*
(parsing, grouping by context, operation intros, rendering, filters) is
platform-neutral too. Only `narrate.describe()` — the command→English dictionary
— needs macOS entries, so that `ip -6 route replace X dev gw-mesh` **and**
`route -n add -inet6 X -interface utun7` translate to the same sentence
("Route traffic for X over the tunnel"). One narrator, one audit format,
identical human output on both platforms — **and the trail never lies, because
you log the command that actually ran, not a Linux fiction.**

> Do **not** translate at the command layer (rewrite macOS commands into Linux
> ones for logging). An audit trail that records a command that didn't run is
> worthless. Log reality; translate to English in the narrator.

### Interface naming — mostly pre-paid by multi-mesh

The mesh interface name is `cfg.wg_interface` (`[network] interface`, default
`gw-mesh`), threaded everywhere as data — because
[a node on two meshes](README.md) runs two daemons, each with its own
`interface = …`. So the downstream code already reads a variable, not a constant.

On macOS: utun forces the *shape* (`utunN`, not an arbitrary string), but
`wireguard-go` can request a specific unit, so `interface = "utun7"` just works
with the plumbing that exists. The only genuinely-new wrinkle is a mild
inversion — on Linux the config name is an *input* to `ip link add`; on macOS
it's either a utun number you pin in config (and hope is free) or a name you read
back after the tunnel starts. Small tweak to one creation path.

There is exactly **one** hardcoded interface name left: `DOOR_IFACE = "gw-door"`
in `door.py`. Make it configurable (or dynamically assigned) and the naming story
is done.

### Routing verbs and semantics — a dictionary plus two gotchas

The command shapes are a straight mapping (`ip -6 route replace X dev gw-mesh` →
`route -n add -inet6 X -interface utunN`). Two semantic traps:

- **No atomic replace.** Linux `ip route replace` is add-or-update in one shot,
  and the reconcile loop leans on that idempotence — it can "replace" every cycle
  and converge. macOS `route` has `add`/`change`/`delete` with no atomic upsert,
  so a replace becomes query-then-add-or-change, or delete-then-add (briefly
  routeless). Per-command minor; loop-wide it's a subtle correctness surface.
- **Point-to-point addressing.** utun is P2P, so assigning the overlay /128 is
  the `ifconfig utunN inet6 <local> <remote> prefixlen 128` local+remote dance,
  not a flat `ip addr add`.

## The expensive parts

### 1. Interface lifecycle: a supervised process, not a kernel object

On Linux, `ip link add … type wireguard` conjures a kernel interface that just
*exists*, persistent and independent of any process. greasewood's model assumes
this: create the interface once at startup, then reconcile only ever touches
peers on a thing the kernel holds.

On macOS there is no kernel WireGuard. The interface is created by
`wireguard-go`, a **userspace process**, and lives and dies with it. So
greasewood gains a lifecycle it doesn't have today: start `wireguard-go`, detect
a crash, restart it, tear it down. The kernel used to be the supervisor; now the
daemon is. Two interfaces (mesh + door) means two processes to babysit. `wg
set`/`wg show` still work against it (same UAPI socket), so the *peer* management
ports unchanged — it's the interface's existence that becomes a managed thing.

### 2. Door isolation: routing → filtering (`pf`)

This is the one to be careful with, because it's a **security boundary** and
can't be approximated.

Today (`wg.setup_door_routing`): a dedicated routing table with a `blackhole
default`, plus `ip -6 rule from GUEST_DOOR_IP lookup <table>`. Any packet
*sourced* from the joining node consults a table that blackholes everything, so
it can't route into the mesh even if IP forwarding is on — a second wall behind
WireGuard's allowed-ips.

macOS has **no policy routing** — no source-based table selection at all. The
equivalent is **`pf`**, a *filtering* model, not a *routing* one: a pf anchor
like `block drop from <guest_door_ip> to any` with a narrow pass for the enroll
endpoint. Why it's the hard part:

- **Different model, different failure modes.** A routing blackhole and a pf drop
  fail, order, and verify differently (`ip -6 rule show` vs `pfctl -a <anchor>
  -sr`). The door-isolation tests and the `gw diagnose` story get rewritten.
- **It strains greasewood's firewall ethos.** greasewood's rule is "never touch
  the host firewall; print the rules, you apply them." The door isolation is the
  *one* deliberate exception where greasewood manipulates kernel state itself,
  because it's a security control, not user policy. On Linux that's a
  self-contained routing table nobody else uses. On macOS it's `pf`, which is
  more monolithic — greasewood must own a pf anchor without clobbering the user's
  pf config, and pf being enabled at all isn't guaranteed.

## The tail

- **launchd, not systemd.** The `greasewood.service`/`.path` units and the
  [sandboxing hardening](systemd/greasewood.service) rewrite as a launchd plist —
  and launchd's sandboxing (`sandbox-exec`/App Sandbox) is different and weaker
  than the systemd directives, so that hardening regresses.
- **Resolver caching.** `/etc/hosts` still works, but macOS's `mDNSResponder`
  caches hard; changes may need `dscacheutil -flushcache`, so the "edit
  /etc/hosts and it resolves" immediacy softens.
- **Integration tests.** The suite is podman + Linux netns and can't run on
  macOS. You'd need real utuns on a Mac CI runner (expensive, flakier) — a
  from-scratch harness.
- **One upside — the Secure Enclave.** `id_priv` could live in the Enclave
  instead of on disk. That is *why* the design parks hardware-backed identity in
  "v2, the macOS port": it's the natural home for the one hardware-security
  feature greasewood deliberately deferred.

## Recommended shape, if it ever happens

1. **Extract a `Backend` driver** — `create_interface`, `set_peer`, `add_route`,
   `remove_route`, `isolate_door`, `destroy_interface`, … The current `wg`/`ip`
   code becomes the Linux impl; a macOS impl is `wireguard-go` supervision +
   `route`/`ifconfig` + a `pf` anchor. **Every backend command still goes through
   the audited `wg._run`,** so the trail stays honest per-platform for free.
2. **Extend `narrate.describe()`** with the macOS verbs, and let the door-
   isolation narration branch (blackhole table vs pf drop) — one narrator,
   identical human output.
3. **Translate the systemd units** to a launchd plist.

Two genuinely-hard subsystems (process supervision, `pf` isolation), everything
else mechanical, and the audit/narrator layer free. The interesting takeaway:
the codebase having already done the harder, more general thing —
per-mesh-configurable interfaces for multi-mesh — quietly makes the port cheaper
than it looks.
