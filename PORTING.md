# Porting notes

Exploratory notes on what a **macOS port** would actually cost. greasewood is
[Linux-only by design](README.md#linux-only) and there is no port planned — this
document exists so the reasoning isn't lost, and so that if the day ever comes,
whoever picks it up starts from a clear-eyed estimate instead of a hunch.

The short version: the parts that *look* hard (naming, the audit trail) are
cheap; one thing needs a modest rethink (the interface is a process, not a kernel
object — but a launchd job absorbs most of that); and the one genuinely hard,
security-critical subsystem is re-expressing the door's isolation in `pf`.
Everything else is mechanical.

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
| **Interface *lifecycle*** | medium | The interface is a `wireguard-go` process, not a kernel object — but a dedicated launchd job keeps it up, so greasewood stays a `wg set` client. |
| **Door isolation** | **the hard one, security-critical** | Linux policy routing (blackhole table + `ip rule`) has no macOS equivalent; it becomes a `pf` anchor. |
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

### 1. Interface lifecycle: the interface is a process, not a kernel object

First, clear up a common confusion: the `wg` **tool** is passive on every
platform. It's only a *configurator* — it has never created an interface, and it
needs nothing running. `brew install wireguard-tools`, type `wg show`, and it
prints nothing and exits. That part "just works."

The difference is what a WireGuard **interface** *is*:

- On **Linux**, an interface is a **kernel object**. `ip link add gw-mesh type
  wireguard` creates it and it then simply *exists* — free-standing, no process
  attached. greasewood can crash and restart and every live tunnel keeps running
  in the kernel (a documented property: the daemon isn't in the data path).
- On **macOS** there is no kernel WireGuard, so an interface is a running
  **`wireguard-go` process** on a `utun`. It exists only while that process runs,
  and every tunnel on it drops the instant the process dies. (`wg show` shows
  nothing on a fresh Mac precisely because no `wireguard-go` is running — there's
  no interface for the tool to find.)

So the real cost isn't "you have to start `wg`" — it's that **an interface's
existence is now tied to a process's lifetime**, which is never true on Linux.
*Something* has to keep that process alive. There are two ways, and one is
clearly right:

- **greasewood owns a supervise-and-restart loop** — spawn `wireguard-go`, watch
  its PID, restart on death, tear down on shutdown. Possible, but it grows the
  daemon a babysitter it doesn't have today, and two interfaces (mesh + door)
  means two to mind.
- **A dedicated launchd job keeps `wireguard-go` up** (a plist with
  `KeepAlive`), and greasewood stays a pure `wg set` client that assumes the
  interface exists — which is almost exactly how it treats the kernel interface
  on Linux. **This is the way.** greasewood already delegates its *own* uptime to
  systemd/launchd rather than daemonizing itself, so delegating the tunnel
  process's uptime to launchd is the same move, one layer down. On this path the
  macOS backend's `create_interface` becomes "ensure the launchd job is loaded
  and the utun is up," not "fork and babysit a process."

The one semantic that doesn't fully go away either way: a kernel interface
survives a greasewood restart *and* survives greasewood crashing; a
process-backed one survives a greasewood restart but not the `wireguard-go`
process dying. launchd brings the process back fast, but there's a blink where
tunnels are down that has no Linux analogue. Worth documenting, not worth
losing sleep over. `wg set`/`wg show` work against the interface unchanged (same
UAPI socket), so all the *peer* management ports as-is — it's only the
interface's *existence* that moves from "kernel state" to "a launchd-managed
process."

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

## Longevity of the greasy lane (the one forward-looking risk)

Everything above assumes a root process can keep transparently poking the
kernel's network config with `route`/`ifconfig`/`pfctl`. That's true **today** —
in fact `wg-quick` on macOS *is* exactly that pipeline (`wireguard-go` +
`ifconfig` + `route` + `pfctl`), so the greasy approach is the official CLI path,
not a hypothetical. But it's worth being clear-eyed about the trend line.

Two things to separate:

- **Apple's "networking out of the kernel" push does *not* threaten these
  tools.** That push is about where third-party *code* runs (kext → sandboxed
  Network Extension). `route`/`ifconfig` are a different operation entirely: a
  privileged userland process asking the kernel to modify *its own* routing
  table via `PF_ROUTE`/ioctls. The kernel's config interface isn't going away.
- **The broader lockdown *is* the thing to watch**, and it will arrive as
  friction, not a headline removal:
  - **`configd` owns the network.** macOS's System Configuration daemon reasserts
    its view and can revert raw `ifconfig`/`route` changes to *managed*
    interfaces — already true today. The reprieve: it leaves interfaces it didn't
    create alone, so a utun *you* stood up for a tunnel is mostly unbothered
    (which is why `wg-quick` gets away with it).
  - **Root is being hollowed out.** SIP, TCC, and entitlement-gating have steadily
    converted "root can do anything" into "root can do what Apple has decided,
    increasingly only through entitled/managed paths." Nothing there removes
    `route`/`ifconfig`, but it's the mechanism by which, over a long horizon,
    low-level network config could come to require an *entitled helper* instead
    of a plain subprocess.

So the realistic risk isn't "will `route` exist" — too much (including Apple's
own scripts and `wg-quick`) depends on it. It's "will configuring a tunnel as
root still be a *transparent subprocess*, or a signed, entitled helper." The day
it's the latter, a Mac port keeps *working* but stops being *greasy* — the audit
trail would be recording a helper's mediated calls, not the raw commands.

And it's the same force one more time: Apple gates root's low-level config for
the same reason it pushes Network Extensions — network changes should flow
through channels that are *observable, entitled, and Apple-mediated*, which is
the philosophical inverse of greasewood's *transparent, unmediated, audit-it-
yourself* premise. So the greasy lane isn't just unsupported; it rows against a
current whose whole point is to eliminate the kind of access greasewood is built
on. **Not imminent, viable now — but the day that friction lands, the honest
question is the same as the Network Extension fork, arriving from a different
direction: is it still greasewood, or just wearing the name?**

## Recommended shape, if it ever happens

1. **Extract a `Backend` driver** — `create_interface`, `set_peer`, `add_route`,
   `remove_route`, `isolate_door`, `destroy_interface`, … The current `wg`/`ip`
   code becomes the Linux impl; the macOS impl configures peers with the same
   `wg`, adds routes with `route`/`ifconfig`, isolates the door with a `pf`
   anchor, and lets `create_interface` mean "ensure the launchd `wireguard-go`
   job is up" rather than forking a process itself. **Every backend command
   still goes through the audited `wg._run`,** so the trail stays honest
   per-platform for free.
2. **Extend `narrate.describe()`** with the macOS verbs, and let the door-
   isolation narration branch (blackhole table vs pf drop) — one narrator,
   identical human output.
3. **Translate the systemd units** to a launchd plist.

Two genuinely-hard subsystems (process supervision, `pf` isolation), everything
else mechanical, and the audit/narrator layer free. The interesting takeaway:
the codebase having already done the harder, more general thing —
per-mesh-configurable interfaces for multi-mesh — quietly makes the port cheaper
than it looks.
