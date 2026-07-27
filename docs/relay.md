# Relay: connecting peers that can't reach each other directly

greasewood is **direct-or-fail** by default: every pair of nodes forms its own
WireGuard tunnel, end-to-end, and if they can't reach each other, they simply
don't connect. That's the right default — no middlemen, no traffic funnels, full
end-to-end privacy. But some pairs *can't* go direct no matter what:

- an **IPv4-only** node (public wifi, no IPv6) and a node reachable **only over
  IPv6** (a GUA, no public v4) share no underlay address family — a direct
  tunnel is impossible, not just inconvenient;
- two nodes each behind their own NAT, with no reachable endpoint on either side.

The symptom is quiet: `gw diagnose` shows the grant fine and the endpoint fine,
and `gw watch` just says *no handshake*. There's nothing to fix at either end —
they have no common ground.

**Relay gives them one: the anchor.** When enabled, the anchor forwards traffic
between two peers that can each reach *it* but not each other. Because the
overlay is uniformly IPv6 (every address is `hash(id_pub)`), and the anchor
terminates each leg, it transparently bridges the underlay families too — the
IPv4-only node reaches the anchor over v4, the anchor reaches the v6-only node
over v6, and the overlay packet flows straight through. It's ordinary WireGuard
hub-and-spoke; the kernel forwards, there's no relay daemon.

## Two switches, both explicit

Relaying a pair takes **two independent yeses**. Either one missing means no
relaying, and neither implies the other.

**1. The anchor offers relay at all.** Live, no rebuild, no re-enrollment:

```bash
# on the anchor
sudo gw relay on
```

That enables IPv6 forwarding and flips a self-signed `relay` flag on the
anchor's own record, which the fleet picks up within one sync cycle.

**2. A grant names the pair.** In `grants.toml`, `relay = true` says *these two*
may fall back to the anchor:

```toml
[[grant]]
from  = ["host:laptop"]
to    = ["host:nas"]
ports = ["tcp/2049"]
relay = true
```

Then `sudo gw policy apply`, as with any policy change.

This is deliberate. Relay is decrypt-and-forward (see the warning below), so
which traffic the anchor is allowed to see is a decision you write down — never
one inferred from a pair happening to fail to connect. **A pair with no
`relay = true` grant is never relayed**, however unreachable it is and however
enabled the anchor is; it stays direct-or-fail. A mesh running with no policy at
all gets no relaying either, since there's no grant to carry the opt-in.

Relay changes nothing for pairs that *can* go direct — they always do,
regardless of what the grant says.

### It's a standing permission, not a mode

You write the grant once. Nothing is toggled per trip: a laptop that grows a
`relay = true` grant to the home NAS goes direct on the home LAN, falls back to
the anchor from IPv4-only cafe wifi, and returns to a direct tunnel on the next
5-second cycle when it walks back in — all from that one line, with no anchor
login at either end. The pair is re-evaluated every cycle from what each node
currently publishes, so "prefer direct, relay only when stuck" is continuous,
not a state you enter and leave.

```bash
sudo gw relay off       # stop relaying; nodes fall back to direct-or-fail
gw relay status         # show whether relay is on + IPv6 forwarding state
```

!!! note "If your anchor is also your router"
    `net.ipv6.conf.all.forwarding` is machine-wide, and on a site router it is
    what makes the box a router. greasewood therefore only ever turns it **on**,
    and turns it back off only if greasewood was the one that enabled it (it
    records that in `relay-forwarding-owned` in the data dir). Forwarding that
    was already on when you enabled relay is left exactly as found — `gw relay
    off` will not take your LAN offline.

!!! warning "The anchor sees relayed traffic"
    Relay is **decrypt-and-forward**, not an opaque bounce: the anchor
    terminates both WireGuard tunnels, so it can **see (and could tamper with)**
    the traffic of pairs it relays. Direct tunnels stay end-to-end private;
    relayed ones are visible to the anchor. Anything *inside* (SSH, TLS) is
    still protected by its own encryption, and per-role **port grants are still
    enforced** end-to-end (the receiving node sees the real source and filters
    on it) — but the WireGuard-layer privacy guarantee does not hold for relayed
    flows. It's your anchor, holding the CA; decide if that trust is acceptable
    for the traffic in question. For a pair that otherwise *cannot connect at
    all*, it usually is.

## What it does and doesn't change

- **Grants are unchanged.** Relay only carries pairs a grant *already* allows,
  and only those that additionally say `relay = true`; it never widens access.
  The receiving node still enforces its per-role port filter against the real
  source address.
- **It falls back cleanly.** The moment a pair *can* go direct again (a node
  gains IPv6, an endpoint becomes reachable), they drop the relay and form a
  direct tunnel on the next cycle.
- **A live tunnel is never relayed.** Reachability is judged from the live
  session first, the advertised endpoint second. An outbound-only peer (behind
  NAT/CGNAT, or a laptop) advertises no endpoint you can dial, but if it dialled
  *you*, that tunnel is up and direct — relay leaves it alone. Only once the
  session has been dead longer than the live-link window does the pair fold into
  the anchor.
- **A peer that can still dial you is never relayed either.** "I can't dial it"
  is only half the question; relaying is right only when *neither* direction can
  open the tunnel. A NATed node advertises no endpoint whether it's on the same
  LAN or on cafe wifi, so nodes publish the underlay families they can originate
  on (`families` on the record, like `version`). A laptop that still has IPv6
  will dial your v6 endpoint, so it stays a direct peer; the same laptop on
  IPv4-only wifi facing a v6-only host can't, and folds into the anchor. This
  matters because folding REPLACES the direct peer: relay a peer that could have
  dialled you and its handshakes arrive at a node that no longer knows its key,
  which is worse than not relaying at all. A peer that publishes no families (an
  older node) is given the benefit of the doubt and stays direct.
- **`gw watch` shows the edge.** A relayed peer counts as reachable while the
  anchor link is live, so the segment-health view shows the connection (via
  relay) rather than a false gap.
- **The anchor is a funnel + single point of failure** for relayed flows —
  all their traffic goes through it. Fine for a laptop reaching a home server;
  think twice before relaying high-bandwidth or latency-sensitive pairs.

## Rollout note

`relay` is a new field on the node record. A relay-**off** record is byte-for-
byte identical to before (the field is omitted), so mixed-version fleets
interoperate fine while relay is off. But an old node can't verify a record that
*carries* the field. So: **upgrade the fleet's binaries first, then run
`gw relay on`.** (Same rule as any record-format addition.)
