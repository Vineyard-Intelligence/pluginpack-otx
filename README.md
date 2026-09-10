# pluginpack-otx

Pulls the **AlienVault OTX** reports ("pulses") that name a selected indicator, and stages the
substantial ones as campaigns — with their ATT&CK techniques, malware families and named adversary.

Consumes `infrastructure.ip_address`, `infrastructure.domain`, `web.url`, `threat.file_hash`,
`threat.vulnerability`. Produces `threat.campaign`, `threat.attack_pattern`, `threat.malware`,
`threat.threat_actor`.

## Why OTX

Every other keyless source here answers *what is this address*. OTX answers *who has written about
it, and what did they say it was part of* — an indicator arrives already connected to a named
report, so a bare IP becomes a campaign, a technique and a malware family in one hop.

Two plugins:

- **OTX Pulses** — the reports that name an indicator, as campaigns with their ATT&CK techniques,
  malware families and actor.
- **OTX Passive DNS** — what a name resolved to and *when*, and backwards from an IP, every hostname
  seen pointing at it.

## The API key is required, and it buys throughput — not data

Two separate measurements, and conflating them is easy:

- **Data: identical.** The same indicator returns the same pulses with and without a key — 26 either
  way, identical top-level keys, one byte of difference in the response. A key reveals nothing extra.
- **Rate limit: not identical at all.** Anonymous callers are cut off after a handful of requests
  (HTTP 429, no `Retry-After`, no rate headers). Measured at the same instant: an anonymous burst was
  refused **25 out of 25** while keyed requests returned 200, and a keyed burst of 20 ran clean.

The key was optional at first, on the grounds that the data is identical. That reading was right
about the response and wrong about the product: *works, then stops after six nodes* is not a working
plugin, it is one that produces a partial answer with no signal that the answer is partial. A key is
free and takes a minute. Being told so up front beats discovering it as a half-collected graph.

A throttled lookup is still reported as **throttled** — never as "nothing known", which would turn a
rate limit into a false negative on every remaining node.

`/passive_dns` refuses anonymous callers outright, so requiring a key is also what makes the second
plugin possible at all.

## Passive DNS: the dates, and the reverse direction

Certificate Transparency finds subdomains, Shodan resolves a name, Domain Recon reads today's A
record — all of them answer *now*. Passive DNS answers *since when, and until when*, which is what
separates infrastructure a subject still uses from infrastructure they had abandoned before the
events under investigation. The dates go on the edge label, because that is what a reader sees.

Given an IP it runs backwards: every hostname observed pointing at that address. Nothing else
installed here does that.

Two traps it defends against, both measured:

- **`NXDOMAIN` appears in the address field** — 14 of 120 records for `mail.ru`. It is the resolver's
  answer, not a host. Left in, every domain whose lookup ever failed converges on one node called
  NXDOMAIN. On an A record the address check rejects it anyway; on a **CNAME** the target is a
  hostname, so "not an IP" is satisfied and it sails through into a domain node. That path is what
  the sentinel list is for.
- **Which field is the discovery depends on the direction.** A record is always (hostname →
  address). Query a domain and `address` is the finding; query an IP and `address` **is the seed**,
  repeated on all 500 rows, while `hostname` is the finding.

## `domain` and `hostname` are different namespaces in OTX

Measured 2026-09-10:

| | `/domain/` | `/hostname/` |
|---|---|---|
| `mail.ru` | 50 pulses | 0 |
| `cdn.jsdelivr.net` | 0 | 50 pulses |
| `bbc.co.uk` | 23 pulses | 0 |
| `news.bbc.co.uk` | 0 | 5 pulses |

One `infrastructure.domain` node can be either — the type holds apexes and subdomains alike — so
asking only one endpoint returns an empty result that reads exactly like *OTX knows nothing*. Every
subdomain in a graph would have come back clean.

**The Public Suffix List decides which**, via [`tldts`](https://github.com/remusao/tldts) with
`allowPrivateDomains: true`. Counting labels cannot: all three of `bbc.co.uk` (registrable),
`cdn.jsdelivr.net` (a host), and `user.blogspot.com` (registrable, because `blogspot.com` is itself
a public suffix) have three labels and are not the same kind of name.

A hand-rolled lookup was built first and measured against the PSL project's own 78-case suite
alongside tldts. Size was a wash — 38.7KB gzipped hand-rolled against 46.4KB, and tldts is smaller
before compression. Correctness was not: the hand-rolled version failed 4 cases, **all of them
IDN**, because the list stores 299 rules as Unicode (`公司.cn`) while a graph holds punycode
(`xn--55qx5d.cn`) — closing that means carrying a punycode encoder. It had already failed 10 more
from a data trim that silently dropped the single-label wildcards `*.ck` and `*.mm`. Both bugs
surfaced within an hour of running the official suite, which is the whole argument: tldts already
has that suite and a maintainer. Its own 2 failures are leading-dot inputs (`.example.com`), which
a hostname field does not produce.

The fallback survives, but it is no longer the mechanism — it is the staleness net. When `tldts`
returns no registrable domain at all (a suffix registered after the bundled snapshot was cut), both
endpoints are tried. Otherwise one request, decided.

## Licences

Apache-2.0, and the bundle carries [`tldts`](https://github.com/remusao/tldts) (MIT), which embeds
the Mozilla [Public Suffix List](https://publicsuffix.org/) (MPL-2.0). Both are dependencies
declared in `package.json` and inlined by the build; sources are at their respective projects.

## The filter is the plugin

Without it this is a noise generator. Measured on one ordinary malicious IP, OTX returned 26 pulses:

| | count |
|---|---|
| scratch pulses named `0`, `test`, `Ste`, `ossim`, `web2`, `20220127clone` | 19 |
| a 24,876-indicator bulk feed dump | 1 |
| actual reports | 6 |

A **non-empty description** separated those two groups perfectly — every real report carried 34–607
characters, every scratch pulse carried zero. The cost is stated rather than hidden: a genuine pulse
that is only a name and a list of IOCs is dropped too, and the run reports how many went that way.

The size cap (`max_pulse_indicators`, default 1000) is the second half. A pulse holding thousands of
indicators is a feed, and linking to it builds a hub that every address in that feed joins — which
reads as a discovery and is not one.

## Checks

```
npm run build      # bundle + manifest + selftest
npm run selftest   # runs against the real 26-pulse OTX response in src/fixture-otx.json
```

The fixture is a real response, kept because a hand-written two-pulse fixture would prove the happy
path and none of the behaviour that matters.
