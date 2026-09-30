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

A key returns the same data as anonymous access. What it changes is the rate limit: anonymous callers
are cut off after a handful of requests (HTTP 429), which leaves a partially collected graph, and
`/passive_dns` refuses anonymous callers outright. A key is free and takes a minute.

A throttled lookup is still reported as **throttled** — never as "nothing known".

## Passive DNS: the dates, and the reverse direction

Passive DNS answers *since when, and until when* — what separates infrastructure a subject still uses
from infrastructure they had abandoned before the events under investigation. The dates go on the
edge label.

Given an IP it runs backwards: every hostname observed pointing at that address.

Resolver answers such as `NXDOMAIN` that appear in the address field are dropped rather than turned
into a domain node.

## `domain` and `hostname` are different namespaces in OTX

| | `/domain/` | `/hostname/` |
|---|---|---|
| `mail.ru` | 50 pulses | 0 |
| `cdn.jsdelivr.net` | 0 | 50 pulses |
| `bbc.co.uk` | 23 pulses | 0 |
| `news.bbc.co.uk` | 0 | 5 pulses |

One `infrastructure.domain` node can be either, and asking the wrong endpoint returns an empty result
that reads exactly like *OTX knows nothing*. **The Public Suffix List decides which**, via
[`tldts`](https://github.com/remusao/tldts) with `allowPrivateDomains: true`. When `tldts` returns no
registrable domain (a suffix newer than the bundled list), both endpoints are tried.

## Licences

Apache-2.0, and the bundle carries [`tldts`](https://github.com/remusao/tldts) (MIT), which embeds
the Mozilla [Public Suffix List](https://publicsuffix.org/) (MPL-2.0). Both are dependencies
declared in `package.json` and inlined by the build; sources are at their respective projects.

## The filter is the plugin

OTX returns scratch pulses (named `0`, `test`, `ossim`, …) and bulk feed dumps alongside real
reports. A pulse with an **empty description** is dropped. A genuine pulse that is only a name and a
list of IOCs is dropped too, and the run reports how many went that way.

The size cap (`max_pulse_indicators`, default 1000) is the second half. A pulse holding thousands of
indicators is a feed, and linking to it builds a hub that reads as a discovery and is not one.

## Checks

```
npm run build      # bundle + manifest + selftest
npm run selftest   # runs against the real 26-pulse OTX response in src/fixture-otx.json
```
