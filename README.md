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

## The API key is optional, and it buys throughput — not data

Two separate measurements, and conflating them is easy:

- **Data: identical.** The same indicator returns the same pulses with and without a key — 26 either
  way, identical top-level keys, one byte of difference in the response. A key reveals nothing extra.
- **Rate limit: not identical at all.** Anonymous callers are cut off after a handful of requests
  (HTTP 429, no `Retry-After`, no rate headers). Measured at the same instant: an anonymous burst was
  refused **25 out of 25** while keyed requests returned 200, and a keyed burst of 20 ran clean.

So the plugin works with no key for a few nodes at a time, and a free OTX key is what lets a
selection of any size finish. A throttled lookup is reported as **throttled** — never as "nothing
known", which would turn a rate limit into a false negative on every remaining node.

`/passive_dns` is the one endpoint where a key changes the answer outright (it refuses anonymous
callers), which is why it is not used here rather than used and quietly failing.

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

Label count picks which to try first; the fallback is what makes it correct rather than
usually-right. `bbc.co.uk` has three labels and is an apex, and no label count tells it from
`cdn.jsdelivr.net` without the public suffix list — so a three-label name that comes back empty on
`/hostname/` is retried on `/domain/`. A two-label name is never a subdomain and needs no second
request.

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
