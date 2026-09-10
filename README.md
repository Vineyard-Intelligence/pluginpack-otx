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

## Keyless — measured, not assumed

On 2026-09-10 the same indicator was fetched with and without an OTX API key: **26 pulses either
way, identical top-level keys, one byte of difference.** So this pack declares no config and holds
no secret. The one endpoint where a key does matter (`/passive_dns`) refuses anonymous callers
outright, which is why it is not used here rather than used and quietly failing.

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
