// OTX pack — reads AlienVault OTX "pulses" for an indicator and stages the reports that name it.
//
// A pulse is a community-published threat report with a list of indicators attached. That makes it
// the one thing OTX has that the rest of this platform's collectors do not: an indicator arrives
// here already CONNECTED to a named campaign, the ATT&CK techniques that campaign used, the malware
// families it dropped, and sometimes the actor. Every other keyless source answers "what is this
// address"; this one answers "who has written about it, and what did they say it was part of".
//
// THE API KEY IS OPTIONAL, AND IT BUYS THROUGHPUT RATHER THAN DATA. Two measurements, and running
// them together is how the wrong conclusion gets drawn. The DATA is identical: the same indicator
// returns the same pulses with and without a key — 26 either way, identical top-level keys, one
// byte of difference. The RATE LIMIT is not identical at all: anonymous callers are cut off after a
// handful of requests, and at the same instant an anonymous burst was refused 25 times out of 25
// while keyed requests returned 200. So the pack declares the key OPTIONAL and secret — it works
// without one for a few nodes, and a free key is what lets a large selection finish. A throttled
// lookup is reported as throttled, never as "nothing known".
//
// `/passive_dns` is the one endpoint where a key changes the answer outright (it refuses anonymous
// callers), which is why it is not used here rather than used and quietly failing.
import { definePluginPack } from './sdk';
import { otxPulses } from './pulses';
import { otxPassiveDns } from './passive-dns';

// The pack's page in the marketplace drawer, in Markdown. `summary` is the card's one line and must
// equal the registry entry's. Images are never loaded and links are shown, not followed, so sources
// are named by plain URL.
const PACK_PAGE = [
    'Adds what the AlienVault OTX community has published about an indicator: the threat reports ("pulses") that name it, with their ATT&CK techniques, malware families and adversary, and the passive DNS history that shows what a name resolved to, and when. A bare indicator arrives already connected to a named report.',
    '',
    '## Plugins',
    '',
    '### OTX Pulses',
    '',
    '- **Runs on:** selected IP Address, Domain, URL, File Hash and Vulnerability (CVE) nodes. A File Hash is looked up by its SHA-256, else its SHA-1, else its MD5.',
    "- **Adds:** each usable pulse as a Campaign node (`campaign_name`, `description`, `first_seen` from the pulse's creation date, `attribution`, `otx_pulse_url`, `otx_indicator_count`) linked `reported in` from the indicator. The pulse's ATT&CK techniques become Attack Pattern nodes and its malware families Malware nodes (`malware_type` `unknown`, since OTX gives no classification), both linked `uses`; its adversary becomes a Threat Actor node linked `attributed to`. Within a run, one pulse is one node however many of the selected indicators it names.",
    '- **Parameter:** `max_pulse_indicators` (default 1000).',
    '- **Filter:** OTX returns scratch pulses (named `0`, `test`, `ossim` and the like) and bulk feed dumps alongside real reports. A pulse with an empty description is dropped, and so is a pulse with more than `max_pulse_indicators` indicators, which is a feed rather than a report. A genuine pulse that is only a name and a list of IOCs is dropped too. The run states how many pulses each rule removed.',
    '',
    '### OTX Passive DNS',
    '',
    '- **Runs on:** selected Domain and IP Address nodes.',
    '- **Adds, for a Domain:** the subdomains in its records as Domain nodes (`subdomain`); for each name, the IP Address nodes it resolved to (`resolved to`) and its CNAME targets as Domain nodes (`aliased to`).',
    '- **Adds, for an IP Address:** the Domain nodes observed resolving to it (`resolved to`).',
    '- **Dates:** each edge label carries the first and last observation dates, for example `resolved to (2024-01-02 → 2024-03-04)`, and the edge data keeps `first_seen`, `last_seen` and `record_type`.',
    '- **Parameter:** `max_records` per indicator (default 50). Only A, AAAA and CNAME records are used, newest first, so a capped result is the most recent window rather than the whole history.',
    '- **Notes:** resolver answers such as `NXDOMAIN` that appear in the address field are dropped rather than turned into nodes.',
    '',
    '## Domains and hostnames',
    '',
    'OTX indexes registrable domains (`/domain/`) and hostnames (`/hostname/`) as separate namespaces, and asking the wrong one returns an empty answer that reads like "OTX knows nothing". Both plugins decide which applies from the Public Suffix List, through the bundled `tldts` with private suffixes included. When the list has no registrable domain for a name (a suffix newer than the bundled list), both endpoints are tried.',
    '',
    '## Requirements',
    '',
    '- **A free OTX API key.** Each plugin has an `OTX API key` setting, stored as a per-user secret. Without a key both plugins stop before sending any request: OTX cuts anonymous callers off after a handful of requests, and refuses anonymous passive DNS lookups outright. A key returns the same pulse data as anonymous access; what it changes is the rate limit.',
    '- Runs in the web app and in the desktop app.',
    '- Uses `infrastructure.ip_address`, `infrastructure.domain` and `web.url` (Infrastructure type pack), and `threat.file_hash`, `threat.vulnerability`, `threat.campaign`, `threat.attack_pattern`, `threat.malware` and `threat.threat_actor` (Threat).',
    '',
    '## Cost and limits',
    '',
    'The key is free. A pulse lookup refused by the rate limit (HTTP 429) is reported as rate-limited, never as "nothing known", so the indicators it left unanswered can be run again. An indicator OTX knows with nothing reported against it is reported as a real negative.',
    '',
    '## What it contacts',
    '',
    'Only `https://otx.alienvault.com/api/v1/indicators`. OTX receives each indicator looked up, together with the API key (sent in the `X-OTX-API-KEY` header). The indicators themselves are never contacted.',
    '',
    '## Data and licences',
    '',
    '- Pulses are community-published reports. Each Campaign node keeps the address of its pulse in `otx_pulse_url`, so the claim can be read at its source. This repository does not restate the OTX terms of use.',
    '- The bundle includes tldts and tldts-core (MIT, https://github.com/remusao/tldts), which embed the Public Suffix List (MPL-2.0, https://publicsuffix.org/). Their notices are in `THIRD_PARTY_NOTICES.md` and at the top of `dist/pack.mjs`.',
    '',
    '## Source',
    '',
    'https://github.com/Vineyard-Intelligence/pluginpack-otx (Apache-2.0). `node build.mjs` installs the locked tldts with `npm ci`, then builds `dist/pack.mjs` and the manifest with a pinned esbuild, so the published bundle can be checked against the source and the lockfile.',
].join('\n');

export default definePluginPack({
    identifier: 'run.vineyard.pluginpacks.otx',
    content_type: 'vineyard:pluginpack',
    name: 'AlienVault OTX',
    version: '1.3.0',
    summary:
        'Looks up selected indicators in AlienVault OTX: the threat reports ("pulses") that name them, and passive DNS history. Requires a free OTX API key.',
    description: PACK_PAGE,
    plugins: [otxPulses, otxPassiveDns],
});
