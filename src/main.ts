// OTX pack — reads AlienVault OTX "pulses" for an indicator and stages the reports that name it.
//
// A pulse is a community-published threat report with a list of indicators attached. That makes it
// the one thing OTX has that the rest of this platform's collectors do not: an indicator arrives
// here already CONNECTED to a named campaign, the ATT&CK techniques that campaign used, the malware
// families it dropped, and sometimes the actor. Every other keyless source answers "what is this
// address"; this one answers "who has written about it, and what did they say it was part of".
//
// THE API KEY IS REQUIRED (since 1.1.0), AND WHAT IT BUYS IS A RUN THAT FINISHES. Two measurements,
// and running them together is how the wrong conclusion gets drawn. The DATA is identical: the same
// indicator returns the same pulses with and without a key — 26 either way, identical top-level
// keys, one byte of difference. The RATE LIMIT is not identical at all: anonymous callers are cut
// off after a handful of requests, and at the same instant an anonymous burst was refused 25 times
// out of 25 while keyed requests returned 200. The key was optional first, on the strength of the
// first measurement; "works, then stops after six nodes" is a partial answer with no sign that it is
// partial, so both plugins now ask for the (free) key before they start (pulses.ts says more). A
// throttled lookup is reported as throttled, never as "nothing known".
//
// `/passive_dns` is the one endpoint where a key changes the answer outright (it refuses anonymous
// callers). With the key required anyway, OTX Passive DNS (passive-dns.ts) uses it.
import { definePluginPack } from './sdk';
import { otxPulses } from './pulses';
import { otxPassiveDns } from './passive-dns';

// The pack's page in the marketplace drawer, in Markdown. `summary` is the card's one line and must
// equal the registry entry's. Images are never loaded and links are shown, not followed, so sources
// are named by plain URL.
const PACK_PAGE = [
    'Keyless sources answer what an indicator is; OTX answers who has written about it and what they said it was part of, so a bare indicator arrives tied to a named report. Passive DNS dates each resolution, separating infrastructure a subject still uses from infrastructure abandoned before the events under investigation.',
    '',
    '**Needs:** a free OTX API key. It returns the same pulse data as anonymous access, but OTX cuts anonymous callers off after a handful of requests and refuses anonymous passive DNS outright.',
    '',
    "**Who sees it:** only OTX, which receives each indicator looked up and the analyst's API key. The indicators themselves are never contacted.",
    '',
    '**Read results with care:**',
    "- Pulses are community-published reports; each Campaign keeps its pulse's address in `otx_pulse_url`, so the claim can be read at its source.",
    '- Besides scratch pulses and bulk feed dumps, the filter drops a genuine pulse that is only a name and a list of IOCs; the run states how many each rule removed.',
    '- A lookup refused by the rate limit is reported as rate-limited, never as "nothing known", so it can be run again.',
    '',
    '**Data and licences:** OTX pulses and passive DNS; this repository does not restate the OTX terms of use. The pack includes tldts and tldts-core (MIT, https://github.com/remusao/tldts), which embed the Public Suffix List (MPL-2.0, https://publicsuffix.org/); notices are in `THIRD_PARTY_NOTICES.md`.',
    '',
    '**Source:** https://github.com/Vineyard-Intelligence/pluginpack-otx (Apache-2.0)',
].join('\n');

export default definePluginPack({
    identifier: 'run.vineyard.pluginpacks.otx',
    content_type: 'vineyard:pluginpack',
    name: 'AlienVault OTX',
    version: '1.3.1',
    summary:
        'Looks up selected indicators in AlienVault OTX: the threat reports ("pulses") that name them, and passive DNS history. Requires a free OTX API key.',
    description: PACK_PAGE,
    plugins: [otxPulses, otxPassiveDns],
});
