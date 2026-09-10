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

export default definePluginPack({
    identifier: 'run.vineyard.pluginpacks.otx',
    content_type: 'vineyard:pluginpack',
    name: 'AlienVault OTX',
    version: '1.0.0',
    description:
        'Pulls the OTX threat reports ("pulses") that name a selected IP, domain, URL, file hash or CVE, and stages each as a campaign with the ATT&CK techniques, malware families and actor it records. Runs without an API key; an optional free key removes the anonymous rate limit.',
    plugins: [otxPulses],
});
