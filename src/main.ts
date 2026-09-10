// OTX pack — reads AlienVault OTX "pulses" for an indicator and stages the reports that name it.
//
// A pulse is a community-published threat report with a list of indicators attached. That makes it
// the one thing OTX has that the rest of this platform's collectors do not: an indicator arrives
// here already CONNECTED to a named campaign, the ATT&CK techniques that campaign used, the malware
// families it dropped, and sometimes the actor. Every other keyless source answers "what is this
// address"; this one answers "who has written about it, and what did they say it was part of".
//
// IT IS KEYLESS, AND THAT WAS MEASURED RATHER THAN ASSUMED. On 2026-09-10 the same indicator was
// fetched with and without an OTX API key: 26 pulses either way, identical top-level keys, one byte
// of difference in the response. So this pack declares no config and holds no secret. The key that
// exists for OTX buys nothing on `/general`, and the one endpoint where it does matter
// (`/passive_dns`) refuses anonymous callers outright — which is why that endpoint is not used here
// rather than being used and quietly failing.
import { definePluginPack } from './sdk';
import { otxPulses } from './pulses';

export default definePluginPack({
    identifier: 'run.vineyard.pluginpacks.otx',
    content_type: 'vineyard:pluginpack',
    name: 'AlienVault OTX',
    version: '1.0.0',
    description:
        'Pulls the OTX threat reports ("pulses") that name a selected IP, domain, URL, file hash or CVE, and stages each as a campaign with the ATT&CK techniques, malware families and actor it records. Keyless, no server.',
    plugins: [otxPulses],
});
