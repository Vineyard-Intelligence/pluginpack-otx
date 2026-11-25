// OTX Pulses — indicator → the reports that name it.
import { definePlugin } from './sdk';
import type { HostContext, RunResult, GraphNode, SafeResponse } from './sdk';
import { domainPaths } from './indicator-type';

const BASE = 'https://otx.alienvault.com/api/v1/indicators';

/**
 * Which OTX indicator endpoint a graph node maps to, and the value to look up.
 *
 * `null` for a node type OTX has no endpoint for, which is how the run counts what it passed over
 * rather than silently returning nothing for a selection the analyst thought was covered.
 */
function target(n: GraphNode): { paths: string[]; label: string } | null {
    const d = (n.data ?? {}) as Record<string, unknown>;
    const s = (k: string) => (typeof d[k] === 'string' ? (d[k] as string).trim() : '');
    switch (n.type) {
        case 'infrastructure.ip_address': {
            const ip = s('ip_address');
            if (!ip) return null;
            return { paths: [`${ip.includes(':') ? 'IPv6' : 'IPv4'}/${encodeURIComponent(ip)}`], label: ip };
        }
        case 'infrastructure.domain': {
            const d2 = s('domain_name');
            return d2 ? { paths: domainPaths(d2), label: d2 } : null;
        }
        case 'web.url': {
            const u = s('url');
            return u ? { paths: [`url/${encodeURIComponent(u)}`], label: u } : null;
        }
        case 'threat.vulnerability': {
            const cve = s('cve_id');
            return cve ? { paths: [`cve/${encodeURIComponent(cve)}`], label: cve } : null;
        }
        case 'threat.file_hash': {
            // OTX resolves any of the three under one `file` endpoint; prefer the strongest present.
            const h = s('sha256') || s('sha1') || s('md5');
            return h ? { paths: [`file/${encodeURIComponent(h)}`], label: h } : null;
        }
        default:
            return null;
    }
}

interface Pulse {
    id?: string;
    name?: string;
    description?: string;
    created?: string;
    modified?: string;
    adversary?: string;
    indicator_count?: number;
    attack_ids?: Array<{ id?: string; name?: string; display_name?: string }>;
    malware_families?: Array<{ id?: string; display_name?: string } | string>;
    tags?: string[];
}

/**
 * THE FILTER IS THE PLUGIN. Without it this is a noise generator.
 *
 * Measured on one ordinary malicious IP (45.155.205.233, 2026-09-10), OTX returned 26 pulses. Eleven
 * were named "0", "test", "Ste", "web2", "ossim" or "20220127clone" — somebody's scratch pulse, with
 * no indicators in them at all. One held 24,876 indicators: a bulk feed dump, not a report. Staging
 * all 26 would put eleven nodes named "0" and "test" on the canvas and wire this address into a
 * 24,876-member hub that every other address in that feed also joins. That hub is the damaging half:
 * it does not look like noise, it looks like a discovery.
 *
 * A NON-EMPTY DESCRIPTION is the discriminator, and it is not a guess — it separated the two groups
 * perfectly in that sample. Every pulse a human would call a report carried 34 to 607 characters of
 * description; every scratch pulse carried zero. The cost is honest and stated: a real pulse that is
 * nothing but a name and a list of IOCs ("Log4Shell IPv4 IOC", 11 indicators, no description) is
 * dropped too, because nothing in its metadata distinguishes it from "Ste". The run reports how many
 * went that way instead of hiding the trade.
 */
const MIN_DESCRIPTION = 1;

function usable(p: Pulse, maxIndicators: number): 'ok' | 'no_description' | 'too_broad' {
    if ((p.description ?? '').trim().length < MIN_DESCRIPTION) return 'no_description';
    if ((p.indicator_count ?? 0) > maxIndicators) return 'too_broad';
    return 'ok';
}

/** Refusals already logged in this run, so a budget refusal over a long selection is one line. */
const keepNoted = new WeakMap<HostContext, Set<string>>();

/**
 * Keep a call's raw answer on the node it describes (plugin raw results, spec §5). Every call site
 * goes through here, for three reasons:
 *   - desktop builds before ctx.retain have none, and a bare call there is a TypeError that would
 *     fail a run that otherwise works, so the check is `typeof`, not truthiness;
 *   - only status, response headers and body are handed over, built afresh: nothing about the
 *     request (the URL with the indicator in it, the X-OTX-API-KEY header) can ride along on a
 *     response object the host would have to trust;
 *   - a refusal (over budget, a config value seen in the body) or a throw costs the raw copy, never
 *     the run: the mapped nodes are already staged and are what the analyst ran this for.
 */
async function keep(ctx: HostContext, nodeId: string, op: string, res: SafeResponse): Promise<void> {
    if (typeof ctx.retain !== 'function' || !(res.status > 0)) return;
    let reason = '';
    try {
        // The response's own text, not a re-serialised parse, so the host hashes the bytes OTX sent.
        const body = await res.text();
        const out = await ctx.retain(nodeId, op, { status: res.status, headers: { ...(res.headers ?? {}) }, body });
        if (out && out.kept === false) reason = typeof out.reason === 'string' && out.reason ? out.reason : 'refused';
    } catch {
        reason = 'the host could not keep it';
    }
    if (!reason) return;
    let noted = keepNoted.get(ctx);
    if (!noted) keepNoted.set(ctx, (noted = new Set()));
    if (noted.has(`${op}\0${reason}`)) return;
    noted.add(`${op}\0${reason}`);
    ctx.progress?.log?.(`Raw ${op} result not kept — ${reason}`);
}

const familyName = (m: { id?: string; display_name?: string } | string): string =>
    typeof m === 'string' ? m.trim() : String(m.display_name ?? m.id ?? '').trim();

export const otxPulses = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.otx_pulses',
        content_type: 'vineyard:plugin',
        name: 'OTX Pulses',
        version: '1.1.3',
        description:
            'Fetches the AlienVault OTX pulses that name each selected IP Address, Domain, URL, File Hash or Vulnerability (CVE) and adds each as a Campaign node linked by "reported in"; its ATT&CK techniques and malware families become Attack Pattern and Malware nodes ("uses"), its adversary a Threat Actor ("attributed to"). Skips pulses without a description or with more than max_pulse_indicators (default 1000) indicators. Requires a free OTX API key.',
        icon: 'radar',
        author: { name: 'VINEYARD', url: 'https://vineyard.run' },
        license: 'Apache-2.0',
        platforms: {
            primary: 'web',
            web: { runtime: 'sandbox-js', entry: 'dist/pack.mjs' },
            desktop: { runtime: 'sandbox-js', entry: 'dist/pack.mjs' },
        },
        io: {
            consumes: [
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'ip_address' },
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'domain' },
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'web', name: 'url' },
                { typepack: 'run.vineyard.typepacks.threat', category: 'threat', name: 'file_hash' },
                { typepack: 'run.vineyard.typepacks.threat', category: 'threat', name: 'vulnerability' },
            ],
            produces: [
                { typepack: 'run.vineyard.typepacks.threat', category: 'threat', name: 'campaign' },
                { typepack: 'run.vineyard.typepacks.threat', category: 'threat', name: 'attack_pattern' },
                { typepack: 'run.vineyard.typepacks.threat', category: 'threat', name: 'malware' },
                { typepack: 'run.vineyard.typepacks.threat', category: 'threat', name: 'threat_actor' },
            ],
        },
        params: {
            type: 'object',
            properties: {
                max_pulse_indicators: {
                    type: 'integer',
                    title: 'Max indicators per pulse',
                    default: 1000,
                    minimum: 1,
                    description: 'Pulses with more indicators than this are skipped. Default 1000.',
                },
            },
        },
        scopes: {
            graph: ['node:read', 'node:create', 'edge:create'],
            // Optional, and it is about throughput rather than access. Anonymous callers get the
            // same pulses and then get cut off; a free key removes the throttle.
            config: [
                {
                    key: 'api_key',
                    label: 'OTX API key',
                    type: 'string',
                    secret: true,
                    scope: 'user',
                    optional: false,
                },
            ],
            network: [
                {
                    endpoint: 'https://otx.alienvault.com/api/v1/indicators',
                    methods: ['GET'],
                    purpose: 'Fetch the OTX pulses that reference each selected indicator.',
                },
            ],
        },
        lifecycle: { persistence: 'opt-in', controls: ['progress', 'cancel'], progress: 'determinate' },
    },

    async run(ctx: HostContext): Promise<RunResult> {
        if (!ctx.net?.fetch) return { summary: 'Network capability not granted to this plugin', counts: { campaigns: 0 } };
        const ids = ctx.input.selection;
        if (!ids.length)
            return { summary: 'Select an IP, domain, URL, file hash or CVE node first', counts: { campaigns: 0 } };

        const maxIndicators = Number(ctx.params?.max_pulse_indicators ?? 1000) || 1000;

        // REQUIRED, AND THE REASON IS THE RATE LIMIT RATHER THAN THE DATA. Measured 2026-09-10: the
        // same indicator returns the same pulses with and without a key, so a key reveals nothing
        // extra. What it buys is a run that finishes — anonymous callers are cut off after a handful
        // of requests (HTTP 429, no Retry-After, no rate headers), and at the same instant an
        // anonymous burst was refused 25 times out of 25 while a keyed burst of 20 ran clean.
        //
        // It was optional first, on the grounds that the data is identical. That reading was right
        // about the response and wrong about the product: "works, then stops after six nodes" is not
        // a working plugin, it is one that produces a partial answer and no signal that the answer
        // is partial. A key is free and takes a minute; being told so up front beats discovering it
        // as a half-collected graph.
        const apiKey = String(ctx.config?.api_key ?? '').trim();
        if (!apiKey)
            return {
                summary:
                    'This plugin needs a free AlienVault OTX API key. Without one OTX cuts the run off after a few indicators, which produces a partly-collected graph that looks complete. Sign in at otx.alienvault.com, copy the key from your profile settings, and paste it into this plugin’s settings.',
                counts: { campaigns: 0 },
            };
        const headers = { 'X-OTX-API-KEY': apiKey };

        let looked = 0;
        let clean = 0; // OTX knows the indicator and has nothing on it
        let campaigns = 0;
        let noDescription = 0;
        let tooBroad = 0;
        let unsupported = 0;
        let failed = 0;
        let limited = 0;
        const named: string[] = [];
        // Within one run, one pulse becomes one node however many seeds it covers — which is the
        // point: two addresses in the same report converge on it.
        const pulseNode = new Map<string, string>();
        const actorNode = new Map<string, string>();
        const techNode = new Map<string, string>();
        const malwareNode = new Map<string, string>();

        const reuse = async (
            cache: Map<string, string>,
            key: string,
            make: () => Promise<GraphNode>,
        ): Promise<string> => {
            const hit = cache.get(key);
            if (hit) return hit;
            const node = await make();
            cache.set(key, String(node.id));
            return String(node.id);
        };

        for (let i = 0; i < ids.length; i++) {
            if (ctx.signal?.aborted) break;
            const node = await ctx.graph!.get!(ids[i]);
            const t = node ? target(node) : null;
            if (!t) {
                unsupported++;
                continue;
            }
            ctx.progress?.set?.({
                percent: Math.round(((i + 1) / ids.length) * 100),
                message: `OTX: ${t.label} (${i + 1}/${ids.length})`,
            });

            // Walk the candidate endpoints in order and stop at the first that ACTUALLY ANSWERS.
            // For everything but a domain there is one, so this is a single request; for a domain
            // the second is paid only when the first came back empty, which is exactly when there
            // is still no answer.
            let pulses: Pulse[] = [];
            let broke = false;
            let throttled = false;
            // The one response kept for this indicator, whole as OTX sent it: the 200 that lists at
            // least one pulse. Only one endpoint can be it, since the walk stops there.
            let answer: SafeResponse | null = null;
            for (const path of t.paths) {
                if (ctx.signal?.aborted) break;
                try {
                    const res = await ctx.net.fetch(`${BASE}/${path}/general`, { method: 'GET', headers });
                    // 404 is a real answer — OTX has never seen this indicator under this type —
                    // and counts as a clean lookup, but it is not kept (see below).
                    if (res.status === 404) continue;
                    // 429 is the anonymous rate limit, and it is NOT an empty result. Counting it as
                    // "nothing known" would turn a throttle into a false negative on every remaining
                    // node of the selection, which is the exact shape this plugin exists to avoid.
                    // Its own outcome, and NOT also a failure: counting it both ways put one
                    // refused lookup on two lines of the summary, which reads as two problems.
                    if (res.status === 429) {
                        throttled = true;
                        break;
                    }
                    if (!res.ok) {
                        broke = true;
                        break;
                    }
                    const doc = (await res.json()) as { pulse_info?: { count?: number; pulses?: Pulse[] } };
                    const got = doc?.pulse_info?.pulses ?? [];
                    if (Array.isArray(got) && got.length) {
                        pulses = got;
                        answer = res;
                        break;
                    }
                } catch {
                    broke = true;
                    break;
                }
            }
            if (throttled) {
                limited++;
                continue;
            }
            if (broke) {
                failed++;
                continue;
            }
            // Kept on the indicator only, op "pulses" (analyst's decision, 2026-11-25). The pulse
            // list in this answer is what each Campaign below was made from, but a Campaign gets no
            // copy of its own entry: a slice cut out of this response is no longer the answer OTX
            // gave, and the "reported in" edge already says where the Campaign came from (spec
            // §5-3). Kept whole, the answer also still holds the pulses the filter below drops,
            // which no node carries.
            //
            // Only an answer with at least one pulse is kept. A 404 and a 200 with
            // pulse_info.count 0 were kept until 1.5.0 as "OTX has nothing on this", but they add
            // nothing to the node: the analyst opened an empty review entry and a stored copy that
            // said nothing (analyst's decision, 2026-11-25, reversing the earlier one). The run's
            // summary still counts them as clean. A throttled or failed lookup above keeps nothing
            // either: it says something about the account, not about the indicator.
            if (answer) await keep(ctx, ids[i], 'pulses', answer);
            looked++;
            if (!pulses.length) {
                clean++;
                continue;
            }

            for (const p of pulses) {
                // Collapsed, because a pulse name is free text and really does contain newlines —
                // "VirusTotal report\n                    for file.exe" is a live one. The name is
                // the node's label AND its identity, so a raw newline both breaks the label and
                // splits one report into two nodes when another pulse wraps it differently.
                const name = String(p.name ?? '')
                    .replace(/\s+/g, ' ')
                    .trim();
                if (!name) continue;
                const verdict = usable(p, maxIndicators);
                if (verdict === 'no_description') {
                    noDescription++;
                    continue;
                }
                if (verdict === 'too_broad') {
                    tooBroad++;
                    continue;
                }

                const adversary = String(p.adversary ?? '').trim();
                const campaignId = await reuse(pulseNode, name.toLowerCase(), () =>
                    ctx.graph!.createNode!({
                        type: 'threat.campaign',
                        data: {
                            campaign_name: name,
                            description: String(p.description ?? '').trim(),
                            ...(p.created ? { first_seen: p.created } : {}),
                            ...(adversary ? { attribution: adversary } : {}),
                            // Undeclared, deliberately: the pulse page is the source somebody can
                            // open, and a report node nobody can trace back to its text is a claim
                            // with no address. Same pattern as Wayback's wayback_timestamp.
                            ...(p.id ? { otx_pulse_url: `https://otx.alienvault.com/pulse/${p.id}` } : {}),
                            ...(typeof p.indicator_count === 'number' ? { otx_indicator_count: p.indicator_count } : {}),
                        },
                    }),
                );
                if (named.length < 4 && !named.includes(name)) named.push(name);
                if (pulseNode.size > campaigns) campaigns = pulseNode.size;

                await ctx.graph!.createEdge!({
                    from: ids[i],
                    to: campaignId,
                    label: 'reported in',
                    data: { source: 'otx', pulse_id: p.id ?? '' },
                });

                if (adversary) {
                    const actorId = await reuse(actorNode, adversary.toLowerCase(), () =>
                        ctx.graph!.createNode!({ type: 'threat.threat_actor', data: { actor_name: adversary } }),
                    );
                    await ctx.graph!.createEdge!({ from: campaignId, to: actorId, label: 'attributed to' });
                }

                for (const a of p.attack_ids ?? []) {
                    const tech = String(a.id ?? '').trim();
                    const techName = String(a.name ?? a.display_name ?? tech).trim();
                    if (!tech) continue;
                    const techId = await reuse(techNode, tech.toUpperCase(), () =>
                        ctx.graph!.createNode!({
                            type: 'threat.attack_pattern',
                            data: { name: techName || tech, technique_id: tech },
                        }),
                    );
                    await ctx.graph!.createEdge!({ from: campaignId, to: techId, label: 'uses' });
                }

                for (const m of p.malware_families ?? []) {
                    const fam = familyName(m);
                    if (!fam) continue;
                    const mwId = await reuse(malwareNode, fam.toLowerCase(), () =>
                        // malware_type is required by the typepack and OTX gives no classification,
                        // so 'unknown' rather than a guess from the family name.
                        ctx.graph!.createNode!({
                            type: 'threat.malware',
                            data: { name: fam, malware_type: 'unknown', is_family: true },
                        }),
                    );
                    await ctx.graph!.createEdge!({ from: campaignId, to: mwId, label: 'uses' });
                }
            }
        }

        campaigns = pulseNode.size;
        const parts: string[] = [
            campaigns
                ? `${campaigns} report(s) from ${looked} indicator(s)${named.length ? ` — ${named.join('; ')}` : ''}`
                : looked
                ? `No usable report for any of ${looked} indicator(s)`
                : 'No indicator was successfully looked up',
        ];
        if (techNode.size || malwareNode.size || actorNode.size)
            parts.push(
                `${techNode.size} ATT&CK technique(s), ${malwareNode.size} malware family(ies), ${actorNode.size} actor(s)`,
            );
        // Both of these are stated even when the headline is good. A run that dropped 19 pulses and
        // does not say so has reported a filtered view as the whole answer.
        if (noDescription) parts.push(`${noDescription} pulse(s) skipped as scratch entries (no description)`);
        if (tooBroad) parts.push(`${tooBroad} skipped as feed dumps (over ${maxIndicators} indicators)`);
        if (clean) parts.push(`${clean} indicator(s) are in OTX with nothing reported against them — a real negative, not a failed lookup`);
        if (unsupported) parts.push(`${unsupported} selected node(s) are a type OTX has no lookup for`);
        if (limited)
            parts.push(
                `${limited} lookup(s) were REFUSED BY THE RATE LIMIT, not answered — those indicators are unknown, not clean. ` +
                    'Wait and re-run the remaining nodes.',
            );
        if (failed) parts.push(`${failed} lookup(s) failed`);
        return {
            summary: parts.join('. ') + '.',
            counts: {
                campaigns,
                techniques: techNode.size,
                malware: malwareNode.size,
                actors: actorNode.size,
                clean,
                skipped_no_description: noDescription,
                skipped_too_broad: tooBroad,
                rate_limited: limited,
                failed,
            },
        };
    },
});
