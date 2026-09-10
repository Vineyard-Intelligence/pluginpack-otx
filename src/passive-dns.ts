// OTX Passive DNS — what this name resolved to, and when.
//
// THE AXIS NOTHING ELSE HERE COVERS IS THE DATE. Certificate Transparency finds subdomains, Shodan
// resolves a name, Domain Recon reads today's A record — all of them answer "now". Passive DNS
// answers "since when, and until when", which is the question that separates infrastructure the
// subject still uses from infrastructure they abandoned before the events under investigation.
//
// And it runs BACKWARDS, which nothing installed here does keyless: given an IP, every hostname
// observed pointing at it. That is the reverse pivot the pack was missing.
import { definePlugin } from './sdk';
import type { HostContext, RunResult, GraphNode } from './sdk';

const BASE = 'https://otx.alienvault.com/api/v1/indicators';

interface Record_ {
    hostname?: string;
    address?: string;
    record_type?: string;
    first?: string;
    last?: string;
    asn?: string;
}

const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const isIpv4 = (s: string) => IPV4.test(s) && s.split('.').every((o) => Number(o) <= 255);
const isIpv6 = (s: string) => s.includes(':') && /^[0-9a-fA-F:.]+$/.test(s);

/**
 * OTX puts SENTINELS in the address field, and they are the hub this plugin would otherwise build.
 *
 * `NXDOMAIN` appears as an address on 16 of mail.ru's AAAA records — it is the resolver's answer,
 * not a host. Left in, every domain whose lookup ever failed converges on one node called NXDOMAIN,
 * which is a false cluster with as many edges as the graph has domains, and it does not look like a
 * bug: it looks like a discovery. Same for the empty and null forms.
 */
const SENTINEL = new Set(['NXDOMAIN', 'SERVFAIL', 'REFUSED', 'NOERROR', 'N/A', '-', '']);

const dom = (n: GraphNode) => String((n.data as Record<string, unknown>)?.domain_name ?? '').trim();
const ipv = (n: GraphNode) => String((n.data as Record<string, unknown>)?.ip_address ?? '').trim();

export const otxPassiveDns = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.otx_passive_dns',
        content_type: 'vineyard:plugin',
        name: 'OTX Passive DNS',
        version: '1.0.0',
        description:
            "Reads OTX's passively-observed DNS history for each selected domain or IP: which addresses a name resolved to and when, and — running backwards from an IP — every hostname seen pointing at it. The dates are the point: they separate infrastructure a subject still uses from infrastructure they had already abandoned. Needs a free OTX API key.",
        icon: 'history',
        author: { name: 'VINEYARD', url: 'https://vineyard.run' },
        license: 'Apache-2.0',
        platforms: {
            primary: 'web',
            web: { runtime: 'sandbox-js', entry: 'inline' },
            desktop: { runtime: 'sandbox-js', entry: 'inline', min_app_version: '0.1.0' },
        },
        io: {
            consumes: [
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'domain' },
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'ip_address' },
            ],
            produces: [
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'ip_address' },
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'domain' },
            ],
        },
        params: {
            type: 'object',
            properties: {
                max_records: {
                    type: 'integer',
                    title: 'Records to take per indicator',
                    default: 50,
                    minimum: 1,
                    description:
                        'OTX returns hundreds — mail.ru has 556, 8.8.8.8 has 500 hostnames that mostly belong to strangers who misconfigured their DNS. Taking them all makes a hub rather than a finding. The newest are kept, and the run says how many it left behind.',
                },
            },
        },
        scopes: {
            graph: ['node:read', 'node:create', 'edge:create'],
            config: [
                { key: 'api_key', label: 'OTX API key', type: 'string', secret: true, scope: 'user', optional: false },
            ],
            network: [
                {
                    endpoint: 'https://otx.alienvault.com/api/v1/indicators',
                    methods: ['GET'],
                    purpose: "Read an indicator's passively-observed DNS history.",
                },
            ],
        },
        lifecycle: { persistence: 'opt-in', controls: ['progress', 'cancel'], progress: 'determinate' },
    },

    async run(ctx: HostContext): Promise<RunResult> {
        if (!ctx.net?.fetch) return { summary: 'Network capability not granted to this plugin', counts: { records: 0 } };
        const ids = ctx.input.selection;
        if (!ids.length) return { summary: 'Select a domain or IP node first', counts: { records: 0 } };

        const apiKey = String(ctx.config?.api_key ?? '').trim();
        if (!apiKey)
            return {
                summary:
                    'This plugin needs a free AlienVault OTX API key. Anonymous callers are refused on this endpoint outright — it is not rate-limited, it is closed. Sign in at otx.alienvault.com and paste the key from your profile settings.',
                counts: { records: 0 },
            };
        const headers = { 'X-OTX-API-KEY': apiKey };
        const maxRecords = Number(ctx.params?.max_records ?? 50) || 50;

        let looked = 0;
        let empty = 0;
        let created = 0;
        let dropped = 0; // sentinels and unparseable addresses
        let truncated = 0;
        let failed = 0;
        let skipped = 0;
        const ipNode = new Map<string, string>();
        const domNode = new Map<string, string>();

        const reuse = async (cache: Map<string, string>, key: string, make: () => Promise<GraphNode>) => {
            const hit = cache.get(key);
            if (hit) return hit;
            const n = await make();
            cache.set(key, String(n.id));
            created++;
            return String(n.id);
        };

        for (let i = 0; i < ids.length; i++) {
            if (ctx.signal?.aborted) break;
            const node = await ctx.graph!.get!(ids[i]);
            if (!node) {
                skipped++;
                continue;
            }
            const isDomain = node.type === 'infrastructure.domain';
            const seedValue = isDomain ? dom(node) : node.type === 'infrastructure.ip_address' ? ipv(node) : '';
            if (!seedValue) {
                skipped++;
                continue;
            }
            // A domain node holds apexes and subdomains alike, and OTX indexes those separately —
            // the same split the pulses plugin hit. Three labels or more is tried as a hostname
            // first, and an empty answer falls back.
            const paths = isDomain
                ? seedValue.split('.').filter(Boolean).length >= 3
                    ? [`hostname/${encodeURIComponent(seedValue)}`, `domain/${encodeURIComponent(seedValue)}`]
                    : [`domain/${encodeURIComponent(seedValue)}`]
                : [`${seedValue.includes(':') ? 'IPv6' : 'IPv4'}/${encodeURIComponent(seedValue)}`];

            ctx.progress?.set?.({
                percent: Math.round(((i + 1) / ids.length) * 100),
                message: `Passive DNS: ${seedValue} (${i + 1}/${ids.length})`,
            });

            let records: Record_[] = [];
            let broke = false;
            for (const path of paths) {
                if (ctx.signal?.aborted) break;
                try {
                    const res = await ctx.net.fetch(`${BASE}/${path}/passive_dns`, { method: 'GET', headers });
                    if (res.status === 404) continue;
                    if (!res.ok) {
                        broke = true;
                        break;
                    }
                    const doc = (await res.json()) as { passive_dns?: Record_[] };
                    const got = doc?.passive_dns ?? [];
                    if (got.length) {
                        records = got;
                        break;
                    }
                } catch {
                    broke = true;
                    break;
                }
            }
            if (broke) {
                failed++;
                continue;
            }
            looked++;
            if (!records.length) {
                empty++;
                continue;
            }

            // Newest first, then capped: when a cap has to throw something away, the records worth
            // keeping are the ones closest to the events being investigated.
            const usable = records
                .filter((r) => {
                    const t = String(r.record_type ?? '').toUpperCase();
                    return t === 'A' || t === 'AAAA' || t === 'CNAME';
                })
                .sort((a, b) => String(b.last ?? '').localeCompare(String(a.last ?? '')));
            const take = usable.slice(0, maxRecords);
            if (usable.length > take.length) truncated += usable.length - take.length;

            for (const r of take) {
                const addr = String(r.address ?? '').trim();
                const host = String(r.hostname ?? '').trim();
                const type = String(r.record_type ?? '').toUpperCase();
                if (!addr || !host) {
                    dropped++;
                    continue;
                }

                // WHICH FIELD IS THE NEW THING DEPENDS ON WHICH WAY THE QUERY RAN, and getting this
                // backwards does not look like a bug. A record is always (hostname → address). Ask
                // OTX about a DOMAIN and `hostname` is the seed or one of its subdomains while
                // `address` is the discovery; ask about an IP and `address` IS THE SEED, repeated on
                // every one of the 500 rows, while `hostname` is the discovery. Building the node
                // from `address` in both cases created a duplicate of the seed IP and drew an edge
                // from it to the seed — a self-link wearing a pivot's clothes, which the fixture
                // could not catch because a domain-shaped response was standing in for an
                // IP-shaped one.
                let fromId: string;
                let toId: string;

                if (isDomain) {
                    // The record belongs to its OWN hostname, often a subdomain of the seed rather
                    // than the seed. Hanging it on the apex loses which name actually resolved.
                    if (SENTINEL.has(addr.toUpperCase())) {
                        dropped++;
                        continue;
                    }
                    fromId = ids[i];
                    if (host.toLowerCase() !== seedValue.toLowerCase()) {
                        fromId = await reuse(domNode, host.toLowerCase(), () =>
                            ctx.graph!.createNode!({ type: 'infrastructure.domain', data: { domain_name: host } }),
                        );
                        await ctx.graph!.createEdge!({ from: ids[i], to: fromId, label: 'subdomain' });
                    }
                    if (type === 'CNAME') {
                        if (isIpv4(addr) || isIpv6(addr)) {
                            dropped++;
                            continue;
                        }
                        toId = await reuse(domNode, addr.toLowerCase(), () =>
                            ctx.graph!.createNode!({ type: 'infrastructure.domain', data: { domain_name: addr } }),
                        );
                    } else {
                        if (!isIpv4(addr) && !isIpv6(addr)) {
                            dropped++;
                            continue;
                        }
                        toId = await reuse(ipNode, addr.toLowerCase(), () =>
                            ctx.graph!.createNode!({
                                type: 'infrastructure.ip_address',
                                data: { ip_address: addr, version: isIpv6(addr) ? 'ipv6' : 'ipv4' },
                            }),
                        );
                    }
                } else {
                    // Reverse: the hostname is what was found, and it pointed at the seed.
                    if (SENTINEL.has(host.toUpperCase()) || isIpv4(host) || isIpv6(host)) {
                        dropped++;
                        continue;
                    }
                    fromId = await reuse(domNode, host.toLowerCase(), () =>
                        ctx.graph!.createNode!({ type: 'infrastructure.domain', data: { domain_name: host } }),
                    );
                    toId = ids[i];
                }

                const [from, to] = [fromId, toId];
                const window =
                    r.first && r.last && r.first.slice(0, 10) !== r.last.slice(0, 10)
                        ? `${r.first.slice(0, 10)} → ${r.last.slice(0, 10)}`
                        : String(r.last ?? r.first ?? '').slice(0, 10);
                await ctx.graph!.createEdge!({
                    from,
                    to,
                    // The dates are IN the label, not only in data: this edge's whole value over the
                    // "resolves to" one another plugin draws is WHEN, and a reader looking at the
                    // canvas sees labels.
                    label: window ? `${type === 'CNAME' ? 'aliased to' : 'resolved to'} (${window})` : type === 'CNAME' ? 'aliased to' : 'resolved to',
                    data: { source: 'otx_passive_dns', record_type: type, ...(r.first ? { first_seen: r.first } : {}), ...(r.last ? { last_seen: r.last } : {}) },
                });
            }
        }

        const parts: string[] = [
            created
                ? `${created} node(s) from ${looked} indicator(s)`
                : looked
                ? `No usable DNS history for any of ${looked} indicator(s)`
                : 'No indicator was successfully looked up',
        ];
        if (truncated)
            parts.push(
                `${truncated} record(s) beyond the ${maxRecords}-record cap were not taken — the newest were kept, so this is a window, not the whole history`,
            );
        if (dropped) parts.push(`${dropped} record(s) held a resolver sentinel (NXDOMAIN and the like) rather than an address`);
        if (empty) parts.push(`${empty} indicator(s) have no passive DNS in OTX — a real negative, not a failed lookup`);
        if (skipped) parts.push(`${skipped} selected node(s) were not a domain or IP`);
        if (failed) parts.push(`${failed} lookup(s) failed`);
        return {
            summary: parts.join('. ') + '.',
            counts: { created, indicators: looked, truncated, sentinels: dropped, empty, failed },
        };
    },
});
