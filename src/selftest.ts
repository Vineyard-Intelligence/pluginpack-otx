// Self-check for the OTX pulses plugin. Run: npm run selftest
//
// The fixture is the REAL OTX response for 45.155.205.233 (2026-09-10), trimmed to the fields this
// plugin reads. Twenty-six pulses, of which nineteen are somebody's scratch entry ("0", "test",
// "Ste", "ossim", "20220127clone") and one is a 24,876-indicator feed dump. That distribution is
// not an unlucky sample — it is what an ordinary malicious IP looks like in OTX, and it is the
// entire reason this plugin has a filter. Testing against a hand-written two-pulse fixture would
// have proved the happy path and none of the behaviour that matters.
import { createMockContext, type MockContext } from './sdk';
import { otxPulses } from './pulses';
import { otxPassiveDns } from './passive-dns';
import FIXTURE from './fixture-otx.json';
import PDNS from './fixture-pdns.json';
import PDNS_IP from './fixture-pdns-ip.json';

declare const process: { exit(code: number): never };

const fail: string[] = [];
const check = (cond: unknown, msg: string) => {
    if (!cond) fail.push(msg);
};

const GRANTS = {
    graph: ['node:read', 'node:create', 'edge:create'],
    network: [{ endpoint: 'https://otx.alienvault.com/api/v1/indicators' }],
} as const;

interface Call {
    url: string;
    headers: Record<string, string>;
}

async function run(
    nodes: Array<{ id: string; type: string; data: Record<string, unknown> }>,
    opts: { params?: Record<string, unknown>; body?: (url: string) => { status: number; body: string } } = {},
) {
    const calls: Call[] = [];
    const ctx = createMockContext({
        selection: nodes.map((n) => n.id),
        nodes,
        grantedScopes: GRANTS as never,
        params: opts.params,
        config: { api_key: 'k' },
        netHandler: async (url: string, init?: { headers?: Record<string, string> }) => {
            calls.push({ url, headers: init?.headers ?? {} });
            const r = opts.body ? opts.body(url) : { status: 200, body: JSON.stringify(FIXTURE) };
            return { ...r, headers: { 'content-type': 'application/json' } } as never;
        },
    }) as MockContext;
    const result = await otxPulses.run(ctx);
    return { result, ctx, calls };
}

async function runConfig(config: Record<string, string>, nodes: Array<{ id: string; type: string; data: Record<string, unknown> }>) {
    const calls: Call[] = [];
    const ctx = createMockContext({
        selection: nodes.map((n) => n.id),
        nodes,
        grantedScopes: GRANTS as never,
        config,
        netHandler: async (url: string, init?: { headers?: Record<string, string> }) => {
            calls.push({ url, headers: init?.headers ?? {} });
            return { status: 200, body: JSON.stringify(FIXTURE), headers: { 'content-type': 'application/json' } } as never;
        },
    }) as MockContext;
    await otxPulses.run(ctx);
    return { ctx, calls };
}

const ip = (id: string, addr: string) => ({ id, type: 'infrastructure.ip_address', data: { ip_address: addr } });
const typed = (ctx: MockContext, t: string) => ctx.mock.createdNodes.filter((n) => n.type === t);

// ── 1. THE FILTER, AGAINST THE REAL DISTRIBUTION ───────────────────────────────────────────────
{
    const { result, ctx, calls } = await run([ip('n0', '45.155.205.233')]);
    check(calls.length === 1, `one indicator is one request, got ${calls.length}`);
    check(/\/IPv4\/45\.155\.205\.233\/general$/.test(calls[0].url), `the IPv4 endpoint is used: ${calls[0].url}`);

    // The key is required now and must reach the request. It was optional first, on the grounds
    // that the data is identical with and without one — true of the response, wrong about the
    // product: anonymous callers are cut off after a handful of indicators, so the honest choice
    // was between "asks for a free key up front" and "silently returns a partial graph".
    const hdrs = Object.fromEntries(Object.entries(calls[0].headers).map(([k, v]) => [k.toLowerCase(), v]));
    check(hdrs['x-otx-api-key'] === 'k', `the configured key must reach the request, saw ${JSON.stringify(calls[0].headers)}`);

    const camps = typed(ctx, 'threat.campaign');
    check(camps.length === 6, `26 pulses must yield 6 reports, got ${camps.length}`);
    const names = camps.map((c) => String(c.data.campaign_name));
    for (const junk of ['0', 'test', 'Ste', 'ossim', 'web2', '20220127clone'])
        check(!names.includes(junk), `scratch pulse "${junk}" reached the graph`);
    check(!names.includes('IOCs - 2022111350'), 'the 24,876-indicator feed dump reached the graph');
    check(names.includes('Apache Log4j Vulnerability Called Log4Shell Actively Exploited'), 'a real report was dropped');

    const summary = String((result as { summary?: string }).summary ?? '');
    check(/19 pulse\(s\) skipped as scratch/.test(summary), `the run must say it dropped 19 scratch pulses: ${summary}`);
    check(/1 skipped as feed dumps/.test(summary), `the run must say it dropped the feed dump: ${summary}`);

    // The pulse's own page, so a report node can be traced back to the text behind it.
    const log4j = camps.find((c) => String(c.data.campaign_name).startsWith('Apache Log4j'))!;
    check(/^https:\/\/otx\.alienvault\.com\/pulse\/[0-9a-f]+$/.test(String(log4j.data.otx_pulse_url)), 'the campaign carries its OTX pulse URL');
    check(String(log4j.data.description).length > 0, 'and its description');
    // A pulse name is free text and live ones contain newlines. The name is both the label and the
    // identity, so a raw one breaks the label and splits one report across two nodes.
    for (const c of camps)
        check(!/[\r\n\t]|\s{2,}/.test(String(c.data.campaign_name)), `campaign name carries raw whitespace: ${JSON.stringify(c.data.campaign_name)}`);
}

// ── 2. WHAT THE PULSES CARRY ───────────────────────────────────────────────────────────────────
{
    const { ctx } = await run([ip('n0', '45.155.205.233')]);
    const tech = typed(ctx, 'threat.attack_pattern').map((n) => String(n.data.technique_id));
    check(tech.includes('T1190'), `T1190 is in the fixture's attack_ids, got [${tech.join(', ')}]`);
    check(new Set(tech).size === tech.length, 'a technique named by two pulses must be one node, not two');
    const mw = typed(ctx, 'threat.malware').map((n) => String(n.data.name));
    check(mw.includes('Mirai'), `Mirai is in the fixture's malware_families, got [${mw.join(', ')}]`);
    check(typed(ctx, 'threat.threat_actor').length === 0, 'no pulse in the fixture names an adversary, so no actor may be invented');

    const edges = ctx.mock.createdEdges;
    check(edges.some((e) => e.from === 'n0' && e.label === 'reported in'), 'the seed links to the report');
    check(edges.some((e) => e.label === 'uses'), 'the report links to its techniques and malware');
}

// ── 3. TWO SEEDS IN ONE REPORT CONVERGE ON ONE NODE ────────────────────────────────────────────
// This is the whole value of the source: it is what turns two unrelated-looking addresses into one
// story. Creating a second copy of the report per seed would destroy exactly that.
{
    const { ctx } = await run([ip('n0', '45.155.205.233'), ip('n1', '45.155.205.234')]);
    check(typed(ctx, 'threat.campaign').length === 6, `two seeds in the same reports still make 6 nodes, got ${typed(ctx, 'threat.campaign').length}`);
    const toCampaign = ctx.mock.createdEdges.filter((e) => e.label === 'reported in');
    check(toCampaign.length === 12, `but each seed gets its own edge: expected 12, got ${toCampaign.length}`);
}

// ── 4. THE CAP IS A PARAMETER, AND MOVING IT MOVES THE ANSWER ──────────────────────────────────
{
    const wide = await run([ip('n0', '1.1.1.1')], { params: { max_pulse_indicators: 30000 } });
    check(typed(wide.ctx, 'threat.campaign').length === 7, `raising the cap admits the feed dump: got ${typed(wide.ctx, 'threat.campaign').length}`);
    const narrow = await run([ip('n0', '1.1.1.1')], { params: { max_pulse_indicators: 10 } });
    check(typed(narrow.ctx, 'threat.campaign').length === 3, `lowering it keeps only the small reports: got ${typed(narrow.ctx, 'threat.campaign').length}`);
}

// ── 5. AN EMPTY ANSWER IS A FINDING, NOT A FAILURE ─────────────────────────────────────────────
// "OTX has this indicator and nothing is reported against it" and "the lookup broke" lead to
// opposite decisions, so they are counted apart and both are said out loud.
{
    const empty = await run([ip('n0', '8.8.8.8')], { body: () => ({ status: 200, body: JSON.stringify({ pulse_info: { count: 0, pulses: [] } }) }) });
    check(typed(empty.ctx, 'threat.campaign').length === 0, 'nothing is staged for an indicator with no pulses');
    check(/nothing reported against them/.test(String((empty.result as { summary?: string }).summary)), 'and the run says it is a real negative');

    const gone = await run([ip('n0', '8.8.8.8')], { body: () => ({ status: 404, body: '' }) });
    check(/nothing reported against them/.test(String((gone.result as { summary?: string }).summary)), '404 is "OTX has never seen it", not a failure');

    const broke = await run([ip('n0', '8.8.8.8')], { body: () => ({ status: 500, body: '' }) });
    check(/1 lookup\(s\) failed/.test(String((broke.result as { summary?: string }).summary)), 'a 500 is reported as a failure, not as a clean result');
    check(typed(broke.ctx, 'threat.campaign').length === 0, 'and stages nothing');
}

// ── 6. EVERY CONSUMED TYPE REACHES ITS OWN ENDPOINT ────────────────────────────────────────────
{
    const cases: Array<[Record<string, unknown>, string, RegExp]> = [
        [{ ip_address: '2001:db8::1' }, 'infrastructure.ip_address', /\/IPv6\/2001%3Adb8%3A%3A1\/general$/],
        [{ domain_name: 'evil.test' }, 'infrastructure.domain', /\/domain\/evil\.test\/general$/],
        // Routed by the Public Suffix List, not by label count — see test 7.
        [{ domain_name: 'cdn.evil.test' }, 'infrastructure.domain', /\/hostname\/cdn\.evil\.test\/general$/],
        [{ url: 'http://evil.test/a?b=1' }, 'web.url', /\/url\/http%3A%2F%2Fevil\.test%2Fa%3Fb%3D1\/general$/],
        [{ cve_id: 'CVE-2021-44228' }, 'threat.vulnerability', /\/cve\/CVE-2021-44228\/general$/],
        [{ sha256: 'a'.repeat(64), md5: 'b'.repeat(32) }, 'threat.file_hash', new RegExp(`/file/${'a'.repeat(64)}/general$`)],
    ];
    for (const [data, type, want] of cases) {
        const { calls } = await run([{ id: 'n0', type, data }]);
        check(calls.length === 1 && want.test(calls[0].url), `${type} → wrong endpoint: ${calls[0]?.url ?? 'no call'}`);
    }
    // A hash node holding only an md5 still resolves — the endpoint takes any of the three.
    const md5only = await run([{ id: 'n0', type: 'threat.file_hash', data: { md5: 'c'.repeat(32) } }]);
    check(new RegExp(`/file/${'c'.repeat(32)}/general$`).test(md5only.calls[0]?.url ?? ''), 'an md5-only hash node is still looked up');

    const other = await run([{ id: 'n0', type: 'identity.person', data: { full_name: 'nobody' } }]);
    check(other.calls.length === 0, 'a type OTX has no endpoint for costs no request');
    check(/no lookup for/.test(String((other.result as { summary?: string }).summary)), 'and is counted, not silently dropped');
}

// ── 7. THE PUBLIC SUFFIX LIST DECIDES WHICH NAMESPACE A NAME IS IN ────────────────────────────
//
// OTX indexes `domain` and `hostname` separately and will not answer for the wrong one — measured,
// mail.ru has 50 pulses under /domain/ and 0 under /hostname/, cdn.jsdelivr.net the reverse. Asking
// the wrong endpoint returns an empty result that reads exactly like "OTX knows nothing".
//
// Counting labels cannot decide it. All three of these have three labels and they are not the same
// kind of name, which is why this went to tldts and the PSL rather than a heuristic.
{
    const cases: Array<[string, 'domain' | 'hostname', string]> = [
        ['evil.test', 'domain', 'two labels: registrable'],
        ['cdn.jsdelivr.net', 'hostname', 'three labels, a host under jsdelivr.net'],
        ['bbc.co.uk', 'domain', 'three labels, but co.uk is a public suffix so this IS registrable'],
        ['news.bbc.co.uk', 'hostname', 'four labels under a two-label suffix'],
        ['user.blogspot.com', 'domain', 'blogspot.com is a PRIVATE-section suffix — this is registrable'],
        ['a.user.blogspot.com', 'hostname', 'and this sits under it'],
        ['xn--85x722f.xn--55qx5d.cn', 'domain', 'IDN in punycode: xn--55qx5d.cn (公司.cn) is a suffix'],
    ];
    for (const [name, want, why] of cases) {
        const { calls } = await run([{ id: 'n0', type: 'infrastructure.domain', data: { domain_name: name } }]);
        check(calls.length === 1, `${name}: the list is certain, so one request — got ${calls.length} (${why})`);
        check(
            new RegExp(`/${want}/${name.replace(/\./g, '\\.')}/general$`).test(calls[0]?.url ?? ''),
            `${name} should be a ${want} (${why}) — asked ${calls[0]?.url}`,
        );
    }
}

// ── 7b. A NAME THE LIST CANNOT PLACE STILL GETS BOTH TRIES ─────────────────────────────────────
// The fallback is no longer the mechanism, it is the staleness net: a suffix registered after the
// bundled snapshot was cut leaves tldts with no registrable domain at all, and that is the one case
// left where asking twice is right.
{
    const seen: string[] = [];
    await run([{ id: 'n0', type: 'infrastructure.domain', data: { domain_name: 'co.uk' } }], {
        body: (url: string) => {
            seen.push(url);
            return { status: 200, body: JSON.stringify({ pulse_info: { count: 0, pulses: [] } }) };
        },
    });
    check(seen.length === 2, `a bare public suffix has no registrable form, so both are tried — got ${seen.length}`);
    check(/\/hostname\//.test(seen[0]) && /\/domain\//.test(seen[1]), `wrong order: ${seen.join(' then ')}`);
}

// ── 8. A RATE LIMIT IS NOT AN EMPTY RESULT ─────────────────────────────────────────────────────
// The anonymous limit is real: measured 25 refusals out of 25 while keyed requests succeeded at the
// same instant. Counting a 429 as "nothing known" turns a throttle into a false negative on every
// remaining node of a selection.
{
    const { result, ctx } = await run([{ id: 'n0', type: 'infrastructure.ip_address', data: { ip_address: '8.8.8.8' } }], {
        body: () => ({ status: 429, body: '{"detail":"Rate limit exceeded"}' }),
    });
    check(typed(ctx, 'threat.campaign').length === 0, 'nothing is staged from a throttled lookup');
    const summary = String((result as { summary?: string }).summary ?? '');
    check(/REFUSED BY THE RATE LIMIT/.test(summary), `the run must say it was throttled: ${summary}`);
    check(!/nothing reported against them/.test(summary), 'and must NOT report it as a clean negative');
    check(/Wait and re-run/.test(summary), `a throttle with a key already set has one remedy — waiting: ${summary}`);
    // One refused lookup is ONE problem. Counting it as throttled AND failed put the same event on
    // two lines of the summary, which reads as two nodes having gone wrong.
    check(!/lookup\(s\) failed/.test(summary), `a throttled lookup must not also be counted as failed: ${summary}`);
    check(!/for any of 0 indicator/.test(summary), `"for any of 0 indicator(s)" is nonsense when nothing was reached: ${summary}`);
}

// ── 9. WHATEVER KEY IS CONFIGURED IS THE ONE THAT IS SENT ──────────────────────────────────────
// Not a fixed string, not a default: a plugin that ignores the configured value and sends something
// of its own would pass every other assertion here while charging somebody else's quota.
{
    const withKey = await runConfig({ api_key: 'a-different-key' }, [
        { id: 'n0', type: 'infrastructure.ip_address', data: { ip_address: '8.8.8.8' } },
    ]);
    const h = Object.fromEntries(Object.entries(withKey.calls[0].headers).map(([k, v]) => [k.toLowerCase(), v]));
    check(h['x-otx-api-key'] === 'a-different-key', `the configured key must be sent verbatim, saw ${JSON.stringify(withKey.calls[0].headers)}`);
}

// ══ PASSIVE DNS ════════════════════════════════════════════════════════════════════════════════
// The fixture is 120 real records from mail.ru (2026-09-10) — 107 A, 12 AAAA, 1 CNAME, and 14 of
// them carry NXDOMAIN in the address field. That last number is why this plugin has a sentinel
// list at all.
const PDNS_GRANTS = {
    graph: ['node:read', 'node:create', 'edge:create'],
    network: [{ endpoint: 'https://otx.alienvault.com/api/v1/indicators' }],
} as const;

async function runPdns(
    nodes: Array<{ id: string; type: string; data: Record<string, unknown> }>,
    opts: { config?: Record<string, string>; params?: Record<string, unknown>; body?: (url: string) => { status: number; body: string } } = {},
) {
    const calls: Call[] = [];
    const ctx = createMockContext({
        selection: nodes.map((n) => n.id),
        nodes,
        grantedScopes: PDNS_GRANTS as never,
        params: opts.params,
        config: opts.config ?? { api_key: 'k' },
        netHandler: async (url: string, init?: { headers?: Record<string, string> }) => {
            calls.push({ url, headers: init?.headers ?? {} });
            const r = opts.body ? opts.body(url) : { status: 200, body: JSON.stringify(PDNS) };
            return { ...r, headers: { 'content-type': 'application/json' } } as never;
        },
    }) as MockContext;
    const result = await otxPassiveDns.run(ctx);
    return { result, ctx, calls };
}

// ── P1. NXDOMAIN NEVER BECOMES A NODE ──────────────────────────────────────────────────────────
// It is the resolver's answer, not a host. Left in, every domain whose lookup ever failed converges
// on one node called NXDOMAIN — a false cluster with an edge per domain in the graph, which does
// not look like a bug, it looks like a discovery.
{
    const { result, ctx } = await runPdns([{ id: 'n0', type: 'infrastructure.domain', data: { domain_name: 'mail.ru' } }], {
        params: { max_records: 500 },
    });
    const names = ctx.mock.createdNodes.map((n) => String(Object.values(n.data)[0]));
    check(!names.some((v) => /NXDOMAIN|SERVFAIL|REFUSED/i.test(v)), `a resolver sentinel became a node: ${names.filter((v) => /NXDOMAIN/i.test(v)).join(', ')}`);
    check(/record\(s\) held a resolver sentinel/.test(String((result as { summary?: string }).summary)), 'and the run says how many it dropped');

    // Every address that DID become a node is a real address.
    for (const n of ctx.mock.createdNodes.filter((x) => x.type === 'infrastructure.ip_address'))
        check(/^[0-9.]+$|:/.test(String(n.data.ip_address)), `not an address: ${n.data.ip_address}`);
}

// ── P1b. THE SENTINEL LIST'S OWN PATH: A CNAME ─────────────────────────────────────────────────
// On an A record the address check already rejects NXDOMAIN, because it is not an address. On a
// CNAME the target IS a hostname, so "not an IP" is satisfied and NXDOMAIN sails through into a
// DOMAIN node — which is the hub, and the only guard against it is the sentinel list. The real
// mail.ru response holds one CNAME, so this path was untested until it was written by hand.
{
    const doctored = {
        passive_dns: [
            { hostname: 'a.evil.test', address: 'NXDOMAIN', record_type: 'CNAME', first: '2025-01-01T00:00:00', last: '2025-06-01T00:00:00' },
            { hostname: 'b.evil.test', address: 'SERVFAIL', record_type: 'CNAME', first: '2025-01-01T00:00:00', last: '2025-06-01T00:00:00' },
            { hostname: 'c.evil.test', address: 'real.example.com', record_type: 'CNAME', first: '2025-01-01T00:00:00', last: '2025-06-01T00:00:00' },
        ],
    };
    const { ctx } = await runPdns([{ id: 'n0', type: 'infrastructure.domain', data: { domain_name: 'evil.test' } }], {
        body: () => ({ status: 200, body: JSON.stringify(doctored) }),
    });
    const domains = ctx.mock.createdNodes.filter((n) => n.type === 'infrastructure.domain').map((n) => String(n.data.domain_name));
    check(!domains.some((d) => /NXDOMAIN|SERVFAIL/i.test(d)), `a resolver sentinel became a DOMAIN node: ${domains.join(', ')}`);
    check(domains.includes('real.example.com'), 'a genuine CNAME target must still be created');
}

// ── P2. THE DATES ARE THE POINT, AND THEY ARE ON THE LABEL ─────────────────────────────────────
// This edge's whole value over the "resolves to" another plugin draws is WHEN. A reader looking at
// the canvas sees labels, not edge data.
{
    const { ctx } = await runPdns([{ id: 'n0', type: 'infrastructure.domain', data: { domain_name: 'mail.ru' } }]);
    const edges = ctx.mock.createdEdges.filter((e) => /resolved to|aliased to/.test(e.label));
    check(edges.length > 0, 'no dated resolution edge was drawn');
    check(edges.some((e) => /\(\d{4}-\d{2}-\d{2}/.test(e.label)), `no edge label carries a date: ${edges.slice(0, 3).map((e) => e.label).join(' | ')}`);
    check(edges.every((e) => (e.data as Record<string, unknown>)?.source === 'otx_passive_dns'), 'edges must name their source');
}

// ── P3. A SUBDOMAIN'S HISTORY BELONGS TO THE SUBDOMAIN ─────────────────────────────────────────
// The record is about its own hostname. Hanging it on the apex loses which name actually resolved.
{
    const { ctx } = await runPdns([{ id: 'n0', type: 'infrastructure.domain', data: { domain_name: 'mail.ru' } }], {
        params: { max_records: 500 },
    });
    const subs = ctx.mock.createdNodes.filter((n) => n.type === 'infrastructure.domain');
    check(subs.length > 0, 'the fixture has 83 distinct hostnames; none became a node');
    check(ctx.mock.createdEdges.some((e) => e.label === 'subdomain'), 'a discovered hostname is not linked back to the seed');
    check(!subs.some((n) => String(n.data.domain_name).toLowerCase() === 'mail.ru'), 'the seed must not be recreated as its own subdomain');
}

// ── P4. AN IP SEED RUNS BACKWARDS, AND THE DISCOVERY IS THE HOSTNAME ───────────────────────────
//
// This is the assertion that was WRONG first, and the way it was wrong is the lesson. A record is
// always (hostname → address). Query a domain and `address` is the discovery; query an IP and
// `address` IS THE SEED, repeated on all 500 rows, while `hostname` is the discovery. The original
// test fed a DOMAIN-shaped fixture to an IP seed, so `address` happened to hold a different IP and
// the code looked right while it was in fact duplicating the seed and drawing an edge to itself.
// A fixture standing in for a shape it does not have proves nothing — so this one is a real
// /IPv4/8.8.8.8/passive_dns response.
{
    const { ctx, calls } = await runPdns([{ id: 'n0', type: 'infrastructure.ip_address', data: { ip_address: '8.8.8.8' } }], {
        params: { max_records: 20 },
        body: () => ({ status: 200, body: JSON.stringify(PDNS_IP) }),
    });
    check(/\/IPv4\/8\.8\.8\.8\/passive_dns$/.test(calls[0].url), `wrong endpoint: ${calls[0].url}`);

    // The seed must not be recreated as one of its own findings.
    const ips = ctx.mock.createdNodes.filter((n) => n.type === 'infrastructure.ip_address');
    check(ips.length === 0, `an IP seed discovers HOSTNAMES, not addresses — it created ${ips.map((n) => n.data.ip_address).join(', ')}`);
    const domains = ctx.mock.createdNodes.filter((n) => n.type === 'infrastructure.domain');
    check(domains.length > 0, 'the hostnames that pointed at this address must become nodes');
    check(
        domains.some((n) => String(n.data.domain_name) === 'zenixasia.com'),
        `a known hostname from the real response is missing: ${domains.slice(0, 4).map((n) => n.data.domain_name).join(', ')}`,
    );

    const edges = ctx.mock.createdEdges;
    check(edges.length > 0 && edges.every((e) => e.to === 'n0'), 'every edge must point AT the seed address');
    check(!edges.some((e) => e.from === e.to), 'the seed must never be linked to itself');
    check(edges.some((e) => /resolved to \(\d{4}/.test(e.label)), `the dates must survive the reverse direction: ${edges[0]?.label}`);
}

// ── P5. THE CAP IS A WINDOW, AND THE RUN SAYS SO ───────────────────────────────────────────────
// mail.ru has 556 records and 8.8.8.8 has 500 hostnames mostly belonging to strangers who
// misconfigured their DNS. Taking them all makes a hub; taking some silently makes a lie.
{
    const { result, ctx } = await runPdns([{ id: 'n0', type: 'infrastructure.domain', data: { domain_name: 'mail.ru' } }], {
        params: { max_records: 5 },
    });
    check(ctx.mock.createdEdges.filter((e) => /resolved to|aliased to/.test(e.label)).length <= 5, 'the cap is not applied');
    const summary = String((result as { summary?: string }).summary);
    check(/record\(s\) beyond the 5-record cap/.test(summary), `the run must name what it left behind: ${summary}`);
    check(/a window, not the whole history/.test(summary), 'and must say the result is partial');
}

// ── P6. THE KEY IS REQUIRED, AND REFUSING COSTS NO REQUEST ─────────────────────────────────────
{
    const { result, calls } = await runPdns([{ id: 'n0', type: 'infrastructure.domain', data: { domain_name: 'mail.ru' } }], { config: {} });
    check(calls.length === 0, 'a run with no key must not call OTX at all');
    check(/needs a free AlienVault OTX API key/.test(String((result as { summary?: string }).summary)), 'and must say what to do');
}
{
    const { calls } = await runPdns([{ id: 'n0', type: 'infrastructure.ip_address', data: { ip_address: '1.2.3.4' } }], { config: { api_key: 'secret' } });
    const h = Object.fromEntries(Object.entries(calls[0].headers).map(([k, v]) => [k.toLowerCase(), v]));
    check(h['x-otx-api-key'] === 'secret', 'the key must reach the request');
}

// ── P7. PULSES ALSO REFUSES WITHOUT A KEY NOW ──────────────────────────────────────────────────
// It was optional first, on the grounds that the data is identical. That was right about the
// response and wrong about the product: "works, then stops after six nodes" produces a partial
// answer with no signal that it is partial.
{
    const calls: Call[] = [];
    const ctx = createMockContext({
        selection: ['n0'],
        nodes: [{ id: 'n0', type: 'infrastructure.ip_address', data: { ip_address: '8.8.8.8' } }],
        grantedScopes: GRANTS as never,
        config: {},
        netHandler: async (url: string) => {
            calls.push({ url, headers: {} });
            return { status: 200, body: JSON.stringify(FIXTURE), headers: {} } as never;
        },
    }) as MockContext;
    const result = await otxPulses.run(ctx);
    check(calls.length === 0, 'pulses must not call OTX without a key either');
    check(/needs a free AlienVault OTX API key/.test(String((result as { summary?: string }).summary)), 'and must say so');
}

if (fail.length) {
    console.error(`FAIL — ${fail.length} problem(s):`);
    for (const f of fail) console.error(`  - ${f}`);
    process.exit(1);
}
console.log(`ok — ${FIXTURE.pulse_info.pulses.length} fixture pulses, all checks passed`);
