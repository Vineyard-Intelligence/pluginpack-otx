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
import FIXTURE from './fixture-otx.json';

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
        netHandler: async (url: string, init?: { headers?: Record<string, string> }) => {
            calls.push({ url, headers: init?.headers ?? {} });
            const r = opts.body ? opts.body(url) : { status: 200, body: JSON.stringify(FIXTURE) };
            return { ...r, headers: { 'content-type': 'application/json' } } as never;
        },
    }) as MockContext;
    const result = await otxPulses.run(ctx);
    return { result, ctx, calls };
}

const ip = (id: string, addr: string) => ({ id, type: 'infrastructure.ip_address', data: { ip_address: addr } });
const typed = (ctx: MockContext, t: string) => ctx.mock.createdNodes.filter((n) => n.type === t);

// ── 1. THE FILTER, AGAINST THE REAL DISTRIBUTION ───────────────────────────────────────────────
{
    const { result, ctx, calls } = await run([ip('n0', '45.155.205.233')]);
    check(calls.length === 1, `one indicator is one request, got ${calls.length}`);
    check(/\/IPv4\/45\.155\.205\.233\/general$/.test(calls[0].url), `the IPv4 endpoint is used: ${calls[0].url}`);

    // Keyless is the claim in the description and the manifest declares no config, so nothing may
    // send an OTX key header — a plugin that quietly needs one is a plugin that stops working for
    // everyone who does not have one.
    const hdrs = Object.keys(calls[0].headers).map((h) => h.toLowerCase());
    check(!hdrs.some((h) => h.includes('otx') || h === 'authorization'), `no key header may be sent, saw ${hdrs.join(', ')}`);

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

if (fail.length) {
    console.error(`FAIL — ${fail.length} problem(s):`);
    for (const f of fail) console.error(`  - ${f}`);
    process.exit(1);
}
console.log(`ok — ${FIXTURE.pulse_info.pulses.length} fixture pulses, all checks passed`);
