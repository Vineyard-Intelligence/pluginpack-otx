// Functional test harness for pluginpack-otx/dist/pack.mjs: plugin raw results (ctx.retain).
// Run: node test-plugin.mjs   (after `node build.mjs`; src/selftest.ts covers the mapping itself)
//
// The OTX answer is src/fixture-otx.json, the real /general response for 45.155.205.233
// (2026-09-10) trimmed to the fields the plugin reads: 26 pulses, of which 6 survive the filter.
//
// Invariants, from the plugin raw results spec (§5):
//   - OTX Pulses keeps ONE thing per indicator: the final /general answer, whole and as OTX sent it,
//     on the selected indicator's node, op "pulses", and only when that answer is a 200 listing at
//     least one pulse. A 404 and a 200 with no pulses add nothing to the node and are not kept
//     (analyst's decision, 2026-11-25, reversing 1.4.0, which kept them as findings); neither is a
//     403, a 429 or any other failure.
//   - No Campaign (or any other created node) gets a raw result. A slice cut out of the indicator's
//     answer is not an answer OTX gave (analyst's decision, 2026-11-25).
//   - For a domain asked under two endpoints, only one response is kept: the one with pulses. If
//     neither has any, nothing is. Never a body stitched from both.
//   - Nothing handed to retain carries the API key, its header name or the request URL.
//   - A refusal object or a throw from retain never fails the run, and is logged once per reason.
//   - A host without ctx.retain (every desktop build before it) stages exactly the same graph.
//   - OTX Passive DNS keeps nothing.
import { readFileSync } from "node:fs";
import pack from "./dist/pack.mjs";

const FIXTURE = JSON.parse(readFileSync(new URL("./src/fixture-otx.json", import.meta.url), "utf8"));
const [pulsesPlugin, pdnsPlugin] = pack.plugins;
const ok = [];
const fail = [];
const check = (name, cond) => (cond ? ok : fail).push(name);

const SECRET_KEY = "otx-SECRET-key-0123456789abcdef";
const RESPONSE_HEADERS = { "content-type": "application/json", etag: '"otx-1"', date: "Wed, 25 Nov 2026 00:00:00 GMT" };
const EMPTY = { indicator: "x", type: "hostname", pulse_info: { count: 0, pulses: [] } };

function makeGraph(nodeById) {
  const createdNodes = [];
  const createdEdges = [];
  return {
    createdNodes,
    createdEdges,
    async get(id) {
      return nodeById[id] || null;
    },
    async createNode(draft) {
      const node = { id: `n${createdNodes.length + 1}`, type: draft.type, data: draft.data };
      createdNodes.push(node);
      return node;
    },
    async createEdge(edge) {
      createdEdges.push(edge);
      return { id: `e${createdEdges.length}`, ...edge };
    },
  };
}

function makeNet(respond) {
  const calls = [];
  return {
    calls,
    async fetch(url, init) {
      calls.push({ url, init });
      const { status, body, headers } = respond(url, init, calls.length);
      const text = typeof body === "string" ? body : JSON.stringify(body);
      return {
        ok: status >= 200 && status < 300,
        status,
        headers: headers ?? {},
        async json() {
          return JSON.parse(text);
        },
        async text() {
          return text;
        },
      };
    },
  };
}

function ctxFor({ nodes, selection, respond, config, params }) {
  const graph = makeGraph(nodes);
  const net = makeNet(respond);
  const logs = [];
  return {
    graph,
    net,
    logs,
    ctx: {
      run: { runId: "r1", projectId: "p1", pluginId: "x", grantedScopes: {}, platform: "desktop" },
      input: { selection },
      params: params ?? {},
      config: config ?? { api_key: SECRET_KEY },
      graph,
      net,
      progress: { set() {}, log: (m) => logs.push(m) },
      signal: undefined,
    },
  };
}

function retainSpy(answer = async () => ({ kept: true })) {
  const calls = [];
  const fn = async (...args) => {
    calls.push(args);
    return answer(...args);
  };
  fn.calls = calls;
  return fn;
}

const leaks = (calls) => {
  const s = JSON.stringify(calls);
  return [SECRET_KEY, "X-OTX-API-KEY", "otx.alienvault.com/api", "/general"].filter((x) => s.includes(x));
};
const bodyOf = (call) => (typeof call?.[2]?.body === "string" ? JSON.parse(call[2].body) : call?.[2]?.body);
const ip = (id, addr) => ({ id, type: "infrastructure.ip_address", data: { ip_address: addr } });

// ---- one indicator, a full answer -----------------------------------------------------------
{
  const nodes = { ip1: ip("ip1", "45.155.205.233") };
  const spy = retainSpy();
  const t = ctxFor({ nodes, selection: ["ip1"], respond: () => ({ status: 200, body: FIXTURE, headers: RESPONSE_HEADERS }) });
  t.ctx.retain = spy;
  const res = await pulsesPlugin.run(t.ctx);
  const campaigns = t.graph.createdNodes.filter((n) => n.type === "threat.campaign");
  check("the run still maps the six usable pulses", res.counts.campaigns === 6 && campaigns.length === 6);
  check("retain: exactly one call, on the looked-up indicator, op pulses", spy.calls.length === 1 && spy.calls[0][0] === "ip1" && spy.calls[0][1] === "pulses");
  check("retain: no call targets a Campaign node", !spy.calls.some((c) => campaigns.some((n) => n.id === c[0])));
  check("retain: no call targets any node the run created", !spy.calls.some((c) => t.graph.createdNodes.some((n) => n.id === c[0])));
  check("retain: the whole answer, as the text OTX sent", typeof spy.calls[0]?.[2].body === "string" && spy.calls[0][2].body === JSON.stringify(FIXTURE));
  check("retain: ...including the pulses the filter dropped", bodyOf(spy.calls[0])?.pulse_info?.pulses?.length === 26);
  check("retain: status and the response's own headers", spy.calls[0]?.[2].status === 200 && spy.calls[0]?.[2].headers.etag === '"otx-1"');
  check("retain: only status, headers and body", spy.calls[0] && Object.keys(spy.calls[0][2]).sort().join() === "body,headers,status");
  check("retain: a fresh headers object, not the response's own", spy.calls[0]?.[2].headers !== RESPONSE_HEADERS);
  check("retain: no opts passed", spy.calls[0]?.length === 3);
  check("retain: no API key, key header or request URL", leaks(spy.calls).length === 0);
  check("retain: the request really carried the key", t.net.calls[0].init.headers["X-OTX-API-KEY"] === SECRET_KEY);
  check("retain: nothing logged when kept", !t.logs.some((l) => /not kept/.test(l)));

  // The same run on a host without retain: same graph, same result.
  const old = ctxFor({ nodes, selection: ["ip1"], respond: () => ({ status: 200, body: FIXTURE, headers: RESPONSE_HEADERS }) });
  const oldRes = await pulsesPlugin.run(old.ctx);
  check("old host: no ctx.retain, the run returns the same result", !("retain" in old.ctx) && JSON.stringify(oldRes) === JSON.stringify(res));
  check("old host: ...and stages the same nodes and edges", JSON.stringify(old.graph.createdNodes) === JSON.stringify(t.graph.createdNodes) && JSON.stringify(old.graph.createdEdges) === JSON.stringify(t.graph.createdEdges));
  check("old host: says nothing about raw results", !old.logs.some((l) => /not kept/.test(l)));
  const notFn = ctxFor({ nodes, selection: ["ip1"], respond: () => ({ status: 200, body: FIXTURE }) });
  notFn.ctx.retain = true;
  const notFnRes = await pulsesPlugin.run(notFn.ctx).catch((e) => e);
  check("old host: a retain that is not a function is left alone", !(notFnRes instanceof Error) && notFnRes.counts.campaigns === 6);
}

// ---- two indicators naming the same pulses ---------------------------------------------------
{
  const spy = retainSpy();
  const t = ctxFor({
    nodes: { a: ip("a", "192.0.2.1"), b: ip("b", "192.0.2.2") },
    selection: ["a", "b"],
    respond: () => ({ status: 200, body: FIXTURE }),
  });
  t.ctx.retain = spy;
  const res = await pulsesPlugin.run(t.ctx);
  check("two indicators: one call each, on each indicator", spy.calls.map((c) => `${c[0]}:${c[1]}`).join() === "a:pulses,b:pulses");
  check("two indicators: the shared Campaigns get nothing", res.counts.campaigns === 6 && spy.calls.every((c) => c[0] === "a" || c[0] === "b"));
}

// ---- which answers are kept -----------------------------------------------------------------
{
  const spy = retainSpy();
  const byIp = {
    "192.0.2.1": { status: 404, body: { detail: "Not found." } },
    "192.0.2.2": { status: 403, body: { detail: "Authentication required" } },
    "192.0.2.3": { status: 429, body: { detail: "Request was throttled." } },
    "192.0.2.4": { status: 500, body: "Internal Server Error" },
    "192.0.2.5": { status: 401, body: { detail: "Invalid API key" } },
    "192.0.2.6": { status: 200, body: { ...EMPTY, indicator: "192.0.2.6", type: "IPv4" } },
  };
  const nodes = Object.fromEntries(Object.keys(byIp).map((addr, i) => [`i${i + 1}`, ip(`i${i + 1}`, addr)]));
  const t = ctxFor({ nodes, selection: Object.keys(nodes), respond: (url) => byIp[url.match(/IPv4\/([^/]+)\//)[1]] });
  t.ctx.retain = spy;
  const res = await pulsesPlugin.run(t.ctx);
  check("misses: neither a 404 nor a 200 with no pulses is kept", !spy.calls.some((c) => c[0] === "i1" || c[0] === "i6"));
  check("misses: 403, 429, 500 and 401 are not kept", !spy.calls.some((c) => ["i2", "i3", "i4", "i5"].includes(c[0])));
  check("misses: no retain call at all", spy.calls.length === 0);
  check("misses: the run counts them as before", res.counts.rate_limited === 1 && res.counts.failed === 3 && res.counts.clean === 2);
  check("misses: and logs nothing about raw results", !t.logs.some((l) => /not kept/.test(l)));
}

// ---- an empty answer keeps nothing, a non-empty one is kept whole ----------------------------
{
  // The case the analyst hit: a 200 whose pulse_info.count is 0 gave an empty review entry.
  const spy = retainSpy();
  const one = { ...FIXTURE, pulse_info: { ...FIXTURE.pulse_info, count: 1, pulses: FIXTURE.pulse_info.pulses.slice(0, 1) } };
  const t = ctxFor({
    nodes: { e: ip("e", "192.0.2.10"), z: ip("z", "192.0.2.11"), f: ip("f", "192.0.2.12") },
    selection: ["e", "z", "f"],
    respond: (url) =>
      url.includes("192.0.2.10")
        ? { status: 200, body: { ...EMPTY, indicator: "192.0.2.10", type: "IPv4" } }
        : url.includes("192.0.2.11")
        ? { status: 200, body: { indicator: "192.0.2.11", type: "IPv4", pulse_info: { count: 0 } } }
        : { status: 200, body: one, headers: RESPONSE_HEADERS },
  });
  t.ctx.retain = spy;
  const res = await pulsesPlugin.run(t.ctx);
  check("empty: count 0 / no pulses keeps nothing, one pulse is kept", spy.calls.map((c) => c[0]).join() === "f");
  check("empty: the kept one is the whole response text", spy.calls[0]?.[2].status === 200 && spy.calls[0][2].body === JSON.stringify(one));
  check("empty: both empty answers still count as clean", res.counts.clean === 2);
}

// ---- a domain asked under two endpoints: one original response, never stitched ---------------
{
  // github.io is itself a public suffix, so the plugin asks /hostname/ first and falls back to /domain/.
  const dom = { d: { id: "d", type: "infrastructure.domain", data: { domain_name: "github.io" } } };
  const run = async (first, second) => {
    const spy = retainSpy();
    const t = ctxFor({ nodes: dom, selection: ["d"], respond: (url) => (url.includes("/hostname/") ? first : second) });
    t.ctx.retain = spy;
    await pulsesPlugin.run(t.ctx);
    return { spy, t };
  };
  let r = await run({ status: 404, body: { detail: "Not found." } }, { status: 200, body: FIXTURE });
  check("domain: hostname 404 then domain 200 keeps the 200 alone", r.t.net.calls.length === 2 && r.spy.calls.length === 1 && r.spy.calls[0][2].status === 200 && r.spy.calls[0][2].body === JSON.stringify(FIXTURE));
  r = await run({ status: 200, body: EMPTY }, { status: 404, body: { detail: "Not found." } });
  r = await run({ status: 200, body: EMPTY }, { status: 200, body: FIXTURE });
  check("domain: an empty 200 then a 200 with pulses keeps the second alone", r.t.net.calls.length === 2 && r.spy.calls.length === 1 && r.spy.calls[0][2].body === JSON.stringify(FIXTURE));
  r = await run({ status: 200, body: EMPTY }, { status: 404, body: { detail: "Not found." } });
  check("domain: an empty 200 then a 404 keeps nothing", r.t.net.calls.length === 2 && r.spy.calls.length === 0);
  r = await run({ status: 200, body: EMPTY }, { status: 200, body: { ...EMPTY, indicator: "other" } });
  check("domain: two empty 200s keep nothing", r.t.net.calls.length === 2 && r.spy.calls.length === 0);
  r = await run({ status: 200, body: FIXTURE }, { status: 500, body: "x" });
  check("domain: a first answer with pulses ends the walk and is kept", r.t.net.calls.length === 1 && r.spy.calls.length === 1 && r.spy.calls[0][2].status === 200);
  r = await run({ status: 404, body: { detail: "Not found." } }, { status: 404, body: { detail: "Not found either." } });
  check("domain: two 404s keep nothing", r.t.net.calls.length === 2 && r.spy.calls.length === 0);
  r = await run({ status: 404, body: { detail: "Not found." } }, { status: 403, body: { detail: "no" } });
  check("domain: a 404 then a 403 is a failed lookup and keeps nothing", r.spy.calls.length === 0);
}

// ---- refusals and throws -------------------------------------------------------------------
{
  const refuse = retainSpy(async () => ({ kept: false, reason: "over this run's raw-result budget" }));
  const t = ctxFor({
    nodes: { a: ip("a", "192.0.2.1"), b: ip("b", "192.0.2.2"), c: ip("c", "192.0.2.3") },
    selection: ["a", "b", "c"],
    respond: () => ({ status: 200, body: FIXTURE }),
  });
  t.ctx.retain = refuse;
  const res = await pulsesPlugin.run(t.ctx).catch((e) => e);
  check("refusal: the run still succeeds with everything mapped", !(res instanceof Error) && res.counts.campaigns === 6 && refuse.calls.length === 3);
  check("refusal: said once, not once per indicator", t.logs.filter((l) => /^Raw pulses result not kept — over this run's raw-result budget$/.test(l)).length === 1);

  const bare = retainSpy(async () => ({ kept: false }));
  const b = ctxFor({ nodes: { a: ip("a", "192.0.2.1") }, selection: ["a"], respond: () => ({ status: 200, body: FIXTURE }) });
  b.ctx.retain = bare;
  await pulsesPlugin.run(b.ctx);
  check("refusal without a reason: logged as refused", b.logs.includes("Raw pulses result not kept — refused"));

  const thrower = retainSpy(async () => {
    throw new Error("host blew up");
  });
  const h = ctxFor({ nodes: { a: ip("a", "192.0.2.1"), b: ip("b", "192.0.2.2") }, selection: ["a", "b"], respond: () => ({ status: 200, body: FIXTURE }) });
  h.ctx.retain = thrower;
  const hres = await pulsesPlugin.run(h.ctx).catch((e) => e);
  check("throw: the run still succeeds with everything mapped", !(hres instanceof Error) && hres.counts.campaigns === 6 && thrower.calls.length === 2);
  check("throw: logged once, without the host's message", h.logs.filter((l) => /Raw pulses result not kept/.test(l)).length === 1 && !h.logs.some((l) => /blew up/.test(l)));
}

// ---- OTX Passive DNS keeps nothing ----------------------------------------------------------
{
  const pdns = JSON.parse(readFileSync(new URL("./src/fixture-pdns-ip.json", import.meta.url), "utf8"));
  const spy = retainSpy();
  const t = ctxFor({ nodes: { a: ip("a", "45.155.205.233") }, selection: ["a"], respond: () => ({ status: 200, body: pdns }) });
  t.ctx.retain = spy;
  const res = await pdnsPlugin.run(t.ctx).catch((e) => e);
  check("passive DNS: runs and keeps nothing", !(res instanceof Error) && t.net.calls.length > 0 && spy.calls.length === 0);
}

check("pack version is 1.5.0", pack.version === "1.5.0");

for (const n of ok) console.log(`ok   ${n}`);
for (const n of fail) console.log(`FAIL ${n}`);
console.log(`\n${ok.length} passed, ${fail.length} failed`);
if (fail.length) process.exit(1);
