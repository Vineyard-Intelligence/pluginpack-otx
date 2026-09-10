// Which OTX indicator endpoint a name belongs to.
//
// OTX indexes `domain` and `hostname` as SEPARATE namespaces and will not answer for the wrong one.
// Measured 2026-09-10: mail.ru has 50 pulses under /domain/ and 0 under /hostname/;
// cdn.jsdelivr.net has 0 under /domain/ and 50 under /hostname/. One infrastructure.domain node can
// be either — the type holds apexes and subdomains alike — so asking the wrong endpoint returns an
// empty result that reads exactly like "OTX knows nothing".
//
// COUNTING LABELS CANNOT DECIDE THIS, and the failures are not exotic. bbc.co.uk has three labels
// and is registrable; cdn.jsdelivr.net has three and is a host; user.blogspot.com is registrable
// because blogspot.com is itself a public suffix. Only the Public Suffix List knows.
//
// WHY tldts AND NOT A HAND-ROLLED LOOKUP. Both were built and measured against the PSL project's
// own 78-case suite. Bundled size was a wash — 38.7KB gzipped hand-rolled against 46.4KB for tldts,
// and tldts is the smaller of the two before compression. Correctness was not: the hand-rolled
// version failed 4 cases, ALL OF THEM IDN, because the list stores 299 rules as Unicode (`公司.cn`)
// while a graph holds punycode (`xn--55qx5d.cn`), and closing that gap means carrying a punycode
// encoder. It had already failed 10 more before that, from a data trim that silently dropped the
// single-label wildcards `*.ck` and `*.mm`. Both bugs were found by the official suite in under an
// hour, which is the argument: tldts already has that suite and a maintainer. Its own 2 failures
// are leading-dot inputs (".example.com"), which a hostname field does not produce.
//
// allowPrivateDomains IS THE POINT, not a tuning flag. Without it tldts ignores the PSL's private
// section, so blogspot.com and uk.com stop being suffixes and user.blogspot.com is misread as a
// host under blogspot.com. That section is where the interesting OSINT cases live — *.github.io,
// *.blogspot.com, *.s3.amazonaws.com are each a registrable unit belonging to a different party.
import { parse } from 'tldts';

/**
 * Endpoints to try, in order.
 *
 * Usually ONE: the list decides, and a second request buys nothing. The fallback survives for the
 * case the list cannot cover — a suffix registered after the bundled snapshot was cut, where
 * `parse` returns no registrable domain at all. That is staleness, not ambiguity, and it is the
 * only remaining reason to ask twice.
 */
export function domainPaths(name: string): string[] {
    const host = name.trim().replace(/\.$/, '');
    const asDomain = `domain/${encodeURIComponent(host)}`;
    const asHostname = `hostname/${encodeURIComponent(host)}`;
    const { domain } = parse(host, { allowPrivateDomains: true });

    // No registrable domain: either the name IS a public suffix, or the list has never heard of the
    // TLD. Nothing to be confident about, so try the more specific type first and fall back.
    if (!domain) return [asHostname, asDomain];
    return domain.toLowerCase() === host.toLowerCase() ? [asDomain] : [asHostname];
}
