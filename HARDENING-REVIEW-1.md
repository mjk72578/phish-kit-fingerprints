# HARDENING REVIEW 1 — cluster.py / abuse-resolve.py / report-gen.py v1.0.0

**Reviewer:** Monday (first pass) | **Date:** 2026-10-08 ~12:45 CDT
**Status:** ALL FINDINGS CLOSED 2026-10-08 ~13:30 CDT — implemented by build
subagent per LT's "implement your fix list", sandboxed tests passed on all
three tools against the 19 real cases. Tools bumped to 1.0.1. Awaiting LT's
grade. Fix status per finding at the bottom of this file.

## cluster.py — campaign clusterer

### H1 (MEDIUM) — `sender_localpart` merge key over-merges on generic localparts
`build_features` adds `("sender_localpart", from_local)` as a union key for ANY
non-"return-" localpart. Two unrelated phishes both sent from `support@evil1.com`
and `support@evil2.com` share the key `("sender_localpart","support")` and get
merged into one campaign. Same for `info@`, `noreply@`, `admin@`, `service@`.
The campaign-ID pattern (`alert-151-40575`) is a strong signal; generic
localparts are not.
**Fix:** only use `sender_localpart` as a merge key when the localpart looks
campaign-specific (matches the campaign-ID regex OR length >= 12 with mixed
alnum, etc.). Otherwise record it as evidence only.

### H2 (MEDIUM) — `relay_subnet` /24 merge key over-merges on shared relays
The SPF-designated sender IP's /24 becomes a merge key. Shared outbound relays
(iCloud `57.103.65.0/24`, Gmail's ranges) serve thousands of unrelated senders;
two unrelated phishes relayed through the same /24 falsely merge. The docstring
claims "deliberately conservative" — this key is not.
**Fix:** demote `relay_subnet` to evidence-only, or require it to corroborate
with at least one other key before merging.

### H3 (LOW) — `_PUBLIC_SUFFIXES` incomplete → false brand-spoof flags
The hardcoded suffix list misses common suffixes (co.kr IS missing here though
abuse-resolve.py has it, com.br, etc.). `mail.amazon.co.kr` splits registrable
as `co.kr` with sub-labels `[mail, amazon]` → false `brand_subdomain_spoof`
flag on legitimate mail. Since brand-spoof IS a merge key, this can wrongly
merge unrelated messages.
**Fix:** share one suffix implementation across all three tools (see R5), and
expand the list.

### H4 (LOW) — double-parse of .eml in `load_eml`
`_headers_from_eml` parses the file, then `load_eml` re-opens and re-parses it
just to pull Message-ID. Wasteful, not wrong.
**Fix:** return the parsed message object (or the Message-ID) from
`_headers_from_eml`.

### H5 (INFO) — defanged URLs in raw .eml bodies are not extracted
`extract_urls` excludes `[`/`]`, so `evil[.]com` in a pasted .eml body is
missed. Case-dir path is unaffected (uses urls.json).
**Fix:** document, or add a refang-and-extract step for .eml input.

## abuse-resolve.py — abuse-contact resolver

### A1 (LOW) — `http_get_json` has no response size cap
WHOIS path caps at 256KB; the HTTPS/RDAP path reads unlimited. A malicious or
broken RDAP endpoint could exhaust memory. Trusted-infra risk, but inconsistent.
**Fix:** cap `resp.read()` like the WHOIS path.

### A2 (LOW) — cache entries never expire
Abuse contacts change; a stale cache silently sends reports to dead addresses.
`--refresh` exists but nothing prompts it.
**Fix:** 30-day TTL on cache entries (keep `--refresh` as override), note age
in output.

### A3 (LOW) — `_IP_RE` is IPv4-only
IPv6 addresses in Received headers are never extracted for resolution.
**Fix:** add IPv6 pattern (ipaddress module already imported).

### A4 (INFO) — private/reserved IPs get RDAP-queried wastefully
Received-header extraction pulls RFC1918/CGNAT/doc IPs; each burns an RDAP
attempt before failing. (report-gen.py's `ok_ip` already filters these —
the filtering should live here too.)
**Fix:** filter non-global IPs in `_iocs_from_eml` / before `resolve_ip`.

### A5 (INFO) — first A record only
`resolve_domain_a_record` takes the first non-placeholder address; round-robin
hosts can have diverse hosting.
**Fix:** document, or resolve all A records and union the hosting results.

### A6 (INFO) — suffix list diverges from cluster.py's
Two different hand-rolled PSLs in the pipeline will eventually disagree on the
same domain. See R5.

## report-gen.py — abuse-report generator

### R1 (HIGH/correctness) — apple-icloud template uses the wrong address
`build_apple` drafts to `abuse@icloud.com`. Verified TODAY (12:24 CDT, live
bounce): Apple's working phishing-report address is **reportphishing@apple.com**.
The template's "verify at support.apple.com" hedge does not save it — the tool
would have pointed LT at a dead/wrong desk. (The op's e1 went to
`reportphish@apple.com` and bounced for the same class of reason.)
**Fix:** default the apple-icloud recipient to `reportphishing@apple.com`,
keep the verify note.

### R2 (MEDIUM/crash) — `sorted(by_contact)` TypeErrors on None names
Keys are `(email or "TBD", name)`. When two unresolved contacts share the
`"TBD"` email slot with different names and one name is None, tuple comparison
hits `None < str` → `TypeError: '<' not supported between 'str' and
'NoneType'`. Trigger: 2+ domains with no resolved registrar contact where at
least one has `name=None`. Same pattern in `build_hosting`.
**Fix:** sort on `(email or "TBD", name or "")`.

### R3 (MEDIUM/correctness) — From-domain auto-reported without alignment check
`filter_iocs` adds the From domain straight to the registrar-report list. If
From is spoofed (e.g. `support@paypal.com` via an open relay / compromised
sender), the draft recommends suspending an innocent domain's registrar. The
"verify ownership" caution exists only for `context_domains`, not for From.
**Fix:** check SPF/DKIM alignment for the From domain (headers.json has
authentication results + anomalies) before adding it; otherwise move it to
context with the ownership warning.

### R4 (LOW) — courtesy sleeps bypassed
`resolve_contacts` sets `mod.Options.sleep = False` and the subprocess fallback
passes `--no-sleep`. Tool 2's politeness guarantee evaporates when driven by
tool 3. Fine at current IOC volumes; the tradeoff should be documented, and
sleep should stay ON for `--cluster` bulk runs.
**Fix:** document; consider keeping sleeps when input count > N.

### R5 (INFO) — duplicated primitives across all three tools
`strip_addr`, the hand-rolled public-suffix lists, and `_ADDR_RE` are
copy-pasted across cluster.py / abuse-resolve.py / report-gen.py with slight
divergences (the suffix lists already disagree — H3/A6).
**Fix:** extract a shared `_scamintel_util.py` (stdlib, portable). Single
source of truth for addr parsing, suffix handling, defang.

## Recommended fix order (reviewer's take)
1. R1 — wrong Apple address (points the user at a dead desk TODAY)
2. R2 — crash bug (real, triggerable)
3. H1 + H2 — clustering false-merge keys (integrity of campaign output)
4. R3 — spoofed-From registrar report (reputational risk if sent blindly)
5. R5 + H3 + A6 — shared util module (kills three findings at once)
6. A1, A2, A3, H4, R4, A4, A5, H5 — robustness pass

## Open questions for LT
- H1: what's the right "campaign-specific localpart" heuristic? (length +
  entropy? blocklist of generic names?)
- R3: do we have SPF/DKIM alignment reliably in headers.json for the From
  check, or do we go the simpler route (always warn on From-domain)?
- R5: shared util module — yes? (my recommendation: yes, now, before tools
  4-5 get built on the diverged copies)

## FIX STATUS — 2026-10-08 ~13:30 CDT (all verified by sandboxed test runs)

| ID | Status | What changed / verification |
|---|---|---|
| H1 | FIXED | `campaign_specific_localpart()`: merge key only for campaign-ID-style localparts or len>=10 non-generic (blocklist in util). Synthetic test: support@evil1.com + support@evil2.com → correctly NOT merged. Real data: C4's 9 members still merge via `alert-151-40575`; C1's short localparts (ita, portist…) correctly demoted to evidence. |
| H2 | FIXED | `relay_subnet` removed from merge keys; recorded as cluster evidence (`evidence.relay_subnets`). Synthetic test: two msgs sharing 57.103.65.0/24, otherwise unrelated → NOT merged. Real data: C1's 4 members still merge via shared Return-Path (cohesion 1.00). |
| H3 | FIXED | Via R5: cluster.py now uses the shared util suffix list (abuse-resolve.py's broader set, incl. co.kr). `mail.amazon.co.kr`-class false brand-spoof flags eliminated. |
| H4 | FIXED | `_headers_from_eml` now returns Message-ID from the single parse; `load_eml` no longer re-opens the file. Verified: .eml test inputs show correct Message-IDs. |
| H5 | FIXED (documented) | `extract_urls` docstring now states defanged URLs in raw .eml are not extracted; case-dir path (urls.json) unaffected. |
| A1 | FIXED | `http_get_json` caps body at 256KB, mirroring the WHOIS path; oversize → recorded note, no crash. |
| A2 | FIXED | 30-day cache TTL (`CACHE_TTL_DAYS`); stale entries re-resolve with a note; fresh cache hits note their age (verified: "[served from cache, age 0.0 days]"). `--refresh` still forces. |
| A3 | FIXED | `_IPV6_RE` added; matches validated through `ipaddress.ip_address` (over-match safe). |
| A4 | FIXED | `_iocs_from_eml` now keeps only `is_global` addresses — RFC1918/CGNAT/loopback/doc ranges no longer burn RDAP attempts. |
| A5 | FIXED (documented) | `resolve_domain_a_record` docstring states first-usable-address behavior and the round-robin limitation. |
| A6 | FIXED | Via R5: one canonical suffix list; both tools delegate to `_scamintel_util.registrable_domain`. |
| R1 | FIXED | apple-icloud template now drafts to `reportphishing@apple.com` (verified working 2026-10-08 after live bounce), confidence line updated. Verified in generated draft. |
| R2 | FIXED | Both builders sort on `(email or "TBD", name or "")`. Unit test with two TBD/None contacts: no TypeError. |
| R3 | FIXED | `load_case` now returns parsed auth identity (smtp.mailfrom, DKIM header.i, header.from); `filter_iocs` reports the From domain ONLY on SPF/DKIM alignment, else context_domains with ownership warning. Verified: spoofed paypal.com → context-only; DKIM-aligned lket17.bsgvo.my.id → reported; missing auth → safe direction. |
| R4 | FIXED | Documented in `resolve_contacts`; sleeps now kept for bulk runs (>10 inputs), bypassed only for small runs, in both module and subprocess paths. |
| R5 | FIXED | `_scamintel_util.py` created (ADDR_RE, strip_addr, display_name, MULTI_SUFFIXES, registrable_domain, GENERIC_LOCALPARTS, defang). All three tools import from it with sys.path fallback. Pure stdlib, portable. |

Open-question resolutions (per parent-task decisions): H1 heuristic = campaign-ID
regex OR (len>=10 AND not on generic blocklist); R3 = SPF/DKIM alignment check
from headers.json auth data (not always-warn); R5 = yes, built now.

Sandboxed test summary: cluster.py on 19 real cases → all 5 campaigns correct
(C4=9 @0.94, C5=4 @1.00, before-deletion=4 @1.00, C1=4 @1.00, C3 singleton);
abuse-resolve.py on 5 known IOCs → all contacts resolved (IONOS, OVH, Name.com,
Gname, Metaregistrar); report-gen.py --target all on C1 + C4 cases → all drafts
generated, no crashes, Apple draft correct. Nothing sent or submitted in any
test (drafts/stdout only).

---

## LT REVIEW ROUND 2 — 2026-10-08 ~13:00 CDT (LT's own findings)

**Reviewer:** LT (Miles) | **Status:** ALL 9 CLOSED 2026-10-08 ~13:05 CDT —
implemented per his spec ("run the patches"), sandboxed tests passed.
Tools bumped to 1.0.2. LT's grade: pending.

| ID | Area | Status | What changed / verification |
|---|---|---|---|
| LT-1 | abuse-resolve.py SSRF via redirects | FIXED | New `_SafeRedirectHandler(urllib.request.HTTPRedirectHandler)`: inspects the Location header, resolves the target host (bounded by Options.timeout), and raises HTTPError — aborting the redirect — when the scheme isn't http(s) or any resolved address isn't globally routable. Installed via `build_opener` in `http_get_json`, so all RDAP/bootstrap HTTPS goes through it. Unit: fake 301 to 169.254.169.254 → refused; to 8.8.8.8 → allowed; to file:/// → refused. |
| LT-2 | abuse-resolve.py WHOIS tarpit | FIXED | `whois_query` now records `start_time` before the recv loop and breaks when `time.time() - start_time > Options.timeout` — a trickling server can no longer hold the connection past the deadline. Unit (socketpair trickling 1 byte/0.3s, timeout 2.0s): returned in ~2.6s instead of hanging. |
| LT-3 | abuse-resolve.py redaction over-match | FIXED | `_is_redacted` rewritten: checks the DOMAIN portion against a proxy-service blocklist (contactprivacy.com, whoisguard.com, domainsbyproxy.com, privacyguardian.org, whoisprivacyprotect.com, perfectprivacy.com, privacyprotect.org, incl. subdomains) and the localpart against proxy prefixes (redacted, privacyproxy, whois-, domainadmin). Unit: `privacy@cloudflare.com` / `domain-privacy@aws.com` NOT flagged; `redacted@contactprivacy.com` / `privacyproxy9@x.com` flagged. 9/9 cases correct. |
| LT-4 | abuse-resolve.py fast-flux | FIXED | `resolve_domain_a_record` now returns ALL globally routable IPs (was: first only; the old A5 "documented limitation" is now actually fixed). `resolve_domain` runs each IP through `resolve_ip` and unions the footprints: providers/ASNs joined, first usable abuse contact wins, per-IP detail in notes. Polite sleeps kept (bulk runs slower, as LT noted). Unit (mocked 2-IP fast-flux): union correct; single-IP output form unchanged. Live-DNS check limited: this sandbox's resolver returns 198.18/15 for everything, so the multi-IP path was verified by mock, not live DNS. |
| LT-5 | report-gen.py auth-header parsing | FIXED | `_parse_auth` now strips RFC 5322 folding whitespace (`\r\n[ \t]+` → space) and `(comments)` before the smtp.mailfrom=/dkim= regexes. Unit: folded + comment-stuffed header parses to the right domains; plain headers unchanged. |
| LT-6 | cluster.py .eml memory cap | FIXED | `_headers_from_eml` checks `os.path.getsize` first; files over 5MB (`_MAX_EML_BYTES`) are skipped with a stderr warning (the skip lands in the run's "skipped" list via `load_eml`). Unit: 6MB .eml skipped, small .eml parses normally. |
| LT-7 | cluster.py URL trailing punctuation | FIXED | `extract_urls` now `.rstrip(".,;:?!")` on each match — trailing only, in-URL punctuation preserved. Unit: `"see http://evil.com/login."` → clean URL; `http://evil.com/a,b/c` unchanged. Regression: full cases/ clustering identical with and without this patch (no merge behavior change). |
| LT-8 | _scamintel_util.py double defang | FIXED | `defang` uses `(?<!\[)\.(?!\])` per LT's spec. Extended the identical guard to `:` and `@` — both had the same double-wrap flaw (`[:]`→`[[:]]`, `[@]`→`[[@]]`), so dots-only would not have made defang idempotent as the patch intends. Fresh defang output form unchanged (`hxxp[:]//evil[.]com`); re-runs are now byte-identical. Flagged for LT in case he wants dots-only strictness. |
| LT-9 | _scamintel_util.py display_name ReDoS | FIXED | Input capped at `raw[:500]` before the regex. Unit: 10KB bracket-free string returns "" in <0.001s (was: backtrack risk); normal quoted/unquoted display names parse identically. |

### Round-2 regression results (drafts/stdout only — nothing sent)
- cluster.py on original campaign cases (22 dirs, ingest-* excluded): C4=9
  @0.94, C5=4 @1.00, before-deletion=4 @1.00, C1=4 @1.00, C3 singleton —
  all correct, identical to the 1.0.1 baseline.
- NOTE (not a regression): on the full current cases/ (34 msgs, incl. 12 new
  ingest-* cases from tool-5 testing), C1's cluster grew to 12 members —
  3 ingest emails genuinely share the abused iCloud return-path
  `kyla.pike@icloud.com` ("John Pike" meeting invite, "Alex for Paramount+
  care", sales-dev-recruiter lure). The abused account is STILL ACTIVE and
  sending new phish — operationally significant, flagged for LT. Cohesion
  0.50 honestly reflects the multi-lure span. Verified the growth is NOT
  caused by the LT-7 rstrip patch (identical clustering with it reverted).
- abuse-resolve.py on 5 known IOCs (IONOS, OVH, Name.com, Gname,
  Metaregistrar): all resolve; fresh --refresh run exercises the
  redirect-guarded opener live.
- report-gen.py --target all on C1 + C4 cases: all drafts generate, no
  crashes, Apple draft → reportphishing@apple.com.
