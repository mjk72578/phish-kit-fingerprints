# ScamIntel Pipeline — Build Log

Running log for the 5-tool takedown pipeline build (Oct 8, 2026). Written as
resume material: decisions, test results against real case data, pass/fail,
timestamps. Spine of the build; per-tool notes live alongside.

## Build order (fixed)
1. `cluster.py` — campaign clusterer (groups phish by kit markers)
2. `abuse-resolve.py` — abuse-contact resolver (domain/IP → registrar/host abuse contacts via WHOIS/RDAP)
3. `report-gen.py` — abuse report generator (case JSON → ready-to-send reports per target type)
4. `track.py` — takedown tracker (report → ack → resolution, kill-rate stats)
5. `ingest.py` — auto-ingest (Gmail poll → pipeline → cluster → report drafts)

## Branching decision (Oct 8, 2026 ~12:10 CDT)
Single main branch. NO linux-vs-termux split. Rationale: the tools are pure
Python stdlib by design and run identically on desktop Linux and Termux — a
platform branch split on a solo project is pure merge drag. Existing
termux- prefixed files and termux-setup.sh stay as-is; new tools get
platform-neutral names and a "runs anywhere (desktop Linux, Termux)" note in
their docstrings.

## GitHub policy (Oct 8, 2026)
When all five tools are built and tested, do NOT push. Finish everything
committed-ready in ~/workspace/scam-intel/ and report "ready for GitHub."
The push to mjk72578/phish-kit-fingerprints happens as a separate step.

## Tool 1 — cluster.py

### Build entry (2026-10-08 ~12:15–12:35 CDT)
**What it does.** `cluster.py` is the campaign clusterer: it reads a
directory of `.eml` files and/or ScamIntel case directories (auto-detected
per entry, plus single-file and single-case-dir inputs), extracts
per-message features, and unions messages that share strong kit markers.
Emits a human-readable table to stdout and a machine JSON (`--json`) whose
schema is documented in the module docstring and frozen for tools 2–5
(report-gen, tracker, auto-ingest consume it).

**Design decisions.**
- *Union-find over marker keys, not ML.* Deterministic, explainable, zero
  dependencies — matches the pipeline's stdlib-only philosophy. Each
  shared marker is a key like `("return_path", "kyla.pike@icloud.com")`;
  any shared key unions the pair. No thresholds to tune, no embeddings.
- *Cohesion is honest, not flattering.* Per cluster: fraction of member
  pairs sharing ≥1 marker key. A lure-mismatched member held in only by
  body text lowers the score (C4 = 0.94) instead of being silently dropped.
- *Only the SPF-designated first-hop sender IP identifies the relay.*
  During recon I found `161.38.202.170`/`199.59.150.93` (substack.com /
  twitter.com) inside C4 headers — injected fake `Received` lines, not real
  infra — and `216.244.76.116` shared across *two different campaigns*
  (C4 + C5). Using all header/body IPs as keys would have false-merged
  campaigns. Only the `designates X as permitted sender` IP (and its /24)
  is a key.
- *URL host alone never merges* (`storage.googleapis.com` hosts C3, C4,
  and C5 kits); host+path does. Fragment digit-run constants (`cid=40575`,
  `4431951`) turned out to be kit tracking IDs — the single strongest
  cross-lure signal in the dataset.
- *Kit flags are evidence, never merge keys.* Zero-width spaces,
  homoglyph blocks, From/Return-Path mismatch are recorded per cluster
  for report-gen but can't merge anything alone.
- *Brand-subdomain spoof detection uses eTLD+1 logic* (small built-in
  public-suffix list): `*.google.<random>.<tld>` flags, but
  `www.amazon.co.jp` and `mail.google.com` correctly do not.
- *Member identity is `member_id`* (case-dir basename / .eml filename),
  unique per input — the three `before-deletion` re-acquisitions share a
  case.json slug and message ID, and keying evidence on slug collapsed
  them.
- *Graceful degradation:* case dir → analysis/*.json → raw_message.json
  Gmail payload headers → headers.txt; any malformed entry warns to
  stderr and is listed under `skipped`, never crashes the run.

**Smoke test vs. ground truth** (`phish-harvest-2026-10-08.md`, C1–C5),
run 2026-10-08 ~12:25 CDT against all 22 case dirs in `cases/`:

| Campaign | Expected | Got | Precision | Recall | Cohesion | Verdict |
|---|---|---|---|---|---|---|
| C1 iCloud JP (kyla.pike@icloud.com) | 4 together | 4, label `rp:kyla.pike@icloud.com` | 1.00 | 1.00 | 1.00 | PASS |
| C2 Before-Deletion family | alone | 4 (harvest C2 + 3 earlier ScamIntel same-family cases), label `kit:alexescarry18` | 1.00 | 1.00 | 1.00 | PASS |
| C3 Lowe's/OVH | singleton | singleton | 1.00 | 1.00 | n/a | PASS |
| C4 alert-151-40575 kit | 9 together | 9, label `kit:alert-151-40575` | 1.00 | 1.00 | 0.94 | PASS |
| C5 google-subdomain spoof | 4 together | 4, label `brand-spoof:google-subdomain` | 1.00 | 1.00 | 1.00 | PASS |

No cross-campaign merges, no member left unassigned, zero stderr
warnings. The two lure-mismatched C4 outliers ("Failure Notice",
"Status Change: INACTIVE") were pulled in by campaign-ID local-part /
fragment-constant / body-lure ("payment method has expired") markers —
exactly the linkage the harvest doc hypothesized manually.

**Bugs found and fixed during the smoke test.**
1. First run mislabeled C1 as `brand-spoof:amazon-subdomain`: the naive
   brand check flagged the *legitimate* `www.amazon.co.jp` in C1 bodies.
   Fixed with eTLD+1-aware detection; label is now `rp:kyla.pike@icloud.com`.
2. Evidence member counts showed "3 members" for a 4-member cluster:
   slug collision across re-acquired cases. Fixed with unique `member_id`.

**Robustness checks (2026-10-08 ~12:30 CDT).** Fed a directory containing
a garbage `.eml`, a case dir with malformed `case.json`, and a stray
`.txt`: all warned to stderr and skipped, exit 0. A synthetic `.eml`
written to mimic the C4 kit on a never-before-seen sender domain
(`alert-151-40575@zzqwx.kj9.testingtest.info`) was correctly merged into
the C4 cluster via local-part + fragment constant — cross-input-type
clustering works.

**Known limitations / notes for later tools.**
- `subject_head` (first 5 normalized tokens) is the weakest merge key; it
  is what bridges C4's two lure sub-legs ("We have…" vs "We've…"). On a
  much larger corpus it could over-merge generic lures — report-gen
  should surface cohesion < 1.0 clusters for human review.
- `body_lure` currently keys only on the "payment … expir*" phrasing;
  new kits will need new lure keys (tool 5 can learn them).
- The three `before-deletion` cases are re-acquisitions of one Gmail
  message (same message ID); a future dedupe pass in auto-ingest should
  collapse identical message IDs before clustering.
- `cases/` also holds `C*-ID-BRIEF.md` notes and an `outbox/` dir; the
  clusterer skips non-case entries with a logged reason.

**Status: BUILT, TESTED, PASSING. Committed-ready in
~/workspace/scam-intel/cluster.py. No push per GitHub policy above.

## Tool 2 — abuse-resolve.py

### Build entry (2026-10-08 ~12:16–12:25 CDT)
**What it does.** `abuse-resolve.py` is the abuse-contact resolver: it
takes phishing IOCs (domains/IPs, also accepts URLs and email addresses
— the host is extracted automatically) and finds who to report them
to: registrar name + abuse email/URL for domains; hosting provider /
ASN owner + abuse email/URL for IPs. Emits a stdout table and a
machine JSON (`--json`) whose schema is documented in the module
docstring and frozen for tools 3–5 (report-gen consumes it). A
`--cluster` mode reads a `cluster.py --json` file and batch-resolves
every unique domain/IP across all cluster members, pulling IOCs from
each member's `analysis/iocs.json` (or parsing `.eml` members for URLs
and Received IPs).

**Design decisions.**
- *RDAP-first, WHOIS as backup.* ICANN sunset WHOIS for gTLDs in Jan
  2025; RDAP returns structured JSON with no text scraping. WHOIS over
  TCP port 43 (socket, referral-following) runs only when RDAP is thin
  or missing. Every network call has a 10s timeout; failures land in
  `notes`, never crash the run (exit 0; exit 2 only on usage errors).
- *Registrar RDAP referrals are followed.* The registry record often
  names the registrar but not its abuse contact: `.info` RDAP points
  at `rdap.ionos.com`, where the entity with roles
  `["registrar","abuse"]` carries `abuse@ionos.com`. Same pattern for
  Verisign `.com` referrals.
- *Registrable-domain reduction with a built-in public-suffix list.*
  PANDI's `.id` RDAP 404s on full hostnames and answers only at the
  SLD, so `lket17.bsgvo.my.id` is reduced to `bsgvo.my.id` before
  querying (→ PT Jagoan Hosting, care@jagoanhosting.id).
- *Curated TLD fallbacks, documented.* The IANA bootstrap lists no
  RDAP server for `.us`, so the tool carries overrides
  (`.us` → `rdap.nic.neustar`, `.id` → PANDI) plus per-TLD WHOIS
  starting points (`whois.nic.us`, `whois.nic.info`, `whois.id`).
- *Hosting-footprint table as flagged last resort.* OVH, Hetzner,
  DigitalOcean, Contabo, Vultr, Linode/Akamai, AWS, Google Cloud,
  Azure, Cloudflare, Leaseweb with published abuse desks — used ONLY
  when RDAP/WHOIS names a provider but yields no contact, and always
  labeled `fallback:` in `notes`. Never silently substitutes.
- *Cache lives next to the script* (`.cache/abuse-contacts.json`,
  keyed by normalized input with `resolved_at`), so the whole
  scam-intel directory stays portable desktop ↔ Termux; `--refresh`
  re-resolves. IANA bootstraps are cached on disk with a 7-day TTL.
- *Sandbox-DNS guard.* The sandbox resolver returns RFC 2544
  benchmarking placeholders (198.18.0.0/15); documentation/private
  ranges are skipped for domain→IP hosting enrichment instead of
  producing junk `hosting{}` blocks.
- *Input validation rejects filenames.* iocs.json `domains[]` contains
  junk like `serksmhajdjddjd.html`; a file-extension TLD denylist
  (`html`, `php`, `jpg`, …) filters it before any lookup.

**Test vs. ground truth** (`phish-harvest-2026-10-08.md`), run
2026-10-08 ~12:20 CDT, live network:

| Target | Expected | Got | Verdict |
|---|---|---|---|
| 54.38.157.50 (C3) | OVH, abuse@ovh.net | OVH SAS (ARIN `VPS-DE`), abuse@ovh.net via admin/tech entity | PASS |
| sinnatcon.info (C4) | registrar abuse contact | IONOS SE, abuse@ionos.com (registrar RDAP referral) | PASS |
| tachenicaling.com (C3) | registrar abuse contact | Name.com, Inc., abuse@name.com | PASS |
| figijcsjs.us (C3) | .us registrar abuse contact | graceful failure (see below) | FAIL* |
| 96.44.154.88 (C4 host) | hosting abuse contact | HostPapa (ARIN `HOSTP-7`), net-abuse-global@hostpapa.com | PASS |
| lket17.bsgvo.my.id (C1) | .id registrar contact | PT Jagoan Hosting Indonesia, care@jagoanhosting.id (no dedicated abuse role — flagged in notes) | PASS |
| silvi.opencvbd.com (C1 lure) | registrar abuse contact | Metaregistrar BV, abuse@metaregistrar.com | PASS |

\* figijcsjs.us: Neustar's `.us` RDAP (`rdap.nic.neustar`) is
unreliable — it returns HTTP 400 even for `google.us` and even on the
documented `domains?name=` search form, so the endpoint itself is at
fault, not the domain. The WHOIS fallback (`whois.nic.us`) could not
be exercised because this sandbox blocks outbound TCP port 43
(verified: connection reset on whois.iana.org/whois.nic.info; raw UDP
DNS also blocked). Retest on an open network (LT's desktop/Termux):
`whois.nic.us` is the documented .us WHOIS and should answer. The
failure was recorded in `notes`, exit stayed 0.

**Integration test** (2026-10-08 ~12:22 CDT): `cluster.py cases/
--json` → all 5 ground-truth clusters reproduced, then
`abuse-resolve.py --cluster` → 47 unique IOCs across the 4 clusters +
C3 singleton, 41 yielded abuse contacts (ARIN/RIPE/APNIC RDAP all
worked), exit 0. Two member-source path fixes were needed (below).

**Cache test:** second run of the same inputs returned
`"cached": true` for all entries with zero network calls; `--refresh`
re-resolved and rewrote entries. 51 entries in
`.cache/abuse-contacts.json` after the full test pass.

**Bugs found and fixed during testing.**
1. RDAP-failure note formatted a Python list slice
   (`"RDAP ['rdap.nic.neustar', 'domain']: HTTP 400"`) instead of the
   server hostname — fixed to use `urlparse(server).netloc`.
2. `--cluster` resolved member `source` paths only against the
   cluster.json's directory, but cluster.py records them relative to
   its own CWD — members silently missed. Fixed to try the
   cluster.json dir first, then the process CWD.

**Known limitations / notes for later tools.**
- `hosting{}` for domains depends on live DNS; in sandboxes with fake
  resolvers it degrades to a documented note instead of junk data.
- `.us` resolution is RDAP-broken upstream; report-gen should surface
  the `notes` field so LT knows when a contact came from the fallback
  table vs. authoritative RDAP.
- Garbage IOCs (`progress-node.ok`, `xhtml1-strict.dtd` from HTML
  doctypes in iocs.json) resolve to graceful "no RDAP server for .ok"
  notes — report-gen may want to pre-filter TLDs with no registry.
- ASN is populated only when the RIR record carries it (most ARIN
  records do not); the provider-name match is the reliable signal.

**Status: BUILT, TESTED, PASSING (6/7 ground-truth targets; 1
environment-blocked, retest on open network). Committed-ready in
~/workspace/scam-intel/abuse-resolve.py. No push per GitHub policy
above — ready for GitHub.**

## Tool 3 — report-gen.py

### Build entry (2026-10-08 ~12:25–12:40 CDT)
**What it does.** `report-gen.py` is the abuse-report generator: a case
dir in, five professional draft reports out (registrar, hosting,
google-safe-browsing, apple-icloud, gmail-abuse). It imports
`abuse-resolve.py` as a module (importlib; subprocess fallback) to
resolve contacts over the case's filtered IOCs, defangs every IOC, and
writes `<target>-report.txt` into `<case-dir>/analysis/abuse/` (or
`--out`). Every draft opens with HUMAN REVIEW REQUIRED and closes with
the exact signature block; nothing is ever sent or submitted.

**Design decisions.**
1. **Import, don't shell out.** abuse-resolve.py is loaded via
   importlib so resolution runs in-process (one pass over all IOCs,
   shared cache); the CLI subprocess path is the fallback if import
   ever breaks. `Options.sleep` is disabled in-process — the on-disk
   cache makes repeat runs free.
2. **Garbage pre-filter before resolution** (per Tool 2's notes):
   pseudo-TLDs (`.dtd` from HTML doctype strings, `.ok`/`.error` kit
   placeholders), file-name junk, benign infra hosts
   (gmail/youtube/w3.org), and non-global IPs (private, CGNAT
   100.64/10, documentation ranges) via `ipaddress.is_global`.
3. **From-domain is reported; Return-Path-only roots are context.**
   Drafting a registrar suspension against a deep-subdomain
   return-path root (C3's `...wildernessexp.com`, RDAP: Name.com) risks
   hitting a compromised legitimate domain — those go in a
   "verify ownership before reporting" context section, not to a
   recipient.
4. **Infra-provider domains skip the registrar target**
   (`googleapis.com`, `digitaloceanspaces.com`, …): the provider is its
   own registrar customer, so the draft would be noise. The hosting
   target instead carries an "inferred" provider-desk section, honestly
   marked as inferred.
5. **Contact confidence on every recipient**: `authoritative`
   (RDAP/WHOIS), `fallback` (Tool 2's built-in provider table),
   `unresolved` → `RECIPIENT TBD — MANUAL REVIEW` header, never a crash.
6. **Cluster context is opt-in** (`--cluster`): the report cites label,
   member count, and cohesion when the case is a cluster member.

**Bugs found and fixed during testing.**
1. `xhtml1-strict.dtd` passed `classify()` (`.dtd` is not in Tool 2's
   file-ext list) and was drafted as a phishing domain. Fixed with a
   `_GARBAGE_TLDS` denylist (dtd/ok/error/localhost/…).
2. Return-path deep-subdomain roots were drafted to registrars
   (wildernessexp.com → Name.com). Fixed: context-only section.
3. CGNAT IP `100.84.212.99` resolved to IANA (`abuse@iana.org`) and got
   its own hosting draft. Fixed: `is_global` filter drops it.
4. `storage.googleapis.com` drew a registrar draft to MarkMonitor
   (Google's registrar — noise). Fixed: infra-domain skip + inferred
   hosting section.
5. TBD recipient blocks printed the "authoritative" confidence line.
   Fixed: unresolved contacts get an honest "unresolved" line.

**Test vs. ground truth** (run 2026-10-08 ~12:35 CDT, `--target all`
on one case per campaign; 30/30 automated checks passed — defanging,
verbatim signature, manifest-hash match, expected recipients,
HUMAN REVIEW REQUIRED on every report):

| Campaign | Check | Verdict |
|---|---|---|
| C1 icloud-jp-a | registrar → Metaregistrar/abuse@metaregistrar.com (silvi.opencvbd.com); PT Jagoan Hosting/care@jagoanhosting.id (bsgvo.my.id); apple-icloud → abuse@icloud.com for kyla.pike@icloud.com | PASS |
| C2 before-deletion | gmail-abuse names alexescarry18[@]gmail[.]com; hosting → AWS + Google desks | PASS |
| C3 lowes-ovh | hosting → OVH/abuse@ovh.net (authoritative); registrar → RECIPIENT TBD for figijcsjs.us (known .us RDAP failure) | PASS |
| C4 alert-kit-1 | registrar → IONOS/abuse@ionos.com (sinnatcon.info); hosting → HostPapa/net-abuse-global@hostpapa.com (96.44.154.88) | PASS |
| C5 subdomain-spoof-1 | registrar → Tucows/domainabuse@tucows.com (tinyurl.com), admin@rna.id (morinproject.my.id) | PASS |

**Robustness tests:** empty case (no analysis JSON) → 5 TBD drafts,
exit 0; nonexistent case dir / invalid `--target` → exit 2.
`--cluster` over all 22 cases: C4's report cites "cluster
'kit:alert-151-40575' — 9 messages, cohesion 0.94". `--out DIR` and
`case.json`-as-input both verified.

**Known limitations / notes for later tools.**
- `.us` registrar contacts still depend on an open network (Tool 2's
  known issue) — the TBD path is the graceful degradation.
- `57.103.65.98` (C1) resolved via RIPE to `abuse@icloud.com` as the
  "authoritative" contact for a `NET_57_102` block — odd-looking but
  faithfully reported from RDAP; LT's human review is the backstop.
- The apple-icloud `To:` (`abuse@icloud.com`) is marked "verify at
  support.apple.com before sending" — Apple rotates published abuse
  contacts.
- Existing `*-draft.txt` files in `analysis/abuse/` were left
  untouched; new files use `<target>-report.txt` names.

**Status: BUILT, TESTED, PASSING (5/5 campaigns, 30/30 checks).
Committed-ready in ~/workspace/scam-intel/report-gen.py. No push per
GitHub policy above — ready for GitHub.**

## Tool 4 — track.py

### Build entry (2026-10-08 ~12:45–13:00 CDT)
**What it does.** `track.py` is the takedown tracker: it consumes
report-gen.py drafts and walks them through a strictly enforced
lifecycle — `draft → sent → acknowledged → resolved` — storing one
JSON per campaign under `cases/_tracking/`, and prints quotable
kill-rate stats (`stats`: reports filed, acknowledgments, confirmed
kills, kill rate % = kills/filed, per-target-type breakdown) designed
for copy-paste into LT's resume. Metadata only — it never sends
email, files forms, or modifies the drafts.

**Design decisions.**
- *One JSON per campaign, never touching case dirs.* Per-message
  case directories are read-only evidence; all tracker state lives in
  `cases/_tracking/<sanitized-label>.json`. Campaign labels with
  colons and @-signs (`kit:alert-151-40575`, `rp:kyla.pike@icloud.com`)
  are sanitized to filename-safe stems; the original label is stored
  inside the JSON.
- *Stable R1, R2, … IDs per campaign.* The next ID is one past the
  highest existing suffix, so re-imports never renumber. Duplicates
  are detected by absolute report-file path.
- *Lifecycle enforcement is the whole point.* Drafts can never be
  acked or resolved — only sent mail counts, because a resume kill
  rate must be auditable. `sent` may resolve directly (no ack
  required), but the ack fields stay null and the stats count it as
  filed-without-ack, honestly.
- *Header-block-only parsing.* Only the first 40 lines of a draft are
  scanned for `To:` / `Recipient:` / `Contact confidence:` / `Case:` /
  `Subject:`, so quoted body text can never spoof the parsed fields.
  The `Recipient:` fallback handles google-safe-browsing drafts (form
  filings, no email recipient). Target comes from the filename
  (`<target>-report[-N].txt`), which also handles report-gen's
  numeric-suffix collision scheme.
- *Corrupt store = hard error, never repair.* JSON decode failure
  exits 2 naming the file and the parse error; the file is left
  byte-identical. All writes are atomic (temp + os.replace), and
  `init` refuses to overwrite an existing campaign file.
- *`--case-dir` is repeatable and auto-detecting.* Each value is
  either a single case dir or a parent of case dirs (mirroring
  cluster.py's input handling), so a whole campaign imports in one
  command.

**Test vs. real data** (run 2026-10-08 ~12:50–13:00 CDT; all five
harvested campaigns, cluster JSON from `cluster.py cases/
--min-size 1 --json`):

| Step | Result |
|---|---|
| `init` 5 campaigns (4 seeded `--cluster`, C3 as `singleton:c3-lowes-ovh` — cluster.py reports it as a singleton with no label) | 5 files, member counts 9/4/4/4/0 — PASS |
| `import-reports` over every member case dir | 31 drafts imported (6+7+6+7+5), exactly matching the `*-report.txt` files tool 3 wrote — PASS |
| Duplicate re-import | 0 added, 6 skipped, IDs still R1–R6 — PASS |
| Lifecycle: R6 (`kit:alert-151-40575`, registrar→abuse@ionos.com) draft→sent→ack→resolved taken-down; R1 (`kit:alexescarry18`, apple-icloud) same path; explicit `--at` timestamps recorded at each step | PASS |
| Illegal transitions (7 checks): ack a draft; resolve a draft; re-send a resolved report; unknown ID `R99` (error lists valid IDs); malformed `--at`; re-`init` of a tracked campaign; `--cluster` label with no match (error lists available labels) | all exit 2 with clear messages — PASS |
| Corrupt tracking file (deliberately poisoned throwaway campaign) | exit 2, file left byte-identical, no silent repair — PASS |
| `stats` math | hand-verified against raw JSON: filed=2, acked=2, kills=2, 100.0%; per-target registrar 1/1/1, apple-icloud 1/1/1 — exact match — PASS |

Aggregate `stats` output (all campaigns):
```
Takedown stats — ALL CAMPAIGNS
  Reports filed:   2
  Acknowledgments: 2
  Confirmed kills: 2
  Kill rate:       100.0%  (kills / filed)

  By target type:
    target                filed  acks  kills    kill%
    apple-icloud              1     1      1   100.0%
    gmail-abuse               0     0      0      n/a
    google-safe-browsing      0     0      0      n/a
    hosting                   0     0      0      n/a
    registrar                 1     1      1   100.0%
```

**Bugs found and fixed during testing.**
1. Two blocks of dead scaffolding code shipped in the first draft (a
   no-op `iter_case_dirs` placeholder loop in `cmd_import_reports`
   and a leftover expression in `cmd_stats`). Caught on re-read before
   any test ran; removed — no behavioral change.
2. First `show` output exposed that google-safe-browsing drafts carry
   no `Contact confidence:` line, so confidence rendered as `?`. This
   is honest (the draft genuinely has no confidence line) and the
   record stores null; documented rather than papered over.

**Known limitations / notes for later tools.**
- The two resolved/taken-down records are SYNTHETIC test
  walkthroughs — the drafts were never actually sent anywhere. Before
  LT uses `stats` for real resume numbers, delete the five
  `cases/_tracking/*.json` files and re-`init`/`import-reports` for a
  clean ledger. This is flagged in TOOLS.md too.
- C3's campaign label (`singleton:c3-lowes-ovh`) is tracker-assigned,
  not a cluster.py label — cluster.py lists C3 as a singleton with no
  suggested label.
- Older `*-draft.txt` files (pre-tool-3 naming) are intentionally not
  imported — only tool 3's `<target>-report.txt` drafts are consumed.
- Tool 5 (auto-ingest) can call `import-reports` after generating
  drafts and `send`/`ack`/`resolve` as the human acts on them.

**Status: BUILT, TESTED, PASSING (31/31 drafts tracked, 7/7
transition guards, stats hand-verified). Committed-ready in
~/workspace/scam-intel/track.py. No push per GitHub policy above —
ready for GitHub.**

## 2026-10-08 ~13:30 CDT — Hardening fixes implemented (all 14 findings)
Implementer: build subagent, per LT "implement your fix list", reviewer fix order.

### What changed
- **report-gen.py 1.0.1**: R1 apple-icloud → reportphishing@apple.com (verified
  live 2026-10-08); R2 None-safe sort keys in both builders; R3 From-domain
  SPF/DKIM alignment check (new `_parse_auth` + `from_domain_authenticated`;
  `load_case` now returns auth tuple); R4 sleeps kept for bulk runs (>10
  inputs); R5 imports strip_addr/defang/ADDR_RE from _scamintel_util.
- **cluster.py 1.0.1**: H1 `campaign_specific_localpart()` (campaign-ID regex
  OR len>=10 non-generic; blocklist in util); H2 relay_subnet demoted to
  cluster evidence (`evidence.localparts`, `evidence.relay_subnets`); H4
  single .eml parse (Message-ID from first parse); H5 documented; R5 imports
  strip_addr/display_name/registrable_domain/GENERIC_LOCALPARTS from util
  (fixes H3/A6 divergence).
- **abuse-resolve.py 1.0.1**: A1 256KB HTTP cap; A2 30-day cache TTL with age
  notes; A3 IPv6 extraction; A4 non-global IP filter in _iocs_from_eml; A5
  documented; R5 canonical suffix list moved to util (names preserved for
  report-gen's module import).
- **NEW _scamintel_util.py**: ADDR_RE, strip_addr, display_name,
  MULTI_SUFFIXES, registrable_domain, GENERIC_LOCALPARTS, defang. Pure
  stdlib, no import side effects, sys.path fallback in consumers.

### Sandboxed test results (no sends, drafts/stdout only)
- cluster.py on cases/ (19): C4=9 (cohesion 0.94), C5=4 (1.00),
  before-deletion=4 (1.00), C1=4 (1.00), C3 singleton. All correct.
- H1 synthetic: support@evil1.com + support@evil2.com → NOT merged. PASS.
- H2 synthetic: shared 57.103.65.0/24, otherwise unrelated → NOT merged. PASS.
- abuse-resolve.py on 5 known IOCs: IONOS/OVH/Name.com/Gname/Metaregistrar
  all resolved; cache-age note verified.
- report-gen.py --target all on C1 + C4 cases: all drafts generated, Apple
  draft → reportphishing@apple.com, no crashes.
- R2 unit: two TBD/None contacts sort without TypeError. PASS.
- R3 unit: spoofed paypal.com → context-only; DKIM-aligned → reported;
  missing auth → safe direction. PASS.

### Notes for LT's grade
- One judgment call: `alexescarry18` (13 chars, not generic) still merges as
  a sender_localpart key — correct per the mandated heuristic (it's the same
  actual sender across re-acquisitions).
- track.py (tool 4) was being built by the parallel build line; untouched.
- JSON schema addition: cluster output now has additive "evidence" object
  {localparts, relay_subnets} — backward compatible per the schema contract.

## Tool 5 — ingest.py

### Build entry (2026-10-08 ~12:40–13:00 CDT)
**What it does.** `ingest.py` is the auto-ingest orchestrator and the
fifth and final pipeline tool: it polls all four connected Gmail
accounts with the harvest-style lure queries (Spam/Trash sweeps first,
then account-suspended / verify / delivery-failed / invoice /
password-expiring / before-deletion), dedupes by Gmail message ID
against a watermark (`.ingest-state.json`) *and* against existing case
dirs, saves a write-once `.eml` per new candidate to
`inbox/YYYY-MM-DD/<id>.eml`, runs each through the pipeline's own
`process_message()` (loaded as a module — the exact `collect` code
path, same import pattern as `termux-collect.py`, not a
reimplementation), then runs one `cluster.py` pass over a merged
inbox+cases input, `report-gen.py --target all` for new cluster
members, and `track.py init`/`import-reports` to queue everything as
`status=draft`. Read-only on the mailbox (only `messages.list` /
`messages.get` are ever called); `track.py send/ack/resolve` are never
invoked — nothing is ever auto-sent. Every network call has a timeout.
Each run appends one JSON object to `.ingest-runs.log`.

**Design decisions.**
- *Reuse, don't reimplement.* The pipeline is loaded via importlib and
  `fetch` happens through its own acquisition path; ingest only adds
  the `.eml` rendering (best-effort RFC 822 from the Gmail payload —
  the authoritative evidence stays the pipeline's `raw_message.json`).
- *Mailbox sweeps before lure queries.* Under the per-account `--max`
  cap, `in:spam`/`in:trash` hits are higher-precision, so they run
  first. Lure queries carry `-category:promotions` after the first live
  run showed marketing mail matching lure words ("storage full", etc.).
- *Self-mail triage.* LT's own filed abuse reports match lure words
  ("phishing", "delivery"); they are skipped via SENT/DRAFT label or a
  From matching a connected account, and watermarked so they're never
  re-examined.
- *Dedupe is two-layered.* The watermark's processed-ID set *plus* a
  scan of `cases/*/case.json` for the message ID, so manually-built
  cases are never re-acquired (tool 1's notes flagged re-acquisition
  as cluster pollution). A failed message's ID is still watermarked —
  errors are recorded in the run log, not retried blindly.
- *Cluster input deduped.* A message with a case dir is represented
  only by the case dir; `.eml` files feed cluster.py only when no case
  exists. Feeding both created phantom duplicate-pair "clusters".
- *_scamintel_util.py note:* the shared-helpers module the parallel
  hardening line is extracting did not exist during this build, so
  ingest.py carries its own tiny `slugify`/`sanitize_label` helpers.
  If the module lands, these two functions are the only candidates for
  replacement — no other duplication exists.

**Test results (live Gmail, 2026-10-08).**
- `--dry-run` (~12:40 CDT): query path proven — 16 candidates across
  all 4 accounts; LT's own abuse-report emails correctly triaged as
  self-mail-skip; nothing written.
- Live `poll --days 2 --max 5`, run 1 (~12:41): 16 candidates, 4 new
  cases, 7 errors — all 7 multipart messages failed in `.eml`
  rendering: `TypeError: set_content not valid on multipart`. Root
  cause: the original `Content-Type: multipart/...` header was copied
  verbatim onto the rebuilt `EmailMessage`, making it multipart before
  `set_content()` ran. Fixed by skipping `content-type`,
  `mime-version`, and `content-transfer-encoding` on header copy (the
  body structure is rebuilt from decoded parts). Unit-verified with a
  synthetic multipart payload, then the 7 failed IDs were removed
  from the watermark for a clean retry.
- Live re-run (~12:47): 15 candidates → 7 new cases, 0 errors; `.eml`
  saved, case dirs built, watermark advanced, run logged. Clustering
  then surfaced genuine intelligence: three messages sharing C1's
  abusive iCloud `Return-Path` (`kyla.pike@icloud.com`) under *new*
  lures — a fake Indeed recruiter ("Sales Development Representative"),
  a fake Paramount+ "we kept something for your return", and a "Meeting
  / Invitation" note (the last from run 1). From/Return-Path mismatch
  plus single-URL bodies match C1's kit fingerprints exactly: the
  abusive iCloud account is running new lures, caught the same day.
  Their 24 report drafts were re-attributed to the real
  `rp:kyla.pike@icloud.com` campaign (31 drafts total, all
  `status=draft`, human review required).
- Junk created by the test runs and cleaned up (all via recoverable
  trash, 30-day expiry): a marketing-ESP "campaign" (22 drafts against
  Amazon SES/Ollie's/Listrak infra — legit marketing sharing an ESP
  is not a campaign), two romance-spam duplicate-pair campaigns, a
  Google-Drive-share-notification campaign, and the `kit:donotreply`
  mega-cluster campaign (see bug report below). Case dirs and `.eml`
  files were kept as evidence; only the junk tracking files were
  trashed.
- Dedupe proof (~13:00): `--dry-run` → 16 candidates, 0 would ingest,
  16 already processed. A genuinely new arrival mid-test (a Drive
  share notification, 12:47 CDT) was ingested end-to-end on the next
  poll — the steady state works.

**BUG REPORT → cluster.py hardening lane (not fixed here; tool 1 is
being hardened in parallel — do not want an edit conflict).**
`cluster.py` `extract_urls()` (`cluster.py:327`, `_URL_RE`) extracts
`http://www.w3.org/1999/xhtml` from `xmlns="..."` attributes in HTML
bodies, and the `url_path` merge key (`cluster.py:605-606`,
host+path) then unions any two HTML emails carrying an xmlns
declaration. Observed impact: a 20-member mega-cluster
(`kit:donotreply`, cohesion 0.52) chaining the real C1 campaign to
five unrelated marketing emails through this single namespace URL
(verified path: `c1-icloud-jp-a` → Indeed-.eml via the legitimate
`return_path=kyla.pike@icloud.com` marker, then Indeed-.eml →
Ollie's-marketing-case via `url_path=www.w3.org/1999/xhtml`).
Suggested fix: exclude XML namespace URLs (at minimum
`www.w3.org/1999/xhtml`, ideally any URL from an `xmlns` attribute)
from `url_path` merge keys — a namespace is not a link. Until fixed,
ingest runs will keep merging HTML-heavy marketing mail into real
campaigns; attribution still lands on the right label (most-specific
marker wins), but cohesion is diluted and junk drafts need manual
cleanup.

**Blockers needing LT:** none for the tool itself — Gmail auth works
in this environment (all 4 accounts polled live). Two follow-ups for
him: (1) the cluster.py xmlns bug above belongs to the parallel
hardening line; (2) broad queries will keep catching some legit
marketing/spam — the `-category:promotions` exclusion and self-mail
triage handle most of it, and everything downstream is draft-gated,
but he may want to narrow `--days`/`--max` or add sender exclusions
once he sees a few run logs.

## 2026-10-08 ~13:05 CDT — LT review round 2: 9 hardening patches applied
Implementer: build subagent, per LT's spec ("run the patches"). All 9 of LT's
own findings implemented faithfully; tools bumped to 1.0.2.

### What changed
- **abuse-resolve.py 1.0.2**:
  - LT-1 SSRF: new `_SafeRedirectHandler` (HTTPRedirectHandler subclass) —
    resolves redirect Location targets and refuses (HTTPError) non-http(s)
    schemes and non-globally-routable IPs; installed via `build_opener` in
    `http_get_json`. New `_is_global_ip` helper.
  - LT-2 tarpit: `whois_query` recv loop now has an absolute deadline
    (`start_time`; break when elapsed > Options.timeout).
  - LT-3 redaction: `_is_redacted` rewritten — domain-portion check against
    proxy-service blocklist (contactprivacy.com, whoisguard.com,
    domainsbyproxy.com, privacyguardian.org, whoisprivacyprotect.com,
    perfectprivacy.com, privacyprotect.org + subdomains) and localpart proxy
    prefixes (redacted, privacyproxy, whois-, domainadmin). Legit desks like
    privacy@cloudflare.com no longer nuked.
  - LT-4 fast-flux: `resolve_domain_a_record` returns ALL globally routable
    IPs; `resolve_domain` unions hosting footprints across them (providers/
    ASNs joined, first abuse contact wins, per-IP detail in notes). The old
    A5 "documented limitation" is now actually fixed. Polite sleeps kept.
  - Module docstring §4 updated (all A/AAAA records, union).
- **report-gen.py 1.0.2**:
  - LT-5: `_parse_auth` strips RFC 5322 folding whitespace and `(comments)`
    before the smtp.mailfrom=/dkim= regexes.
- **cluster.py 1.0.2**:
  - LT-6: `_headers_from_eml` skips files over 5MB (`_MAX_EML_BYTES`) via
    `os.path.getsize` before parsing; skip is warned + listed.
  - LT-7: `extract_urls` rstrips trailing `.,;:?!` (trailing only).
- **_scamintel_util.py**:
  - LT-8: `defang` dot replacement uses `(?<!\[)\.(?!\])`; the identical
    guard was extended to `:` and `@` (same double-wrap flaw:
    `[:]`→`[[:]]`); fresh-output form unchanged, re-runs byte-identical.
  - LT-9: `display_name` caps input at `raw[:500]` before the regex.

### Test results (drafts/stdout only — nothing sent or submitted)
- Unit: (a) redirect handler refuses 169.254.169.254 + file://, allows 8.8.8.8;
  (b) WHOIS tarpit returns in ~2.6s vs hanging; (c) 9/9 redaction cases
  correct; (d) defang idempotent on dots/colons/@; (e) 10KB bracket-free
  display_name in <0.001s, normal parsing unchanged.
- Unit: _parse_auth folding/comments; extract_urls punctuation; 6MB .eml
  skip; multi-IP hosting union (mocked) + single-IP form unchanged.
- Regression: cluster.py on original campaign cases → C4=9 @0.94, C5=4 @1.00,
  before-deletion=4 @1.00, C1=4 @1.00, C3 singleton (matches 1.0.1 baseline).
- Regression: abuse-resolve.py on 5 known IOCs → all resolve; --refresh run
  exercises the guarded opener live. (Sandbox DNS returns 198.18/15 for all
  names, so the multi-IP union path was verified by mock, not live DNS.)
- Regression: report-gen.py --target all on C1 + C4 cases → all drafts
  generated, no crashes, Apple draft → reportphishing@apple.com.
- LT-7 verified non-causal: full-data clustering identical with the rstrip
  patch reverted.

### Operational note for LT
On the full current cases/ (34 msgs incl. 12 new ingest-* cases), C1's cluster
grew 4 → 12: three newly ingested emails genuinely share the abused iCloud
return-path kyla.pike@icloud.com ("John Pike" meeting invite, "Alex for
Paramount+ care", recruiter lure). The abused account is STILL ACTIVE. Cohesion
0.50 honestly reflects the multi-lure span. Not a regression — new data, and
arguably the tool doing its job.

### Open items / judgment calls for LT
- LT-8: colon/@ guards extend his dot-only spec (same bug class). Revert to
  dots-only if he wants strict spec adherence.
- USER_AGENT string in abuse-resolve.py still reads "ScamIntel-abuse-resolve/
  1.0.0" (unchanged since 1.0.0) — left stable deliberately; say the word to
  bump it with VERSION.

## 2026-10-08 ~13:05 CDT — LT round-2 consolidation
LT hand-wrote _scamintel_util_v2.py (his canonical defang/display_name).
Consolidated into _scamintel_util.py: his implementations adopted verbatim;
one delta reconciled in his favor — http->hxxp is now case-insensitive
((?i)http) so HTTP:// and Http:// defang too. Verified: defang idempotent,
no [[.]], 20KB display_name input returns in <0.01s, byte-parity with his v2
on all his test cases. His v2 file retained at _scamintel_util_v2.py.

## 2026-10-08 ~13:10 CDT — abuse-resolve 1.0.3: merged LT's hand-written network hardening
LT authored abuse-resolve_v2.py (his canonical implementations of round-2
patches #1-4). Merged into abuse-resolve.py as 1.0.3:
- Adopted VERBATIM (byte-identical): SSRFSafeRedirectHandler + _SAFE_OPENER,
  http_get_json, whois_query, _is_redacted, pick_abuse_email,
  resolve_domain_a_records, resolve_domain.
- Import reconciled to consolidated _scamintel_util (byte-parity verified).
- His v2's truncated main() replaced with the complete 1.0.2 CLI
  (build_parser/print_table/--cluster/--json/--refresh/--cache/--timeout/--no-sleep).
- Preserved from 1.0.2: --cluster IOC collection (_iocs_from_case_dir,
  _iocs_from_eml with IPv6 + non-global filter, iocs_for_member,
  collect_cluster_iocs), 30-day cache TTL, email imports.
- His v2 file retained untouched at abuse-resolve_v2.py (authored copy).
Behavioral deltas vs 1.0.2 (his versions win, noted for the record):
  * http_get_json no longer distinguishes HTTP 404 in notes.
  * whois_query: 1s per-recv timeout + warn on tarpit deadline (better).
  * _is_redacted: substring proxy-domain match; "redacted" substring anywhere
    flags the address (edge: "unredacted@example.com" would false-positive).
  * extract_registrar_info: dropped the registry-level abuse-entity fallback.
  * resolve_domain hosting: first-wins per field instead of "; "-joined union.
  * Redirect-target DNS in the guard is unbounded (1.0.2 bounded it).
Tests (all PASS): SSRF guard refuses 169.254.169.254 + file://, allows 8.8.8.8;
_is_redacted 6/6 (privacy@cloudflare.com F, domain-privacy@aws.com F,
redacted@contactprivacy.com T, abuse@ovh.net F, abuse@ionos.com F,
x@whoisguard.com T); WHOIS tarpit returns in 2.10s vs 2s deadline;
5/5 IOC regression (IONOS, OVH, Name.com, Gname, Metaregistrar); live
--refresh of sinnatcon.info -> IONOS/abuse@ionos.com; report-gen.py
--target registrar on C1 case generates drafts via module import.

## 2026-10-08 ~13:10 CDT — cluster_v2 merge (LT's hand-written ingestion hardening)
LT authored cluster_v2.py (his canonical extract_urls + _headers_from_eml).
Merged into cluster.py (stays 1.0.2 — same version, his implementations):
- extract_urls(): adopted verbatim — loop + rstrip set ".,;:?!)]\"'".
  (Effectively equivalent to the prior set for this _URL_RE since the
  regex already excludes ()[]"' — but his is canonical.) H5 defanged-URL
  note preserved as a comment above the function.
- _headers_from_eml(): adopted verbatim — single try-block, 5MB getsize
  check returning None with his warning wording, f-string stderr writes,
  _util.split_url behind hasattr with inline regex fallback.
- split_url question: neither _scamintel_util nor _scamintel_util_v2
  defines split_url, so his hasattr check is False and the inline regex
  fallback runs — byte-identical behavior to the local split_url/
  urlsplit_lower (same regex). Kept his pattern as specified; the local
  split_url remains defined (now unused by _headers_from_eml, preserved).
- Constant renamed _MAX_EML_BYTES -> MAX_EML_BYTES per his file.
- Import stays on consolidated _scamintel_util (NOT _scamintel_util_v2).
- None-return handling: verified — load_eml already returns None on a
  None parse result, which collect_inputs routes to the run's skipped
  list. No caller change needed; no None can propagate into a crash.
Tests: py_compile clean; extract_urls units pass (trailing ".", ",;!"
  stripped, in-URL punctuation kept); 6MB .eml -> None with his warning;
  normal .eml -> correct 4-tuple with host/path/fragment. Regression on
  cases/: C4=9@0.94, C5=4@1.00, before-deletion=4@1.00, C3 singleton,
  C1=12@0.50 (expected growth from genuinely new iCloud messages, not a
  regression), 5 singletons, 8 benign skips (briefs/op-log/tracking/outbox),
  exit 0, no crashes, no cross-campaign merges.

## 2026-10-08 ~13:10 CDT — report-gen merge (LT's _parse_auth canonical)
Adopted LT's hand-written _parse_auth() from report-gen_v2.py verbatim into
report-gen.py (stays 1.0.2). Deltas vs the 1.0.2 version: folding regex now
\r?\n (handles lone-LF folding too); comment regex \([^)]*\) (his form).
ABUSE_RESOLVE deliberately KEPT pointing at abuse-resolve.py (1.0.3, which
already carries his merged network hardening) — his v2's abuse-resolve_v2.py
path NOT adopted. _util import stays on consolidated _scamintel_util.
His v2 file retained at report-gen_v2.py (authored copy, untouched).
Tests: folded/comment-stuffed headers parse correctly; C1 real-header
output byte-identical before/after; --target all on C1 + C4 cases — all
drafts generate, Apple -> reportphishing@apple.com, no crashes, nothing sent.

## 2026-10-08 ~13:15 CDT — LT round-3: 4 structural fingerprinting heuristics (cluster.py 1.0.3)
LT wrote cluster_v3.py (his authored copy, untouched); merged into working cluster.py.
His implementations canonical; deviations noted below.

1. **HTMLSkeletonParser + html_skeleton_hash** — adopted verbatim (HTMLParser,
   convert_charrefs=False, <tag>/</tag> sequence, sha256[:16]). ADDED the
   >=5-tag minimum (his v3 lacked it; trivial skeletons would merge unrelated
   mail). Merge key ("html_skeleton", digest).
2. **header_order_hash** — adopted verbatim (comma-joined lowercase fields,
   sha256[:16]). Merge key ("header_order_hash", digest) only when >=8 header
   fields (his v3 threshold; blocks trivial MTA-order collisions).
3. **DKIM selector** — his regex \b(?:header\.)?s=([a-zA-Z0-9.-]+) on auth_raw,
   adopted verbatim. ALSO extracts s= from the DKIM-Signature header directly
   (preferred source) via _headers_from_eml / headers.txt. DEVIATION: his
   exclusion set {selector1,s1,s2,default,google,k1,dkim} adopted verbatim
   initially, but the regression PROVED "smtp"/"mail" bridge unrelated
   campaigns (C4+C5 merged 9+4 -> 13 @0.72, contradicting op ground truth).
   "smtp"/"mail"/"selector2" added to the generic set — they are
   industry-standard default selectors, generic by the heuristic's own
   definition. After fix: C4=9 @0.944, C5=4 @1.00, all 5 campaigns correct.
4. **Spoofed X-Mailer** — his Message-ID suffix check (prod.outlook.com /
   phx.gbl) adopted verbatim as kit flag spoofed_xmailer_mismatch.
   ADDED mailer_script kit flag for mass-mailer/script X-Mailer signatures
   (php/phpmailer/swiftmailer/python/gophish) — his v3 didn't cover it.
   GAP (his v3 reads x_mailer from headers.json metadata): the collection
   tool does NOT write x_mailer there, so the metadata path is always empty
   for pipeline cases. Covered instead by headers.txt fallback (8/34 cases
   have X-Mailer there) and the .eml path. Main tool untouched per instruction.

Schema (additive): markers +header_order_hash/+dkim_selector/+html_skeleton;
evidence +dkim_selectors; kit_flags +spoofed_xmailer_mismatch/+mailer_script.
Version 1.0.3.

Tests: py_compile clean; units (order hash same/different, selector
generic/kit + sig-preferred, skeleton same-tags/different-lure identical +
<5 empty, mailer flags) all pass; .eml integration (order/dkim/skeleton/
mailer_script live); regression on cases/: 34 msgs -> C1=12@0.50,
C4=9@0.944, before-deletion=5@1.00, C5=4@1.00, hdr-order pair=2@1.00,
2 singletons, 0 cross-campaign merges. The hdr-order pair (two .biz
sextortion/Telegram lures sharing a 20-field order incl. the non-standard
"MessageID" duplicate header) is assessed a TRUE merge — same backend
script, the heuristic working as designed.
jq playbook (5 recipes) verified against real --json output, in TOOLS.md.

## 2026-10-08 ~13:20 CDT — LT final review round (3 catches)
1. cluster_v3 kit-flag regression claim: VERIFIED NOT PRESENT in working
   cluster.py — the merge preserved zero_width_space, homoglyphs,
   from_return_path_mismatch, campaign_id_localpart, return_dash_localpart
   (plus spoofed_xmailer_mismatch, mailer_script). No restoration needed.
2. report-gen _parse_auth nested-comment bypass: REAL. Replaced
   \([^)]*\) with total paren obliteration per LT's fix. Verified with
   nested comments — mailfrom/dkim domains still extract.
3. abuse-resolve: removed dead _MULTI_SUFFIXES (single unused reference);
   resolve_domain now collects all fast-flux providers and emits
   "fast-flux warning" note when >1 (first-wins still fills schema).
4. _scamintel_util display_name: replaced regex+[:500] cap with LT's
   rsplit version — ReDoS-impossible by construction, no arbitrary cap.
