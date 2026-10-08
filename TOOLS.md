# ScamIntel Pipeline — Tool Reference

One section per tool, in build order. Each section: what it does, how to
run it, what it reads/writes. Tools 2–5 append their own sections below.

All tools are pure Python stdlib — they run identically on desktop Linux
and Termux, single main branch, no platform split.

---

## Tool 1 — `cluster.py`: campaign clusterer

Groups phishing messages into campaigns from shared kit fingerprints.

**Run:**
```
python3 cluster.py <path> [--json out.json] [--min-size N]
```
- `<path>`: directory of `.eml` files and/or ScamIntel case directories
  (each entry auto-detected), a single case dir, a single `case.json`,
  or a single `.eml` file.
- `--json out.json`: machine-readable result (schema in the module
  docstring; frozen for tools 2–5).
- `--min-size N`: minimum members per reported cluster (default 2);
  smaller groups are listed as singletons.

**Reads:** `analysis/headers.json`, `analysis/urls.json`,
`analysis/iocs.json`, falling back to `evidence/raw_message.json` and
`analysis/headers.txt`; or raw `.eml` via the stdlib email parser.

**Writes:** stdout table (cluster label, size, cohesion, defining markers
with evidence, members, singletons); optional `--json` file:
`{tool, version, generated, input, message_count, skipped[], clusters[],
singletons[]}`. Each cluster carries `label`, `members[]`
(`member_id`, `slug`, `message_id`, `source`), `size`, `markers[]`
(`type`, `value`, `evidence{members[], detail}`), `kit_flags[]`, and
`cohesion` (0.0–1.0).

**Marker types** (merge keys): `return_path`, `sender_localpart`,
`url_path`, `url_fragment_const`, `subject_template`, `subject_head`,
`relay_subnet`, `brand_subdomain_spoof`, `body_lure`.
Kit-flag types (evidence only): `zero_width_space`,
`homoglyph_<block>`, `from_return_path_mismatch`,
`campaign_id_localpart`, `return_dash_localpart`.

**Behavior notes:** read-only, no network, never crashes on a malformed
entry (warns to stderr, lists it under `skipped`). Suggested labels pick
the most campaign-specific marker
(`kit:alert-151-40575`, `rp:kyla.pike@icloud.com`,
`brand-spoof:google-subdomain`, …).

**Smoke test (2026-10-08):** 22 case dirs → C1×4, C2-family×4, C4×9,
C5×4 clustered; C3 singleton. Precision 1.00 / recall 1.00 on all five
ground-truth groups from `phish-harvest-2026-10-08.md`.

---

## Tool 2 — `abuse-resolve.py`: abuse-contact resolver

Finds WHO to report phishing IOCs to: registrar + registrar abuse
contact for domains, hosting provider / ASN owner + abuse contact for
IPs.

**Run:**
```
python3 abuse-resolve.py example.com 54.38.157.50 [--json out.json] [--refresh]
python3 abuse-resolve.py --cluster clusters.json [--json out.json]
```
- Positional inputs: domains, IPs, full URLs, or email addresses —
  the host part is extracted and classified automatically.
- `--cluster CLUSTER.JSON`: a `cluster.py --json` file; resolves every
  unique domain/IP across all cluster members (IOCs from each member's
  `analysis/iocs.json`; `.eml` members parsed for URLs/Received IPs).
- `--json out.json`: machine-readable result (schema in the module
  docstring; stable for tool 3/report-gen).
- `--refresh`: bypass the on-disk cache and re-resolve.
- `--cache PATH`, `--timeout SEC` (default 10), `--no-sleep`.

**Reads:** the network (RDAP over HTTPS via the IANA bootstrap
registries, WHOIS over TCP port 43 with referral following);
`--cluster` reads a cluster.py JSON plus each member's
`analysis/iocs.json` (or parses `.eml` members). Nothing else.

**Writes:** stdout table
(input, kind, registrar/provider, abuse contact, cached?, notes);
optional `--json` file:
`{tool, version, generated, input, results[]}`. Each result:
`{input, kind ("domain"|"ip"), registrar{name, abuse_email, abuse_url},
hosting{provider, asn, abuse_email, abuse_url}, cached, resolved_at,
notes}`. Cache at `<script-dir>/.cache/abuse-contacts.json`
(keyed by normalized input, with `resolved_at`).

**Behavior notes:** RDAP-first (ICANN sunset WHOIS for gTLDs in Jan
2025), WHOIS as fallback, then a built-in table of major
VPS/hosting-provider abuse desks (OVH, Hetzner, DigitalOcean, Contabo,
Vultr, Linode/Akamai, AWS, Google Cloud, Azure, Cloudflare, Leaseweb)
used ONLY when RDAP/WHOIS names a provider but yields no contact —
always flagged in `notes`. Subdomains reduce to the registrable domain
(`lket17.bsgvo.my.id` → `bsgvo.my.id`, PANDI RDAP only answers at the
SLD). Registrar RDAP referrals are followed (`.info` → IONOS registrar
RDAP, which holds the real abuse contact). TLD quirks handled:
`.us` has no IANA-bootstrap RDAP server (curated override
`rdap.nic.neustar` + `whois.nic.us` fallback); `.id` answers only at the
SLD. A domain's `hosting{}` is enriched via its A record → IP path.
Timeouts on every network call; a failed lookup is recorded in
`notes` and never crashes the run (exit 0); exit 2 on usage errors.
Courtesy pauses between queries (`--no-sleep` to skip). Read-only
recon for defensive abuse reporting — nothing is filed or sent.

**Smoke test (2026-10-08):** all 7 ground-truth targets from
`phish-harvest-2026-10-08.md` — 6/7 returned plausible abuse contacts:
`54.38.157.50`→OVH/abuse@ovh.net, `sinnatcon.info`→IONOS/abuse@ionos.com,
`tachenicaling.com`→Name.com/abuse@name.com,
`96.44.154.88`→HostPapa/net-abuse-global@hostpapa.com,
`lket17.bsgvo.my.id`→PT Jagoan Hosting/care@jagoanhosting.id,
`silvi.opencvbd.com`→Metaregistrar/abuse@metaregistrar.com.
`figijcsjs.us` failed gracefully: Neustar's `.us` RDAP endpoint is
unreliable (HTTP 400 even for google.us) and outbound port 43 is
blocked in the sandbox — retest on an open network, where
`whois.nic.us` should answer. `--cluster` over all 22 case dirs:
47 unique IOCs, 41 yielded contacts, exit 0.

---

## Tool 3 — `report-gen.py`: abuse-report generator

Drafts professional, ready-to-review abuse reports for a ScamIntel case —
one per recipient type — resolving the right abuse contacts through
`abuse-resolve.py` (Tool 2) and defanging every IOC so drafts are safe to
read, paste, and file.

**Run:**
```
report-gen.py <case-dir> --target {registrar,hosting,google-safe-browsing,apple-icloud,gmail-abuse,all} [--out DIR]
report-gen.py <case-dir> --target all --cluster clusters.json
```
- `<case-dir>`: a ScamIntel case directory (or its `case.json`).
- `--target`: which report(s) to draft (`all` = all five).
- `--out DIR`: write drafts to DIR instead of
  `<case-dir>/analysis/abuse/`.
- `--cluster CLUSTER.JSON`: a `cluster.py --json` file — if the case is a
  cluster member, reports cite campaign volume (label, size, cohesion).

**Reads:** `case.json`, `analysis/iocs.json`, `analysis/headers.json`,
`analysis/urls.json`; imports `abuse-resolve.py` as a module (shell-out
fallback) for contact resolution over the filtered IOCs.

**Writes:** `<target>-report.txt` files (never overwrites — numeric suffix
on collision); stdout summary of what was generated, for whom, and with
what contact confidence. Targets:
- `registrar` — registrar abuse desk per phishing domain
  (deduped; requested action: suspend account / clientHold).
- `hosting` — hosting-provider abuse desk per phishing IP and per
  domain A-record (deduped; requested action: takedown / suspend /
  null-route). Infra-provider domains (googleapis.com, …) get an
  "inferred" provider-desk section instead of RDAP noise.
- `google-safe-browsing` — form-ready text (defanged URLs to paste;
  no recipient — it is a web form).
- `apple-icloud` — abusive iCloud senders; `abuse@icloud.com` marked
  "verify at support.apple.com before sending".
- `gmail-abuse` — abusive Gmail senders; in-product report text
  (Gmail has no direct abuse email).

**Report anatomy:** `HUMAN REVIEW REQUIRED` draft header → recipient +
contact-confidence line → subject → incident summary (lure
characterization, subject, sender, date, volume) → defanged IOC
sections → requested action → `EVIDENCE MANIFEST` (case_id, slug,
message_id, evidence_sha256, manifest_sha256, tool_version,
generated, report timestamp) → the exact signature block.

**Behavior notes:** defanging = `http`→`hxxp`, `.`→`[.]`, `:`→`[:]`,
`@`→`[@]` on every IOC (URLs, domains, IPs, emails); the signature and
manifest identifiers stay verbatim. Contact confidence is
`authoritative` (RDAP/WHOIS), `fallback` (Tool 2's built-in provider
table — marked honestly), or `unresolved`. Pre-filtering drops garbage
IOCs (pseudo-TLDs: `.dtd`, `.ok`, `.error`, file-name junk), benign
hosts (gmail/youtube/w3 infra), and non-routable IPs (private, CGNAT
100.64/10, documentation ranges). From-domain joins the reported set;
Return-Path/Reply-To-only domains are context-only (verify
ownership before reporting — may be compromised infrastructure).
Missing IOCs or unresolvable contacts → draft still generated with
`RECIPIENT TBD — MANUAL REVIEW`; never crashes (exit 0; exit 2 on
usage errors). Drafts only — nothing is ever sent or submitted.

**Test (2026-10-08 ~12:35 CDT):** `--target all` against one case from
each of the 5 campaigns — all 30 checks passed (defanging: zero raw
`http(s)://`, zero raw phishing IOCs outside To:/signature lines;
verbatim signature on every report; manifest hashes match case.json;
expected recipients present):
- C1 (`c1-icloud-jp-a`): registrar → Metaregistrar/abuse@metaregistrar.com
  (silvi.opencvbd.com), PT Jagoan Hosting/care@jagoanhosting.id
  (bsgvo.my.id); apple-icloud → abuse@icloud.com for kyla.pike@icloud.com.
- C2 (`c2-before-deletion`): gmail-abuse names
  alexescarry18[@]gmail[.]com; hosting → AWS
  (trustandsafety@support.aws.com) + Google
  (network-abuse@google.com).
- C3 (`c3-lowes-ovh`): hosting → OVH/abuse@ovh.net; registrar →
  RECIPIENT TBD for figijcsjs.us (known .us RDAP failure, Tool 2).
- C4 (`c4-alert-kit-1`): registrar → IONOS/abuse@ionos.com
  (sinnatcon.info); hosting → HostPapa/net-abuse-global@hostpapa.com
  (96.44.154.88).
- C5 (`c5-subdomain-spoof-1`): registrar → Tucows/domainabuse@tucows.com
  (tinyurl.com), admin@rna.id (morinproject.my.id).
Robustness: empty case → 5 TBD drafts, exit 0; bad case dir / bad
target → exit 2. `--cluster` cites `kit:alert-151-40575` volume
(9 messages, cohesion 0.94) inside the C4 report.

---

## Tool 4 — `track.py`: takedown tracker

Tracks abuse-report drafts from filing through acknowledgment to
resolution, and computes quotable kill-rate stats for the resume.

**Run:**
```
track.py init --campaign LABEL [--cluster clusters.json]
track.py import-reports --campaign LABEL --case-dir DIR [--case-dir DIR ...]
track.py send --campaign LABEL --report-id ID [--at ISO-8601]
track.py ack --campaign LABEL --report-id ID [--at ISO-8601] [--note TEXT]
track.py resolve --campaign LABEL --report-id ID --outcome {taken-down,no-action,partial,escalated} [--at ISO-8601] [--evidence TEXT]
track.py show --campaign LABEL
track.py stats [--campaign LABEL]
```
- `init`: create `cases/_tracking/<sanitized-label>.json`; `--cluster`
  seeds `members[]` from the cluster.py JSON campaign whose label
  matches exactly. Refuses to overwrite an existing file (exit 2).
- `import-reports`: scan `<case-dir>/analysis/abuse/*-report.txt`
  (each `--case-dir` may be a single case dir or a parent of case
  dirs — auto-detected); parse target (from the filename), `To:` /
  `Recipient:` line, contact-confidence, case slug, subject; add each
  as `status=draft`. Duplicates skipped by absolute report-file path;
  IDs (`R1`, `R2`, …) are stable across re-imports.
- `send` / `ack` / `resolve`: `draft → sent → acknowledged → resolved`
  (sent may resolve directly). Drafts can never be acked or resolved.
  `--at` defaults to now (UTC ISO-8601); unknown IDs, bad timestamps,
  and illegal transitions are rejected with a clear error, exit 2.
- `show`: human-readable campaign ledger — members, every report with
  ID, status, target, recipient, confidence, timestamps, outcome.
- `stats`: reports filed (sent+), acknowledgments, confirmed kills
  (`outcome=taken-down`), kill rate % = kills / filed, plus a
  per-target-type breakdown. With no `--campaign`, prints every
  campaign then an ALL CAMPAIGNS aggregate — clean, copy-pasteable
  resume numbers.

**Reads:** report-gen.py drafts (header block only — first 40 lines —
so quoted body text can't spoof parsed fields); `--cluster` reads a
cluster.py `--json`.

**Writes:** one JSON per campaign at
`cases/_tracking/<sanitized-label>.json`
(`kit:alert-151-40575` → `kit_alert-151-40575.json`):
`{campaign, members[], reports[], created_at, updated_at}`. Each
report:
`{id, target, to, contact_confidence, report_file, case_slug,
case_dir, subject, status, sent_at, ack_at, ack_note, resolved_at,
outcome, outcome_evidence, imported_at}`. Atomic writes
(temp file + `os.replace`); `updated_at` bumped on every mutation.
Per-message case directories are never touched.

**Behavior notes:** metadata only — nothing is ever sent, filed, or
submitted. A corrupt tracking file is a hard error (exit 2) naming the
file — it is never silently overwritten or repaired. Timestamps accept
any ISO-8601 the stdlib parses (trailing `Z` OK). Exit 2 on all
usage/state/corrupt-file errors; 0 otherwise.

**Test (2026-10-08 ~12:35–12:45 CDT):** all 5 harvested campaigns
initialized (4 labels from `cluster.py cases/ --min-size 1 --json`;
C3 has no cluster label, so it was initialized as
`singleton:c3-lowes-ovh` with no `--cluster` seeding). `import-reports`
over every member case dir: 31 drafts imported (6+7+6+7+5 — the exact
tool-3 output), duplicate re-import adds 0 and renumbers nothing. Two
reports walked the full lifecycle
(draft→sent→ack→resolved taken-down) with explicit `--at` timestamps;
7 illegal-transition/state checks all rejected with exit 2 and clear
messages (ack a draft, resolve a draft, re-send a resolved report,
unknown ID `R99` listing the valid IDs, malformed `--at`, re-`init`
of an existing campaign, unknown `--cluster` label listing the
available ones). A deliberately corrupted tracking file errored
cleanly (exit 2) and was left byte-identical on disk. `stats` math
verified by hand against the raw JSON: 2 filed / 2 acked / 2 kills =
100.0%, with the per-target split (registrar 1/1, apple-icloud 1/1)
matching. NOTE: the two resolved records are synthetic test
walkthroughs (the drafts were never actually sent) — re-`init` the
campaigns (delete the `_tracking` files first) for real-world numbers.

---
---

## Tool 5 — `ingest.py`: auto-ingest orchestrator

The final tool and the pipeline's orchestrator. Polls Gmail for new
likely-phish, acquires and analyzes each one through the ScamIntel
evidence pipeline, clusters everything, drafts abuse reports for new
cluster members, and queues them as DRAFTS for human review.

**Run:**
```
ingest.py poll [--days N] [--max N] [--dry-run]
ingest.py status
```
- `poll --days N`: look-back window in days (default 7).
- `poll --max N`: candidate cap per account after unioning all queries
  (default 50).
- `poll --dry-run`: run the queries, list what WOULD be ingested
  (new / already-processed / case-exists / self-mail-skip), change
  nothing — no .eml saves, no cases, no state, no run log.
- `status`: watermark per account (last poll, candidate count,
  processed-ID count) plus the last run-log summary.

**Poll queries** (from `phish-harvest-2026-10-08.md`): Spam and Trash
sweeps first (highest precision under the `--max` cap), then lure
queries — account-suspended, verify, delivery-failed, invoice,
password-expiring, before-deletion. Lure queries carry
`-category:promotions` to cut marketing noise. Every query gets
`newer_than:{days}d` appended and runs per connected Gmail account.

**Per-candidate flow:** metadata fetch → triage (skip LT's own mail:
SENT/DRAFT label or From matching a connected account address — his
filed abuse reports match lure words) → dedupe (watermarked message ID
*or* an existing case dir for that ID — re-acquired messages pollute
clusters, so an ID is never processed twice) → full fetch (the raw
Gmail API bytes, identical to what pipeline `collect` acquires) →
write-once `.eml` in `inbox/YYYY-MM-DD/<id>.eml` (skipped if the file
exists) → `process_message()` from `email-phish-takedown-2.2.py`,
loaded as a module (the exact `collect` code path, not a
reimplementation; same pattern as `termux-collect.py`) into `cases/`.

**Downstream orchestration (every poll):** one `cluster.py` pass over a
merged input — symlinks to every case dir plus inbox `.eml` files that
have *no* case dir yet (a message is never fed twice; duplicate
.eml+case inputs created phantom size-2 "clusters") — then
`report-gen.py --target all --cluster` for every NEW cluster member,
then `track.py init` (new campaigns only) + `import-reports`, so every
draft lands with `status=draft`.

**Reads:** Gmail via `hatch_gws_cli` (`users.messages.list` and
`users.messages.get` only); `cases/*/case.json` (dedupe index);
`.ingest-state.json`.

**Writes:** `inbox/YYYY-MM-DD/<id>.eml` (write-once); `cases/`
(pipeline case dirs); `.cache/ingest-cluster/` (symlink input dir) and
`.cache/ingest-clusters.json`; `cases/_tracking/*.json` (drafts only);
`.ingest-state.json` (per-account watermark: last poll, candidate
count, processed message IDs, capped at 10,000); `.ingest-runs.log`
(one JSON object per run: timestamp, candidates, new cases, clusters,
drafts queued, errors + error details).

**Hard rules (enforced):** read-only on the mailbox — `list` and `get`
are the only Gmail methods ever called; no label changes, deletes,
read-marking, or trashing. `track.py` is only ever invoked as
`init`/`import-reports` — `send`/`ack`/`resolve` are never called by
this tool, so nothing is ever auto-sent. One failing message never
kills the run: the error goes to stderr and the run log, the message's
ID is still watermarked (never retried blindly), and the run continues;
`poll` exits 0 with an `errors` count. Every network-facing call
carries a timeout (60s list, 120s get, 300s cluster, 900s report-gen,
120s track).

**Behavior notes:** slugs are `ingest-<subject-head>-<id8>` (the
pipeline appends its case-ID hash, so uniqueness is guaranteed).
Singletons get no reports (no campaign context yet) and are noted in
the run log. On Termux (no `hatch_gws_cli`), `poll` fails fast with a
pointer to `termux-collect.py`; everything else is pure stdlib.

**Test (2026-10-08 ~12:40–13:00 CDT, live Gmail):** `--dry-run`
proved the query path (16 candidates across all 4 accounts, LT's own
abuse-report emails correctly triaged as self-mail-skip). Bounded live
`poll --days 2 --max 5`: first run hit a real bug (see BUILD-NOTES),
fixed, re-ran clean — 11 candidates → 11 cases + 11 `.eml` files,
0 errors; cluster found 3 messages sharing the C1 abusive iCloud
`Return-Path` (`kyla.pike@icloud.com`) under *new* lures (fake Indeed
recruiter, fake Paramount+ "return", "Meeting / Invitation") — genuine
campaign evolution the pipeline caught the same day; their 24 drafts
were re-attributed to the real `rp:kyla.pike@icloud.com` campaign
(status=draft, human review). Junk campaigns the test runs created
(marketing-ESPs cluster, romance-spam pairs, a Drive-share
notification) were trashed (recoverable, 30-day expiry). Final
`--dry-run`: 16 candidates, 0 would ingest, 16 already processed —
dedupe proven. A genuine new arrival mid-test (Drive share
notification) was ingested end-to-end on the next poll, proving the
steady state.

---

## Appendix — `jq` playbook for `cluster.py --json` output

`jq` (`pkg install jq` on Termux, preinstalled on most desktop Linux)
is the fastest way to interrogate a clustering run. All recipes below
were verified 2026-10-08 against real `cluster.py --json` output.
Schema paths used: `.clusters[].markers[]` (`.type`, `.value`,
`.evidence.members[]`), `.clusters[].kit_flags[]` (`.type`,
`.members[]`), `.clusters[].evidence.dkim_selectors[]`.

**1. List clusters by size (biggest first):**
```bash
jq -r '.clusters | sort_by(-.size)[] | "\(.size)\t\(.label)\tcohesion=\(.cohesion)"' clusters.json
```

**2. Show members carrying a given kit flag** (e.g. `mailer_script`):
```bash
jq -r '.clusters[]
  | select([.kit_flags[].type] | index("mailer_script"))
  | "\(.label): " + ([.kit_flags[] | select(.type=="mailer_script") | .members[]] | join(", "))' clusters.json
```
Swap the flag name for any kit-flag type: `spoofed_xmailer_mismatch`,
`from_return_path_mismatch`, `zero_width_space`, `homoglyph_<block>`.

**3. Extract all clustered URL paths** (CAUTION: these are live,
clickable IOCs — not defanged; handle per OpSec):
```bash
jq -r '.clusters[].markers[] | select(.type=="url_path") | .value' clusters.json | sort -u
```

**4. Find clusters containing a given IOC** (domain, IP, selector…):
```bash
jq --arg ioc "digitaloceanspaces" -r \
  '.clusters[] | select(.markers | map(.value) | join(" ") | contains($ioc)) | "\(.label) (size=\(.size))"' clusters.json
```

**5. Dump DKIM selectors seen per cluster** (infrastructure linkage):
```bash
jq -r '.clusters[] | "\(.label): " + (.evidence.dkim_selectors | join(", "))' clusters.json
```
