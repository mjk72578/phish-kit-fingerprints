#!/usr/bin/env python3
"""
report-gen.py 1.0.2 — ScamIntel TOOL 3/5: abuse-report generator.

Takes a ScamIntel case directory and drafts professional abuse reports
for the chosen recipient type(s), resolving the right abuse contacts
via abuse-resolve.py (TOOL 2) and defanging every IOC so the drafts
are safe to read, paste, and file.

Runs anywhere: desktop Linux and Termux (pure stdlib).

Pipeline position: TOOL 3 of 5
    cluster.py -> abuse-resolve.py -> report-gen.py (this) -> tracker
    -> auto-ingest
Consumes a ScamIntel case dir (case.json + analysis/*.json; schemas
documented in the tool docstrings) and optionally a cluster.py --json
for campaign volume context.

Usage:
    report-gen.py <case-dir> --target {registrar,hosting,
        google-safe-browsing,apple-icloud,gmail-abuse,all} [--out DIR]
    report-gen.py <case-dir> --target all --cluster clusters.json

    <case-dir>  ScamIntel case directory (or a path to its case.json).
    --target    Which report(s) to draft. "all" drafts all five.
    --out DIR   Write reports to DIR instead of
                <case-dir>/analysis/abuse/.
    --cluster   cluster.py --json file: if this case belongs to a
                cluster, the reports cite campaign volume
                (member count, cohesion, label).

Target types:
    registrar            Abuse desk of each phishing domain's registrar
                         (resolved by abuse-resolve.py). Requested
                         action: suspend the registrant account / put
                         the domain on hold.
    hosting              Abuse desk of the hosting provider behind each
                         phishing IP and each phishing domain's A
                         record. Requested action: take down the
                         content, suspend the account, null-route the
                         IP if dedicated.
    google-safe-browsing Form-ready text for Google's Safe Browsing
                         phishing-page report form (no recipient —
                         it is a web form, so the draft lists the
                         defanged URLs to paste).
    apple-icloud         Abuse path for abusive iCloud accounts used
                         as senders/return-paths. Requested action:
                         terminate the abusive iCloud account.
    gmail-abuse          Report text for abusive Gmail senders
                         (Gmail's abuse flow is in-product / via
                         Google's phishing report form; the draft is
                         the text to file).

Output: one .txt per target type, written to
<case-dir>/analysis/abuse/<target>-report.txt (or --out DIR).
Existing files are never overwritten — a numeric suffix is added
(e.g. registrar-report-2.txt). Stdout prints a summary: which files
were written and for whom (contact + contact-confidence).

Defanging: every IOC (URL, domain, IP, email) is defanged before it
touches a report: dots -> [.], http -> hxxp, @ -> [@]. The signature
block and the evidence-manifest identifiers (case_id, message_id,
hashes) are NOT defanged — hashes are hex, and the signature must
stay verbatim.

Contact confidence: each recipient is labeled
    authoritative — contact came from RDAP/WHOIS records
    fallback      — RDAP/WHOIS named the provider but gave no
                    contact, so the published provider abuse desk
                    from tool 2's built-in table is used (marked
                    honestly in the draft and on stdout)

Garbage IOCs (no real TLD: "xhtml1-strict.dtd", "progress-node.ok",
bare file names) are pre-filtered before resolution; known-benign
hosts (gmail.com as infrastructure, youtube.com, w3.org, ...) are
excluded from the phishing IOC lists. Missing IOCs or unresolvable
contacts never crash the run — the draft is still generated with a
"RECIPIENT TBD — MANUAL REVIEW" header.

Safety: drafts only. This tool writes text files and resolves public
registration data — it never sends, submits, or files anything.
Every draft opens with "HUMAN REVIEW REQUIRED".
"""

import argparse
import importlib.util
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

VERSION = "1.0.2"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ABUSE_RESOLVE = os.path.join(SCRIPT_DIR, "abuse-resolve.py")

# R5 (hardening 2026-10-08): shared primitives (addr parsing, defang)
# live in _scamintel_util.py — single source of truth.
try:
    import _scamintel_util as _util
except ImportError:
    sys.path.insert(0, SCRIPT_DIR)
    import _scamintel_util as _util

SIGNATURE = (
    "Miles Jason Kimmons\n"
    "Owner/Operator, KDI Custom Builds (Licensed, TN)\n"
    "mjk72578@gmail.com"
)

TARGETS = ("registrar", "hosting", "google-safe-browsing",
           "apple-icloud", "gmail-abuse")

# Hosts that are infrastructure/reference noise, never phishing IOCs.
_BENIGN_HOSTS = frozenset([
    "gmail.com", "googlemail.com",
    "youtube.com", "www.youtube.com", "youtu.be",
    "nuclino.com", "www.nuclino.com",
    "w3.org", "www.w3.org",
    "edmundoptics.com", "edmundoptics.mx",
    "amazon.co.jp", "www.amazon.co.jp",
])

# The reporter's own address — never listed as an abusive sender.
_REPORTER_ADDR = "mjk72578@gmail.com"

# Pseudo-TLDs that are file names, placeholders, or kit junk — never real
# registries. abuse-resolve.py's classify() already rejects its own
# _FILE_EXT_TLDS list; these are the extra ones we have met in the wild
# ("xhtml1-strict.dtd" from HTML doctypes, "progress-node.ok/.error").
_GARBAGE_TLDS = frozenset([
    "dtd", "ok", "error", "localhost", "local", "invalid", "example",
    "test", "internal", "lan", "home", "corp", "intranet",
])

# Registrable domains that ARE the infrastructure provider. A registrar
# report against these is noise (the provider is its own registrar
# customer) — the abuse path is the hosting target instead.
_INFRA_DOMAINS = {
    "googleapis.com": ("Google Cloud", "abuse@google.com"),
    "digitaloceanspaces.com": ("DigitalOcean", "abuse@digitalocean.com"),
    "amazonaws.com": ("Amazon Web Services", "abuse@amazonaws.com"),
    "cloudfront.net": ("Amazon Web Services", "abuse@amazonaws.com"),
}


# ---------------------------------------------------------------------------
# small utilities
# ---------------------------------------------------------------------------

def warn(msg):
    sys.stderr.write("report-gen.py: warning: %s\n" % msg)


def load_json(path):
    """Parsed JSON or None (stderr warning) on failure."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        warn("could not parse %s (%s)" % (path, exc))
        return None


def defang(text):
    """Render an IOC unclickable (R5: canonical impl in _scamintel_util)."""
    return _util.defang(text)


_ADDR_RE = _util.ADDR_RE


def strip_addr(raw):
    """Pull the bare addr-spec out (R5: canonical impl in _scamintel_util)."""
    return _util.strip_addr(raw)


# ---------------------------------------------------------------------------
# abuse-resolve.py as a library (import; shell-out fallback)
# ---------------------------------------------------------------------------

def _import_abuse_resolve():
    """Return the abuse-resolve module, or None if it cannot be imported."""
    try:
        spec = importlib.util.spec_from_file_location(
            "abuse_resolve", ABUSE_RESOLVE)
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception as exc:  # broken file, syntax change, ...
        warn("could not import abuse-resolve.py (%s)" % exc)
        return None


def _resolve_via_subprocess(inputs):
    """Fallback: shell out to abuse-resolve.py --json. Returns results.

    R4: --no-sleep is passed only for small runs (<=10 inputs); bulk runs
    keep tool 2's courtesy pauses.
    """
    with tempfile.NamedTemporaryFile("w", suffix=".json",
                                     delete=False) as fh:
        out = fh.name
    try:
        cmd = [sys.executable, ABUSE_RESOLVE]
        if len(inputs) <= 10:
            cmd.append("--no-sleep")
        cmd += ["--json", out] + inputs
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=600)
        if proc.returncode not in (0,):
            warn("abuse-resolve.py exited %d: %s"
                 % (proc.returncode, proc.stderr[-300:]))
        data = load_json(out)
        if isinstance(data, dict):
            return data.get("results", [])
    except Exception as exc:
        warn("abuse-resolve subprocess failed (%s)" % exc)
    finally:
        try:
            os.unlink(out)
        except OSError:
            pass
    return []


def resolve_contacts(inputs, timeout=10.0):
    """Resolve abuse contacts for inputs via abuse-resolve.py.

    Prefers importing it as a module (no process spawn); falls back to
    shelling out. Returns the tool-2 results list (frozen schema).
    A per-input failure never raises — it yields an "unknown" result.
    """
    inputs = [i for i in inputs if i]
    if not inputs:
        return []
    mod = _import_abuse_resolve()
    if mod is not None:
        try:
            # R4 (hardening 2026-10-08): tool 2's courtesy sleeps are
            # bypassed here ONLY for small runs (a handful of IOCs from
            # one case). Bulk runs (>10 inputs, e.g. --cluster over many
            # cases) keep the sleeps to avoid hammering RDAP/WHOIS.
            # The tradeoff is deliberate and documented here.
            mod.Options.timeout = timeout
            mod.Options.sleep = len(inputs) > 10
            cache = mod.load_cache(mod.DEFAULT_CACHE)
            results = []
            for raw in inputs:
                try:
                    results.append(mod.resolve_one(
                        raw, cache, mod.DEFAULT_CACHE, refresh=False))
                except Exception as exc:
                    warn("resolution failed for %r (%s: %s)"
                         % (raw, type(exc).__name__, str(exc)[:100]))
                    results.append(_unknown_result(raw, exc))
            return results
        except Exception as exc:
            warn("module-path resolution failed (%s); trying subprocess" % exc)
    return _resolve_via_subprocess(inputs)


def _unknown_result(raw, exc):
    return {"input": raw, "kind": "unknown",
            "registrar": {"name": None, "abuse_email": None,
                          "abuse_url": None},
            "hosting": {"provider": None, "asn": None,
                        "abuse_email": None, "abuse_url": None},
            "cached": False,
            "resolved_at": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"),
            "notes": "resolution error: %s: %s"
                     % (type(exc).__name__, str(exc)[:120])}


# ---------------------------------------------------------------------------
# sender authentication (R3 hardening 2026-10-08)
# ---------------------------------------------------------------------------

def _parse_auth(raw):
    """Pull sender-identity fields out of Authentication-Results raw text safely."""
    raw = raw or ""
    # Strip RFC 5322 folding whitespace (\r\n followed by space/tab).
    raw = re.sub(r"\r?\n[ \t]+", " ", raw)
    # LT final review: obliterate ALL parentheses instead of regexing
    # comments — nested comments "(a (b) c)" defeat \([^)]*\). Parens have
    # no syntactic role in Authentication-Results key=value pairs, and
    # domains can never contain them, so this is safe.

    out = {"mailfrom_domain": "", "dkim_domain": "", "header_from": "",
           "spf": "", "dkim": "", "dmarc": ""}
    m = re.search(r"smtp\.mailfrom=([^\s;<>]+)", raw, re.I)
    if m:
        addr = m.group(1).strip()
        out["mailfrom_domain"] = addr.rsplit("@", 1)[-1].lower() if "@" in addr else addr.lower()

    m = re.search(r"dkim=pass[^;]*?header\.i=@([^\s;<>]+)", raw, re.I)
    if m:
        out["dkim_domain"] = m.group(1).lower()
    else:
        m = re.search(r"header\.i=@([^\s;<>]+)", raw, re.I)
        if m:
            out["dkim_domain"] = m.group(1).lower()

    m = re.search(r"header\.from=([^\s;<>]+)", raw, re.I)
    if m:
        out["header_from"] = m.group(1).lower()

    for field in ("spf", "dkim", "dmarc"):
        m = re.search(r"\b%s=(\w+)" % field, raw, re.I)
        if m:
            out[field] = m.group(1).lower()
    return out


def from_domain_authenticated(from_dom, auth, mod):
    """True when the From domain is the authenticated sender identity.

    Alignment = From domain matches the SPF envelope-from (smtp.mailfrom)
    domain or the passing DKIM d= (header.i) domain, compared at the
    registrable-domain level. A spoofed From (e.g. support@paypal.com via
    an unrelated relay) fails this check and must NOT go on the
    registrar-report list blindly.
    Returns False when alignment cannot be confirmed (missing data included)
    — the safe direction.
    """
    if not from_dom or not auth:
        return False
    reg = (lambda h: mod.registrable_domain(h)) if mod else (lambda h: h)
    try:
        from_reg = reg(from_dom)
    except Exception:
        return False
    for key in ("mailfrom_domain", "dkim_domain"):
        dom = auth.get(key, "")
        if not dom:
            continue
        try:
            if reg(dom) == from_reg:
                return True
        except Exception:
            continue
    return False


# ---------------------------------------------------------------------------
# case loading + IOC filtering
# ---------------------------------------------------------------------------

def find_case_dir(path):
    """Accept a case dir or a case.json path; return the case dir."""
    p = os.path.normpath(path)
    if os.path.isfile(p) and os.path.basename(p).lower() == "case.json":
        return os.path.dirname(p) or "."
    if os.path.isdir(p) and os.path.exists(os.path.join(p, "case.json")):
        return p
    return None


def load_case(case_dir):
    """Return (case_meta, iocs, headers_meta, url_hosts, senders, auth).

    auth holds the parsed Authentication-Results sender-identity fields
    used by the R3 From-domain alignment check ({} when unavailable).
    """
    cj = load_json(os.path.join(case_dir, "case.json")) or {}
    analysis = os.path.join(case_dir, "analysis")

    iocs = load_json(os.path.join(analysis, "iocs.json")) or {}
    domains = [str(d) for d in (iocs.get("domains") or [])]
    ips = [str(i) for i in (iocs.get("ips") or [])]
    urls = [str(u) for u in (iocs.get("urls") or [])]
    emails = [str(e) for e in (iocs.get("emails") or [])]

    hj = load_json(os.path.join(analysis, "headers.json")) or {}
    meta = hj.get("metadata", {}) or {}
    senders = {}
    for key in ("from", "return_path", "reply_to", "sender"):
        addr = strip_addr(meta.get(key, ""))
        if addr:
            senders[key] = addr
    url_hosts = []
    uj = load_json(os.path.join(analysis, "urls.json")) or {}
    for u in (uj.get("urls") or []):
        host = ((u.get("static") or {}).get("hostname") or "").lower()
        if host:
            url_hosts.append(host)
            full = u.get("url") or ""
            if full and full not in urls:
                urls.append(full)

    auth = {}
    ar = hj.get("authentication_results") or {}
    if isinstance(ar, dict):
        auth = _parse_auth(ar.get("raw", ""))
        # carry the simple pass/fail fields too when present
        for field in ("spf", "dkim", "dmarc"):
            if not auth.get(field) and ar.get(field):
                auth[field] = str(ar[field]).lower()

    return cj, {"domains": domains, "ips": ips, "urls": urls,
                "emails": emails}, meta, senders, url_hosts, auth


def filter_iocs(iocs, senders, url_hosts, mod, auth=None):
    """Pre-filter garbage + benign hosts. Returns clean IOC sets.

    Garbage = things with no real TLD (HTML doctype strings, bare
    file names, placeholder TLDs) — dropped before resolution, per
    tool 2's notes. Benign = known infrastructure/reference hosts.
    Sender domains are added (the phishing domain often lives in
    From/Return-Path, not in iocs.json).

    R3 (hardening 2026-10-08): the From domain joins the report list
    ONLY when SPF/DKIM alignment confirms it as the authenticated
    sender identity. Otherwise it goes to context_domains with the
    ownership warning — a spoofed From must never trigger a registrar
    suspension draft blindly.
    """
    def ok_domain(host):
        host = (host or "").strip().strip(".").lower()
        if not host or host in _BENIGN_HOSTS:
            return None
        if mod is not None:
            host = mod.extract_host(host)
            if mod.classify(host) != "domain":
                return None
        else:
            # stdlib-only fallback: must look like host.tld
            if not re.match(r"^(?=.{1,253}\.?$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
                            r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$", host):
                return None
            tld = host.rsplit(".", 1)[-1]
            if not tld.isalpha() or len(tld) < 2:
                return None
        # garbage pseudo-TLDs (doctype strings, kit placeholders, ...)
        if host.rsplit(".", 1)[-1] in _GARBAGE_TLDS:
            return None
        return host

    def ok_ip(ip):
        # Only globally routable addresses survive: private, CGNAT
        # (100.64/10), loopback, link-local, documentation, and other
        # reserved ranges are extraction noise, not infrastructure.
        ip = (ip or "").strip()
        if not ip:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if not addr.is_global:
            return None
        return str(addr)

    domains, ips, urls = [], [], []
    context_domains = []
    seen_d, seen_i, seen_u, seen_c = set(), set(), set(), set()

    def reg_root(host):
        return mod.registrable_domain(host) if mod else host

    def add_domain(h):
        if h and h not in seen_d:
            seen_d.add(h)
            domains.append(h)

    for d in iocs["domains"]:
        add_domain(ok_domain(d))
    for h in url_hosts:
        add_domain(ok_domain(h))
    # The From domain is the phisher's asserted identity — reported ONLY
    # when sender authentication confirms it (R3). Otherwise it is
    # context: it may be a spoofed brand domain whose registrar must
    # NOT receive a suspension draft without a human ownership check.
    reported_roots = {reg_root(d) for d in domains}
    from_addr = senders.get("from", "")
    from_dom = None
    if "@" in from_addr:
        from_dom = ok_domain(from_addr.rsplit("@", 1)[-1])
    if from_dom:
        if from_domain_authenticated(from_dom, auth or {}, mod):
            add_domain(from_dom)
            reported_roots = {reg_root(d) for d in domains}
        elif (from_dom not in seen_c
                and reg_root(from_dom) not in reported_roots):
            seen_c.add(from_dom)
            context_domains.append(from_dom)
    # Return-Path / Reply-To / Sender roots that are NOT already covered
    # are context only: they may be compromised infrastructure or relay
    # chains, and drafting a registrar suspension against them needs a
    # human ownership check first.
    for key, addr in senders.items():
        if key == "from" or "@" not in addr:
            continue
        h = ok_domain(addr.rsplit("@", 1)[-1])
        if h and reg_root(h) not in reported_roots and h not in seen_c:
            seen_c.add(h)
            context_domains.append(h)

    for ip in iocs["ips"]:
        v = ok_ip(ip)
        if v and v not in seen_i:
            seen_i.add(v)
            ips.append(v)

    for u in iocs["urls"]:
        u = (u or "").strip()
        if not u:
            continue
        host = ok_domain(re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "",
                                u).split("/")[0].split("?")[0])
        if host and u not in seen_u:
            seen_u.add(u)
            urls.append(u)

    emails = []
    seen_e = set()
    for e in list(iocs["emails"]) + list(senders.values()):
        e = strip_addr(e).lower()
        if e and e not in seen_e and e != _REPORTER_ADDR:
            seen_e.add(e)
            emails.append(e)

    return {"domains": domains, "context_domains": context_domains,
            "ips": ips, "urls": urls, "emails": emails}


# ---------------------------------------------------------------------------
# contact confidence
# ---------------------------------------------------------------------------

def confidence_of(result):
    """authoritative (RDAP/WHOIS) vs fallback (built-in provider table)."""
    notes = (result.get("notes") or "").lower()
    if "fallback" in notes:
        return ("fallback",
                "published provider abuse desk — RDAP/WHOIS named the "
                "provider but gave no contact")
    return ("authoritative", "contact from RDAP/WHOIS records")


def contact_line(result, which):
    """(display_name, email, url, confidence_tag, confidence_detail)."""
    blk = result.get(which) or {}
    name = blk.get("name") or blk.get("provider") or "unknown"
    email = blk.get("abuse_email")
    url = blk.get("abuse_url")
    tag, detail = confidence_of(result)
    return name, email, url, tag, detail


# ---------------------------------------------------------------------------
# lure characterization
# ---------------------------------------------------------------------------

_BRAND_HINTS = [
    ("lowe", "Lowe's"),
    ("kobalt", "Lowe's/Kobalt"),
    ("google", "Google"),
    ("icloud", "Apple iCloud"),
    ("apple", "Apple"),
    ("amazon", "Amazon"),
    ("paypal", "PayPal"),
    ("microsoft", "Microsoft"),
    ("delivery", "parcel-delivery"),
    ("配送", "parcel-delivery (Japanese-language)"),
    ("free spins", "casino / free-spins"),
    ("billing", "cloud-billing"),
    ("payment", "payment"),
    ("blocked your account", "account-suspension"),
]


def describe_lure(meta):
    """One-line lure characterization from subject/from."""
    text = " ".join([meta.get("subject", ""), meta.get("from", "")]).lower()
    for needle, label in _BRAND_HINTS:
        if needle in text:
            return "impersonation / %s lure" % label
    return "unspecified phishing lure"


# ---------------------------------------------------------------------------
# cluster context (optional)
# ---------------------------------------------------------------------------

def cluster_context(cluster_path, case_dir):
    """If the case is a member of a cluster.py --json result, return a
    one-line volume summary; else None."""
    if not cluster_path:
        return None
    data = load_json(cluster_path)
    if not isinstance(data, dict):
        return None
    member_id = os.path.basename(os.path.normpath(case_dir))
    for c in data.get("clusters", []) or []:
        members = c.get("members", []) or []
        if any(m.get("member_id") == member_id for m in members):
            return ("campaign volume: cluster '%s' — %d messages, "
                    "cohesion %.2f (cluster.py %s)"
                    % (c.get("label", "?"), c.get("size", len(members)),
                       c.get("cohesion", 0.0),
                       data.get("version", "?")))
    for s in data.get("singletons", []) or []:
        if s.get("member_id") == member_id:
            return ("campaign volume: singleton in clustering run — no "
                    "shared kit markers with other messages")
    return None


# ---------------------------------------------------------------------------
# report assembly
# ---------------------------------------------------------------------------

def _manifest(cj):
    return (
        "EVIDENCE MANIFEST\n"
        "  case_id:         %s\n"
        "  slug:            %s\n"
        "  message_id:      %s\n"
        "  evidence_sha256: %s\n"
        "  manifest_sha256: %s\n"
        "  tool_version:    %s\n"
        "  generated:       %s\n"
        "  report_gen:      report-gen.py %s (ScamIntel TOOL 3/5)\n"
        "  report_date:     %s\n"
        % (cj.get("case_id", "?"), cj.get("slug", "?"),
           cj.get("message_id", "?"), cj.get("evidence_sha256", "?"),
           cj.get("manifest_sha256", "?"), cj.get("tool_version", "?"),
           cj.get("generated", "?"), VERSION,
           datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    )


def _incident_summary(meta, cj, cluster_line):
    lines = [
        "INCIDENT SUMMARY",
        "  lure:    %s" % describe_lure(meta),
        "  subject: %s" % (meta.get("subject", "") or "(none)"),
        "  from:    %s" % defang(meta.get("from", "") or "(none)"),
        "  date:    %s" % (meta.get("date", "") or "(none)"),
        "  volume:  %s" % (cluster_line or
                           "single message (no cluster context supplied)"),
    ]
    return "\n".join(lines) + "\n"


def _ioc_section(title, items):
    if not items:
        return "%s\n  (none identified)\n" % title
    out = [title]
    for it in items:
        out.append("  - %s" % defang(it))
    return "\n".join(out) + "\n"


def _recipient_block(name, email, url, conf_tag, conf_detail, tbd_note):
    if email:
        to_line = "To: %s" % email
        conf_line = "Contact confidence: %s — %s" % (conf_tag, conf_detail)
    else:
        to_line = "To: RECIPIENT TBD — MANUAL REVIEW"
        conf_line = ("Contact confidence: unresolved — no abuse contact "
                     "could be resolved; find the recipient manually")
    lines = [to_line, conf_line]
    if url:
        lines.append("Abuse web form: %s" % url)
    if tbd_note:
        lines.append(tbd_note)
    return "\n".join(lines) + "\n"


_HEADER = (
    "HUMAN REVIEW REQUIRED\n"
    "\n"
    "This is a DRAFT only. Nothing has been sent, submitted, or filed.\n"
    "Review every line, verify the recipient, then send it yourself.\n"
    "\n"
)


def _find_domain_result(results, reg_dom, mod):
    return next((r for r in results
                 if (r.get("kind") == "domain" and
                     (mod.registrable_domain(mod.extract_host(r["input"]))
                      if mod else r["input"]) == reg_dom)), None)


def build_registrar(cj, meta, fiocs, results, cluster_line, mod):
    """One draft per registrar contact (deduped across domains).

    Infrastructure-provider domains (googleapis.com, ...) are skipped:
    the provider is its own registrar customer, so the abuse path is
    the hosting target. Sender-only domains that are not otherwise
    reported are listed as context, not drafted against.
    """
    by_contact = {}
    skipped_infra = []
    for dom in fiocs["domains"]:
        reg_dom = mod.registrable_domain(dom) if mod else dom
        if reg_dom in _INFRA_DOMAINS:
            skipped_infra.append(dom)
            continue
        res = _find_domain_result(results, reg_dom, mod)
        if res is None:
            res = {"input": dom, "kind": "domain",
                   "registrar": {"name": None, "abuse_email": None,
                                 "abuse_url": None},
                   "hosting": {}, "notes": "not resolved"}
        name, email, url, tag, detail = contact_line(res, "registrar")
        key = (email or "TBD", name)
        by_contact.setdefault(key, {"name": name, "email": email, "url": url,
                                    "tag": tag, "detail": detail,
                                    "domains": []})
        if dom not in by_contact[key]["domains"]:
            by_contact[key]["domains"].append(dom)

    if not by_contact:
        by_contact[("TBD", "unknown")] = {
            "name": "unknown", "email": None, "url": None,
            "tag": "n/a", "detail": "no reportable domains identified",
            "domains": []}

    sender_addrs = sorted({strip_addr(meta.get(k, "")) for k in
                           ("from", "return_path", "reply_to", "sender")}
                          - {""})

    reports = []
    # R2 (hardening 2026-10-08): sort key tolerates None names — two
    # unresolved contacts sharing the "TBD" email slot used to crash
    # sorted() with TypeError (None < str).
    for key in sorted(by_contact, key=lambda k: (k[0], k[1] or "")):
        info = by_contact[key]
        tbd = ("No registrar abuse contact could be resolved for these "
               "domains — find the registrar's abuse desk manually before "
               "sending.") if not info["email"] else ""
        body = [
            _HEADER,
            "Case: %s" % cj.get("slug", "?"),
            "",
            _recipient_block(info["name"], info["email"], info["url"],
                             info["tag"], info["detail"], tbd),
            "Subject: Phishing domains registered via %s — suspension "
            "requested" % (info["name"] or "your service"),
            "",
            "Abuse team,",
            "",
            "I am reporting domain(s) registered through your service that "
            "are being used in an active phishing campaign.",
            "",
            _incident_summary(meta, cj, cluster_line),
            _ioc_section("REPORTED DOMAINS (defanged):", info["domains"]),
            "Sender addresses observed (defanged):",
        ]
        for s in sender_addrs:
            body.append("  - %s" % defang(s))
        if fiocs["context_domains"]:
            body += [
                "",
                "ADDITIONAL OBSERVED SENDER DOMAINS (defanged — verify "
                "ownership/control before reporting; may be compromised "
                "infrastructure, not attacker-registered):",
            ]
            for d in fiocs["context_domains"]:
                body.append("  - %s" % defang(d))
        if skipped_infra:
            body += [
                "",
                "INFRASTRUCTURE DOMAINS (not reported to registrar — the "
                "provider is its own registrar customer; report content "
                "to the hosting abuse desk instead):",
            ]
            for d in skipped_infra:
                prov, _em = _INFRA_DOMAINS[
                    mod.registrable_domain(d) if mod else d]
                body.append("  - %s  (provider: %s)" % (defang(d), prov))
        body += [
            "",
            "REQUESTED ACTION",
            "  Suspend the registrant account(s) and place the listed "
            "domain(s)",
            "  on registrar hold (clientHold) pending investigation, per "
            "your",
            "  abuse policy. These domains exist solely to harvest "
            "credentials",
            "  and payment data from victims.",
            "",
            _manifest(cj),
            "Regards,",
            SIGNATURE,
            "",
        ]
        reports.append(("\n".join(body),
                        info["email"] or "RECIPIENT TBD — MANUAL REVIEW",
                        info["tag"] if info["email"] else "unresolved"))
    return reports


def build_hosting(cj, meta, fiocs, results, cluster_line, mod):
    """One draft per hosting-provider contact (deduped across IPs)."""
    by_contact = {}

    def add_hosting(res, label):
        name, email, url, tag, detail = contact_line(res, "hosting")
        key = (email or "TBD", name)
        entry = by_contact.setdefault(
            key, {"name": name, "email": email, "url": url, "tag": tag,
                  "detail": detail, "items": []})
        if label not in entry["items"]:
            entry["items"].append(label)

    for ip in fiocs["ips"]:
        res = next((r for r in results
                    if r.get("kind") == "ip" and
                    (mod.extract_host(r["input"]) if mod else r["input"])
                    == ip), None)
        if res is None:
            res = {"input": ip, "kind": "ip",
                   "registrar": {}, "hosting": {"provider": None,
                                               "asn": None,
                                               "abuse_email": None,
                                               "abuse_url": None},
                   "notes": "not resolved"}
        add_hosting(res, "IP %s" % ip)

    for dom in fiocs["domains"]:
        reg_dom = mod.registrable_domain(dom) if mod else dom
        res = _find_domain_result(results, reg_dom, mod)
        if res and (res.get("hosting") or {}).get("provider"):
            add_hosting(res, "domain %s (hosted content)" % dom)

    # Infrastructure-provider domains: the right desk is the provider's
    # abuse team. Marked "inferred" — no DNS/RDAP was needed to know
    # that storage.googleapis.com is Google.
    inferred = []
    for dom in fiocs["domains"]:
        reg_dom = mod.registrable_domain(dom) if mod else dom
        if reg_dom in _INFRA_DOMAINS:
            prov, email = _INFRA_DOMAINS[reg_dom]
            inferred.append((dom, prov, email))

    if not by_contact and not inferred:
        by_contact[("TBD", "unknown")] = {
            "name": "unknown", "email": None, "url": None,
            "tag": "n/a", "detail": "no hosting IOCs identified",
            "items": []}

    reports = []
    # R2 (hardening 2026-10-08): see build_registrar — None-safe sort key.
    for key in sorted(by_contact, key=lambda k: (k[0], k[1] or "")):
        info = by_contact[key]
        tbd = ("No hosting abuse contact could be resolved — identify the "
               "provider manually (WHOIS the IP) before sending.") \
            if not info["email"] else ""
        body = [
            _HEADER,
            "Case: %s" % cj.get("slug", "?"),
            "",
            _recipient_block(info["name"], info["email"], info["url"],
                             info["tag"], info["detail"], tbd),
            "Subject: Phishing content hosted on your infrastructure — "
            "takedown requested",
            "",
            "Abuse team,",
            "",
            "I am reporting phishing infrastructure operating on your "
            "network. The lure was delivered by email and the credential-"
            "harvesting pages are served from the infrastructure below.",
            "",
            _incident_summary(meta, cj, cluster_line),
            _ioc_section("REPORTED HOSTING IOCs (defanged):", info["items"]),
            _ioc_section("PHISHING URLs (defanged):", fiocs["urls"]),
        ]
        if inferred:
            body += [
                "INFRASTRUCTURE-PROVIDER CONTENT (defanged) — report to "
                "the provider's abuse desk, not the registrar:",
                "Contact confidence: inferred — well-known infrastructure "
                "domain (verify the provider's current abuse contact "
                "before sending).",
            ]
            for dom, prov, email in inferred:
                body.append("  - %s  -> %s (%s)" % (defang(dom), prov,
                                                   defang(email)))
            body.append("")
        body += [
            "REQUESTED ACTION",
            "  Remove the phishing content, suspend the hosting account "
            "responsible,",
            "  and null-route the offending IP address if it is dedicated "
            "to this",
            "  activity, per your abuse policy.",
            "",
            _manifest(cj),
            "Regards,",
            SIGNATURE,
            "",
        ]
        reports.append(("\n".join(body),
                        info["email"] or "RECIPIENT TBD — MANUAL REVIEW",
                        info["tag"]))
    return reports


def build_gsb(cj, meta, fiocs, cluster_line):
    """Form-ready text for Google's Safe Browsing phishing-page report."""
    body = [
        _HEADER,
        "Case: %s" % cj.get("slug", "?"),
        "",
        "GOOGLE SAFE BROWSING — PHISHING PAGE REPORT (form-ready text)",
        "",
        "Recipient: none — file via Google's \"Report a phishing page\" "
        "form",
        "(Safe Browsing). Paste the URL list below into the form.",
        "",
        _incident_summary(meta, cj, cluster_line),
        _ioc_section("PHISHING URLs TO REPORT (defanged — re-arm before "
                     "pasting into the form):", fiocs["urls"]),
        _ioc_section("PHISHING DOMAINS (defanged):", fiocs["domains"]),
        "NOTES FOR THE FORM",
        "  Lure: %s" % describe_lure(meta),
        "  The pages above harvest credentials / payment data. The email "
        "lure",
        "  impersonates a trusted brand to drive victims to these URLs.",
        "",
        _manifest(cj),
        "Regards,",
        SIGNATURE,
        "",
    ]
    return [("\n".join(body), "Google Safe Browsing web form (no email)",
             "n/a")]


def build_apple(cj, meta, fiocs, cluster_line):
    """Abuse path for abusive iCloud accounts (senders/return-paths)."""
    icloud_addrs = sorted({a for a in fiocs["emails"]
                           if a.endswith("@icloud.com")})
    if icloud_addrs:
        # R1 (hardening 2026-10-08): Apple's working phishing-report desk
        # is reportphishing@apple.com — verified live 2026-10-08 after
        # abuse@icloud.com / reportphish@apple.com both bounced.
        to_line = ("To: reportphishing@apple.com "
                   "(Apple's phishing-report desk — verified working "
                   "2026-10-08; confirm at support.apple.com if unsure)")
        conf = ("verified 2026-10-08 — reportphishing@apple.com is Apple's "
                "phishing report address")
        tbd = ""
    else:
        to_line = "To: RECIPIENT TBD — MANUAL REVIEW"
        conf = "n/a"
        tbd = ("No abusive iCloud account was identified in this case — "
               "this draft is a placeholder. Do not send as-is.")
    body = [
        _HEADER,
        "Case: %s" % cj.get("slug", "?"),
        "",
        to_line,
        "Contact confidence: %s" % conf,
    ]
    if tbd:
        body.append(tbd)
    body += [
        "",
        "Subject: Abusive iCloud account used for phishing — termination "
        "requested",
        "",
        "Apple abuse team,",
        "",
        "I am reporting iCloud account(s) being used to send phishing "
        "email. The account(s) appear in the sender / return-path of "
        "messages whose sole purpose is credential theft.",
        "",
        _incident_summary(meta, cj, cluster_line),
        _ioc_section("ABUSIVE ICLOUD ACCOUNTS (defanged):", icloud_addrs),
        _ioc_section("PHISHING URLs (defanged):", fiocs["urls"]),
        "REQUESTED ACTION",
        "  Terminate the abusive iCloud account(s) and block further "
        "phishing",
        "  sends from them, per your acceptable-use policy.",
        "",
        _manifest(cj),
        "Regards,",
        SIGNATURE,
        "",
    ]
    return [("\n".join(body),
             "reportphishing@apple.com" if icloud_addrs
             else "RECIPIENT TBD — MANUAL REVIEW",
             "verified 2026-10-08" if icloud_addrs else "n/a")]


def build_gmail(cj, meta, fiocs, cluster_line):
    """Report text for abusive Gmail senders."""
    gmail_addrs = sorted({a for a in fiocs["emails"]
                          if a.endswith(("@gmail.com", "@googlemail.com"))})
    if gmail_addrs:
        to_line = ("To: (no direct Gmail abuse email — file via Gmail's "
                   "\"Report phishing\" button or Google's phishing "
                   "report form; text below is ready to paste)")
        conf = "n/a — Gmail abuse is filed in-product, not by email"
        tbd = ""
    else:
        to_line = "To: RECIPIENT TBD — MANUAL REVIEW"
        conf = "n/a"
        tbd = ("No abusive Gmail sender was identified in this case — "
               "this draft is a placeholder. Do not send as-is.")
    body = [
        _HEADER,
        "Case: %s" % cj.get("slug", "?"),
        "",
        to_line,
        "Contact confidence: %s" % conf,
    ]
    if tbd:
        body.append(tbd)
    body += [
        "",
        "GMAIL PHISHING REPORT (form-ready text)",
        "",
        "I am reporting Gmail account(s) used to send phishing email.",
        "",
        _incident_summary(meta, cj, cluster_line),
        _ioc_section("ABUSIVE GMAIL SENDERS (defanged):", gmail_addrs),
        _ioc_section("PHISHING URLs (defanged):", fiocs["urls"]),
        "REQUESTED ACTION",
        "  Suspend the abusive Gmail account(s) for phishing, per "
        "Google's",
        "  acceptable-use policy.",
        "",
        _manifest(cj),
        "Regards,",
        SIGNATURE,
        "",
    ]
    return [("\n".join(body),
             "Gmail in-product report flow" if gmail_addrs
             else "RECIPIENT TBD — MANUAL REVIEW",
             "n/a")]


# ---------------------------------------------------------------------------
# file writing
# ---------------------------------------------------------------------------

def unique_path(path):
    """Never overwrite an existing draft — add a numeric suffix."""
    if not os.path.exists(path):
        return path
    base, ext = os.path.splitext(path)
    n = 2
    while os.path.exists("%s-%d%s" % (base, n, ext)):
        n += 1
    return "%s-%d%s" % (base, n, ext)


def write_reports(out_dir, target, reports):
    """Write (text, recipient, confidence) tuples. Returns file paths."""
    paths = []
    for idx, (text, recipient, conf) in enumerate(reports):
        if len(reports) == 1:
            fname = "%s-report.txt" % target
        else:
            fname = "%s-report-%d.txt" % (target, idx + 1)
        path = unique_path(os.path.join(out_dir, fname))
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            paths.append((path, recipient, conf))
        except OSError as exc:
            warn("could not write %s (%s)" % (path, exc))
    return paths


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="report-gen.py",
        description="ScamIntel TOOL 3/5: draft abuse reports for a "
                    "phishing case. Resolves the right abuse contacts "
                    "via abuse-resolve.py (TOOL 2), defangs every IOC, "
                    "and writes one draft .txt per target type. "
                    "DRAFTS ONLY — nothing is ever sent or submitted.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  report-gen.py cases/c3-lowes-ovh-74339bb28b436679 "
               "--target all\n"
               "  report-gen.py cases/c4-alert-kit-1-5eb29788d3510447 "
               "--target registrar --out /tmp/drafts\n"
               "  report-gen.py cases/c1-icloud-jp-a-910ea40cfbd19ca8 "
               "--target apple-icloud --cluster clusters.json\n")
    p.add_argument("case", help="ScamIntel case directory (or path to its "
                                "case.json).")
    p.add_argument("--target", required=True,
                   choices=list(TARGETS) + ["all"],
                   help="which report(s) to draft: registrar, hosting, "
                        "google-safe-browsing, apple-icloud, gmail-abuse, "
                        "or all")
    p.add_argument("--out", default=None, metavar="DIR",
                   help="write drafts to DIR instead of "
                        "<case-dir>/analysis/abuse/")
    p.add_argument("--cluster", default=None, metavar="CLUSTER.JSON",
                   help="cluster.py --json file: cite campaign volume "
                        "when this case belongs to a cluster")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    case_dir = find_case_dir(args.case)
    if not case_dir:
        sys.stderr.write("error: %s is not a ScamIntel case dir "
                         "(no case.json)\n" % args.case)
        return 2

    cj, iocs, meta, senders, url_hosts, auth = load_case(case_dir)

    mod = _import_abuse_resolve()
    fiocs = filter_iocs(iocs, senders, url_hosts, mod, auth)

    # Resolve everything once; each target type picks what it needs.
    resolve_inputs = list(fiocs["domains"]) + list(fiocs["ips"])
    results = resolve_contacts(resolve_inputs)

    cluster_line = cluster_context(args.cluster, case_dir)

    out_dir = args.out or os.path.join(case_dir, "analysis", "abuse")
    try:
        os.makedirs(out_dir, exist_ok=True)
    except OSError as exc:
        sys.stderr.write("error: cannot create %s (%s)\n" % (out_dir, exc))
        return 2

    targets = list(TARGETS) if args.target == "all" else [args.target]
    builders = {
        "registrar": lambda: build_registrar(cj, meta, fiocs, results,
                                             cluster_line, mod),
        "hosting": lambda: build_hosting(cj, meta, fiocs, results,
                                         cluster_line, mod),
        "google-safe-browsing": lambda: build_gsb(cj, meta, fiocs,
                                                  cluster_line),
        "apple-icloud": lambda: build_apple(cj, meta, fiocs, cluster_line),
        "gmail-abuse": lambda: build_gmail(cj, meta, fiocs, cluster_line),
    }

    generated = []
    for target in targets:
        try:
            reports = builders[target]()
        except Exception as exc:  # one bad target never kills the run
            warn("builder %s failed (%s: %s); writing TBD placeholder"
                 % (target, type(exc).__name__, str(exc)[:100]))
            reports = [("%s\nCase: %s\n\nTo: RECIPIENT TBD — MANUAL "
                        "REVIEW\n\nReport generation failed for this "
                        "target; draft manually.\n\nRegards,\n%s\n"
                        % (_HEADER, cj.get("slug", "?"), SIGNATURE),
                        "RECIPIENT TBD — MANUAL REVIEW", "n/a")]
        for path, recipient, conf in write_reports(out_dir, target, reports):
            generated.append((target, path, recipient, conf))

    # ---- stdout summary ----
    print("=" * 72)
    print("report-gen.py %s — drafts for case %s"
          % (VERSION, cj.get("slug", "?")))
    print("=" * 72)
    print("IOCs kept after filtering: %d domains (+%d context-only), "
          "%d IPs, %d URLs, %d emails"
          % (len(fiocs["domains"]), len(fiocs["context_domains"]),
             len(fiocs["ips"]), len(fiocs["urls"]), len(fiocs["emails"])))
    if cluster_line:
        print(cluster_line)
    print("")
    for target, path, recipient, conf in generated:
        print("[%s] %s" % (target, path))
        print("    -> %s  (confidence: %s)" % (recipient, conf))
    print("")
    print("DRAFTS ONLY — nothing sent. Human review required before "
          "any report is filed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
