#!/usr/bin/env python3
"""
cluster.py 1.0.3 — ScamIntel TOOL 1/5: campaign clusterer.

Groups phishing messages into campaigns from shared kit fingerprints.
Reads ScamIntel case directories and/or raw .eml files, extracts
per-message features, and unions messages that share strong markers.

Runs anywhere: desktop Linux and Termux (pure stdlib).

Pipeline position: TOOL 1 of 5
    cluster.py (this) -> abuse-resolver -> report-gen -> tracker -> auto-ingest
Later tools consume the --json output; its schema is documented below
and must stay backward compatible (additive changes only).

Usage:
    cluster.py <path> [--json out.json] [--min-size N]

    <path>      Directory holding .eml files and/or ScamIntel case
                directories (each entry auto-detected), a single case
                directory, a single case.json, or a single .eml file.
    --json      Write machine-readable clustering result to out.json.
    --min-size  Minimum members for a reported cluster (default 2).
                Smaller groups are listed as singletons.

How clustering works:
    1. FEATURE EXTRACTION per message. From a case directory the tool
       prefers analysis/headers.json, analysis/urls.json and
       analysis/iocs.json, falling back to evidence/raw_message.json
       (Gmail payload headers) and then to the raw headers.txt dump.
       From a .eml file it parses with the stdlib email parser.
       Extracted: From/Return-Path/Reply-To addresses and domains,
       subject plus a normalized subject template (random tokens, dates,
       IDs stripped) and a subject head (first content tokens), Date,
       Message-ID, the SPF-designated sender relay IP (/24), URL
       hostnames + paths, digit-run constants embedded in URL fragments
       (kit tracking IDs such as cid=40575), and KIT MARKERS:
       zero-width-space stuffing, Unicode homoglyph blocks in display
       names/subjects, campaign-ID local-parts (alert-151-40575),
       <random>.google.<random>.<tld> brand-subdomain spoofing,
       From/Return-Path mismatch, and body lure phrases
       ("payment method has expired"). LT round-3 adds structural
       fingerprints: the ordered header-field sequence (sha256, backend
       mailer fingerprint — PHP mail() and custom mailers have
       distinctive non-RFC orders), the DKIM s= selector (kit
       infrastructure linkage; generic selectors like selector1/s1 are
       never merge keys), the HTML tag skeleton hash (exact DOM tag
       sequence, attributes/text stripped — kit templates recycle it),
       and X-Mailer analysis (spoofed Outlook/Exchange claims and
       script-framework mailers as kit flags, never merge keys).
    2. UNION-FIND over shared markers. Each marker becomes a key like
       ("return_path", "kyla.pike@icloud.com"). Any two messages sharing
       a key are unioned. Deliberately conservative choices:
         - Only the SPF-designated first-hop sender IP is used for relay
           identity. Other IPs in headers/bodies are often injected junk
           (fake Received lines) or shared benign infra and would cause
           false merges.
         - URL host alone never merges (storage.googleapis.com hosts many
           kits); host+path does.
         - Kit flags (zero-width spaces, homoglyphs, mismatch) are
           recorded as evidence but never merge keys on their own.
         - sender_localpart merges ONLY for campaign-specific localparts
           (campaign-ID style like alert-151-40575, or >=10 chars and not
           on the generic blocklist: support@/info@/noreply@/...). Generic
           names are evidence only (H1 hardening 2026-10-08).
         - relay_subnet never merges: shared outbound relays (iCloud,
           Gmail /24s) serve thousands of unrelated senders. Recorded as
           cluster evidence only (H2 hardening 2026-10-08).
         - header_order_hash merges only on >=8 header fields: short
           generic MTA orders could otherwise collide across unrelated
           mail (LT round-3).
         - dkim_selector merges only for non-generic selectors
           (selector1/s1/default/google/... are shared by legitimate
           senders — evidence only). Kit frameworks recycle distinctive
           selectors across their infrastructure (LT round-3).
         - html_skeleton merges only on >=5 HTML tags: trivial skeletons
           would merge unrelated mail. Exact tag-sequence hash (stdlib);
           true fuzzy hashing is future work (LT round-3).
         - X-Mailer findings (spoofed_xmailer_mismatch, mailer_script)
           are kit flags, never merge keys (LT round-3).
    3. COHESION per cluster = fraction of member pairs sharing at least
       one marker key (1.0 = every pair shares a marker). Honest about
       odd members: a lure-mismatched message held in only by body text
       lowers cohesion instead of being silently dropped.
    4. LABELS are suggested from the most campaign-specific marker
       present (campaign-ID local-part > brand spoof > return-path >
       fragment constant > URL path > body lure > subject > relay).

Machine JSON schema (--json), stable for tools 2-5:
    {
      "tool": "cluster.py",
      "version": "1.0.3",
      "generated": "<ISO-8601 UTC>",
      "input": "<path as given>",
      "message_count": N,
      "skipped": [{"source": ..., "reason": ...}],
      "clusters": [
        {
          "label": "kit:alert-151-40575",
          "members": [{"member_id": "c4-alert-kit-1-5eb29788d3510447",
                       "slug": "c4-alert-kit-1", "message_id": "...",
                       "source": "..."}],
          "size": 9,
          "markers": [
            {"type": "sender_localpart", "value": "alert-151-40575",
             "evidence": {"members": [...], "detail": "..."}}
          ],
          "kit_flags": [
            {"type": "from_return_path_mismatch",
             "members": [...], "detail": "..."}
          ],
          "evidence": {
            "localparts": ["alert-151-40575"],
            "relay_subnets": ["57.103.65.0/24"],
            "dkim_selectors": ["smtp"]
          },
          "cohesion": 0.92
        }
      ],
      "singletons": [
        {"member_id": ..., "slug": ..., "message_id": ..., "source": ...,
         "reason": "no shared markers"}
      ]
    }
    "member_id" is unique per input (case-dir basename or .eml filename);
    "slug" is the case's own slug and may repeat across re-acquisitions.
    Marker "type" values: return_path, sender_localpart, url_path,
    url_fragment_const, subject_template, subject_head, relay_subnet,
    brand_subdomain_spoof, body_lure, header_order_hash, dkim_selector,
    html_skeleton. Kit-flag "type" values:
    zero_width_space, homoglyph_<block>, from_return_path_mismatch,
    campaign_id_localpart, return_dash_localpart,
    spoofed_xmailer_mismatch, mailer_script.

Robustness: a malformed entry never crashes the run — a warning goes to
stderr and the entry is skipped (listed under "skipped").

Safety: read-only. Never touches the network, never modifies inputs,
never submits anything anywhere. Defensive analysis only.
"""

import argparse
import email
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser

# R5 (hardening 2026-10-08): shared primitives (addr parsing, public
# suffixes, defang) live in _scamintel_util.py — single source of truth.
try:
    import _scamintel_util as _util
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import _scamintel_util as _util

VERSION = "1.0.3"

# ---------------------------------------------------------------------------
# small utilities
# ---------------------------------------------------------------------------

def warn(msg):
    sys.stderr.write("cluster.py: warning: %s\n" % msg)


def load_json(path):
    """Return parsed JSON dict/list, or None (with stderr warning) on failure."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:  # malformed JSON, unreadable file, ...
        warn("could not parse %s (%s); skipping" % (path, exc))
        return None


def utcnow_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# address helpers (R5: strip_addr/display_name from _scamintel_util)
# ---------------------------------------------------------------------------

strip_addr = _util.strip_addr
display_name = _util.display_name


def split_addr(addr):
    if "@" in addr:
        local, domain = addr.rsplit("@", 1)
        return local, domain
    return addr, ""


# ---------------------------------------------------------------------------
# kit-marker detectors
# ---------------------------------------------------------------------------

_ZWSP_RE = re.compile(r"[\u200b\u200c\u200d\ufeff\u2060\u180e]")

# Unicode blocks abused for homoglyph display names / subjects.
_HOMOGLYPH_BLOCKS = [
    ("small_caps", 0x1D00, 0x1D7F),     # ᴀʙᴄ + phonetic extensions
    ("math_bold", 0x1D400, 0x1D433),    # 𝐀𝐁𝐂
    ("math_bold_lower", 0x1D41A, 0x1D44D),  # 𝐚𝐛𝐜
    ("math_sans_bold", 0x1D5A0, 0x1D5D3),   # 𝖠𝖡𝖢
    ("fullwidth", 0xFF00, 0xFFEF),      # ＡＢＣ
]

def find_zwsp(text):
    return bool(text and _ZWSP_RE.search(text))


def find_homoglyphs(text):
    """Return sorted list of homoglyph block names present in text."""
    if not text:
        return []
    found = set()
    for ch in text:
        o = ord(ch)
        for name, lo, hi in _HOMOGLYPH_BLOCKS:
            if lo <= o <= hi:
                found.add(name)
                break
    return sorted(found)


_CAMPAIGN_ID_RE = re.compile(r"^[a-z]{2,}-\d{1,}-\d{2,}$")

def is_campaign_id_localpart(local):
    """alert-151-40575 style: word, digits, digits."""
    return bool(local and _CAMPAIGN_ID_RE.match(local))


# H1 (hardening 2026-10-08): generic localparts are NEVER merge keys.
# Two unrelated phishes from support@evil1.com and support@evil2.com must
# not merge. Only campaign-specific localparts union messages.
# Blocklist lives in _scamintel_util (R5); heuristic here.
_GENERIC_LOCALPARTS = _util.GENERIC_LOCALPARTS


def campaign_specific_localpart(local):
    """True when a sender localpart is distinctive enough to be a merge key.

    Campaign-ID style (alert-151-40575) always qualifies. Otherwise the
    localpart must be at least 10 chars and not on the generic blocklist.
    Generic names are recorded as evidence only — never merge keys.
    """
    if not local or local.startswith("return-"):
        return False
    if is_campaign_id_localpart(local):
        return True
    return len(local) >= 10 and local.lower() not in _GENERIC_LOCALPARTS


_BRANDS = ("google", "apple", "icloud", "amazon", "microsoft", "paypal")

# R5 (hardening 2026-10-08): public-suffix handling now comes from
# _scamintel_util (single source of truth; fixes H3/A6 divergence).
# Two-level (and a few three-level) public suffixes are handled inside
# registrable_domain() so that www.amazon.co.jp is NOT flagged while
# gtgzeegl.google.morinproject.my.id IS.
_registrable_domain = _util.registrable_domain


def brand_subdomain_spoof(domain):
    """Detect '<brand>' used as a subdomain label under someone else's domain.

    e.g. gtgzeegl.google.morinproject.my.id -> 'google'.
    Legit placements (mail.google.com, www.amazon.co.jp) do NOT match:
    the brand must sit strictly LEFT of the registrable domain.
    """
    if not domain:
        return ""
    reg = _registrable_domain(domain)
    labels = domain.lower().split(".")
    reg_labels = reg.split(".")
    sub_labels = labels[:len(labels) - len(reg_labels)] if len(labels) > len(reg_labels) else []
    for lab in sub_labels:
        if lab in _BRANDS:
            return lab
    return ""


# ---------------------------------------------------------------------------
# subject normalization
# ---------------------------------------------------------------------------

_DATE_RE = re.compile(
    r"(mon|tue|wed|thu|fri|sat|sun),?\s+\d{1,2}\s+"
    r"(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\s+\d{4}"
    r"(\s+\d{1,2}:\d{2}(:\d{2})?(\s*[+-]\d{4})?)?",
    re.I,
)
_NUM_RE = re.compile(r"[#]?\d[\d,.\-]*")
_EMAIL_TOKEN_RE = re.compile(r"\S+@\S+")
_PUNCT_RE = re.compile(r"[^\w\s\u0080-\uffff]", re.UNICODE)

_CONTRACTIONS = {
    "we've": "we have", "we'll": "we will", "we'd": "we would",
    "you've": "you have", "you'll": "you will", "they've": "they have",
    "it's": "it is", "don't": "do not", "can't": "can not",
    "won't": "will not", "isn't": "is not", "aren't": "are not",
}

def normalize_subject(subject):
    """Strip random per-message tokens -> campaign lure template.

    Removes: zero-width chars, dates, digit runs / #IDs, email tokens,
    tokens with digits (personalized user IDs), extra punctuation.
    Expands a few contractions so "We've blocked" == "We have blocked".
    """
    if not subject:
        return ""
    s = _ZWSP_RE.sub("", subject)
    s = s.replace("\u2019", "'").replace("\u2018", "'")
    s = s.lower()
    s = _DATE_RE.sub(" ", s)
    toks = []
    for tok in s.split():
        tok = _EMAIL_TOKEN_RE.sub("", tok)
        if not tok:
            continue
        if any(c.isdigit() for c in tok):
            continue  # personalized IDs, counts, #tags
        tok = _CONTRACTIONS.get(tok, tok)
        tok = _PUNCT_RE.sub("", tok)
        if tok:
            toks.append(tok)
    return " ".join(toks)


def subject_head(template, n=5):
    toks = template.split()
    if len(toks) < 2:
        return ""
    return " ".join(toks[:n])


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------

_URL_RE = re.compile(r"https?://[^\s<>'\"()\[\]]+", re.I)

# H5 (hardening 2026-10-08, documented limitation): already-defanged
# URLs (evil[.]com) are NOT extracted — the bracket chars are excluded
# deliberately so live URLs are found. For .eml input carrying defanged
# IOCs, refang first or use the case-dir path (urls.json).
def extract_urls(text):
    """Extract http(s) URLs from text and trim trailing punctuation."""
    if not text:
        return []
    raw_urls = _URL_RE.findall(text)
    cleaned = []
    for u in raw_urls:
        u_clean = u.rstrip(".,;:?!)]\"'")
        if u_clean:
            cleaned.append(u_clean)
    return cleaned


def split_url(url):
    """Return (host, path, fragment) lowercased host, raw path/fragment."""
    try:
        u = urlsplit_lower(url)
        return u["host"], u["path"], u["fragment"]
    except Exception:
        return "", "", ""


def urlsplit_lower(url):
    # minimal scheme://host/path#fragment splitter (stdlib only)
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://([^/#?]+)([^#]*)?(#(.*))?$", url)
    if not m:
        return {"host": "", "path": "", "fragment": ""}
    return {"host": m.group(1).lower(), "path": m.group(2) or "",
            "fragment": m.group(4) or ""}


_FRAG_DIGIT_RE = re.compile(r"\d{4,}")

def fragment_consts(fragment):
    """Digit runs (>=4) embedded in URL fragments: kit tracking constants.

    e.g. '#?act=cl&...&lid=151&cid=40575' -> {'40575', ...}.
    Per-recipient randoms differ per message; shared ones are kit IDs.
    """
    if not fragment:
        return set()
    return set(_FRAG_DIGIT_RE.findall(fragment))


_DESIGNATED_IP_RE = re.compile(r"designates\s+(\d{1,3}(?:\.\d{1,3}){3})\s+as permitted sender")

def designated_sender_ip(auth_raw):
    m = _DESIGNATED_IP_RE.search(auth_raw or "")
    return m.group(1) if m else ""


def subnet24(ip):
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return ".".join(parts[:3]) + ".0/24"
    return ""


# ---------------------------------------------------------------------------
# LT round-3 (2026-10-08): structural fingerprinting heuristics
# Implementations from LT's cluster_v3.py are canonical (adopted verbatim);
# integration notes inline. Pure stdlib.
# ---------------------------------------------------------------------------

class HTMLSkeletonParser(HTMLParser):
    """Strips attributes and text, keeping only the structural tag sequence."""
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append("<%s>" % tag)

    def handle_endtag(self, tag):
        self.tags.append("</%s>" % tag)


def html_skeleton_hash(text):
    """SHA256[:16] of the HTML tag sequence (exact structural hash).

    Kit templates recycle the same DOM while rotating lures and domains,
    so the bare tag skeleton still matches across a campaign. Requires
    >=5 tags — trivial skeletons (a lone <div>) would merge unrelated
    mail. Exact hash (stdlib); true fuzzy hashing (ssdeep-style) is
    future work.
    """
    if not text:
        return ""
    parser = HTMLSkeletonParser()
    try:
        parser.feed(text)
    except Exception:
        return ""
    if len(parser.tags) < 5:
        return ""
    return hashlib.sha256("".join(parser.tags).encode("utf-8")).hexdigest()[:16]


def header_order_hash(header_keys):
    """SHA256[:16] of the lowercase header field sequence.

    PHP mail() and custom Python/Go mailers emit distinctive,
    non-RFC-standard header orders — the sequence fingerprints the
    backend script. Caveat: shared legitimate platforms also have
    consistent orders; within this pipeline's already-suspicious input
    that's acceptable, and merges additionally require >=8 fields (see
    build_features) so trivial 3-line MTA orders can't collide.
    """
    if not header_keys:
        return ""
    normalized = [k.lower().strip() for k in header_keys if k]
    if not normalized:
        return ""
    return hashlib.sha256(",".join(normalized).encode("utf-8")).hexdigest()[:16]


_DKIM_S_RE = re.compile(r"\bs=([a-zA-Z0-9.-]+)")
_DKIM_S_AUTH_RE = re.compile(r"\b(?:header\.)?s=([a-zA-Z0-9.-]+)", re.I)

# DKIM selectors reused by legitimate senders (O365, Google, ...) are
# shared by unrelated mail — never merge keys. Anything else is
# distinctive enough to union on: kit frameworks recycle selectors
# across their infrastructure.
#
# DEVIATION from LT's v3 verbatim set (documented, regression-proven):
# "smtp" and "mail" are added. The 2026-10-08 regression showed
# dkim_selector|smtp bridging the established C4 and C5 campaigns
# (8 members, cohesion 0.94->0.72). "smtp"/"mail" are industry-standard
# DEFAULT selectors (Postfix/OpenDKIM out-of-the-box, many providers) —
# generic by this heuristic's own definition. "selector2" added for
# symmetry with "selector1".
_GENERIC_DKIM_SELECTORS = frozenset(
    "selector1 selector2 s1 s2 default google k1 dkim smtp mail".split())


def dkim_selector_from_sig(sig_value):
    """s= selector from a DKIM-Signature header value (unfolded first).

    Preferred source — the signature itself, not the receiver's
    Authentication-Results transcription of it.
    """
    if not sig_value:
        return ""
    unfolded = re.sub(r"\s+", " ", sig_value)
    m = _DKIM_S_RE.search(unfolded)
    return m.group(1).lower() if m else ""


def dkim_selector_from_auth(auth_raw):
    """s= selector from Authentication-Results (header.s= stanza)."""
    if not auth_raw:
        return ""
    m = _DKIM_S_AUTH_RE.search(auth_raw)
    return m.group(1).lower() if m else ""


def campaign_dkim_selector(sel):
    """True when a DKIM selector is distinctive enough to merge on."""
    return bool(sel) and sel.lower() not in _GENERIC_DKIM_SELECTORS


def spoofed_xmailer(x_mailer, message_id):
    """Outlook/Exchange user-agent lie detector (LT v3 logic).

    Genuine Outlook/Exchange mail carries prod.outlook.com or phx.gbl in
    the Message-ID. A mailer claiming Outlook/Exchange without that
    marker is a spoofed user-agent — a kit flag, never a merge key.
    """
    xm = (x_mailer or "").lower()
    if "outlook" in xm or "exchange" in xm:
        mid = (message_id or "").lower()
        if "prod.outlook.com" not in mid and "phx.gbl" not in mid:
            return True
    return False


_SCRIPT_MAILER_TOKENS = ("phpmailer", "swiftmailer", "gophish", "python", "php")


def mailer_script_flag(x_mailer):
    """Mass-mailer/script framework advertised in X-Mailer.

    PHPMailer, SwiftMailer, GoPhish, raw python/php mailers — the
    fingerprints of kit-built sending scripts. Kit flag only.
    """
    xm = (x_mailer or "").lower()
    return any(t in xm for t in _SCRIPT_MAILER_TOKENS)


_HEADER_FIELD_RE = re.compile(r"^([A-Za-z0-9-]+):", re.M)
_XMAILER_RE = re.compile(r"^x-mailer:[ \t]*(.*)$", re.M | re.I)


# ---------------------------------------------------------------------------
# feature extraction: case directory
# ---------------------------------------------------------------------------

def _headers_from_case(casedir):
    """Return (headers_dict, raw_headers_text, urls_list, bodies_text)."""
    headers, urls, bodies_text, headers_txt = {}, [], "", ""
    adir = os.path.join(casedir, "analysis")

    hj = load_json(os.path.join(adir, "headers.json"))
    if isinstance(hj, dict):
        md = hj.get("metadata", {}) or {}
        an = hj.get("anomalies", {}) or {}
        headers = {
            "from": md.get("from", "") or hj.get("from", ""),
            "return_path": md.get("return_path", "") or hj.get("return_path", ""),
            "reply_to": md.get("reply_to", "") or hj.get("reply_to", ""),
            "subject": md.get("subject", ""),
            "date": md.get("date", ""),
            "auth_raw": (hj.get("authentication_results", {}) or {}).get("raw", ""),
            "anomalies": [a.get("type", "") for a in (an.get("anomalies", []) or [])],
            # LT round-3: the collection tool does not currently write
            # x_mailer into metadata (gap documented in BUILD-NOTES) —
            # the headers.txt fallback below usually fills it instead.
            "x_mailer": md.get("x_mailer", "") or hj.get("x_mailer", "") or md.get("user_agent", ""),
        }

    uj = load_json(os.path.join(adir, "urls.json"))
    if isinstance(uj, dict):
        for u in uj.get("urls", []) or []:
            st = u.get("static", {}) or {}
            if st.get("hostname"):
                urls.append({
                    "url": u.get("url", ""),
                    "host": st.get("hostname", "").lower(),
                    "path": st.get("path", ""),
                    "fragment": st.get("fragment", ""),
                })

    bj = load_json(os.path.join(adir, "bodies.json"))
    if isinstance(bj, dict):
        for key in ("html", "text", "body"):
            v = bj.get(key)
            if isinstance(v, str):
                bodies_text += "\n" + v
    elif isinstance(bj, str):
        bodies_text = bj

    # fallback: raw Gmail payload headers
    if not headers.get("from") and not headers.get("subject"):
        rm = load_json(os.path.join(casedir, "evidence", "raw_message.json"))
        if isinstance(rm, dict):
            hdrs = {}
            for part in (rm.get("payload", {}) or {}).get("headers", []) or []:
                hdrs[part.get("name", "").lower()] = part.get("value", "")
            headers = {
                "from": hdrs.get("from", ""),
                "return_path": hdrs.get("return-path", ""),
                "reply_to": hdrs.get("reply-to", ""),
                "subject": hdrs.get("subject", ""),
                "date": hdrs.get("date", ""),
                "auth_raw": hdrs.get("authentication-results", ""),
                "anomalies": [],
                "x_mailer": hdrs.get("x-mailer", "") or hdrs.get("user-agent", ""),
            }
            bodies_text += "\n" + (rm.get("snippet", "") or "")

    # last resort: headers.txt dump for Received lines
    htxt_path = os.path.join(adir, "headers.txt")
    if os.path.exists(htxt_path):
        try:
            with open(htxt_path, "r", encoding="utf-8", errors="replace") as fh:
                headers_txt = fh.read(200000)
        except Exception as exc:
            warn("could not read %s (%s)" % (htxt_path, exc))

    # LT round-3: ordered header field names for the header-order hash.
    # Prefer the Gmail payload header list (inherently ordered); fall
    # back to line-initial "Field:" lines of the headers.txt dump.
    # Folded continuation lines (leading whitespace) are not fields.
    header_keys = []
    rm = load_json(os.path.join(casedir, "evidence", "raw_message.json"))
    if isinstance(rm, dict):
        for part in (rm.get("payload", {}) or {}).get("headers", []) or []:
            name = part.get("name", "")
            if name:
                header_keys.append(name)
    if not header_keys and headers_txt:
        header_keys = [m.group(1) for m in
                       _HEADER_FIELD_RE.finditer(headers_txt)]
    if headers_txt and not headers.get("x_mailer"):
        m = _XMAILER_RE.search(headers_txt)
        if m:
            headers["x_mailer"] = m.group(1).strip()
    headers["header_keys"] = header_keys

    return headers, urls, bodies_text, headers_txt


# ---------------------------------------------------------------------------
# feature extraction: .eml file
# ---------------------------------------------------------------------------

# LT round-2: .eml parse cap — clustering needs headers/URLs only, so a
# bloated message (50MB+ of junk base64 attachments, a known gateway-
# evasion trick) must not exhaust memory. Oversize files are skipped
# and logged; the skip lands in the run's "skipped" list via load_eml.
MAX_EML_BYTES = 5 * 1024 * 1024  # 5MB Memory Cap


# H4 (hardening 2026-10-08): the Message-ID comes from the same single
# parse — callers must not re-open the file for it.
def _headers_from_eml(path):
    headers, urls, bodies_text = {}, [], ""
    try:
        size = os.path.getsize(path)
        if size > MAX_EML_BYTES:
            sys.stderr.write(f"cluster.py: warning: {path} exceeds 5MB limit ({size}b); skipping\n")
            return None
        with open(path, "rb") as fh:
            msg = BytesParser(policy=policy.default).parse(fh)
    except Exception as exc:
        sys.stderr.write(f"cluster.py: warning: could not parse eml {path} ({exc})\n")
        return None

    def get(name):
        v = msg.get(name, "")
        return str(v) if v else ""

    # LT round-3: msg.keys() preserves wire order (duplicates kept) —
    # the raw sequence fingerprints the sending script/MTA.
    headers = {
        "from": get("From"), "return_path": get("Return-Path"),
        "reply_to": get("Reply-To"), "subject": get("Subject"),
        "date": get("Date"), "auth_raw": get("Authentication-Results"),
        "anomalies": [],
        "x_mailer": get("X-Mailer") or get("User-Agent"),
        "dkim_sig": get("DKIM-Signature"),
        "header_keys": [k for k in msg.keys()],
    }
    message_id = get("Message-ID").strip("<> ")

    try:
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype in ("text/plain", "text/html"):
                    try:
                        bodies_text += "\n" + part.get_content()
                    except Exception:
                        pass
        else:
            try:
                bodies_text = str(msg.get_content())
            except Exception:
                pass
    except Exception as exc:
        sys.stderr.write(f"cluster.py: warning: body extraction failed for {path} ({exc})\n")

    for u in extract_urls(bodies_text):
        host, upath, frag = _util.split_url(u) if hasattr(_util, 'split_url') else ("", "", "")
        # fallback implementation if split_url isn't in util:
        if not host:
            m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://([^/#?]+)([^#]*)?(#(.*))?$", u)
            if m:
                host, upath, frag = m.group(1).lower(), m.group(2) or "", m.group(4) or ""
        if host:
            urls.append({"url": u, "host": host, "path": upath, "fragment": frag})

    return headers, urls, bodies_text, message_id


_PAYMENT_EXPIRED_RE = re.compile(r"payment.{0,60}expir", re.I | re.S)

def build_features(slug, message_id, source, headers, urls, bodies_text):
    """Assemble the feature record + merge keys for one message."""
    from_raw = headers.get("from", "")
    rp_raw = headers.get("return_path", "")
    rt_raw = headers.get("reply_to", "")
    from_addr = strip_addr(from_raw)
    rp_addr = strip_addr(rp_raw)
    rt_addr = strip_addr(rt_raw)
    from_local, from_domain = split_addr(from_addr)
    rp_local, rp_domain = split_addr(rp_addr)
    disp = display_name(from_raw)
    subject = headers.get("subject", "")
    subj_template = normalize_subject(subject)
    subj_head = subject_head(subj_template)

    text_for_markers = " ".join([from_raw, subject, bodies_text or ""])
    zwsp = find_zwsp(text_for_markers)
    homoglyphs = sorted(set(find_homoglyphs(disp) + find_homoglyphs(subject)))

    relay_ip = designated_sender_ip(headers.get("auth_raw", ""))
    relay_sub = subnet24(relay_ip)

    url_paths = []
    frag_consts = set()
    brand_spoofs = set()
    for u in urls:
        host = u.get("host", "")
        path = u.get("path", "")
        if host and path:
            url_paths.append((host, path))
        frag_consts |= fragment_consts(u.get("fragment", ""))
        b = brand_subdomain_spoof(host)
        if b:
            brand_spoofs.add(b)
    for dom in (from_domain, rp_domain):
        b = brand_subdomain_spoof(dom)
        if b:
            brand_spoofs.add(b)

    body_lures = set()
    if bodies_text and _PAYMENT_EXPIRED_RE.search(bodies_text):
        body_lures.add("payment-expired")

    mismatch = bool(from_addr and rp_addr and from_addr != rp_addr)

    # LT round-3: structural fingerprints. DKIM selector prefers the
    # DKIM-Signature header itself over the receiver's auth-results
    # transcription. X-Mailer flags are evidence only, never merge keys.
    dkim_sel = (dkim_selector_from_sig(headers.get("dkim_sig", "")) or
                dkim_selector_from_auth(headers.get("auth_raw", "")))
    x_mailer = headers.get("x_mailer", "")
    spoofed_mailer = spoofed_xmailer(x_mailer, message_id)
    script_mailer = mailer_script_flag(x_mailer)
    skel = html_skeleton_hash(bodies_text or "")
    hkeys = headers.get("header_keys") or []
    hhash = header_order_hash(hkeys)

    # Unique per input: case dirs can share a case.json "slug" when the same
    # message was acquired more than once, so evidence sets key on this.
    member_id = os.path.basename(os.path.normpath(source)) or source

    feats = {
        "slug": slug,
        "member_id": member_id,
        "message_id": message_id,
        "source": source,
        "from_addr": from_addr,
        "from_domain": from_domain,
        "from_local": from_local,
        "display_name": disp,
        "return_path": rp_addr,
        "reply_to": rt_addr,
        "subject": subject,
        "subject_template": subj_template,
        "subject_head": subj_head,
        "date": headers.get("date", ""),
        "relay_ip": relay_ip,
        "relay_subnet": relay_sub,
        "url_hosts": sorted({u.get("host", "") for u in urls if u.get("host")}),
        "dkim_selector": dkim_sel,
        "x_mailer": x_mailer,
        "html_skeleton": skel,
        "kit_flags": {
            "zero_width_space": zwsp,
            "homoglyphs": homoglyphs,
            "from_return_path_mismatch": mismatch,
            "campaign_id_localpart": is_campaign_id_localpart(from_local),
            "return_dash_localpart": from_local.startswith("return-") or rp_local.startswith("return-"),
            "spoofed_xmailer_mismatch": spoofed_mailer,
            "mailer_script": script_mailer,
        },
    }

    # ---- merge keys ----
    # H1 (hardening 2026-10-08): sender_localpart is a merge key ONLY for
    # campaign-specific localparts. Generic names (support@, info@, ...)
    # are evidence, never keys — they caused false merges.
    keys = []
    if rp_addr:
        keys.append(("return_path", rp_addr))
    if campaign_specific_localpart(from_local):
        # same distinctive local-part reused across the kit (domains rotate)
        keys.append(("sender_localpart", from_local))
    for host, path in url_paths:
        keys.append(("url_path", host + path))
    for c in sorted(frag_consts):
        keys.append(("url_fragment_const", c))
    if len(subj_template) >= 8:
        keys.append(("subject_template", subj_template))
    if subj_head:
        keys.append(("subject_head", subj_head))
    # H2 (hardening 2026-10-08): relay_subnet demoted to evidence-only.
    # Shared outbound relays (iCloud, Gmail /24s) serve thousands of
    # unrelated senders — a /24 match is not campaign identity.
    for b in sorted(brand_spoofs):
        keys.append(("brand_subdomain_spoof", b))
    for l in sorted(body_lures):
        keys.append(("body_lure", l))
    # LT round-3: structural merge keys.
    if skel:
        keys.append(("html_skeleton", skel))
    # Header-order merges only on >=8 fields: short generic MTA orders
    # would otherwise collide across unrelated mail (LT v3).
    if hhash and len(hkeys) >= 8:
        keys.append(("header_order_hash", hhash))
    # Non-generic DKIM selectors are kit-infrastructure fingerprints.
    if campaign_dkim_selector(dkim_sel):
        keys.append(("dkim_selector", dkim_sel))
    feats["keys"] = keys
    feats["kit_flag_list"] = _flag_keys(feats)
    return feats


def _flag_keys(feats):
    kf = feats["kit_flags"]
    out = []
    if kf["zero_width_space"]:
        out.append(("kit_flag", "zero_width_space"))
    for h in kf["homoglyphs"]:
        out.append(("kit_flag", "homoglyph_" + h))
    if kf["from_return_path_mismatch"]:
        out.append(("kit_flag", "from_return_path_mismatch"))
    if kf["campaign_id_localpart"]:
        out.append(("kit_flag", "campaign_id_localpart:" + feats["from_local"]))
    if kf["return_dash_localpart"]:
        out.append(("kit_flag", "return_dash_localpart"))
    if kf["spoofed_xmailer_mismatch"]:
        out.append(("kit_flag", "spoofed_xmailer_mismatch"))
    if kf["mailer_script"]:
        out.append(("kit_flag", "mailer_script"))
    return out


# ---------------------------------------------------------------------------
# input loading
# ---------------------------------------------------------------------------

def load_case_dir(casedir):
    cj = load_json(os.path.join(casedir, "case.json"))
    if not isinstance(cj, dict):
        warn("no usable case.json in %s; skipping" % casedir)
        return None
    headers, urls, bodies_text, _headers_txt = _headers_from_case(casedir)
    if not headers.get("from") and not headers.get("subject") and not urls:
        warn("no usable features in %s; skipping" % casedir)
        return None
    slug = cj.get("slug") or os.path.basename(os.path.normpath(casedir))
    return build_features(slug, cj.get("message_id", ""),
                          os.path.normpath(casedir), headers, urls, bodies_text)


def load_eml(path):
    got = _headers_from_eml(path)
    if got is None:
        return None
    headers, urls, bodies_text, message_id = got
    if not headers.get("from") and not headers.get("subject"):
        warn("no usable headers in %s; skipping" % path)
        return None
    base = os.path.basename(path)
    return build_features(os.path.splitext(base)[0], message_id, path,
                          headers, urls, bodies_text)


def looks_like_case_dir(entry_path):
    return os.path.isdir(entry_path) and os.path.exists(
        os.path.join(entry_path, "case.json"))


def collect_inputs(path):
    """Return (features_list, skipped_list). Auto-detects entry types."""
    feats, skipped = [], []

    def add(feat, src):
        if feat is None:
            skipped.append({"source": src, "reason": "feature extraction failed"})
        else:
            feats.append(feat)

    if os.path.isdir(path):
        # single case dir given directly?
        if looks_like_case_dir(path):
            add(load_case_dir(path), path)
            return feats, skipped
        for entry in sorted(os.listdir(path)):
            if entry.startswith("."):
                continue
            full = os.path.join(path, entry)
            if looks_like_case_dir(full):
                add(load_case_dir(full), full)
            elif os.path.isfile(full) and entry.lower().endswith(".eml"):
                add(load_eml(full), full)
            elif os.path.isfile(full) and entry.lower() == "case.json":
                add(load_case_dir(os.path.dirname(full)), full)
            else:
                skipped.append({"source": full, "reason": "not a case dir or .eml file"})
    elif os.path.isfile(path):
        if path.lower().endswith(".eml"):
            add(load_eml(path), path)
        elif os.path.basename(path).lower() == "case.json":
            add(load_case_dir(os.path.dirname(path) or "."), path)
        else:
            skipped.append({"source": path, "reason": "not a .eml file or case.json"})
    else:
        warn("input path does not exist: %s" % path)
        skipped.append({"source": path, "reason": "path does not exist"})

    return feats, skipped


# ---------------------------------------------------------------------------
# clustering: union-find over shared marker keys
# ---------------------------------------------------------------------------

class UnionFind:
    def __init__(self, n):
        self.parent = list(range(n))

    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def cluster_features(feats, min_size=2):
    n = len(feats)
    uf = UnionFind(n)
    key_to_idxs = {}
    for i, f in enumerate(feats):
        for key in f["keys"]:
            key_to_idxs.setdefault(key, []).append(i)
    for key, idxs in key_to_idxs.items():
        first = idxs[0]
        for j in idxs[1:]:
            uf.union(first, j)

    groups = {}
    for i in range(n):
        groups.setdefault(uf.find(i), []).append(i)

    clusters, singletons = [], []
    for idxs in groups.values():
        members = [feats[i] for i in idxs]
        if len(members) >= min_size:
            clusters.append(_build_cluster(members))
        else:
            for m in members:
                singletons.append({
                    "member_id": m["member_id"], "slug": m["slug"],
                    "message_id": m["message_id"], "source": m["source"],
                    "reason": "no shared markers",
                })

    # biggest first, then label, for stable output
    clusters.sort(key=lambda c: (-c["size"], c["label"]))
    singletons.sort(key=lambda s: s["slug"])
    return clusters, singletons


def _shared_markers(members):
    """Keys present in >=2 members -> marker records with evidence."""
    key_members = {}
    for m in members:
        for key in m["keys"]:
            key_members.setdefault(key, set()).add(m["member_id"])
    markers = []
    for (ktype, value), ids in sorted(key_members.items()):
        if len(ids) >= 2:
            detail = _marker_detail(ktype, value, members)
            markers.append({
                "type": ktype, "value": value,
                "evidence": {"members": sorted(ids), "detail": detail},
            })
    # strongest marker types first for readability
    order = {"sender_localpart": 0, "brand_subdomain_spoof": 1,
             "return_path": 2, "url_fragment_const": 3, "url_path": 4,
             "body_lure": 5, "subject_template": 6, "subject_head": 7,
             "relay_subnet": 8, "header_order_hash": 9, "dkim_selector": 10,
             "html_skeleton": 11}
    markers.sort(key=lambda mk: (order.get(mk["type"], 99), mk["value"]))
    return markers


def _marker_detail(ktype, value, members):
    by_id = {m["member_id"]: m for m in members}
    if ktype == "return_path":
        return "shared Return-Path <%s>" % value
    if ktype == "sender_localpart":
        doms = sorted({by_id[i]["from_domain"] for i in by_id
                       if value == by_id[i]["from_local"]})
        return "sender local-part <%s> reused across domains: %s" % (
            value, ", ".join(doms) or "?")
    if ktype == "url_path":
        return "shared kit URL path %s" % value
    if ktype == "url_fragment_const":
        return "shared tracking constant %s in URL fragments (kit ID)" % value
    if ktype == "subject_template":
        return "shared normalized subject template"
    if ktype == "subject_head":
        return "shared subject opening: %r" % value
    if ktype == "relay_subnet":
        return "shared sender relay subnet %s" % value
    if ktype == "brand_subdomain_spoof":
        return "brand <%s> abused as subdomain label" % value
    if ktype == "body_lure":
        return "shared body lure phrasing: %s" % value
    if ktype == "header_order_hash":
        return "shared header order hash (backend mailer fingerprint)"
    if ktype == "dkim_selector":
        return "shared DKIM selector s=%s (kit infrastructure)" % value
    if ktype == "html_skeleton":
        return "shared HTML tag skeleton (kit template reuse)"
    return ""


def _cluster_kit_flags(members):
    """Kit flags seen in a majority of members -> cluster-level evidence."""
    counts = {}
    for m in members:
        for fk in m["kit_flag_list"]:
            counts.setdefault(fk, set()).add(m["member_id"])
    out = []
    for (ktype, value), ids in sorted(counts.items()):
        if len(ids) * 2 >= len(members):
            out.append({"type": value, "members": sorted(ids),
                        "detail": "%d/%d members" % (len(ids), len(members))})
    return out


_LABEL_PRIORITY = ["sender_localpart", "brand_subdomain_spoof", "return_path",
                   "url_fragment_const", "url_path", "body_lure",
                   "subject_template", "subject_head", "relay_subnet",
                   "header_order_hash", "dkim_selector", "html_skeleton"]

def suggest_label(markers):
    by_type = {}
    for mk in markers:
        by_type.setdefault(mk["type"], []).append(mk["value"])
    for t in _LABEL_PRIORITY:
        if t in by_type:
            v = sorted(by_type[t])[0]
            if t == "sender_localpart":
                return "kit:%s" % v
            if t == "brand_subdomain_spoof":
                return "brand-spoof:%s-subdomain" % v
            if t == "return_path":
                return "rp:%s" % v
            if t == "url_fragment_const":
                return "frag-cid:%s" % v
            if t == "url_path":
                return "url:%s" % (v[:60] + ("..." if len(v) > 60 else ""))
            if t == "body_lure":
                return "lure:%s" % v
            if t == "subject_template":
                return "subj:%s" % (v[:50] + ("..." if len(v) > 50 else ""))
            if t == "subject_head":
                return "subj-head:%s" % v
            if t == "relay_subnet":
                return "relay:%s" % v
            if t == "header_order_hash":
                return "hdr-order:%s" % v[:16]
            if t == "dkim_selector":
                return "dkim-sel:%s" % v
            if t == "html_skeleton":
                return "skeleton:%s" % v
    return "unlabelled"


def _build_cluster(members):
    members_sorted = sorted(members, key=lambda m: m["slug"])
    markers = _shared_markers(members_sorted)
    n = len(members_sorted)
    # cohesion: fraction of member pairs sharing >=1 marker key
    keysets = [set(m["keys"]) for m in members_sorted]
    shared_pairs = 0
    total_pairs = 0
    for i in range(n):
        for j in range(i + 1, n):
            total_pairs += 1
            if keysets[i] & keysets[j]:
                shared_pairs += 1
    cohesion = (shared_pairs / total_pairs) if total_pairs else 1.0
    # H1/H2 evidence: localparts and relay subnets are recorded for the
    # analyst but never merged on (see build_features).
    return {
        "label": suggest_label(markers),
        "members": [{"member_id": m["member_id"], "slug": m["slug"],
                     "message_id": m["message_id"], "source": m["source"]}
                    for m in members_sorted],
        "size": n,
        "markers": markers,
        "kit_flags": _cluster_kit_flags(members_sorted),
        "evidence": {
            "localparts": sorted({m["from_local"] for m in members_sorted
                                  if m["from_local"]}),
            "relay_subnets": sorted({m["relay_subnet"] for m in members_sorted
                                     if m["relay_subnet"]}),
            "dkim_selectors": sorted({m["dkim_selector"] for m in members_sorted
                                      if m.get("dkim_selector")}),
        },
        "cohesion": round(cohesion, 3),
    }


# ---------------------------------------------------------------------------
# output
# ---------------------------------------------------------------------------

def print_table(clusters, singletons):
    print("=" * 78)
    print("ScamIntel campaign clusters — cluster.py %s" % VERSION)
    print("=" * 78)
    if not clusters:
        print("No multi-message clusters found.")
    for i, c in enumerate(clusters, 1):
        print("")
        print("Cluster %d: %s  (size=%d, cohesion=%.2f)" % (
            i, c["label"], c["size"], c["cohesion"]))
        print("  defining markers:")
        for mk in c["markers"][:6]:
            ev = mk["evidence"]
            print("    - [%s] %s  (%d members)" % (
                mk["type"], mk["value"][:80], len(ev["members"])))
            if ev["detail"]:
                print("      %s" % ev["detail"][:100])
        if len(c["markers"]) > 6:
            print("    ... +%d more markers" % (len(c["markers"]) - 6))
        if c["kit_flags"]:
            print("  kit flags: " + ", ".join(
                "%s (%d/%d)" % (k["type"], len(k["members"]), c["size"])
                for k in c["kit_flags"]))
        print("  members:")
        for m in c["members"]:
            print("    - %s  [%s]" % (m["member_id"], m["message_id"]))
    if singletons:
        print("")
        print("Singletons (%d):" % len(singletons))
        for s in singletons:
            print("  - %s  [%s]  (%s)" % (s["member_id"], s["message_id"], s["reason"]))
    print("")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="cluster.py",
        description="ScamIntel TOOL 1/5: group phishing messages into "
                    "campaigns from shared kit fingerprints.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  cluster.py ~/workspace/scam-intel/cases/\n"
               "  cluster.py ~/workspace/scam-intel/cases/ --json clusters.json\n"
               "  cluster.py message.eml\n"
               "  cluster.py cases/some-case-abc123/ --min-size 3\n",
    )
    parser.add_argument("path", help="Directory of .eml files and/or ScamIntel "
                                     "case dirs, a single case dir, a single "
                                     "case.json, or a single .eml file.")
    parser.add_argument("--json", metavar="OUT", default=None,
                        help="Write machine-readable result JSON to OUT "
                             "(schema documented in the module docstring).")
    parser.add_argument("--min-size", type=int, default=2,
                        help="Minimum members for a reported cluster "
                             "(default 2). Smaller groups -> singletons.")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.min_size < 2:
        args.min_size = 2

    feats, skipped = collect_inputs(args.path)
    clusters, singletons = cluster_features(feats, min_size=args.min_size)

    print_table(clusters, singletons)

    result = {
        "tool": "cluster.py",
        "version": VERSION,
        "generated": utcnow_iso(),
        "input": args.path,
        "message_count": len(feats),
        "skipped": skipped,
        "clusters": clusters,
        "singletons": singletons,
    }
    if args.json:
        try:
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump(result, fh, indent=2, ensure_ascii=False)
                fh.write("\n")
            print("JSON written to %s" % args.json)
        except Exception as exc:
            warn("could not write %s (%s)" % (args.json, exc))
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
