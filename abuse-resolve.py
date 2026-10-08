#!/usr/bin/env python3
"""
abuse-resolve.py 1.0.3 — ScamIntel TOOL 2/5: abuse-contact resolver.

Takes domains and IP addresses (phishing IOCs) and finds WHO to report
them to: registrar + registrar abuse contact for domains, hosting
provider / ASN owner + abuse contact for IPs.

Runs anywhere: desktop Linux and Termux (pure stdlib).

1.0.3 — merged LT's hand-written network hardening (hardening round 2):
his abuse-resolve_v2.py is canonical for the network functions —
SSRFSafeRedirectHandler (aborts HTTP redirects to non-global targets),
WHOIS tarpit protection via absolute time boundary, multi-IP A/AAAA
resolution (DNS round-robin / fast-flux aware), and targeted
privacy/redaction detection. His implementations adopted verbatim;
the complete CLI (main/--cluster/--json/print_table) and the 1.0.2
robustness pieces he didn't touch (cache TTL, IPv6 extraction,
non-global IP filter) are preserved.

Pipeline position: TOOL 2 of 5
    cluster.py -> abuse-resolve.py (this) -> report-gen -> tracker -> auto-ingest
Consumes cluster.py's --json (frozen schema); its own --json schema is
documented below and must stay backward compatible (additive changes only)
because tool 3 (report-gen) consumes it.

Usage:
    abuse-resolve.py example.com 54.38.157.50 [--json out.json] [--refresh]
    abuse-resolve.py --cluster clusters.json [--json out.json]

    <inputs>      One or more domains or IPs. Bare domains, subdomains,
                  full URLs, and email addresses are all accepted — the
                  host part is extracted and classified automatically.
    --cluster    Read a cluster.py --json file and resolve every unique
                  domain/IP across all cluster members (IOCs come from
                  each member's analysis/iocs.json; .eml members are
                  parsed for URLs and Received IPs).
    --json       Write machine-readable result to out.json.
    --refresh    Bypass the on-disk cache and re-resolve everything.
    --cache      Override the cache file path.
    --timeout    Network timeout in seconds (default 10).
    --no-sleep   Skip the courtesy pause between network queries.

How resolution works (RDAP first, WHOIS as backup):
    1. DOMAINS. The input is reduced to its registrable domain
       (eTLD+1: lket17.bsgvo.my.id -> bsgvo.my.id). RDAP is queried
       over HTTPS using the IANA bootstrap registries
       (data.iana.org/rdap/dns.json), plus curated fallbacks for TLDs
       the bootstrap misses (.us -> rdap.nic.neustar). The registrar
       RDAP referral is followed (e.g. .info -> IONOS registrar RDAP)
       because the registrar record carries the real abuse contact.
       If RDAP is thin or missing, classic WHOIS over TCP port 43 is
       tried, following registrar referrals ("Registrar WHOIS
       Server:" / "whois:") from the registry response.
    2. IPS. RDAP over HTTPS via the IANA ipv4/ipv6 bootstrap
       (usually ARIN/RIPE/APNIC/LACNIC/AFRINIC), falling back to WHOIS
       port 43 with referral following ("ReferralServer:"). Abuse
       contacts are taken from entities with the "abuse" role, then
       from admin/tech contacts whose address contains "abuse".
    3. HOSTING FOOTPRINTS. When WHOIS/RDAP gives a provider name but
       no usable abuse contact (thin records, privacy redaction), a
       built-in table of major VPS/hosting providers (OVH, Hetzner,
       DigitalOcean, Contabo, Vultr, Linode/Akamai, AWS, Google Cloud,
       Azure, Cloudflare, Leaseweb) supplies their published abuse
       desks — clearly marked as a fallback in "notes".
    4. DOMAIN -> HOSTING. A domain's hosting{} block is filled by
       resolving ALL its A/AAAA records and unioning the hosting
       footprints across every globally routable IP (fast-flux aware —
       LT round-2 hardening; bulk runs issue more queries).

Machine JSON schema (--json), stable for tools 3-5:
    {
      "tool": "abuse-resolve.py",
      "version": "1.0.0",
      "generated": "<ISO-8601 UTC>",
      "input": "<inputs or cluster path as given>",
      "results": [
        {"input": "sinnatcon.info",
         "kind": "domain",
         "registrar": {"name": "IONOS SE",
                       "abuse_email": "abuse@ionos.com",
                       "abuse_url": null},
         "hosting": {"provider": "HostPapa",
                     "asn": null,
                     "abuse_email": "net-abuse-global@hostpapa.com",
                     "abuse_url": null},
         "cached": false,
         "resolved_at": "<ISO-8601 UTC>",
         "notes": "RDAP via rdap.identitydigital.services; registrar RDAP via rdap.ionos.com"}
      ]
    }
For "kind": "ip", "registrar" is all-null (IPs have no registrar).
"cached": true means the entry came from the on-disk cache.
"notes" records every fallback, failure, and quirk — never empty when
something went wrong.

Caching: JSON file, default <script-dir>/.cache/abuse-contacts.json
(keyed by normalized input, with resolved_at timestamps, 30-day TTL).
Kept next to the script so the whole scam-intel directory stays portable
(desktop <-> Termux). --refresh re-resolves and rewrites the entry.

Robustness: every network call has a timeout (default 10s). A failed
lookup never crashes the run — the failure is recorded in "notes" and
the tool moves on. Exit 0 on a completed run, 2 on usage errors.

Safety / scope: read-only reconnaissance for defensive abuse reporting
only. This tool looks up public registration data to find WHERE to send
abuse reports — it never files a report, never contacts anyone, never
attacks anything. Courtesy pauses between queries; no aggressive
scanning.
"""
#!/usr/bin/env python3
"""
abuse-resolve_v2.py — ScamIntel TOOL 2/5: abuse-contact resolver.

Updates:
    - SSRF protection on HTTP redirects.
    - WHOIS socket tarpit protection via absolute time boundary.
    - Multi-IP extraction for A-records (DNS round-robin/fast-flux).
    - Targeted privacy/redaction detection.

Authored by LT (Miles Jason Kimmons), 2026-10-08 — hardening round 2.
NOTE: main() intentionally truncated — the CLI runner lives in
abuse-resolve.py; this file is the canonical implementation of the
hardened network functions, merged into the working tool.
"""

import argparse
import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse
import email
from email import policy
from email.parser import BytesParser

VERSION = "1.0.3"

try:
    import _scamintel_util as _util
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import _scamintel_util as _util

USER_AGENT = "ScamIntel-abuse-resolve/1.0.3 (+defensive abuse reporting)"
DEFAULT_TIMEOUT = 10.0
WHOIS_SLEEP = 0.5
RDAP_SLEEP = 0.2
BOOTSTRAP_TTL = 7 * 86400
CACHE_TTL_DAYS = 30

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CACHE = os.path.join(SCRIPT_DIR, ".cache", "abuse-contacts.json")

registrable_domain = _util.registrable_domain

TLD_RDAP_OVERRIDE = {"us": "https://rdap.nic.neustar/domain/"}
TLD_WHOIS_SERVER = {
    "us": "whois.nic.us", "info": "whois.nic.info", "id": "whois.id",
    "com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
}

_FILE_EXT_TLDS = frozenset(
    "html htm php asp aspx jsp cgi pl py rb sh css js json xml "
    "jpg jpeg png gif bmp svg ico webp tif tiff pdf txt doc docx "
    "xls xlsx csv zip rar 7z gz tar exe msi dmg mp4 mov avi mkv "
    "mp3 wav ogg woff woff2 ttf eot".split())

_DOC_RANGES = [ipaddress.ip_network(c) for c in
               ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10",
                "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
                "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
                "203.0.113.0/24", "::1/128", "fc00::/7", "fe80::/10")]

HOSTING_FOOTPRINTS = [
    ("OVH", ["AS16276"], ["ovh"], "abuse@ovh.net", "https://www.ovh.com/abuse/"),
    ("Hetzner", ["AS24940"], ["hetzner"], "abuse@hetzner.com", "https://www.hetzner.com/legal/report-abuse/"),
    ("DigitalOcean", ["AS14061"], ["digitalocean"], "abuse@digitalocean.com", "https://www.digitalocean.com/company/contact/abuse"),
    ("Contabo", ["AS51167"], ["contabo"], "abuse@contabo.com", "https://contabo.com/en/abuse/"),
    ("Vultr", ["AS20473", "AS64512"], ["vultr", "choopa"], "abuse@vultr.com", "https://www.vultr.com/abuse/"),
    ("Linode / Akamai", ["AS63949"], ["linode", "akamai"], "abuse@akamai.com", "https://www.akamai.com/abuse"),
    ("Amazon Web Services", ["AS16509", "AS14618"], ["amazon", "aws"], "abuse@amazonaws.com", "https://aws.amazon.com/premiumsupport/abuse/"),
    ("Google Cloud", ["AS15169", "AS396982"], ["google"], "abuse@google.com", "https://support.google.com/code/contact/abuse"),
    ("Microsoft Azure", ["AS8075"], ["microsoft"], "abuse@microsoft.com", "https://cert.microsoft.com/"),
    ("Cloudflare", ["AS13335"], ["cloudflare"], "abuse@cloudflare.com", "https://www.cloudflare.com/abuse/"),
    ("Leaseweb", ["AS16265", "AS9009"], ["leaseweb"], "abuse@leaseweb.com", "https://www.leaseweb.com/en/about-us/report-abuse"),
]

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_ASN_RE = re.compile(r"\bAS(\d{1,10})\b", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"^(?=.{1,253}\.?$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")
_URL_HOST_RE = re.compile(r"https?://([A-Za-z0-9.-]+)(?::\d+)?(?:[/\s\"'<>]|$)", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")

def warn(msg):
    sys.stderr.write("warn: %s\n" % msg)

def utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

class Options:
    timeout = DEFAULT_TIMEOUT
    sleep = True

def polite_pause(kind):
    if not Options.sleep:
        return
    time.sleep(WHOIS_SLEEP if kind == "whois" else RDAP_SLEEP)

class SSRFSafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Aborts HTTP redirects to private/loopback/cloud-metadata IP ranges."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            parsed = urlparse(newurl)
            if parsed.scheme not in ("http", "https"):
                raise Exception("Forbidden scheme")
            if parsed.hostname:
                infos = socket.getaddrinfo(parsed.hostname, None)
                for fam, _, _, _, sockaddr in infos:
                    if not ipaddress.ip_address(sockaddr[0]).is_global:
                        raise Exception(f"Redirect to non-global IP {sockaddr[0]}")
        except Exception as e:
            raise urllib.error.HTTPError(newurl, code, f"SSRF prevented: {e}", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

_SAFE_OPENER = urllib.request.build_opener(SSRFSafeRedirectHandler())

def http_get_json(url):
    req = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json, application/json"})
    try:
        with _SAFE_OPENER.open(req, timeout=Options.timeout) as resp:
            raw = resp.read(257 * 1024)
        polite_pause("rdap")
        if len(raw) > 256 * 1024:
            return None, "response exceeded 256KB cap"
        return json.loads(raw.decode("utf-8", "replace")), None
    except Exception as e:
        polite_pause("rdap")
        return None, f"HTTPS fetch failed: {type(e).__name__}: {str(e)[:100]}"

def whois_query(server, query):
    s = socket.create_connection((server, 43), timeout=Options.timeout)
    start_time = time.time()
    try:
        s.settimeout(1.0) # Check global timeout periodically
        s.sendall((query + "\r\n").encode("utf-8", "replace"))
        chunks = []
        while True:
            if time.time() - start_time > Options.timeout:
                warn(f"WHOIS {server} timed out (tarpit protection)")
                break
            try:
                data = s.recv(16384)
            except socket.timeout:
                continue
            if not data:
                break
            chunks.append(data)
            if sum(len(c) for c in chunks) > 256 * 1024:
                break
    finally:
        s.close()
    polite_pause("whois")
    text = b"".join(chunks).decode("utf-8", "replace")
    if "Other TCP connections is turned off" in text:
        raise OSError("outbound TCP port 43 blocked")
    return text

def _bootstrap_path(kind):
    return os.path.join(os.path.dirname(DEFAULT_CACHE), f"rdap-bootstrap-{kind}.json")

def rdap_bootstrap(kind):
    path = _bootstrap_path(kind)
    try:
        if os.path.exists(path) and time.time() - os.path.getmtime(path) < BOOTSTRAP_TTL:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    obj, note = http_get_json(f"https://data.iana.org/rdap/{kind}.json")
    if obj is None:
        return None
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path + ".tmp", "w", encoding="utf-8") as f:
            json.dump(obj, f)
        os.replace(path + ".tmp", path)
    except Exception:
        pass
    return obj

def rdap_server_for_domain(tld):
    tld = tld.lower().strip(".")
    if tld in TLD_RDAP_OVERRIDE:
        return TLD_RDAP_OVERRIDE[tld]
    boot = rdap_bootstrap("dns")
    if not boot:
        return None
    for service in boot.get("services", []):
        if tld in [t.lower() for t in service[0]] and service[1]:
            base = service[1][0]
            return base if base.endswith("/") else base + "/"
    return None

def rdap_server_for_ip(ip):
    kind = "ipv6" if ":" in ip else "ipv4"
    boot = rdap_bootstrap(kind)
    if not boot:
        return None
    addr = ipaddress.ip_address(ip)
    for service in boot.get("services", []):
        for cidr in service[0]:
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    base = service[1][0]
                    return base if base.endswith("/") else base + "/"
            except ValueError:
                continue
    return None

def _walk_entities(entities, out):
    for ent in entities or []:
        out.append(ent)
        _walk_entities(ent.get("entities"), out)

def all_entities(obj):
    out = []
    _walk_entities(obj.get("entities"), out)
    return out

def vcard_fields(entity):
    fn = org = None
    emails, urls = [], []
    vc = entity.get("vcardArray")
    if isinstance(vc, list) and len(vc) > 1 and isinstance(vc[1], list):
        for item in vc[1]:
            if not (isinstance(item, list) and len(item) >= 4):
                continue
            name, val = item[0], item[3]
            if name == "fn" and fn is None:
                fn = str(val)
            elif name == "org" and org is None:
                org = str(val)
            elif name == "email":
                e = str(val).strip().lower()
                if e and e not in emails:
                    emails.append(e)
            elif name == "url":
                u = str(val).strip()
                if u and u not in urls:
                    urls.append(u)
    return fn, org, emails, urls

def _is_redacted(email_addr):
    email_addr = (email_addr or "").lower()
    if "@" in email_addr:
        domain = email_addr.rsplit("@", 1)[-1]
        if any(p in domain for p in ("contactprivacy", "whoisproxy", "privacyguardian", "whoisguard", "anonymize", "redact")):
            return True
    return "redacted" in email_addr

def pick_abuse_email(emails):
    real = [e for e in emails if not _is_redacted(e)]
    pool = real or emails
    for e in pool:
        if e.startswith("abuse@") or "abuse" in e.split("@")[0]:
            return e, False
    return (pool[0], True) if pool else (None, False)

def extract_registrar_info(domain_obj):
    notes = []
    name = abuse_email = abuse_url = None
    registrar_entity = None
    abuse_entities = []
    for ent in all_entities(domain_obj):
        roles = [r.lower() for r in (ent.get("roles") or [])]
        if "registrar" in roles and registrar_entity is None:
            registrar_entity = ent
        if "abuse" in roles:
            abuse_entities.append(ent)
    if registrar_entity is not None:
        fn, org, emails, urls = vcard_fields(registrar_entity)
        name = org or fn
        if emails:
            abuse_email, generic = pick_abuse_email(emails)
            if generic:
                notes.append(f"registrar contact has no dedicated abuse address; using {abuse_email}")
        if urls:
            abuse_url = urls[0]
        if name:
            notes.append(f"registrar: {name}")
    for ent in abuse_entities:
        _, _, emails, urls = vcard_fields(ent)
        if not abuse_email and emails:
            abuse_email, _ = pick_abuse_email(emails)
        if not abuse_url and urls:
            abuse_url = urls[0]
    return name, abuse_email, abuse_url, notes

def registrar_referral_link(domain_obj):
    self_host = None
    for link in domain_obj.get("links", []) or []:
        if link.get("rel") == "self":
            try:
                self_host = urlparse(link.get("href", "")).netloc.lower()
            except Exception:
                pass
    for link in domain_obj.get("links", []) or []:
        if link.get("rel") not in ("related", "about"):
            continue
        href = link.get("href", "")
        try:
            host = urlparse(href).netloc.lower()
        except Exception:
            continue
        if "rdap" in href.lower() and host and host != self_host:
            return href
    return None

def _whois_find(patterns, text):
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE | re.MULTILINE)
        if m:
            return m.group(1).strip()
    return None

def parse_domain_whois(text):
    info = {}
    info["registrar"] = _whois_find([r"^Registrar:\s*(.+)$", r"^registrar:\s*(.+)$"], text)
    email = _whois_find([r"Registrar Abuse Contact Email:\s*(\S+@\S+)", r"abuse-mailbox:\s*(\S+@\S+)", r"OrgAbuseEmail:\s*(\S+@\S+)"], text)
    if not email:
        for m in _EMAIL_RE.finditer(text):
            e = m.group(0).lower()
            if e.startswith("abuse@") and not _is_redacted(e):
                email = e
                break
    info["abuse_email"] = email
    info["abuse_url"] = _whois_find([r"Registrar Abuse Contact (?:Phone|Website|URL):\s*(\S+)"], text)
    info["referral"] = _whois_find([r"Registrar WHOIS Server:\s*(\S+)", r"^whois:\s*(\S+)", r"ReferralServer:\s*whois://(\S+)"], text)
    return info

def parse_ip_whois(text):
    info = {}
    info["org"] = _whois_find([r"^OrgName:\s*(.+)$", r"^org-name:\s*(.+)$", r"^owner:\s*(.+)$", r"^descr:\s*(.+)$"], text)
    email = _whois_find([r"OrgAbuseEmail:\s*(\S+@\S+)", r"abuse-mailbox:\s*(\S+@\S+)"], text)
    if not email:
        for m in _EMAIL_RE.finditer(text):
            e = m.group(0).lower()
            if e.startswith("abuse@") and not _is_redacted(e):
                email = e
                break
    info["abuse_email"] = email
    asn = _whois_find([r"^OriginAS:\s*(.+)$", r"^origin:\s*(AS\d+)", r"aut-num:\s*(AS\d+)"], text)
    if asn and not asn.upper().startswith("AS"):
        asn = "AS" + asn.strip().split()[0]
    info["asn"] = asn.upper() if asn else None
    info["referral"] = _whois_find([r"ReferralServer:\s*whois://(\S+)", r"^whois:\s*(\S+)"], text)
    info["netname"] = _whois_find([r"^NetName:\s*(.+)$", r"^netname:\s*(.+)$"], text)
    return info

def footprint_match(haystack):
    low = (haystack or "").lower()
    for provider, asns, tokens, email, url in HOSTING_FOOTPRINTS:
        if any(t in low for t in tokens):
            return provider, asns, email, url
    return None, None, None, None

def resolve_domain_rdap(domain, notes):
    reg = {"name": None, "abuse_email": None, "abuse_url": None}
    target = registrable_domain(domain)
    tld = target.rsplit(".", 1)[-1]
    server = rdap_server_for_domain(tld)
    if not server:
        notes.append(f"no RDAP server for .{tld} in IANA bootstrap")
        return reg, False
    try:
        qname = target.encode("idna").decode("ascii")
    except Exception:
        qname = target
    obj, note = http_get_json(server + "domain/" + qname)
    if obj is None:
        notes.append(f"RDAP {urlparse(server).netloc}: {note}")
        return reg, False
    notes.append(f"RDAP via {urlparse(server).netloc}")
    name, email, url, detail = extract_registrar_info(obj)
    notes.extend(detail)
    reg.update(name=name, abuse_email=email, abuse_url=url)

    ref = registrar_referral_link(obj)
    if ref and (not email or not name):
        robj, rnote = http_get_json(ref)
        if robj is not None:
            notes.append(f"registrar RDAP via {urlparse(ref).netloc}")
            rname, remail, rurl, rdetail = extract_registrar_info(robj)
            notes.extend(rdetail)
            reg["name"] = reg["name"] or rname
            reg["abuse_email"] = reg["abuse_email"] or remail
            reg["abuse_url"] = reg["abuse_url"] or rurl
    return reg, True

def resolve_domain_whois(domain, notes):
    reg = {"name": None, "abuse_email": None, "abuse_url": None}
    target = registrable_domain(domain)
    tld = target.rsplit(".", 1)[-1]
    server = TLD_WHOIS_SERVER.get(tld, "whois.iana.org")
    seen = set()
    for _hop in range(3):
        if server in seen:
            break
        seen.add(server)
        try:
            text = whois_query(server, target)
        except Exception as e:
            notes.append(f"WHOIS {server} failed: {type(e).__name__}: {str(e)[:80]}")
            return reg, False
        info = parse_domain_whois(text)
        reg["name"] = reg["name"] or info["registrar"]
        reg["abuse_email"] = reg["abuse_email"] or info["abuse_email"]
        reg["abuse_url"] = reg["abuse_url"] or info["abuse_url"]
        notes.append(f"WHOIS via {server}")
        nxt = info.get("referral")
        if nxt and reg["abuse_email"]:
            break
        if nxt:
            server = nxt
        else:
            break
    ok = bool(reg["name"] or reg["abuse_email"])
    if not ok:
        notes.append("WHOIS returned no registrar/abuse data")
    return reg, ok

def resolve_ip_rdap(ip, notes):
    hosting = {"provider": None, "asn": None, "abuse_email": None, "abuse_url": None}
    server = rdap_server_for_ip(ip)
    if not server:
        notes.append(f"no RDAP server for {ip} in IANA bootstrap")
        return hosting, False
    obj, note = http_get_json(server + "ip/" + ip)
    if obj is None:
        notes.append(f"RDAP {urlparse(server).netloc}: {note}")
        return hosting, False
    notes.append(f"RDAP via {urlparse(server).netloc}")
    provider = obj.get("name")
    emails, org_names = [], []
    abuse_email = abuse_url = None
    asn = obj.get("asn")
    for ent in all_entities(obj):
        roles = [r.lower() for r in (ent.get("roles") or [])]
        fn, org, ems, urls = vcard_fields(ent)
        if org and org not in org_names:
            org_names.append(org)
        emails.extend(e for e in ems if e not in emails)
        if "abuse" in roles:
            if not abuse_email and ems:
                abuse_email, _ = pick_abuse_email(ems)
            if not abuse_url and urls:
                abuse_url = urls[0]
    if not abuse_email:
        mail, _ = pick_abuse_email(emails)
        abuse_email = mail
    if not asn:
        m = _ASN_RE.search(json.dumps(obj.get("remarks", []))[:2000])
        asn = ("AS" + m.group(1)) if m else None
    provider = provider or (org_names[0] if org_names else None)
    hosting.update(provider=provider, asn=asn, abuse_email=abuse_email, abuse_url=abuse_url)
    return hosting, True

def resolve_ip_whois(ip, notes):
    hosting = {"provider": None, "asn": None, "abuse_email": None, "abuse_url": None}
    server, seen = "whois.arin.net", set()
    for _hop in range(3):
        if server in seen:
            break
        seen.add(server)
        try:
            text = whois_query(server, f"n + {ip}")
        except Exception as e:
            notes.append(f"WHOIS {server} failed: {type(e).__name__}: {str(e)[:80]}")
            return hosting, False
        info = parse_ip_whois(text)
        hosting["provider"] = hosting["provider"] or info["org"] or info["netname"]
        hosting["abuse_email"] = hosting["abuse_email"] or info["abuse_email"]
        hosting["asn"] = hosting["asn"] or info["asn"]
        notes.append(f"WHOIS via {server}")
        nxt = info.get("referral")
        if nxt:
            server = nxt
        else:
            break
    ok = bool(hosting["provider"] or hosting["abuse_email"])
    return hosting, ok

def apply_footprint_fallback(hosting, notes):
    if hosting.get("abuse_email"):
        return hosting
    hay = " ".join(x for x in (hosting.get("provider"), hosting.get("asn")) if x)
    provider, asns, email, url = footprint_match(hay)
    if email:
        hosting["provider"] = hosting["provider"] or provider
        hosting["asn"] = hosting["asn"] or (asns[0] if asns else None)
        hosting["abuse_email"] = email
        hosting["abuse_url"] = hosting["abuse_url"] or url
        notes.append(f"fallback: provider footprint match {provider}")
    return hosting

def resolve_ip(ip):
    notes = []
    hosting, ok = resolve_ip_rdap(ip, notes)
    if not ok or not (hosting["provider"] or hosting["abuse_email"]):
        who, _ = resolve_ip_whois(ip, notes)
        for k in hosting:
            hosting[k] = hosting[k] or who[k]
    hosting = apply_footprint_fallback(hosting, notes)
    return hosting, notes

def resolve_domain_a_records(domain):
    """Resolve A/AAAA returning ALL routable addresses to cover fast-flux."""
    ips = []
    try:
        infos = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
    except Exception as e:
        return [], f"DNS failed: {type(e).__name__}: {str(e)[:80]}"
    for fam, _socktype, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if any(addr in r for r in _DOC_RANGES) or not addr.is_global:
            continue
        if ip not in ips:
            ips.append(ip)
    return ips, "resolver returned only private IPs" if not ips else None

def resolve_domain(domain):
    notes = []
    reg = {"name": None, "abuse_email": None, "abuse_url": None}
    reg_rdap, ok = resolve_domain_rdap(domain, notes)
    for k in reg:
        reg[k] = reg[k] or reg_rdap[k]
    if not ok or not (reg["name"] or reg["abuse_email"]):
        reg_whois, _ = resolve_domain_whois(domain, notes)
        for k in reg:
            reg[k] = reg[k] or reg_whois[k]

    hosting = {"provider": None, "asn": None, "abuse_email": None, "abuse_url": None}
    ips, dns_note = resolve_domain_a_records(domain)
    if ips:
        notes.append(f"A records -> {', '.join(ips)}")
        # LT final review: collect EVERY provider across the fast-flux set.
        # First-wins populates the strict schema, but a Cloudflare-fronted
        # IP must not hide a bulletproof host behind it — the full
        # footprint goes in notes with a warning when providers differ.
        discovered_providers = set()
        for ip in ips:
            h_res, hnotes = resolve_ip(ip)
            notes.extend(hnotes)
            if h_res.get("provider"):
                discovered_providers.add(h_res["provider"])
            for k in hosting:
                hosting[k] = hosting[k] or h_res[k]
        if len(discovered_providers) > 1:
            notes.append("fast-flux warning: multiple providers detected "
                         "(%s)" % ", ".join(sorted(discovered_providers)))
    else:
        notes.append(dns_note)
    return reg, hosting, notes

def load_cache(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and "entries" in data:
            return data["entries"]
    except Exception:
        pass
    return {}

def save_cache(path, entries):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path + ".tmp", "w", encoding="utf-8") as f:
            json.dump({"version": 1, "entries": entries}, f, indent=1)
        os.replace(path + ".tmp", path)
    except Exception as e:
        warn(f"could not write cache: {e}")

def extract_host(raw):
    s = raw.strip().strip("<>").strip()
    if "://" in s:
        try:
            s = urlparse(s).netloc or s
        except Exception:
            pass
    if "@" in s and "://" not in raw:
        s = s.rsplit("@", 1)[-1]
    s = s.split("/")[0].split("?")[0].split("#")[0]
    if s.startswith("[") and "]" in s:
        s = s[1:s.index("]")]
    elif s.count(":") == 1 and not s.startswith(":"):
        s = s.split(":")[0]
    return s.strip().rstrip(".").lower()

def classify(host):
    try:
        ipaddress.ip_address(host)
        return "ip"
    except ValueError:
        pass
    if not _DOMAIN_RE.match(host):
        return None
    tld = host.rsplit(".", 1)[-1].lower()
    if not tld.isalpha() or len(tld) < 2 or tld in _FILE_EXT_TLDS or host == "localhost":
        return None
    return "domain"

def _cache_age_days(entry):
    try:
        ts = datetime.strptime(entry.get("resolved_at", ""), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - ts).total_seconds() / 86400.0
    except Exception:
        return float("inf")

def resolve_one(raw, cache, cache_path, refresh):
    host = extract_host(raw)
    kind = classify(host)
    resolved_at = utcnow()
    if kind is None:
        return {"input": raw, "kind": "unknown", "registrar": {"name": None, "abuse_email": None, "abuse_url": None},
                "hosting": {"provider": None, "asn": None, "abuse_email": None, "abuse_url": None},
                "cached": False, "resolved_at": resolved_at, "notes": "invalid domain/IP"}
    key = kind + ":" + host
    stale_note = ""
    if not refresh and key in cache:
        entry = dict(cache[key])
        age = _cache_age_days(entry)
        if age <= CACHE_TTL_DAYS:
            entry["cached"] = True
            entry["input"] = raw
            entry["notes"] = f"{entry.get('notes') or ''} [served from cache]"
            return entry
        stale_note = f"cached entry {age:.1f} days old; re-resolved"

    if kind == "domain":
        registrar, hosting, notes = resolve_domain(host)
    else:
        registrar = {"name": None, "abuse_email": None, "abuse_url": None}
        hosting, notes = resolve_ip(host)

    result = {"input": raw, "kind": kind, "registrar": registrar, "hosting": hosting,
              "cached": False, "resolved_at": resolved_at, "notes": (stale_note + "; " if stale_note else "") + "; ".join(notes)}
    cache[key] = {k: v for k, v in result.items() if k not in ("cached", "input")}
    cache[key]["input"] = host
    save_cache(cache_path, cache)
    return result

SCHEMA_HINT = "cluster.py"


# ---------------------------------------------------------------------------
# --cluster / .eml IOC collection, table output, CLI — carried over from
# 1.0.2 (LT's v2 intentionally truncated main(); these were untouched).
# ---------------------------------------------------------------------------
def _iocs_from_case_dir(case_dir):
    iocs = {"domains": [], "ips": [], "urls": []}
    path = os.path.join(case_dir, "analysis", "iocs.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for k in iocs:
            vals = data.get(k)
            if isinstance(vals, list):
                iocs[k].extend(str(v) for v in vals)
    except (FileNotFoundError, json.JSONDecodeError, OSError) as e:
        warn("no usable iocs.json in %s: %s" % (case_dir, e))
    return iocs


def _iocs_from_eml(eml_path):
    domains, ips, urls = [], [], []
    try:
        with open(eml_path, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)
    except Exception as e:
        warn("cannot parse %s: %s" % (eml_path, e))
        return {"domains": domains, "ips": ips, "urls": urls}
    text_parts = []
    try:
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in ("text/plain", "text/html"):
                try:
                    text_parts.append(part.get_content())
                except Exception:
                    pass
    except Exception:
        pass
    body = "\n".join(str(t) for t in text_parts)
    for m in _URL_HOST_RE.finditer(body):
        urls.append(m.group(0))
        domains.append(m.group(1))

    def _collect_ip(text):
        # A4 (hardening 2026-10-08): only globally routable addresses are
        # infrastructure worth resolving. RFC1918/CGNAT/loopback/link-local/
        # documentation ranges are extraction noise — resolving them just
        # burns RDAP/WHOIS attempts that always fail.
        for rx in (_IP_RE, _IPV6_RE):
            for m in rx.finditer(text):
                try:
                    addr = ipaddress.ip_address(m.group(0))
                except ValueError:
                    continue
                if addr.is_global:
                    ips.append(str(addr))

    for hdr in ("received", "x-originating-ip", "x-sender-ip"):
        for val in msg.get_all(hdr, []):
            _collect_ip(str(val))
    for hdr in ("from", "return-path", "reply-to", "sender"):
        for val in msg.get_all(hdr, []):
            for addr in _EMAIL_RE.findall(str(val)):
                domains.append(addr.rsplit("@", 1)[-1])
    return {"domains": domains, "ips": ips, "urls": urls}


def iocs_for_member(source, base_dir):
    """Resolve a cluster member's source to IOCs (case dir or .eml)."""
    candidates = []
    if os.path.isabs(source):
        candidates.append(source)
    else:
        # cluster.py records sources relative to ITS working directory,
        # which may differ from the cluster.json location.
        candidates.append(os.path.join(base_dir, source))
        candidates.append(os.path.join(os.getcwd(), source))
    src = next((c for c in candidates if os.path.exists(c)), candidates[0])
    if os.path.isdir(src):
        if os.path.exists(os.path.join(src, "case.json")):
            return _iocs_from_case_dir(src)
        warn("member source is a dir without case.json: %s" % source)
        return {"domains": [], "ips": [], "urls": []}
    if os.path.isfile(src):
        low = src.lower()
        if low.endswith(".eml"):
            return _iocs_from_eml(src)
        if os.path.basename(low) == "case.json":
            return _iocs_from_case_dir(os.path.dirname(src))
    warn("member source not found or not a case/.eml: %s" % source)
    return {"domains": [], "ips": [], "urls": []}


def collect_cluster_iocs(cluster_path):
    """Return (ordered unique valid inputs, per-cluster counts)."""
    with open(cluster_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if data.get("tool") != "cluster.py":
        warn("input does not look like cluster.py --json output; "
             "continuing anyway")
    base_dir = os.path.dirname(os.path.abspath(cluster_path))
    ordered, seen = [], set()
    per_cluster = []
    groups = [("cluster", c) for c in data.get("clusters", [])]
    groups += [("singleton", s) for s in data.get("singletons", [])]
    for gtype, grp in groups:
        label = grp.get("label", grp.get("member_id", "?"))
        members = grp.get("members", [grp]) if gtype == "cluster" else [grp]
        count = 0
        for m in members:
            iocs = iocs_for_member(m.get("source", ""), base_dir)
            for raw in iocs["domains"] + iocs["ips"]:
                host = extract_host(str(raw))
                if classify(host) and host not in seen:
                    seen.add(host)
                    ordered.append(host)
                    count += 1
            for raw in iocs["urls"]:
                try:
                    host = urlparse(str(raw)).netloc.split(":")[0].lower()
                except Exception:
                    continue
                host = extract_host(host)
                if classify(host) and host not in seen:
                    seen.add(host)
                    ordered.append(host)
                    count += 1
        per_cluster.append((label, count))
    return ordered, per_cluster


def print_table(results):
    cols = [("INPUT", 30), ("KIND", 6), ("REGISTRAR / PROVIDER", 34),
            ("ABUSE CONTACT", 32), ("CACHE", 6), ("NOTES", 0)]
    header = "  ".join(n.ljust(w) if w else n for n, w in cols)
    print(header)
    print("-" * min(len(header), 160))
    for r in results:
        reg = r["registrar"] or {}
        host = r["hosting"] or {}
        name = reg.get("name") or host.get("provider") or "-"
        contact = (reg.get("abuse_email") or host.get("abuse_email")
                   or "-")
        notes = r.get("notes") or ""
        if len(notes) > 60:
            notes = notes[:57] + "..."
        row = [r["input"][:30].ljust(30), r["kind"].ljust(6),
               name[:34].ljust(34), contact[:32].ljust(32),
               ("yes" if r["cached"] else "no").ljust(6), notes]
        print("  ".join(row))


def build_parser():
    p = argparse.ArgumentParser(
        prog="abuse-resolve.py",
        description="Resolve abuse contacts for phishing IOCs: registrar "
                    "+ abuse desk for domains, hosting provider / ASN "
                    "owner + abuse desk for IPs. RDAP-over-HTTPS first "
                    "(IANA bootstrap), WHOIS port 43 as fallback, known "
                    "hosting-provider abuse desks as last resort. "
                    "Read-only recon for defensive abuse reporting — "
                    "nothing is filed or sent.")
    p.add_argument("inputs", nargs="*",
                   help="domains/IPs (URLs and emails accepted; host "
                        "extracted automatically)")
    p.add_argument("--cluster", metavar="CLUSTER.JSON",
                   help="cluster.py --json output: resolve every unique "
                        "domain/IP across all cluster members")
    p.add_argument("--json", metavar="OUT.JSON", dest="json_out",
                   help="write machine-readable result (stable schema "
                        "for report-gen)")
    p.add_argument("--refresh", action="store_true",
                   help="bypass the on-disk cache and re-resolve")
    p.add_argument("--cache", default=DEFAULT_CACHE,
                   help="cache file path (default: %s)" % DEFAULT_CACHE)
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                   help="network timeout in seconds (default 10)")
    p.add_argument("--no-sleep", action="store_true",
                   help="skip courtesy pauses between network queries")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    Options.timeout = args.timeout
    Options.sleep = not args.no_sleep
    inputs = list(args.inputs)
    cluster_path = args.cluster
    if cluster_path:
        try:
            ciocs, per_cluster = collect_cluster_iocs(cluster_path)
        except (FileNotFoundError, json.JSONDecodeError, OSError) as e:
            sys.stderr.write("error: cannot read cluster file: %s\n" % e)
            return 2
        sys.stderr.write("cluster file: %d unique IOCs\n" % len(ciocs))
        for label, count in per_cluster:
            sys.stderr.write("  %-40s %d IOCs\n" % (label[:40], count))
        inputs.extend(x for x in ciocs if x not in inputs)
    if not inputs:
        build_parser().print_usage(sys.stderr)
        sys.stderr.write("error: give one or more domains/IPs or --cluster\n")
        return 2
    cache = load_cache(args.cache)
    results = []
    for raw in inputs:
        try:
            results.append(resolve_one(raw, cache, args.cache, args.refresh))
        except Exception as e:  # never crash the run on one bad input
            warn("unexpected failure on %r: %s: %s"
                 % (raw, type(e).__name__, str(e)[:120]))
            results.append({"input": raw, "kind": "unknown",
                            "registrar": {"name": None, "abuse_email": None,
                                          "abuse_url": None},
                            "hosting": {"provider": None, "asn": None,
                                        "abuse_email": None,
                                        "abuse_url": None},
                            "cached": False, "resolved_at": utcnow(),
                            "notes": "internal error: %s: %s"
                            % (type(e).__name__, str(e)[:120])})
    print_table(results)
    if args.json_out:
        payload = {"tool": "abuse-resolve.py", "version": VERSION,
                   "generated": utcnow(),
                   "input": (cluster_path or " ".join(args.inputs)),
                   "results": results}
        try:
            with open(args.json_out, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=1)
                f.write("\n")
            sys.stderr.write("wrote %s\n" % args.json_out)
        except OSError as e:
            sys.stderr.write("error: cannot write --json: %s\n" % e)
            return 2
    failed = sum(1 for r in results
                 if not (r["registrar"].get("abuse_email")
                         or r["hosting"].get("abuse_email")))
    if failed:
        sys.stderr.write("%d/%d inputs yielded no abuse contact "
                         "(see notes)\n" % (failed, len(results)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
