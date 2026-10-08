#!/usr/bin/env python3
"""
email-phish-takedown.py 2.2.0 (merged)

Defensive email-phishing intelligence and evidence collector.

Evidence-handling tool first, IOC analyzer second.

Phase A — Acquisition (immutable):
  - Pulls raw Gmail API response bytes through hatch_gws_cli.
  - SHA-256 of the raw bytes is the primary evidence hash. The raw
    message is never re-serialized for hashing; analysis parses a copy.
  - Write-once artifacts: collision raises instead of overwriting.
  - Crash-safe: temp file + fsync + atomic rename under the hood.

Phase B — Analysis (derived, never mutates evidence):
  - IOC extraction, static HTML/JS redirect analysis, URL scoring,
    header/auth analysis, attachment hashing.
  - Optional validated network collection (--network): manual redirect
    tracing, per-hop SSRF validation, TLS inspection, DNS.
  - All derived artifacts land under analysis/ with full lineage
    (artifact_id, source, acquisition_time, sha256, size,
    transformation_performed, parent_artifact_id).

Integrity:
  - manifest.json: tamper-evident artifact manifest (lineage per artifact).
  - manifest_sha256 recorded in case.json; --verify checks it.
  - audit.json: chain-of-custody event trail, written even on failure.
  - Failure containment: a mid-pipeline crash writes a partial case.json
    (status=partial_failure), the audit trail, and the manifest, then
    re-raises. Retries get a run-suffixed directory (no collisions).
  - Standalone verification: --verify <case-dir> reports
    PASS / MISMATCH / MISSING / UNEXPECTED / MANIFEST_TAMPERED.

Safety:
  - No credential submission, no JavaScript execution, no browser automation.
  - Network collection OFF by default; private destinations blocked.
  - Reports and abuse drafts contain defanged URLs; HUMAN REVIEW REQUIRED.
  - Nothing is submitted anywhere automatically.
"""

import argparse
import base64
import binascii
import datetime
import hashlib
import http.client
import html
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional


VERSION = "2.2.0"
SCHEMA_VERSION = "4"

MAX_RESPONSE_BYTES = 2_000_000
MAX_REDIRECT_HOPS = 10
MAX_STATIC_DECODE_LENGTH = 8192
MAX_ITEMS = 500
DEFAULT_TIMEOUT = 15

UA = (
    "email-phish-takedown/"
    + VERSION
    + " (defensive-analysis; human-review)"
)

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".hta", ".msi", ".dll", ".iso", ".img", ".lnk",
    ".url", ".zip", ".rar", ".7z",
}

BLOCKED_IPV4_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
]

BLOCKED_IPV6_NETWORKS = [
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("2001:db8::/32"),
]

URL_RE = re.compile(r"(?i)(?:https?://|www\.)[^\s<>'\"()\[\]]+")
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[A-Z0-9-]+\.)+[A-Z]{2,63}\b", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
HASH_RE = re.compile(r"\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b")

REDIRECT_PARAMS = {
    "url", "u", "uri", "target", "dest", "destination", "redirect",
    "redirect_url", "redirect_uri", "next", "continue", "return",
    "returnurl", "return_url",
}

META_REFRESH_RE = re.compile(
    r"<meta\b[^>]*\bhttp-equiv\s*=\s*['\"]?"
    r"refresh['\"]?[^>]*\bcontent\s*=\s*['\"]?"
    r"[^'\"]*?\burl\s*=\s*([^'\"\s>]+)",
    re.IGNORECASE,
)

JS_REDIRECT_RES = [
    re.compile(r"(?:window\.)?location(?:\.href)?\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"document\.location(?:\.href)?\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"location\.replace\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", re.IGNORECASE),
    re.compile(r"location\.assign\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", re.IGNORECASE),
    re.compile(r"window\.open\s*\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
]

FROM_CHAR_CODE_RE = re.compile(r"String\.fromCharCode\s*\(([^)]{1,4096})\)", re.IGNORECASE)
ATOB_RE = re.compile(r"\batob\s*\(\s*['\"]([A-Za-z0-9+/=_-]{8,8192})['\"]\s*\)", re.IGNORECASE)
BASE64_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9+/_-])([A-Za-z0-9+/_-]{24,8192}={0,2})(?![A-Za-z0-9+/=_-])")
FORM_RE = re.compile(r"<form\b([^>]*)>", re.IGNORECASE | re.DOTALL)
INPUT_RE = re.compile(r"<input\b([^>]*)>", re.IGNORECASE | re.DOTALL)
IFRAME_RE = re.compile(r"<iframe\b([^>]*)>", re.IGNORECASE | re.DOTALL)
SCRIPT_SRC_RE = re.compile(r"<script\b[^>]*\bsrc\s*=\s*['\"]([^'\"]+)", re.IGNORECASE | re.DOTALL)
ATTR_RE = re.compile(r"([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*['\"]([^'\"]*)['\"]", re.IGNORECASE | re.DOTALL)

PROVIDERS = (
    ("DigitalOcean", ("digitalocean.com", "digitaloceanspaces.com")),
    ("Google", ("google.com", "googleusercontent.com")),
    ("Cloudflare", ("cloudflare.com", "pages.dev")),
    ("Amazon AWS", ("amazonaws.com", "aws.amazon.com")),
    ("Microsoft Azure", ("azurewebsites.net", "azure.com")),
    ("GitHub Pages", ("github.io", "github.com")),
    ("Vercel", ("vercel.app", "vercel.com")),
    ("Netlify", ("netlify.app", "netlify.com")),
)

# Files that form the case envelope: described by the manifest but never
# listed as evidence artifacts, and never flagged UNEXPECTED by --verify.
ENVELOPE_FILES = {"manifest.json", "case.json"}


def now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha1_bytes(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def md5_bytes(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def unique(values: List[Any]) -> List[Any]:
    seen = set()
    result = []
    for value in values:
        marker = json.dumps(value, sort_keys=True, default=str)
        if marker not in seen:
            seen.add(marker)
            result.append(value)
    return result


def safe_filename(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value)
    return value[:180] or "unnamed"


def write_atomic_file(path: Path, data: bytes) -> str:
    """
    Write-once + crash-safe evidence write.

    Existence check first: overwriting an existing artifact is a forensic
    integrity failure and raises. Otherwise writes via temp file + fsync +
    atomic rename, so a crash can never leave a torn artifact behind
    (which would otherwise wedge every future run on the collision check).
    Returns the SHA-256 of the bytes written.
    """
    if path.exists():
        raise RuntimeError(
            "FORENSIC INTEGRITY FAILURE: Collision detected! "
            f"Attempted to overwrite existing evidence artifact: {path}"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    digest = sha256_bytes(data)
    fd, temp_path = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-")
    temp_obj = Path(temp_path)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temp_obj, path)
    except Exception:
        try:
            if temp_obj.exists():
                temp_obj.unlink()
        except OSError:
            pass
        raise
    # Read-back verification: the bytes on disk must hash to what we wrote.
    if sha256_bytes(path.read_bytes()) != digest:
        raise IOError(f"read-back verification failed for {path}")
    return digest


def canonical_json_bytes(obj: Any) -> bytes:
    """Deterministic JSON encoding for evidence artifacts."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def make_artifact(
    rel_path: str,
    source: str,
    acquisition_time: str,
    sha256: str,
    size: int,
    transformation: str,
    parent_artifact_id: Optional[str],
) -> Dict[str, Any]:
    """Build a chain-of-custody artifact record for the manifest."""
    return {
        "artifact_id": rel_path,
        "path": rel_path,
        "source": source,  # "acquisition" | "derived"
        "acquisition_time": acquisition_time,
        "sha256": sha256,
        "size": size,
        "transformation_performed": transformation,
        "parent_artifact_id": parent_artifact_id,
    }


def audit_event(
    audit: Optional[List[Dict[str, Any]]],
    event: str,
    **fields: Any,
) -> None:
    """Append a chain-of-custody event. audit=None disables (zero overhead)."""
    if audit is None:
        return
    entry: Dict[str, Any] = {"ts": now_utc(), "event": event}
    entry.update(fields)
    audit.append(entry)


def audit_network_results(
    audit: List[Dict[str, Any]],
    url_intelligence: Dict[str, Any],
) -> None:
    """
    Derive chain-of-custody events from collected network results.

    Reads are tolerant (.get) so this stays compatible with revisions that
    add fields (e.g. pinned_ip from the attack-surface hardening pass).
    """
    for item in url_intelligence.get("urls", []):
        for hop in item.get("network", []):
            audit_event(
                audit,
                "http_fetch",
                url=hop.get("url"),
                hop=hop.get("hop"),
                status=hop.get("status"),
                blocked=hop.get("blocked", False),
                error=hop.get("error"),
                pinned_ip=hop.get("pinned_ip"),
                proxy=hop.get("proxy"),
                body_sha256=hop.get("body_sha256"),
            )
    for tls in url_intelligence.get("tls", []):
        audit_event(
            audit,
            "tls_inspect",
            url=tls.get("url"),
            error=tls.get("error"),
            certificate_sha256=tls.get("certificate_sha256"),
        )

def defang_url(url: str) -> str:
    value = url or ""
    value = value.replace("https://", "hxxps://")
    value = value.replace("http://", "hxxp://")
    value = value.replace("://", "[:]//")
    value = value.replace(".", "[.]")
    return value


def defang_domain(value: str) -> str:
    return (value or "").replace(".", "[.]")


def defang_ip(value: str) -> str:
    return (value or "").replace(".", "[.]")


def normalize_url(url: str) -> Optional[str]:
    if not url:
        return None
    value = html.unescape(url.strip())
    while value and value[-1] in ".,;:!?)]}>":
        value = value[:-1]
    if value.lower().startswith("www."):
        value = "http://" + value
    elif value.startswith("//"):
        value = "http:" + value
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"}:
        return None
    if not parsed.hostname:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    if port is not None and not (1 <= port <= 65535):
        return None
    return urllib.parse.urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path, parsed.query, parsed.fragment))


def extract_urls(text: str) -> List[str]:
    found = []
    for match in URL_RE.findall(text or ""):
        normalized = normalize_url(match)
        if normalized:
            found.append(normalized)
    return unique(found)[:MAX_ITEMS]


def extract_domains(text: str) -> List[str]:
    return unique([value.lower().rstrip(".") for value in DOMAIN_RE.findall(text or "")])[:MAX_ITEMS]


def extract_ips(text: str) -> List[str]:
    return unique(IP_RE.findall(text or ""))[:MAX_ITEMS]


def extract_hashes(text: str) -> List[str]:
    return unique([value.lower() for value in HASH_RE.findall(text or "")])[:MAX_ITEMS]


def extract_emails(text: str) -> List[str]:
    return unique([value.lower() for value in EMAIL_RE.findall(text or "")])[:MAX_ITEMS]


def clean_text(value: str, limit: int = 20000) -> str:
    return (value or "").replace("\x00", "")[:limit]


def try_base64_decode(value: str) -> Optional[str]:
    candidate = re.sub(r"\s+", "", value or "")
    if not candidate or len(candidate) > MAX_STATIC_DECODE_LENGTH:
        return None
    candidates = [candidate, candidate.replace("-", "+").replace("_", "/")]
    for item in candidates:
        padded = item + "=" * (-len(item) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
        except (ValueError, binascii.Error):
            continue
        if not raw:
            continue
        text = raw.decode("utf-8", "replace")
        printable = sum(1 for char in text if char.isprintable() or char in "\r\n\t")
        ratio = printable / max(1, len(text))
        if ratio >= 0.82:
            return text[:MAX_STATIC_DECODE_LENGTH]
    return None


def decode_char_codes(expression: str) -> Optional[str]:
    values = []
    for token in expression.split(","):
        token = token.strip()
        try:
            number = int(token, 0)
        except ValueError:
            continue
        if not 0 <= number <= 0x10FFFF:
            return None
        values.append(number)
    if not values:
        return None
    try:
        result = "".join(chr(number) for number in values)
    except ValueError:
        return None
    return result[:MAX_STATIC_DECODE_LENGTH] if result else None


def static_decode(text: str) -> List[Dict[str, str]]:
    findings = []
    source = clean_text(text, MAX_STATIC_DECODE_LENGTH * 4)
    for match in FROM_CHAR_CODE_RE.finditer(source):
        decoded = decode_char_codes(match.group(1))
        if decoded:
            findings.append({"type": "String.fromCharCode", "decoded": decoded})
    for match in ATOB_RE.finditer(source):
        decoded = try_base64_decode(match.group(1))
        if decoded:
            findings.append({"type": "atob", "decoded": decoded})
    for match in BASE64_CANDIDATE_RE.finditer(source):
        candidate = match.group(1)
        if len(candidate) < 24:
            continue
        decoded = try_base64_decode(candidate)
        if decoded:
            findings.append({"type": "base64", "decoded": decoded})
    return unique(findings)[:MAX_ITEMS]


def html_redirects(text: str) -> List[Dict[str, str]]:
    findings = []
    for match in META_REFRESH_RE.finditer(text or ""):
        destination = html.unescape(match.group(1).strip())
        if destination:
            findings.append({"type": "meta-refresh", "destination": destination})
    findings.extend(static_decode(text))
    return unique(findings)[:MAX_ITEMS]

def fetch_raw_message_bytes(account: str, message_id: str) -> bytes:
    """
    Phase A acquisition: capture the raw Gmail API response bytes.

    The SHA-256 of THESE bytes is the primary evidence hash. Analysis always
    parses a copy; the raw bytes are never re-serialized for hashing.
    """
    command = [
        "hatch_gws_cli", "gmail", "--account", account,
        "users", "messages", "get", "--params",
        json.dumps({"userId": "me", "id": message_id, "format": "full"}),
    ]
    try:
        result = subprocess.run(command, capture_output=True, timeout=120, check=False)
    except FileNotFoundError:
        raise RuntimeError("hatch_gws_cli was not found in PATH")
    except subprocess.TimeoutExpired:
        raise RuntimeError("hatch_gws_cli timed out after 120 seconds")
    if result.returncode != 0:
        raise RuntimeError("hatch_gws_cli failed: " + result.stderr[:1000].decode("utf-8", "replace"))
    return result.stdout


def decode_gmail_body(data: str) -> bytes:
    value = data or ""
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception:
        return b""


def walk_parts(payload: Dict[str, Any], bodies: Dict[str, List[str]], attachments: List[Dict[str, Any]]) -> None:
    mime = payload.get("mimeType", "")
    body = payload.get("body") or {}
    data = body.get("data")
    if data and mime.startswith("text/"):
        raw = decode_gmail_body(data)
        if raw:
            text = raw.decode("utf-8", "replace")
            if mime.lower() == "text/html":
                bodies["html"].append(text)
            else:
                bodies["plain"].append(text)
    filename = payload.get("filename") or ""
    if filename:
        attachments.append({
            "filename": filename,
            "mime": mime,
            "size": body.get("size", 0),
            "attachmentId": body.get("attachmentId"),
            "data": data,
        })
    for part in payload.get("parts", []) or []:
        walk_parts(part, bodies, attachments)


def header(payload: Dict[str, Any], name: str) -> str:
    for item in payload.get("headers", []) or []:
        if item.get("name", "").lower() == name.lower():
            return item.get("value", "")
    return ""


def all_headers(payload: Dict[str, Any]) -> Dict[str, List[str]]:
    result: Dict[str, List[str]] = {}
    for item in payload.get("headers", []) or []:
        name = item.get("name", "")
        value = item.get("value", "")
        if not name:
            continue
        result.setdefault(name.lower(), []).append(value)
    return result


def parse_auth_results(authentication_results: str) -> Dict[str, Any]:
    text = authentication_results or ""
    result = {"raw": text, "spf": None, "dkim": None, "dmarc": None, "arc": None}
    patterns = {
        "spf": r"\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b",
        "dkim": r"\bdkim=(pass|fail|none|temperror|permerror)\b",
        "dmarc": r"\bdmarc=(pass|fail|bestguesspass|none|temperror|permerror)\b",
        "arc": r"\barc=(pass|fail|none|temperror|permerror)\b",
    }
    for key, pattern in patterns.items():
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            result[key] = match.group(1).lower()
    result["note"] = (
        "Authentication results are read from the supplied "
        "Authentication-Results header and are not independently verified."
    )
    return result


def header_analysis(payload: Dict[str, Any]) -> Dict[str, Any]:
    frm = header(payload, "From")
    return_path = header(payload, "Return-Path")
    reply_to = header(payload, "Reply-To")
    sender = header(payload, "Sender")
    result = {"from": frm, "return_path": return_path, "reply_to": reply_to, "sender": sender, "anomalies": []}

    def address(value: str) -> str:
        match = re.search(r"<\s*([^>]+)\s*>", value or "")
        if match:
            return match.group(1).strip().lower()
        match = EMAIL_RE.search(value or "")
        return match.group(0).lower() if match else (value or "").strip().lower()

    from_addr = address(frm)
    return_addr = address(return_path)
    reply_addr = address(reply_to)
    sender_addr = address(sender)

    if from_addr and return_addr and from_addr != return_addr:
        result["anomalies"].append({"type": "from_return_path_mismatch", "from": from_addr, "return_path": return_addr})
    if from_addr and reply_addr and from_addr != reply_addr:
        result["anomalies"].append({"type": "from_reply_to_mismatch", "from": from_addr, "reply_to": reply_addr})
    if from_addr and sender_addr and from_addr != sender_addr:
        result["anomalies"].append({"type": "from_sender_mismatch", "from": from_addr, "sender": sender_addr})
    return result


def mime_analysis(payload: Dict[str, Any]) -> Dict[str, Any]:
    parts = []

    def walk(part: Dict[str, Any], path: str) -> None:
        parts.append({
            "path": path,
            "mimeType": part.get("mimeType", ""),
            "filename": part.get("filename", ""),
            "size": (part.get("body") or {}).get("size", 0),
        })
        for index, child in enumerate(part.get("parts", []) or []):
            walk(child, f"{path}.{index}")

    walk(payload, "0")
    return {"part_count": len(parts), "parts": parts}


def analyze_html(html_body: str) -> Dict[str, Any]:
    text = html_body or ""
    result: Dict[str, Any] = {
        "urls": extract_urls(text),
        "meta_redirects": [],
        "js_redirects": [],
        "decoded": [],
        "forms": [],
        "password_inputs": [],
        "external_form_actions": [],
        "iframes": [],
        "scripts": [],
    }
    for item in html_redirects(text):
        if item["type"] == "meta-refresh":
            result["meta_redirects"].append(item)
        else:
            result["decoded"].append(item)
    for pattern in JS_REDIRECT_RES:
        for match in pattern.finditer(text):
            destination = match.group(1).strip()
            if destination:
                result["js_redirects"].append({"type": "javascript-redirect", "destination": destination})
    for match in FORM_RE.finditer(text):
        attrs = dict(ATTR_RE.findall(match.group(1)))
        action = attrs.get("action", "")
        result["forms"].append({"action": action, "method": attrs.get("method", "")})
        normalized = normalize_url(action)
        if normalized:
            result["external_form_actions"].append(normalized)
    for match in INPUT_RE.finditer(text):
        attrs = dict(ATTR_RE.findall(match.group(1)))
        if attrs.get("type", "").lower() == "password":
            result["password_inputs"].append({"name": attrs.get("name", ""), "id": attrs.get("id", "")})
    for match in IFRAME_RE.finditer(text):
        attrs = dict(ATTR_RE.findall(match.group(1)))
        src = attrs.get("src", "")
        if src:
            result["iframes"].append(src)
    for match in SCRIPT_SRC_RE.finditer(text):
        result["scripts"].append(match.group(1))
    for k in ["meta_redirects", "js_redirects", "decoded", "forms", "password_inputs", "external_form_actions", "iframes", "scripts"]:
        result[k] = unique(result[k])
    return result


def analyze_url(url: str) -> Dict[str, Any]:
    parsed = urllib.parse.urlsplit(url)
    hostname = parsed.hostname or ""
    result: Dict[str, Any] = {
        "url": url,
        "scheme": parsed.scheme.lower(),
        "hostname": hostname.lower(),
        "port": parsed.port,
        "path": parsed.path,
        "query": parsed.query,
        "fragment": parsed.fragment,
        "userinfo": bool(parsed.username or parsed.password),
        "punycode": hostname.lower().startswith("xn--") or ".xn--" in hostname.lower(),
        "ip_literal": False,
        "nonstandard_port": False,
        "percent_encoding": "%" in url,
        "redirect_parameters": [],
        "flags": [],
    }
    try:
        ipaddress.ip_address(hostname)
        result["ip_literal"] = True
    except ValueError:
        pass
    if parsed.port not in (None, 80, 443):
        result["nonstandard_port"] = True
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    for key in query:
        if key.lower() in REDIRECT_PARAMS:
            result["redirect_parameters"].append(key)
    for flag_name, cond in [
        ("userinfo", result["userinfo"]),
        ("punycode", result["punycode"]),
        ("ip_literal", result["ip_literal"]),
        ("nonstandard_port", result["nonstandard_port"]),
        ("percent_encoding", result["percent_encoding"]),
        ("redirect_parameter", result["redirect_parameters"]),
    ]:
        if cond:
            result["flags"].append(flag_name)
    if parsed.scheme.lower() not in {"http", "https"}:
        result["flags"].append("unsupported_scheme")
    return result


def score_url(analysis: Dict[str, Any]) -> Dict[str, Any]:
    score = 0
    reasons = []
    weights = {"userinfo": 30, "punycode": 20, "ip_literal": 25, "nonstandard_port": 15, "percent_encoding": 5, "redirect_parameter": 10}
    for flag, weight in weights.items():
        if flag in analysis.get("flags", []):
            score += weight
            reasons.append(flag)
    confidence = "high" if score >= 50 else ("medium" if score >= 25 else "low")
    return {"score": score, "confidence": confidence, "reasons": reasons}


def providers(urls: List[str], domains: List[str]) -> List[Dict[str, Any]]:
    values = [value.lower() for value in urls + domains]
    hits = []
    for provider, suffixes in PROVIDERS:
        matched = []
        for value in values:
            try:
                host = urllib.parse.urlsplit(value).hostname or value
            except ValueError:
                host = value
            host = host.lower().rstrip(".")
            if any(host == suffix or host.endswith("." + suffix) for suffix in suffixes):
                matched.append(value)
        if matched:
            hits.append({"provider": provider, "matches": unique(matched)})
    return hits

def is_public_ip(ip_obj: ipaddress._BaseAddress) -> bool:
    if not ip_obj.is_global:
        return False
    networks = BLOCKED_IPV4_NETWORKS if ip_obj.version == 4 else BLOCKED_IPV6_NETWORKS
    return not any(ip_obj in network for network in networks)


def resolve_host(hostname: str, port: int) -> List[str]:
    infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    return unique([item[4][0] for item in infos if item[4]])


def validate_target(url: str, allow_private: bool = False) -> Dict[str, Any]:
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError as exc:
        return {"allowed": False, "reason": "invalid_url", "error": str(exc)}
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        return {"allowed": False, "reason": "unsupported_scheme", "scheme": scheme}
    host = parsed.hostname
    if not host:
        return {"allowed": False, "reason": "missing_hostname"}
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError:
        return {"allowed": False, "reason": "invalid_port", "hostname": host}
    lowered = host.lower().rstrip(".")
    if lowered == "localhost" or lowered.endswith((".localhost", ".local", ".internal", ".lan")):
        if not allow_private:
            return {"allowed": False, "reason": "non_public_hostname", "hostname": host}
    try:
        addresses = resolve_host(host, port)
    except Exception as exc:
        return {"allowed": False, "reason": "dns_resolution_failed", "hostname": host, "error": f"{type(exc).__name__}: {exc}"}
    if not addresses:
        return {"allowed": False, "reason": "no_addresses_resolved", "hostname": host}
    address_results = []
    for address in addresses:
        try:
            ip_obj = ipaddress.ip_address(address)
        except ValueError:
            address_results.append({"address": address, "public": False, "error": "invalid_ip"})
            continue
        public = is_public_ip(ip_obj)
        address_results.append({"address": address, "public": public, "version": ip_obj.version})
        if not public and not allow_private:
            return {"allowed": False, "reason": "resolved_to_non_public_ip", "hostname": host, "addresses": address_results}
    return {"allowed": True, "hostname": host, "port": port, "addresses": address_results}


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevent urllib from silently consuming HTTP redirect hops."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def read_limited(response, maximum: int = MAX_RESPONSE_BYTES) -> bytes:
    chunks = []
    remaining = maximum
    while remaining > 0:
        chunk = response.read(min(65536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class PinnedHTTPConnection(http.client.HTTPConnection):
    """
    Connect to the pre-validated pinned IP, not a fresh DNS lookup.

    The original hostname is preserved as self.host, so the HTTP Host
    header is still the real hostname (virtual hosting keeps working).
    """

    def __init__(self, host, port=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None, pinned_ip=None, **kwargs):
        super().__init__(host, port=port, timeout=timeout, source_address=source_address, **kwargs)
        self.pinned_ip = pinned_ip

    def connect(self):
        target = self.pinned_ip if self.pinned_ip else self.host
        self.sock = socket.create_connection((target, self.port), self.timeout, self.source_address)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """
    Same pinning for TLS, with SNI still set to the original hostname.
    """

    def __init__(self, host, port=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None, context=None, pinned_ip=None, **kwargs):
        super().__init__(host, port=port, timeout=timeout, source_address=source_address, context=context, **kwargs)
        self.pinned_ip = pinned_ip

    def connect(self):
        target = self.pinned_ip if self.pinned_ip else self.host
        conn = socket.create_connection((target, self.port), self.timeout, self.source_address)
        if self._tunnel_host:
            self.sock = conn
            self._tunnel()
            conn = self.sock
        self.sock = self._context.wrap_socket(conn, server_hostname=self.host)


class PinnedIPHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, pinned_ip: str):
        super().__init__()
        self.pinned_ip = pinned_ip

    def http_open(self, req):
        return self.do_open(lambda host, **kw: PinnedHTTPConnection(host, pinned_ip=self.pinned_ip, **kw), req)


class PinnedIPHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, pinned_ip: str, context=None):
        super().__init__()
        self.pinned_ip = pinned_ip
        self.context = context

    def https_open(self, req):
        return self.do_open(lambda host, **kw: PinnedHTTPSConnection(host, context=self.context, pinned_ip=self.pinned_ip, **kw), req)


def first_pinned_ip(validation: Dict[str, Any], allow_private: bool = False) -> Optional[str]:
    """Extract the first validated public IP to pin the connection to."""
    for addr_info in validation.get("addresses", []):
        if addr_info.get("public") or allow_private:
            return addr_info.get("address")
    return None


def fetch_once(url: str, timeout: int = DEFAULT_TIMEOUT, user_agent: str = UA, allow_private: bool = False, save_body: bool = True) -> Dict[str, Any]:
    # IP-pinned: validate_target resolves and vets the IPs; the socket then
    # connects to the PINNED address, not a fresh DNS lookup. This closes the
    # DNS-rebinding TOCTOU gap between validation and connection.
    #
    # Proxy caveat: if an HTTP(S) proxy is configured for the URL's scheme,
    # the proxy performs its own upstream DNS resolution, so pinning cannot
    # apply (and pinning the proxy's port would be wrong). In that case we
    # fall back to a normal proxied fetch and disclose it in the result.
    validation = validate_target(url, allow_private=allow_private)
    if not validation.get("allowed"):
        return {"url": url, "blocked": True, "validation": validation}

    parsed_url = urllib.parse.urlsplit(url)
    # A proxy does its own upstream DNS resolution, so pinning cannot apply
    # when one will actually be used for this host (honors no_proxy).
    proxy = None
    if not urllib.request.proxy_bypass(parsed_url.hostname or ""):
        proxy = urllib.request.getproxies().get(parsed_url.scheme.lower())

    pinned_ip = None
    handlers: List[Any] = [NoRedirectHandler()]
    if not proxy:
        pinned_ip = first_pinned_ip(validation, allow_private=allow_private)
        if pinned_ip:
            if parsed_url.scheme.lower() == "https":
                handlers.append(PinnedIPHTTPSHandler(pinned_ip=pinned_ip, context=ssl.create_default_context()))
            else:
                handlers.append(PinnedIPHTTPHandler(pinned_ip=pinned_ip))

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.1",
        },
        method="GET",
    )
    opener = urllib.request.build_opener(*handlers)

    try:
        response = opener.open(request, timeout=timeout)
        status = getattr(response, "status", response.getcode())
        headers = dict(response.headers.items())
        body = read_limited(response) if save_body else b""
        return {
            "url": url,
            "status": status,
            "headers": headers,
            "content_type": headers.get("Content-Type", ""),
            "body_bytes": len(body),
            "body_sha256": sha256_bytes(body) if body else None,
            "body": body.decode("utf-8", "replace"),
            "location": headers.get("Location"),
            "pinned_ip": pinned_ip,
            "proxy": proxy,
            "validation": validation,
        }
    except urllib.error.HTTPError as exc:
        headers = dict(exc.headers.items()) if exc.headers else {}
        body = b""
        if save_body:
            try:
                body = read_limited(exc)
            except Exception:
                body = b""
        return {
            "url": url,
            "status": exc.code,
            "headers": headers,
            "content_type": headers.get("Content-Type", ""),
            "body_bytes": len(body),
            "body_sha256": sha256_bytes(body) if body else None,
            "body": body.decode("utf-8", "replace"),
            "location": headers.get("Location"),
            "pinned_ip": pinned_ip,
            "proxy": proxy,
            "validation": validation,
        }
    except Exception as exc:
        return {"url": url, "error": f"{type(exc).__name__}: {exc}", "pinned_ip": pinned_ip, "proxy": proxy, "validation": validation}


def resolve_redirect_url(current: str, destination: str) -> Optional[str]:
    if not destination:
        return None
    destination = html.unescape(destination.strip())
    if destination.lower().startswith(("javascript:", "data:")):
        return None
    return normalize_url(urllib.parse.urljoin(current, destination))


def trace_redirects(seed_url: str, max_hops: int = MAX_REDIRECT_HOPS, timeout: int = DEFAULT_TIMEOUT, allow_private: bool = False, save_bodies: bool = True) -> List[Dict[str, Any]]:
    chain = []
    seen = set()
    current = normalize_url(seed_url)
    if not current:
        return [{"url": seed_url, "note": "invalid_seed_url"}]
    for hop_number in range(max_hops + 1):
        if current in seen:
            chain.append({"url": current, "hop": hop_number, "note": "loop_detected"})
            break
        seen.add(current)
        validation = validate_target(current, allow_private=allow_private)
        if not validation.get("allowed"):
            chain.append({"url": current, "hop": hop_number, "blocked": True, "validation": validation})
            break
        result = fetch_once(current, timeout=timeout, allow_private=allow_private, save_body=save_bodies)
        record = {
            "url": current,
            "hop": hop_number,
            "status": result.get("status"),
            "content_type": result.get("content_type"),
            "body_bytes": result.get("body_bytes", 0),
            "body_sha256": result.get("body_sha256"),
            "pinned_ip": result.get("pinned_ip"),
        }
        if result.get("blocked"):
            record["blocked"] = True
            record["validation"] = result.get("validation")
            chain.append(record)
            break
        if result.get("error"):
            record["error"] = result["error"]
            chain.append(record)
            break
        headers = result.get("headers", {})
        server_location = headers.get("Location")
        client_destination = None
        client_type = None
        body = result.get("body", "")
        if body:
            for item in html_redirects(body):
                if item["type"] == "meta-refresh":
                    client_type = "meta-refresh"
                    client_destination = item["destination"]
                    break
            if not client_destination:
                for pattern in JS_REDIRECT_RES:
                    match = pattern.search(body)
                    if match:
                        client_type = "javascript-redirect"
                        client_destination = match.group(1).strip()
                        break
        next_url = None
        redirect_type = None
        if server_location:
            next_url = resolve_redirect_url(current, server_location)
            redirect_type = "http-location"
        elif client_destination:
            next_url = resolve_redirect_url(current, client_destination)
            redirect_type = client_type
        if next_url:
            record["redirect_type"] = redirect_type
            record["redirected_to"] = next_url
            next_validation = validate_target(next_url, allow_private=allow_private)
            record["next_validation"] = next_validation
            if not next_validation.get("allowed"):
                record["next_blocked"] = True
                chain.append(record)
                break
        if client_destination:
            record["client_redirect"] = {"type": client_type, "destination": client_destination}
        chain.append(record)
        if not next_url:
            break
        current = next_url
    return chain


def tls_inspect(url: str, timeout: int = DEFAULT_TIMEOUT, allow_private: bool = False) -> Dict[str, Any]:
    # IP-pinned: same TOCTOU closure as fetch_once. The TCP connection goes to
    # the validated pinned IP; SNI still carries the original hostname.
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() != "https":
        return {"url": url, "skipped": True, "reason": "not_https"}
    host = parsed.hostname
    if not host:
        return {"url": url, "error": "missing_hostname"}
    validation = validate_target(url, allow_private=allow_private)
    if not validation.get("allowed"):
        return {"url": url, "tls": True, "error": "blocked_destination", "validation": validation}
    pinned_ip = first_pinned_ip(validation, allow_private=allow_private)
    if not pinned_ip:
        return {"url": url, "hostname": host, "error": "no_pinned_ip_available", "validation": validation}
    try:
        port = parsed.port or 443
        context = ssl.create_default_context()
        with socket.create_connection((pinned_ip, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                cert = tls_socket.getpeercert(binary_form=True)
                certificate = tls_socket.getpeercert()
                return {
                    "url": url,
                    "hostname": host,
                    "port": port,
                    "pinned_ip": pinned_ip,
                    "tls_version": tls_socket.version(),
                    "cipher": tls_socket.cipher(),
                    "certificate_sha256": sha256_bytes(cert) if cert else None,
                    "subject": certificate.get("subject"),
                    "issuer": certificate.get("issuer"),
                    "not_before": certificate.get("notBefore"),
                    "not_after": certificate.get("notAfter"),
                    "validation": validation,
                }
    except Exception as exc:
        return {"url": url, "hostname": host, "pinned_ip": pinned_ip, "error": f"{type(exc).__name__}: {exc}", "validation": validation}


def extract_received_ips(payload: Dict[str, Any]) -> List[str]:
    values = []
    for item in payload.get("headers", []) or []:
        if item.get("name", "").lower() == "received":
            values.extend(extract_ips(item.get("value", "")))
    return unique(values)


def collect_dns(domains: List[str]) -> List[Dict[str, Any]]:
    records = []
    for domain in unique(domains):
        try:
            addresses = resolve_host(domain, 443)
            records.append({"domain": domain, "addresses": addresses})
        except Exception as exc:
            records.append({"domain": domain, "error": f"{type(exc).__name__}: {exc}"})
    return records


def collect_url_intelligence(urls: List[str], network: bool, timeout: int, max_hops: int, allow_private: bool, save_bodies: bool) -> Dict[str, Any]:
    records = []
    redirects = []
    tls_records = []
    for url in urls:
        try:
            static = analyze_url(url)
        except Exception as exc:
            # One malformed URL must not kill the whole case.
            records.append({"url": url, "static": None, "error": f"{type(exc).__name__}: {exc}"})
            continue
        static["score"] = score_url(static)
        record = {"url": url, "static": static}
        if network:
            try:
                chain = trace_redirects(url, max_hops=max_hops, timeout=timeout, allow_private=allow_private, save_bodies=save_bodies)
            except Exception as exc:
                record["network_error"] = f"{type(exc).__name__}: {exc}"
                records.append(record)
                continue
            record["network"] = chain
            redirects.append({"seed": url, "chain": chain})
            for hop in chain:
                hop_url = hop.get("url")
                if hop_url:
                    tls_records.append(tls_inspect(hop_url, timeout=timeout, allow_private=allow_private))
        records.append(record)
    return {"urls": records, "redirects": redirects, "tls": tls_records}

def extract_attachments(
    raw_attachments: List[Dict[str, Any]],
    attachment_dir: Path,
    acquisition_time: str,
    artifacts: List[Dict[str, Any]],
    parent_artifact_id: str,
) -> List[Dict[str, Any]]:
    attachment_dir.mkdir(parents=True, exist_ok=True)
    records = []
    for item in raw_attachments:
        filename = item.get("filename", "unnamed")
        data = item.get("data")
        if not data:
            records.append({"filename": filename, "saved": False, "reason": "no_inline_data"})
            continue
        raw = decode_gmail_body(data)
        if not raw:
            records.append({"filename": filename, "saved": False, "reason": "decode_failed"})
            continue
        safe = safe_filename(filename)
        rel = f"evidence/attachments/{safe}"
        digest = write_atomic_file(attachment_dir / safe, raw)
        artifacts.append(make_artifact(
            rel_path=rel,
            source="acquisition",
            acquisition_time=acquisition_time,
            sha256=digest,
            size=len(raw),
            transformation="mime_attachment_extraction",
            parent_artifact_id=parent_artifact_id,
        ))
        suffix = Path(filename).suffix.lower()
        records.append({
            "filename": filename,
            "saved_as": safe,
            "mime": item.get("mime", ""),
            "size": len(raw),
            "md5": md5_bytes(raw),
            "sha1": sha1_bytes(raw),
            "sha256": digest,
            "suspicious_extension": suffix in SUSPICIOUS_EXTENSIONS,
            "attachmentId": item.get("attachmentId"),
        })
    return records


def aggregate_iocs(message_text: str, url_intelligence: Dict[str, Any], received_ips: List[str]) -> Dict[str, List[str]]:
    urls = extract_urls(message_text)
    domains = extract_domains(message_text)
    ips = extract_ips(message_text)
    hashes = extract_hashes(message_text)
    emails = extract_emails(message_text)
    for item in url_intelligence.get("urls", []):
        url = item.get("url")
        if url:
            urls.append(url)
            try:
                parsed = urllib.parse.urlsplit(url)
                if parsed.hostname:
                    try:
                        ipaddress.ip_address(parsed.hostname)
                        ips.append(parsed.hostname)
                    except ValueError:
                        domains.append(parsed.hostname.lower())
            except ValueError:
                pass
        for hop in item.get("network", []):
            hop_url = hop.get("url")
            if not hop_url:
                continue
            urls.append(hop_url)
            try:
                parsed = urllib.parse.urlsplit(hop_url)
                if parsed.hostname:
                    try:
                        ipaddress.ip_address(parsed.hostname)
                        ips.append(parsed.hostname)
                    except ValueError:
                        domains.append(parsed.hostname.lower())
            except ValueError:
                pass
            destination = hop.get("redirected_to")
            if destination:
                urls.append(destination)
    ips.extend(received_ips)
    return {
        "urls": unique(urls)[:MAX_ITEMS],
        "domains": unique([v.lower().rstrip(".") for v in domains])[:MAX_ITEMS],
        "ips": unique(ips)[:MAX_ITEMS],
        "hashes": unique(hashes)[:MAX_ITEMS],
        "emails": unique(emails)[:MAX_ITEMS],
    }


def make_case_id(message_id: str, evidence_hash: str) -> str:
    return hashlib.sha256((message_id + ":" + evidence_hash).encode()).hexdigest()[:16]


def write_derived_json(
    analysis_dir: Path,
    filename: str,
    obj: Any,
    acquisition_time: str,
    artifacts: List[Dict[str, Any]],
    parent_artifact_id: str,
    transformation: str,
) -> Dict[str, Any]:
    """Write a derived analysis artifact with full chain-of-custody lineage."""
    data = canonical_json_bytes(obj)
    rel = f"analysis/{filename}"
    digest = write_atomic_file(analysis_dir / filename, data)
    record = make_artifact(
        rel_path=rel,
        source="derived",
        acquisition_time=acquisition_time,
        sha256=digest,
        size=len(data),
        transformation=transformation,
        parent_artifact_id=parent_artifact_id,
    )
    artifacts.append(record)
    return record


def build_abuse_drafts(
    analysis_dir: Path,
    slug: str,
    iocs: Dict[str, List[str]],
    sender: str,
    subject: str,
    date_value: str,
    acquisition_time: str,
    artifacts: List[Dict[str, Any]],
    parent_artifact_id: str,
) -> None:
    abuse_dir = analysis_dir / "abuse"
    abuse_dir.mkdir(parents=True, exist_ok=True)
    domains = iocs.get("domains", [])
    urls = iocs.get("urls", [])
    safe_urls = [defang_url(u) for u in unique(urls) if u]

    provider_lines = [
        "HUMAN REVIEW REQUIRED",
        "",
        "This is a draft only. Nothing has been submitted automatically.",
        "",
        f"Case: {slug}",
        "",
        "To: <hosting provider abuse contact>",
        "Subject: Phishing content hosted on your infrastructure",
        "",
        "Abuse team,",
        "",
        "I am reporting suspected phishing infrastructure.",
        "",
        "The lure was delivered by email and appears to impersonate "
        "a legitimate billing/support function.",
        "",
        "Evidence:",
    ]
    for value in safe_urls:
        provider_lines.append(f"- URL: {value}")
    for domain in domains:
        provider_lines.append(f"- Host: {defang_domain(domain)}")
    provider_lines.extend([
        "",
        f"- Sender: {sender}",
        f"- Subject: {subject}",
        f"- Date: {date_value}",
        "",
        "Please investigate the reported content and take "
        "appropriate action under your abuse procedures.",
        "",
        "Regards,",
        "Miles Kimmons",
    ])
    data = ("\n".join(provider_lines) + "\n").encode("utf-8")
    digest = write_atomic_file(abuse_dir / "hosting-provider-draft.txt", data)
    artifacts.append(make_artifact(
        rel_path="analysis/abuse/hosting-provider-draft.txt",
        source="derived", acquisition_time=acquisition_time, sha256=digest,
        size=len(data), transformation="abuse_draft_rendering",
        parent_artifact_id=parent_artifact_id,
    ))

    safe_browsing_lines = [
        "HUMAN REVIEW REQUIRED",
        "",
        "Google Safe Browsing phishing-report draft.",
        "Nothing has been submitted automatically.",
        "",
    ] + [f"- {v}" for v in safe_urls]
    data = ("\n".join(safe_browsing_lines) + "\n").encode("utf-8")
    digest = write_atomic_file(abuse_dir / "google-safe-browsing-draft.txt", data)
    artifacts.append(make_artifact(
        rel_path="analysis/abuse/google-safe-browsing-draft.txt",
        source="derived", acquisition_time=acquisition_time, sha256=digest,
        size=len(data), transformation="abuse_draft_rendering",
        parent_artifact_id=parent_artifact_id,
    ))


def build_report(
    analysis_dir: Path,
    case_id: str,
    slug: str,
    message_id: str,
    evidence_sha256: str,
    metadata: Dict[str, Any],
    iocs: Dict[str, List[str]],
    auth_results: Dict[str, Any],
    header_info: Dict[str, Any],
    attachments: List[Dict[str, Any]],
    html_info: Dict[str, Any],
    url_intelligence: Dict[str, Any],
    dns_records: List[Dict[str, Any]],
    provider_hits: List[Dict[str, Any]],
    network_enabled: bool,
    acquisition_time: str,
    artifacts: List[Dict[str, Any]],
    parent_artifact_id: str,
) -> None:
    """Build the human-readable Markdown report (derived analysis, defanged)."""
    lines = []
    lines.append(f"# Threat Intelligence Report — {slug}")
    lines.append("")
    lines.append(f"Case ID: `{case_id}`")
    lines.append(f"Generated: `{now_utc()}`")
    lines.append(f"Evidence SHA256: `{evidence_sha256}`")
    lines.append("")
    lines.append(
        "> HUMAN REVIEW REQUIRED. This report performs analysis only. "
        "No abuse report or credential submission is automated."
    )
    lines.append("")
    lines.append("## Source email")
    lines.append(f"- Gmail message ID: `{message_id}`")
    lines.append(f"- From: `{metadata.get('from', '')}`")
    lines.append(f"- To: `{metadata.get('to', '')}`")
    lines.append(f"- Subject: `{metadata.get('subject', '')}`")
    lines.append(f"- Date: `{metadata.get('date', '')}`")
    lines.append("")
    lines.append("## Authentication")
    lines.append("```json")
    lines.append(json.dumps(auth_results, indent=2))
    lines.append("```")
    lines.append("")
    lines.append("## Header anomalies")
    if header_info.get("anomalies"):
        lines.append("```json")
        lines.append(json.dumps(header_info["anomalies"], indent=2))
        lines.append("```")
    else:
        lines.append("No obvious From/Return-Path/Reply-To/Sender mismatch was detected.")
    lines.append("")
    lines.append("## URLs")
    for url in [defang_url(u) for u in unique(iocs.get("urls", [])) if u]:
        lines.append(f"- `{url}`")
    lines.append("")
    lines.append("## Domains")
    for domain in iocs.get("domains", []):
        lines.append(f"- `{defang_domain(domain)}`")
    lines.append("")
    lines.append("## IP addresses")
    for ip in iocs.get("ips", []):
        lines.append(f"- `{defang_ip(ip)}`")
    lines.append("")
    lines.append("## Hashes")
    for value in iocs.get("hashes", []):
        lines.append(f"- `{value}`")
    lines.append("")
    lines.append("## Email addresses")
    for value in iocs.get("emails", []):
        lines.append(f"- `{value}`")
    lines.append("")
    lines.append("## Provider heuristics")
    if provider_hits:
        for hit in provider_hits:
            lines.append(f"- **{hit['provider']}**: " + ", ".join(defang_url(v) for v in hit["matches"]))
    else:
        lines.append("No known provider heuristic matched.")
    lines.append("")
    lines.append("## Static URL analysis")
    for item in url_intelligence.get("urls", []):
        static = item.get("static", {})
        lines.append(f"### `{defang_url(item['url'])}`")
        lines.append(f"- Confidence: `{static.get('score', {}).get('confidence', 'unknown')}`")
        lines.append(f"- Score: `{static.get('score', {}).get('score', 0)}`")
        flags = static.get("flags", [])
        lines.append("- Flags: " + (", ".join(flags) if flags else "none"))
    lines.append("")
    lines.append("## Redirect chains")
    for redirect in url_intelligence.get("redirects", []):
        lines.append(f"### Seed: `{defang_url(redirect['seed'])}`")
        for hop in redirect.get("chain", []):
            hop_url = hop.get("url", "")
            line = f"- Hop {hop.get('hop', '?')}: `{defang_url(hop_url)}`"
            if hop.get("status") is not None:
                line += f" — HTTP {hop['status']}"
            if hop.get("redirect_type"):
                line += f" — {hop['redirect_type']}"
            if hop.get("redirected_to"):
                line += " → " + defang_url(hop["redirected_to"])
            if hop.get("blocked"):
                line += " — BLOCKED"
            lines.append(line)
    lines.append("")
    lines.append("## HTML analysis")
    lines.append(f"- Password inputs: {len(html_info.get('password_inputs', []))}")
    lines.append(f"- Forms: {len(html_info.get('forms', []))}")
    lines.append(f"- External form actions: {len(html_info.get('external_form_actions', []))}")
    lines.append(f"- Iframes: {len(html_info.get('iframes', []))}")
    lines.append(f"- External scripts: {len(html_info.get('scripts', []))}")
    lines.append("")
    lines.append("## Attachments")
    if attachments:
        for attachment in attachments:
            lines.append(f"- `{attachment.get('filename', '')}`")
            if attachment.get("sha256"):
                lines.append(f"  - SHA256: `{attachment['sha256']}`")
            if attachment.get("suspicious_extension"):
                lines.append("  - Suspicious extension: YES")
    else:
        lines.append("No attachments were captured.")
    lines.append("")
    lines.append("## DNS")
    for record in dns_records:
        domain = record.get("domain", "")
        if record.get("addresses"):
            addresses = ", ".join(defang_ip(v) for v in record["addresses"])
            lines.append(f"- `{defang_domain(domain)}` → {addresses}")
        else:
            lines.append(f"- `{defang_domain(domain)}` → {record.get('error', 'no result')}")
    lines.append("")
    lines.append("## Collection notes")
    lines.append("- Active network collection: " + ("**ENABLED**" if network_enabled else "**DISABLED**"))
    if network_enabled:
        lines.append("- Network collection may have contacted attacker-controlled infrastructure.")
    lines.append("- JavaScript is never executed.")
    lines.append("- Private/non-public destinations are blocked by default.")
    lines.append("- Redirect hops are manually collected so intermediate HTTP Location responses are preserved.")
    lines.append("- DNS results are resolver observations, not historical/passive DNS.")
    lines.append("- Authentication-Results are read from message headers and are not independently verified.")
    lines.append("- Provider attribution is heuristic.")
    lines.append("")
    lines.append(
        "> This report is an analytical artifact. Provider attribution is heuristic and "
        "should be independently verified before action."
    )
    data = ("\n".join(lines) + "\n").encode("utf-8")
    digest = write_atomic_file(analysis_dir / "report.md", data)
    artifacts.append(make_artifact(
        rel_path="analysis/report.md",
        source="derived", acquisition_time=acquisition_time, sha256=digest,
        size=len(data), transformation="report_rendering",
        parent_artifact_id=parent_artifact_id,
    ))

def build_manifest(
    output_dir: Path,
    artifacts: List[Dict[str, Any]],
    acquisition_time: str,
) -> Dict[str, Any]:
    """
    Write the tamper-evident manifest.

    The manifest lists every evidence and derived artifact with full
    chain-of-custody lineage. Returns the manifest dict including its own
    SHA-256 (which the caller records in case.json).
    """
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "tool_version": VERSION,
        "generated_utc": acquisition_time,
        "artifacts": sorted(artifacts, key=lambda x: x["path"]),
    }
    manifest_bytes = canonical_json_bytes(manifest)
    digest = write_atomic_file(output_dir / "manifest.json", manifest_bytes)
    manifest["manifest_sha256"] = digest
    return manifest


def verify_case(case_dir: Path) -> int:
    """
    Standalone verification: recompute hashes and report
    PASS / MISMATCH / MISSING / UNEXPECTED / MANIFEST_TAMPERED.

    case.json and manifest.json form the case envelope: they are verified
    structurally (manifest hash vs case.json record) but are never flagged
    as UNEXPECTED evidence files.
    """
    manifest_path = case_dir / "manifest.json"
    case_path = case_dir / "case.json"
    if not manifest_path.exists():
        print(f"[!] VERIFICATION FAILED: Missing manifest.json in {case_dir}", file=sys.stderr)
        return 1
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[!] VERIFICATION FAILED: Could not parse manifest.json: {exc}", file=sys.stderr)
        return 1

    failures = 0

    # Anchor check: the manifest itself must match the hash recorded in case.json.
    if case_path.exists():
        try:
            case_data = json.loads(case_path.read_text(encoding="utf-8"))
            recorded = case_data.get("manifest_sha256")
            actual = sha256_bytes(manifest_path.read_bytes())
            if recorded and recorded != actual:
                print(f"MANIFEST_TAMPERED: manifest.json hash {actual} != case.json record {recorded}")
                failures += 1
            elif recorded:
                print("PASS: manifest.json integrity (matches case.json record)")
            else:
                print("MISSING: manifest_sha256 not recorded in case.json")
                failures += 1
        except Exception as exc:
            print(f"[!] Could not verify manifest anchor: {exc}", file=sys.stderr)
            failures += 1
    else:
        print("MISSING: case.json")
        failures += 1

    artifacts = manifest.get("artifacts", [])
    status_counts = {"PASS": 0, "MISMATCH": 0, "MISSING": 0, "UNEXPECTED": 0}
    disk_files = {
        p.relative_to(case_dir).as_posix()
        for p in case_dir.glob("**/*")
        if p.is_file() and p.name not in ENVELOPE_FILES and ".tmp-" not in p.name
    }
    manifest_paths = {art["path"] for art in artifacts}

    for art in artifacts:
        rel_path = art["path"]
        expected_sha256 = art["sha256"]
        file_path = case_dir / rel_path
        # Containment: a manifest must never address files outside the case.
        try:
            file_path.resolve().relative_to(case_dir.resolve())
        except ValueError:
            print(f"UNEXPECTED: {rel_path} (path escapes case directory)")
            status_counts["UNEXPECTED"] += 1
            continue
        if not file_path.exists():
            print(f"MISSING: {rel_path}")
            status_counts["MISSING"] += 1
            continue
        actual_sha256 = sha256_bytes(file_path.read_bytes())
        if actual_sha256 == expected_sha256:
            print(f"PASS: {rel_path}")
            status_counts["PASS"] += 1
        else:
            print(f"MISMATCH: {rel_path} (expected {expected_sha256}, got {actual_sha256})")
            status_counts["MISMATCH"] += 1

    for extra_path in sorted(disk_files - manifest_paths):
        print(f"UNEXPECTED: {extra_path}")
        status_counts["UNEXPECTED"] += 1

    print("\n--- Verification Summary ---")
    for status, count in status_counts.items():
        print(f"{status}: {count}")

    if failures or status_counts["MISMATCH"] or status_counts["MISSING"] or status_counts["UNEXPECTED"]:
        return 1
    return 0


def process_message(
    raw_message_bytes: bytes,
    message_id: str,
    slug: str,
    output_root: Path,
    account: str,
    network: bool = False,
    timeout: int = DEFAULT_TIMEOUT,
    max_hops: int = MAX_REDIRECT_HOPS,
    allow_private: bool = False,
    save_bodies: bool = True,
) -> Path:
    """
    Phase A (acquire, immutable) then Phase B (analyze a copy, derived).

    On mid-pipeline failure: writes a partial case.json
    (status=partial_failure), the audit trail, and the manifest covering
    whatever landed, then re-raises. Retries are safe: they get a
    run-suffixed directory, so write-once artifacts never collide.
    """
    audit: List[Dict[str, Any]] = []
    audit_event(audit, "acquisition_start", message_id=message_id, slug=slug, account=account)

    # Phase A: the SHA-256 of the RAW API bytes is the primary evidence hash.
    evidence_sha256 = sha256_bytes(raw_message_bytes)
    case_id = make_case_id(message_id, evidence_sha256)
    acquisition_time = now_utc()

    base_output_dir = output_root / f"{slug}-{case_id}"
    output_dir = base_output_dir
    if output_dir.exists():
        # Retry isolation: a failed run never blocks a retry, and the
        # partial directory remains as evidence of the attempt.
        nonce = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S%f")
        output_dir = output_root / f"{slug}-{case_id}-run-{nonce}"
        audit_event(audit, "retry_isolated", output_dir=output_dir.name)

    evidence_dir = output_dir / "evidence"
    analysis_dir = output_dir / "analysis"

    output_dir.mkdir(parents=True, exist_ok=True)
    evidence_dir.mkdir(exist_ok=True)
    analysis_dir.mkdir(exist_ok=True)

    audit_event(audit, "evidence_hashed", sha256=evidence_sha256, case_id=case_id)

    artifacts: List[Dict[str, Any]] = []
    raw_artifact_id = "evidence/raw_message.json"

    try:
        # Phase A: preserve the raw bytes, immutably.
        write_atomic_file(evidence_dir / "raw_message.json", raw_message_bytes)
        artifacts.append(make_artifact(
            rel_path=raw_artifact_id,
            source="acquisition",
            acquisition_time=acquisition_time,
            sha256=evidence_sha256,
            size=len(raw_message_bytes),
            transformation="raw_gws_api_capture",
            parent_artifact_id=None,
        ))
        audit_event(audit, "evidence_preserved", file=raw_artifact_id)

        # Phase B: parse a COPY. The raw evidence is never mutated.
        try:
            message = json.loads(raw_message_bytes.decode("utf-8"))
        except Exception as exc:
            raise RuntimeError(f"Failed to parse acquired raw message JSON: {exc}")

        payload = message.get("payload", {})
        bodies: Dict[str, List[str]] = {"plain": [], "html": []}
        raw_attachments: List[Dict[str, Any]] = []
        walk_parts(payload, bodies, raw_attachments)

        plain_body = "\n".join(bodies["plain"])
        html_body = "\n".join(bodies["html"])
        combined_body = plain_body + "\n" + html_body

        # Preserved body material (derived, hashed, lineage-tracked).
        write_derived_json(
            analysis_dir, "bodies.json",
            {"plain": plain_body, "html": html_body},
            acquisition_time, artifacts, raw_artifact_id,
            transformation="mime_body_extraction",
        )

        metadata = {
            "from": header(payload, "From"),
            "to": header(payload, "To"),
            "reply_to": header(payload, "Reply-To"),
            "return_path": header(payload, "Return-Path"),
            "subject": header(payload, "Subject"),
            "date": header(payload, "Date"),
            "sender": header(payload, "Sender"),
        }
        auth_results = parse_auth_results(header(payload, "Authentication-Results"))
        header_info = header_analysis(payload)
        mime_info = mime_analysis(payload)
        html_info = analyze_html(html_body)
        audit_event(audit, "static_analysis_complete")

        for fname, content, transform in [
            ("metadata.json", metadata, "header_extraction"),
            ("auth-results.json", auth_results, "auth_results_parsing"),
            ("headers.json", {"metadata": metadata, "anomalies": header_info, "authentication_results": auth_results}, "header_analysis"),
            ("mime.json", mime_info, "mime_analysis"),
            ("html-analysis.json", html_info, "html_analysis"),
        ]:
            write_derived_json(analysis_dir, fname, content, acquisition_time, artifacts, raw_artifact_id, transformation=transform)

        # headers.txt convenience rendering.
        headers_text = ("\n".join(
            f"{name}: {value}"
            for name, values in all_headers(payload).items()
            for value in values
        ) + "\n").encode("utf-8")
        digest = write_atomic_file(analysis_dir / "headers.txt", headers_text)
        artifacts.append(make_artifact(
            rel_path="analysis/headers.txt", source="derived",
            acquisition_time=acquisition_time, sha256=digest, size=len(headers_text),
            transformation="header_rendering", parent_artifact_id=raw_artifact_id,
        ))

        initial_urls = unique(
            extract_urls(combined_body)
            + html_info.get("urls", [])
            + html_info.get("external_form_actions", [])
        )[:MAX_ITEMS]

        url_intelligence = collect_url_intelligence(
            initial_urls, network=network, timeout=timeout, max_hops=max_hops,
            allow_private=allow_private, save_bodies=save_bodies,
        )
        audit_event(audit, "url_intelligence_complete", url_count=len(initial_urls), network=network)
        audit_network_results(audit, url_intelligence)

        received_ips = extract_received_ips(payload)
        iocs = aggregate_iocs(combined_body, url_intelligence, received_ips)
        audit_event(
            audit, "ioc_aggregation_complete",
            url_count=len(iocs.get("urls", [])),
            domain_count=len(iocs.get("domains", [])),
            ip_count=len(iocs.get("ips", [])),
        )

        provider_hits = providers(iocs["urls"], iocs["domains"])

        dns_records: List[Dict[str, Any]] = []
        if network:
            dns_records = collect_dns(iocs["domains"])
            audit_event(audit, "dns_complete", domain_count=len(iocs["domains"]))

        attachment_records = extract_attachments(
            raw_attachments, evidence_dir / "attachments",
            acquisition_time, artifacts, raw_artifact_id,
        )
        audit_event(audit, "attachments_complete", count=len(attachment_records))

        for fname, content, transform in [
            ("iocs.json", iocs, "ioc_aggregation"),
            ("urls.json", {"enabled": network, "urls": url_intelligence.get("urls", [])}, "url_intelligence"),
            ("redirect-chain.json", {"enabled": network, "redirects": url_intelligence.get("redirects", [])}, "redirect_tracing"),
            ("tls.json", url_intelligence.get("tls", []), "tls_inspection"),
            ("dns.json", dns_records, "dns_collection"),
            ("providers.json", provider_hits, "provider_heuristics"),
            ("attachments.json", attachment_records, "attachment_analysis"),
        ]:
            write_derived_json(analysis_dir, fname, content, acquisition_time, artifacts, raw_artifact_id, transformation=transform)

        build_abuse_drafts(
            analysis_dir, slug, iocs,
            metadata.get("from", ""), metadata.get("subject", ""), metadata.get("date", ""),
            acquisition_time, artifacts, raw_artifact_id,
        )

        build_report(
            analysis_dir, case_id, slug, message_id, evidence_sha256,
            metadata, iocs, auth_results, header_info, attachment_records,
            html_info, url_intelligence, dns_records, provider_hits,
            network, acquisition_time, artifacts, raw_artifact_id,
        )
        audit_event(audit, "pipeline_complete")

        # Audit trail first, so the manifest covers it.
        audit_bytes = canonical_json_bytes(audit)
        digest = write_atomic_file(output_dir / "audit.json", audit_bytes)
        artifacts.append(make_artifact(
            rel_path="audit.json", source="derived",
            acquisition_time=acquisition_time, sha256=digest,
            size=len(audit_bytes),
            transformation="custody_trail_rendering",
            parent_artifact_id=raw_artifact_id,
        ))

        # Manifest + case envelope (written last; hash of manifest anchored in case.json).
        manifest = build_manifest(output_dir, artifacts, acquisition_time)
        case_config = {
            "schema_version": SCHEMA_VERSION,
            "tool_version": VERSION,
            "case_id": case_id,
            "slug": slug,
            "message_id": message_id,
            "account": account,
            "generated": acquisition_time,
            "evidence_sha256": evidence_sha256,
            "manifest_sha256": manifest["manifest_sha256"],
            "network_collection": network,
            "network_settings": {
                "timeout": timeout,
                "max_hops": max_hops,
                "allow_private": allow_private,
                "save_response_bodies": save_bodies,
            },
        }
        write_atomic_file(output_dir / "case.json", canonical_json_bytes(case_config))

        return output_dir

    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        audit_event(audit, "pipeline_failed", error=error)
        try:
            write_atomic_file(
                output_dir / "case.json",
                canonical_json_bytes({
                    "schema_version": SCHEMA_VERSION,
                    "tool_version": VERSION,
                    "case_id": case_id,
                    "slug": slug,
                    "message_id": message_id,
                    "account": account,
                    "generated": acquisition_time,
                    "evidence_sha256": evidence_sha256,
                    "status": "partial_failure",
                    "error": error,
                }),
            )
        except Exception:
            pass
        raise
    finally:
        # Audit trail and manifest are written even on failure, so a partial
        # case directory is always documented and tamper-evident. Existence
        # guards keep the success path (already written above) idempotent.
        try:
            if not (output_dir / "audit.json").exists():
                audit_bytes = canonical_json_bytes(audit)
                digest = write_atomic_file(output_dir / "audit.json", audit_bytes)
                artifacts.append(make_artifact(
                    rel_path="audit.json", source="derived",
                    acquisition_time=acquisition_time, sha256=digest,
                    size=len(audit_bytes),
                    transformation="custody_trail_rendering",
                    parent_artifact_id=raw_artifact_id,
                ))
        except Exception:
            pass
        try:
            if not (output_dir / "manifest.json").exists():
                build_manifest(output_dir, artifacts, acquisition_time)
        except Exception:
            pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Forensically hardened defensive Gmail phishing analyzer. "
            "Phase A acquires raw message bytes immutably; Phase B analyzes a copy. "
            "Use 'collect' to build a case, 'verify' to audit one."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command")

    collect_parser = subparsers.add_parser(
        "collect", help="Acquire a Gmail message and analyze it into a case directory."
    )
    collect_parser.add_argument("--account", required=True, help="Gmail account ID (hatch_gws_cli --account).")
    collect_parser.add_argument("--message-id", required=True, help="Gmail message ID to acquire.")
    collect_parser.add_argument("--slug", required=True, help="Case slug, used in the output directory name.")
    collect_parser.add_argument("-o", "--output", default="~/workspace/scam-intel", help="Evidence root directory.")
    collect_parser.add_argument(
        "--network",
        action="store_true",
        help="Enable opt-in active network collection (redirect tracing, TLS, DNS). OFF by default.",
    )
    collect_parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Network timeout in seconds.")
    collect_parser.add_argument("--max-hops", type=int, default=MAX_REDIRECT_HOPS, help="Maximum redirect hops to trace.")
    collect_parser.add_argument(
        "--allow-private",
        action="store_true",
        help="Allow network collection against private/non-public destinations (lab use only).",
    )
    collect_parser.add_argument(
        "--no-response-bodies",
        action="store_true",
        help="Do not keep response bodies in memory during network collection.",
    )

    verify_parser = subparsers.add_parser(
        "verify", help="Verify the integrity of an existing case directory."
    )
    verify_parser.add_argument("--case-dir", required=True, help="Path to the case directory to verify.")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    if args.command == "verify":
        return verify_case(Path(os.path.expanduser(args.case_dir)))

    if args.command == "collect":
        output_root = Path(os.path.expanduser(args.output))
        output_root.mkdir(parents=True, exist_ok=True)

        try:
            raw_msg_bytes = fetch_raw_message_bytes(args.account, args.message_id)
        except Exception as exc:
            print(f"[!] ACQUISITION FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1

        try:
            output_dir = process_message(
                raw_message_bytes=raw_msg_bytes,
                message_id=args.message_id,
                slug=args.slug,
                output_root=output_root,
                account=args.account,
                network=args.network,
                timeout=args.timeout,
                max_hops=args.max_hops,
                allow_private=args.allow_private,
                save_bodies=not args.no_response_bodies,
            )
        except Exception as exc:
            print(f"[!] PIPELINE FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
            print("[!] A partial case directory may exist; see its audit.json.", file=sys.stderr)
            return 1

        manifest_sha = json.loads((output_dir / "case.json").read_text(encoding="utf-8")).get("manifest_sha256")
        print(f"[+] Forensic evidence package created at: {output_dir}")
        print(f"[+] Evidence SHA256: {sha256_bytes(raw_msg_bytes)}")
        print(f"[+] Manifest SHA256: {manifest_sha}")
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
