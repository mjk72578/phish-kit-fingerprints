#!/usr/bin/env python3
"""
_scamintel_util.py — shared primitives for the ScamIntel pipeline tools.

Single source of truth (R5 hardening 2026-10-08) for the helpers that were
previously copy-pasted across cluster.py / abuse-resolve.py / report-gen.py
with slight divergences (the public-suffix lists already disagreed — H3/A6).

Pure stdlib. Portable: desktop Linux and Termux. No side effects on import.

Contents:
    ADDR_RE, strip_addr, display_name  — email address parsing
    MULTI_SUFFIXES, registrable_domain — eTLD+1 reduction
    GENERIC_LOCALPARTS                  — blocklist for H1 localpart heuristic
    defang                              — IOC defanging for reports
"""

import re

# ---------------------------------------------------------------------------
# address parsing
# ---------------------------------------------------------------------------

ADDR_RE = re.compile(
    r"<?([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})>?")


def strip_addr(raw):
    """Pull the bare addr-spec out of 'Display <a@b>' / '<a@b>' / 'a@b'."""
    if not raw:
        return ""
    m = ADDR_RE.search(raw)
    return m.group(1).lower() if m else ""


def display_name(raw):
    """Rough display-name extraction: text before <addr>.

    LT final review: rsplit-based, no regex at all — ReDoS-impossible by
    construction, no arbitrary length cap needed. For well-formed
    "Display <addr>" input this matches the old regex behavior exactly.
    """
    if not raw:
        return ""
    raw = str(raw)
    if "<" in raw and ">" in raw:
        left = raw.rsplit("<", 1)[0].strip()
        if len(left) >= 2 and left.startswith('"') and left.endswith('"'):
            return left[1:-1].strip()
        return left
    return ""


# ---------------------------------------------------------------------------
# public suffixes / registrable domains
# ---------------------------------------------------------------------------
# Multi-level suffixes only; anything else falls back to last-two-labels.
# This is the broadest of the three lists the tools previously carried
# (abuse-resolve.py's), now canonical for the whole pipeline.

MULTI_SUFFIXES = frozenset("""
co.uk org.uk me.uk net.uk ltd.uk plc.uk ac.uk gov.uk
com.au net.au org.au asn.au id.au
co.jp ne.jp or.jp ac.jp go.jp ad.jp
co.kr ne.kr or.kr go.kr
co.in net.in org.in gen.in
com.br net.br org.br gov.br
co.za net.za org.za gov.za
co.nz net.nz org.nz govt.nz
com.mx net.mx org.mx gob.mx
com.ar net.ar org.ar gov.ar
com.tr net.tr org.tr gov.tr
co.id net.id or.id web.id my.id biz.id ac.id sch.id go.id mil.id desa.id ponpes.id
co.il org.il net.il ac.il gov.il
com.sg net.sg org.sg
com.hk net.hk org.hk
com.tw net.tw org.tw idv.tw
com.cn net.cn org.cn gov.cn
com.ph net.ph org.ph
com.my net.my org.my gov.my
""".split())


def registrable_domain(host):
    """Reduce host to its registrable (eTLD+1) domain.

    lket17.bsgvo.my.id -> bsgvo.my.id ; www.amazon.co.jp -> amazon.co.jp.
    Unknown suffixes fall back to last-two-labels (documented limitation;
    prefer expanding MULTI_SUFFIXES over working around it).
    """
    labels = host.lower().strip(".").split(".")
    if len(labels) < 2:
        return host.lower()
    for n in (3, 2):
        if len(labels) > n:
            cand = ".".join(labels[-n:])
            if cand in MULTI_SUFFIXES:
                return ".".join(labels[-(n + 1):])
    return ".".join(labels[-2:])


# ---------------------------------------------------------------------------
# H1 support: generic sender localparts (never merge keys)
# ---------------------------------------------------------------------------

GENERIC_LOCALPARTS = frozenset(
    "info support noreply no-reply no_reply admin administrator "
    "service services contact hello mail email team help billing "
    "accounts security notify notifications alerts marketing sales "
    "newsletter postmaster webmaster abuse sales info1 contactus "
    "support1 helpdesk".split())


# ---------------------------------------------------------------------------
# defanging
# ---------------------------------------------------------------------------

# LT round-2: already-defanged chars are left alone, so re-running
# defang on defanged text is idempotent (no [[.]], [[:]], [[@]]).
# The same guard covers ".", ":", "@" — all three had the double-wrap
# flaw (colons/@ extended from LT's dot fix; same bug class).
_DEFANG_HTTP_RE = re.compile(r"(?i)http")
_DEFANG_DOT_RE = re.compile(r"(?<!\[)\.(?!\])")
_DEFANG_COLON_RE = re.compile(r"(?<!\[):(?!\])")
_DEFANG_AT_RE = re.compile(r"(?<!\[)@(?!\])")


def defang(text):
    """Render an IOC unclickable: http->hxxp, .->[.] , :->[:], @->[@].

    Idempotent: hxxp[:]//evil[.]com stays exactly as-is on re-run.
    Case-insensitive on the scheme (HTTP://, Http://, ...).
    """
    if not text:
        return ""
    s = str(text)
    s = _DEFANG_HTTP_RE.sub("hxxp", s)
    s = _DEFANG_DOT_RE.sub("[.]", s)
    s = _DEFANG_COLON_RE.sub("[:]", s)
    s = _DEFANG_AT_RE.sub("[@]", s)
    return s
