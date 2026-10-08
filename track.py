#!/usr/bin/env python3
"""
track.py 1.0.0 — ScamIntel TOOL 4/5: takedown tracker.

Tracks abuse-report drafts from filing through acknowledgment to
resolution, and computes quotable kill-rate stats for the resume.

Runs anywhere: desktop Linux and Termux (pure stdlib).

Pipeline position: TOOL 4 of 5
    cluster.py -> abuse-resolve.py -> report-gen.py -> track.py (this)
    -> auto-ingest
Consumes report-gen.py drafts
(<case-dir>/analysis/abuse/<target>-report.txt) and optionally seeds
campaign membership from a cluster.py --json (frozen schemas documented
in those tools' docstrings).

Usage:
    track.py init --campaign LABEL [--cluster clusters.json]
    track.py import-reports --campaign LABEL --case-dir DIR [--case-dir DIR ...]
    track.py send --campaign LABEL --report-id ID [--at ISO-8601]
    track.py ack --campaign LABEL --report-id ID [--at ISO-8601] [--note TEXT]
    track.py resolve --campaign LABEL --report-id ID
        --outcome {taken-down,no-action,partial,escalated}
        [--at ISO-8601] [--evidence TEXT]
    track.py show --campaign LABEL
    track.py stats [--campaign LABEL]

Store: ONE JSON file per campaign at
    <script-dir>/cases/_tracking/<sanitized-label>.json
Per-message case directories are never touched — only the _tracking
store is written. Every mutation is written atomically (temp file +
os.replace) and bumps updated_at.

Tracking-file schema:
    {"campaign": "<label>",
     "members": ["<case slug>", ...],
     "reports": [
        {"id": "R1", "target": "registrar",
         "to": "abuse@ionos.com", "contact_confidence": "authoritative",
         "report_file": "/abs/path/<target>-report.txt",
         "case_slug": "c4-alert-kit-1", "case_dir": "/abs/path",
         "subject": "Phishing domains registered via IONOS SE ...",
         "status": "draft|sent|acknowledged|resolved",
         "sent_at": "<ISO-8601 UTC>", "ack_at": ..., "ack_note": ...,
         "resolved_at": ..., "outcome": "taken-down|no-action|partial|escalated",
         "outcome_evidence": ..., "imported_at": "<ISO-8601 UTC>"}],
     "created_at": "<ISO-8601 UTC>", "updated_at": "<ISO-8601 UTC>"}

Report lifecycle (enforced; illegal moves are rejected, exit 2):
    draft --send--> sent --ack--> acknowledged --resolve--> resolved
    sent can also resolve directly (no ack required).
    A draft can never be acked or resolved: only sent mail counts.

IDs: R1, R2, ... assigned per campaign in import order and stable —
re-importing never renumbers. Unknown IDs are rejected with the list
of valid IDs, exit 2.

Robustness: a corrupt tracking file is a hard error (exit 2) naming
the file — it is never silently overwritten or repaired. init refuses
to overwrite an existing campaign file. Timestamps default to now
(UTC, ISO-8601); --at accepts any ISO-8601 string the stdlib parses
(trailing Z allowed).

Safety: the tracker records metadata only. It never sends email,
never files forms, never modifies report drafts. Human review stays
where report-gen.py left it.

Exit codes: 0 success; 2 usage / state / corrupt-file errors.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone

VERSION = "1.0.0"
TOOL = "track.py"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TRACKING_DIR = os.path.join(SCRIPT_DIR, "cases", "_tracking")

STATUSES = ("draft", "sent", "acknowledged", "resolved")
OUTCOMES = ("taken-down", "no-action", "partial", "escalated")
FILED_STATUSES = ("sent", "acknowledged", "resolved")

_REPORT_RE = re.compile(r"^(.+)-report(?:-\d+)?\.txt$")
_HEADER_LINE_LIMIT = 40  # only scan the header block, never quoted body text


def fail(msg, code=2):
    """Print an error to stderr and exit with the given code."""
    print("%s: error: %s" % (TOOL, msg), file=sys.stderr)
    sys.exit(code)


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def check_at(value):
    """Validate an --at timestamp; return the string unchanged if parseable."""
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail("bad --at timestamp %r: expected ISO-8601 (e.g. 2026-10-08T12:00:00Z)" % value)
    return value


def sanitize_label(label):
    """Map an arbitrary campaign label to a safe filename stem."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", label).strip("._-") or "campaign"


def tracking_path(label):
    return os.path.join(TRACKING_DIR, sanitize_label(label) + ".json")


def load_campaign(label):
    """Load a campaign's tracking file. Corrupt or missing files are hard errors."""
    path = tracking_path(label)
    if not os.path.isfile(path):
        fail("no tracking file for campaign %r (%s) — run '%s init' first"
             % (label, path, TOOL))
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        fail("tracking file is CORRUPT and will NOT be overwritten: %s (%s). "
             "Restore it from backup before continuing." % (path, exc))
    except OSError as exc:
        fail("could not read tracking file %s (%s)" % (path, exc))
    if not isinstance(data, dict) or "reports" not in data:
        fail("tracking file %s has an unrecognized structure — refusing to touch it" % path)
    data.setdefault("members", [])
    return data


def save_campaign(label, data):
    """Atomically write a campaign's tracking file (temp + os.replace)."""
    data["updated_at"] = utcnow()
    path = tracking_path(label)
    tmp_fd, tmp_path = tempfile.mkstemp(prefix=".track-", suffix=".json",
                                       dir=TRACKING_DIR)
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp_path, path)
    except OSError as exc:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        fail("could not write tracking file %s (%s)" % (path, exc))


def find_report(data, report_id):
    for rep in data["reports"]:
        if rep["id"] == report_id:
            return rep
    valid = ", ".join(r["id"] for r in data["reports"]) or "(none)"
    fail("unknown report id %r for campaign %r — valid ids: %s"
         % (report_id, data.get("campaign"), valid))


def next_report_id(data):
    """Next stable ID: one past the highest existing R<n>."""
    hi = 0
    for rep in data["reports"]:
        m = re.fullmatch(r"R(\d+)", rep.get("id", ""))
        if m:
            hi = max(hi, int(m.group(1)))
    return "R%d" % (hi + 1)


# ---------------------------------------------------------------------------
# report parsing
# ---------------------------------------------------------------------------

def parse_report(path):
    """Parse target, recipient, contact confidence, case slug, subject.

    Only the header block (first N lines) is scanned so quoted body
    text can't spoof the fields.
    """
    target = None
    m = _REPORT_RE.match(os.path.basename(path))
    if m:
        target = m.group(1)
    info = {"target": target, "to": None, "contact_confidence": None,
            "case_slug": None, "subject": None}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh):
                if i >= _HEADER_LINE_LIMIT:
                    break
                line = line.rstrip("\n")
                mm = re.match(r"^To:\s*(.+?)\s*$", line)
                if mm and info["to"] is None:
                    info["to"] = mm.group(1)
                    continue
                mm = re.match(r"^Recipient:\s*(.+?)\s*$", line)
                if mm and info["to"] is None:
                    # e.g. google-safe-browsing drafts are form filings, not email
                    info["to"] = mm.group(1)
                    continue
                mm = re.match(r"^Contact confidence:\s*(\S+)", line)
                if mm and info["contact_confidence"] is None:
                    info["contact_confidence"] = mm.group(1)
                    continue
                mm = re.match(r"^Case:\s*(.+?)\s*$", line)
                if mm and info["case_slug"] is None:
                    info["case_slug"] = mm.group(1)
                    continue
                mm = re.match(r"^Subject:\s*(.+?)\s*$", line)
                if mm and info["subject"] is None:
                    info["subject"] = mm.group(1)
    except OSError as exc:
        fail("could not read report file %s (%s)" % (path, exc))
    return info


def iter_case_dirs(given):
    """Yield case directories from a --case-dir argument.

    A --case-dir is either a single case dir (has analysis/abuse) or a
    parent directory whose subdirectories contain case dirs — each
    entry is auto-detected, mirroring cluster.py's input handling.
    """
    given = os.path.abspath(given)
    if not os.path.isdir(given):
        fail("not a directory: %s" % given)
    if os.path.isdir(os.path.join(given, "analysis", "abuse")):
        yield given
        return
    found = False
    for entry in sorted(os.listdir(given)):
        cand = os.path.join(given, entry)
        if os.path.isdir(cand) and os.path.isdir(os.path.join(cand, "analysis", "abuse")):
            found = True
            yield cand
    if not found:
        fail("no case directories (with analysis/abuse/) under %s" % given)


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------

def cmd_init(args):
    os.makedirs(TRACKING_DIR, exist_ok=True)
    path = tracking_path(args.campaign)
    if os.path.exists(path):
        fail("campaign %r is already tracked (%s) — refusing to overwrite; "
             "delete the file yourself if you really want to start over"
             % (args.campaign, path))
    members = []
    if args.cluster:
        try:
            with open(args.cluster, "r", encoding="utf-8") as fh:
                clusters = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            fail("could not read cluster JSON %s (%s)" % (args.cluster, exc))
        match = None
        for c in clusters.get("clusters", []):
            if c.get("label") == args.campaign:
                match = c
                break
        if match is None:
            labels = [c.get("label") for c in clusters.get("clusters", [])]
            fail("no cluster with label %r in %s — available: %s"
                 % (args.campaign, args.cluster, ", ".join(labels) or "(none)"))
        members = [m.get("slug") or m.get("member_id") for m in match.get("members", [])]
    data = {"campaign": args.campaign,
            "members": members,
            "reports": [],
            "created_at": utcnow(),
            "updated_at": utcnow()}
    save_campaign(args.campaign, data)
    print("initialized campaign %r -> %s (%d members)"
          % (args.campaign, path, len(members)))


def cmd_import_reports(args):
    data = load_campaign(args.campaign)
    seen = {r["report_file"] for r in data["reports"]}
    added = skipped = 0
    # handle one or many --case-dir values
    for given in args.case_dir:
        for case_dir in iter_case_dirs(given):
            abuse = os.path.join(case_dir, "analysis", "abuse")
            for fname in sorted(os.listdir(abuse)):
                if not _REPORT_RE.match(fname):
                    continue
                fpath = os.path.abspath(os.path.join(abuse, fname))
                if fpath in seen:
                    skipped += 1
                    continue
                info = parse_report(fpath)
                rep = {"id": next_report_id(data),
                       "target": info["target"],
                       "to": info["to"],
                       "contact_confidence": info["contact_confidence"],
                       "report_file": fpath,
                       "case_slug": info["case_slug"],
                       "case_dir": os.path.abspath(case_dir),
                       "subject": info["subject"],
                       "status": "draft",
                       "sent_at": None, "ack_at": None, "ack_note": None,
                       "resolved_at": None, "outcome": None,
                       "outcome_evidence": None,
                       "imported_at": utcnow()}
                data["reports"].append(rep)
                seen.add(fpath)
                added += 1
                print("  %s  [%s] %-18s -> %s"
                      % (rep["id"], rep["status"], rep["target"] or "?",
                         rep["to"] or "(no recipient parsed)"))
    if added:
        save_campaign(args.campaign, data)
    print("import-reports: %d added, %d already tracked (skipped)"
          % (added, skipped))
    return 0


def transition(args, report_id, frm, to, extra=None):
    data = load_campaign(args.campaign)
    rep = find_report(data, report_id)
    if rep["status"] != frm:
        fail("report %s is %r — can only %s a %r report"
             % (report_id, rep["status"], to, frm))
    rep["status"] = to
    if extra:
        rep.update(extra)
    save_campaign(args.campaign, data)
    print("%s: %s -> %s" % (report_id, frm, to))


def cmd_send(args):
    transition(args, args.report_id, "draft", "sent",
               {"sent_at": args.at or utcnow()})


def cmd_ack(args):
    transition(args, args.report_id, "sent", "acknowledged",
               {"ack_at": args.at or utcnow(), "ack_note": args.note})


def cmd_resolve(args):
    data = load_campaign(args.campaign)
    rep = find_report(data, args.report_id)
    if rep["status"] not in ("sent", "acknowledged"):
        fail("report %s is %r — cannot resolve an unsent report "
             "(send it first)" % (args.report_id, rep["status"]))
    frm = rep["status"]
    rep["status"] = "resolved"
    rep["resolved_at"] = args.at or utcnow()
    rep["outcome"] = args.outcome
    rep["outcome_evidence"] = args.evidence
    save_campaign(args.campaign, data)
    print("%s: %s -> resolved (%s)" % (args.report_id, frm, args.outcome))


def cmd_show(args):
    data = load_campaign(args.campaign)
    print("Campaign: %s" % data["campaign"])
    print("Members:  %d case(s)%s"
          % (len(data["members"]),
             (": " + ", ".join(data["members"][:6]) + (" ..." if len(data["members"]) > 6 else ""))
              if data["members"] else ""))
    print("File:     %s" % tracking_path(args.campaign))
    print("Updated:  %s" % data.get("updated_at"))
    print()
    if not data["reports"]:
        print("No reports tracked yet.")
        return 0
    print("Reports (%d):" % len(data["reports"]))
    for rep in data["reports"]:
        head = "  %-4s [%-12s] %-18s -> %s" % (
            rep["id"], rep["status"], rep["target"] or "?",
            rep["to"] or "(no recipient)")
        print(head)
        detail = "         case: %s  conf: %s" % (
            rep.get("case_slug") or "?", rep.get("contact_confidence") or "?")
        print(detail)
        if rep.get("sent_at"):
            print("         sent: %s" % rep["sent_at"])
        if rep.get("ack_at"):
            note = " — %s" % rep["ack_note"] if rep.get("ack_note") else ""
            print("         ack:  %s%s" % (rep["ack_at"], note))
        if rep["status"] == "resolved":
            ev = " — %s" % rep["outcome_evidence"] if rep.get("outcome_evidence") else ""
            print("         resolved: %s (%s)%s" % (rep["resolved_at"], rep["outcome"], ev))
        print("         file: %s" % rep["report_file"])
    return 0


def campaign_stats(data):
    reps = data["reports"]
    filed = [r for r in reps if r["status"] in FILED_STATUSES]
    acked = [r for r in reps if r.get("ack_at")]
    kills = [r for r in reps
             if r["status"] == "resolved" and r.get("outcome") == "taken-down"]
    by_target = {}
    for r in reps:
        t = r.get("target") or "?"
        b = by_target.setdefault(t, {"filed": 0, "acked": 0, "kills": 0})
        if r["status"] in FILED_STATUSES:
            b["filed"] += 1
        if r.get("ack_at"):
            b["acked"] += 1
        if r["status"] == "resolved" and r.get("outcome") == "taken-down":
            b["kills"] += 1
    return {"filed": len(filed), "acked": len(acked), "kills": len(kills),
            "by_target": by_target}


def fmt_rate(kills, filed):
    return "n/a" if filed == 0 else "%.1f%%" % (100.0 * kills / filed)


def print_stats(title, stats):
    print("%s" % title)
    print("  Reports filed:   %d" % stats["filed"])
    print("  Acknowledgments: %d" % stats["acked"])
    print("  Confirmed kills: %d" % stats["kills"])
    print("  Kill rate:       %s  (kills / filed)" % fmt_rate(stats["kills"], stats["filed"]))
    if stats["by_target"]:
        print()
        print("  By target type:")
        print("    %-20s %6s %5s %6s %8s" % ("target", "filed", "acks", "kills", "kill%"))
        for t in sorted(stats["by_target"]):
            b = stats["by_target"][t]
            print("    %-20s %6d %5d %6d %8s"
                  % (t, b["filed"], b["acked"], b["kills"],
                     fmt_rate(b["kills"], b["filed"])))


def cmd_stats(args):
    if args.campaign:
        data = load_campaign(args.campaign)
        print_stats("Takedown stats — %s" % data["campaign"], campaign_stats(data))
        return 0
    files = sorted(f for f in os.listdir(TRACKING_DIR)
                   if f.endswith(".json") and not f.startswith(".track-")) \
        if os.path.isdir(TRACKING_DIR) else []
    if not files:
        print("No campaigns tracked yet.")
        return 0
    total = {"filed": 0, "acked": 0, "kills": 0, "by_target": {}}
    per_campaign = []
    for f in files:
        path = os.path.join(TRACKING_DIR, f)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            fail("tracking file is CORRUPT and will NOT be overwritten: %s (%s)"
                 % (path, exc))
        st = campaign_stats(data)
        per_campaign.append((data.get("campaign", f), st))
        for k in ("filed", "acked", "kills"):
            total[k] += st[k]
        for t, b in st["by_target"].items():
            tb = total["by_target"].setdefault(t, {"filed": 0, "acked": 0, "kills": 0})
            for k in ("filed", "acked", "kills"):
                tb[k] += b[k]
    for label, st in per_campaign:
        print_stats("Takedown stats — %s" % label, st)
        print()
    print_stats("Takedown stats — ALL CAMPAIGNS", total)
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="track.py",
        description="ScamIntel TOOL 4/5: takedown tracker. "
                    "Tracks abuse-report drafts (report-gen.py output) from "
                    "draft through sent, acknowledged, and resolved, and "
                    "computes quotable kill-rate stats. Store: one JSON per "
                    "campaign under cases/_tracking/. Metadata only — "
                    "nothing is ever sent or filed by this tool.")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("init", help="create a campaign tracking file")
    s.add_argument("--campaign", required=True, help="campaign label")
    s.add_argument("--cluster", default=None,
                   help="cluster.py --json: seed members from the matching cluster label")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("import-reports",
                       help="import report-gen.py drafts as draft reports")
    s.add_argument("--campaign", required=True, help="campaign label")
    s.add_argument("--case-dir", required=True, action="append",
                   help="case dir (or parent of case dirs); repeatable")
    s.set_defaults(func=cmd_import_reports)

    s = sub.add_parser("send", help="mark a draft report as sent")
    s.add_argument("--campaign", required=True)
    s.add_argument("--report-id", required=True)
    s.add_argument("--at", default=None, help="ISO-8601 timestamp (default: now UTC)")
    s.set_defaults(func=cmd_send)

    s = sub.add_parser("ack", help="mark a sent report as acknowledged")
    s.add_argument("--campaign", required=True)
    s.add_argument("--report-id", required=True)
    s.add_argument("--at", default=None, help="ISO-8601 timestamp (default: now UTC)")
    s.add_argument("--note", default=None, help="acknowledgment note")
    s.set_defaults(func=cmd_ack)

    s = sub.add_parser("resolve", help="mark a report resolved with an outcome")
    s.add_argument("--campaign", required=True)
    s.add_argument("--report-id", required=True)
    s.add_argument("--outcome", required=True, choices=OUTCOMES)
    s.add_argument("--at", default=None, help="ISO-8601 timestamp (default: now UTC)")
    s.add_argument("--evidence", default=None, help="outcome evidence note")
    s.set_defaults(func=cmd_resolve)

    s = sub.add_parser("show", help="print a human-readable campaign ledger")
    s.add_argument("--campaign", required=True)
    s.set_defaults(func=cmd_show)

    s = sub.add_parser("stats", help="print quotable kill-rate numbers")
    s.add_argument("--campaign", default=None,
                   help="campaign label (omit for all campaigns)")
    s.set_defaults(func=cmd_stats)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if getattr(args, "at", None):
        args.at = check_at(args.at)
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
