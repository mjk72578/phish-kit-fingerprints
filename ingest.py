#!/usr/bin/env python3
"""
ingest.py 1.0.0 — ScamIntel TOOL 5/5: auto-ingest orchestrator.

The final tool and the pipeline's orchestrator: it polls Gmail for new
likely-phishing messages, acquires and analyzes each one through the
ScamIntel evidence pipeline, clusters everything (inbox + cases),
drafts abuse reports for new cluster members, and queues them as DRAFTS
for human review.

Runs anywhere: desktop Linux and Termux (pure stdlib).

Pipeline position: TOOL 5 of 5
    cluster.py -> abuse-resolve.py -> report-gen.py -> track.py -> ingest.py (this)

Per-run flow:
    1. POLL   — run the harvest-style lure queries
               (account-suspended / verify / delivery-failed / invoice /
               password-expiring / before-deletion + full Spam and Trash
               sweeps) against every connected Gmail account, bounded by
               --days and --max per account.
    2. DEDUPE — never process a Gmail message ID twice. Processed IDs are
               recorded in the watermark state; messages that already have
               a case directory are also skipped (tool 1's notes flagged
               that re-acquired messages pollute clusters).
    3. ACQUIRE — for each new candidate: save a raw .eml to
               inbox/YYYY-MM-DD/<message-id>.eml (write-once; skipped if
               the file already exists), then run the ScamIntel pipeline's
               own collect path (process_message from
               email-phish-takedown-2.2.py, loaded as a module — same code
               path, not a reimplementation) into cases/.
    4. CLUSTER — one cluster.py pass over a merged view of inbox/ (.eml
               files) and cases/ (case directories), via symlinks in a
               scratch input directory.
    5. REPORT — report-gen.py --target all for every NEW cluster member
               (members whose message_id arrived this run), with the
               cluster JSON for campaign-volume context.
    6. TRACK — track.py init (new campaigns only) + import-reports, so
               every draft is queued with status=draft. NOTHING IS EVER
               SENT — drafts wait for human review.

HARD RULES (enforced, not aspirational):
    - READ-ONLY on the mailbox: only users.messages.list and
      users.messages.get are ever called. No label changes, no deletes,
      no marking read, no trashing, no modifying. Ever.
    - NEVER auto-send reports. track.py is only ever used with
      init/import-reports/show/stats; the send/ack/resolve commands are
      never invoked by this tool.
    - One failing message never kills the run: acquisition/analysis
      failures are logged to stderr, counted in the run log, and the run
      continues with the rest. poll exits 0 with an "errors" count.
    - Every network-facing call carries a timeout.

State:
    .ingest-state.json — per-account watermark: last poll time, candidate
        count, and the full set of processed message IDs (dedupe).
    .ingest-runs.log  — one JSON object per line per run: timestamp,
        candidates found, new cases, clusters, drafts queued, errors.

Usage:
    ingest.py poll [--days N] [--max N] [--dry-run]
    ingest.py status

    poll --days N    Look back N days (default 7).
    poll --max N     Cap candidates per account (default 50). The cap
                     applies after unioning all queries per account.
    poll --dry-run   Run the queries, list what WOULD be ingested
                     (new vs already-processed), change nothing:
                     no .eml saves, no cases, no state, no run log.
    status           Show the watermark per account and the last run
                     summary.

Termux note: Gmail acquisition shells out to hatch_gws_cli, which does not
exist on Android. On Termux, poll fails fast with a clear message pointing
at termux-collect.py (file-fed acquisition) instead. Everything else in
this tool is pure stdlib and runs identically.
"""

import argparse
import base64
import binascii
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

VERSION = "1.0.0"

SCRIPT_DIR = Path(__file__).resolve().parent
CASES_DIR = SCRIPT_DIR / "cases"
INBOX_DIR = SCRIPT_DIR / "inbox"
STATE_PATH = SCRIPT_DIR / ".ingest-state.json"
RUN_LOG = SCRIPT_DIR / ".ingest-runs.log"
CACHE_DIR = SCRIPT_DIR / ".cache"
CLUSTER_INPUT_DIR = CACHE_DIR / "ingest-cluster"
CLUSTER_JSON = CACHE_DIR / "ingest-clusters.json"

PIPELINE_SCRIPT = SCRIPT_DIR / "email-phish-takedown-2.2.py"
CLUSTER_SCRIPT = SCRIPT_DIR / "cluster.py"
REPORT_GEN_SCRIPT = SCRIPT_DIR / "report-gen.py"
TRACK_SCRIPT = SCRIPT_DIR / "track.py"

# Timeouts (seconds) on every network-facing or long-running call.
TIMEOUT_LIST = 60
TIMEOUT_GET = 120
TIMEOUT_CLUSTER = 300
TIMEOUT_REPORT_GEN = 900
TIMEOUT_TRACK = 120

DEFAULT_DAYS = 7
DEFAULT_MAX = 50
PROCESSED_CAP = 10000  # bound on the per-account processed-ID list

# Harvest-style lure queries, from phish-harvest-2026-10-08.md.
# Each gets " newer_than:{days}d" appended at poll time.
# Spam and Trash are swept whole (bounded by --max per account).
POLL_QUERIES = [
    # Mailbox sweeps first: Gmail already classified these as suspicious,
    # so they get priority under the per-account --max cap.
    ("mailbox:spam", "in:spam"),
    ("mailbox:trash", "in:trash"),
    ("lure:account-suspended",
     '{"account suspended" "account blocked" "account will be deleted"} -category:promotions'),
    ("lure:verify",
     '{"verify your account" "verify your identity" "confirm your identity"} -category:promotions'),
    ("lure:delivery",
     '{"delivery failed" "could not be delivered" redelivery "package on hold"} -category:promotions'),
    ("lure:invoice",
     '{"invoice" "past due" "payment overdue" "unpaid invoice"} -category:promotions'),
    ("lure:password",
     '{"password expiring" "password will expire" "password has expired"} -category:promotions'),
    ("lure:before-deletion",
     '{"before deletion" "photos will be deleted" "storage full"} -category:promotions'),
]

GWS = "hatch_gws_cli"


# ---------------------------------------------------------------------------
# small utilities
# ---------------------------------------------------------------------------

def utcnow_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log_err(msg):
    sys.stderr.write("ingest.py: %s\n" % msg)


def slugify(text, max_len=40):
    """ASCII dash-slug for case directory names."""
    text = (text or "").lower()
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    return text[:max_len].strip("-") or "untitled"


def sanitize_label(label):
    """Mirror of track.py's sanitize_label for predicting tracking paths."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", label).strip("._-") or "campaign"


def is_self_mail(meta, own_addresses):
    """True when the candidate is LT's own mail (his filed abuse reports,
    sent mail, drafts) rather than inbound phish."""
    labels = set(meta.get("labels", []) or [])
    if "SENT" in labels or "DRAFT" in labels:
        return True
    from_addr = (meta.get("from", "") or "").lower()
    return any(addr and addr.lower() in from_addr for addr in own_addresses)


# ---------------------------------------------------------------------------
# hatch_gws_cli access (read-only: list + get only, never modify/trash/mark)
# ---------------------------------------------------------------------------

def gws(args, timeout):
    """Run hatch_gws_cli, return parsed JSON. Raises RuntimeError on failure."""
    cmd = [GWS] + args
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
    except FileNotFoundError:
        raise RuntimeError(
            "hatch_gws_cli was not found in PATH. Gmail acquisition needs the "
            "desktop hatch CLI; on Termux (no hatch_gws_cli) feed raw Gmail API "
            "response bytes through termux-collect.py instead."
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("hatch_gws_cli timed out after %ds: %s" % (timeout, " ".join(args[:4])))
    if result.returncode != 0:
        raise RuntimeError("hatch_gws_cli failed: %s" % result.stderr[:1000].decode("utf-8", "replace"))
    try:
        return json.loads(result.stdout.decode("utf-8"))
    except Exception as exc:
        raise RuntimeError("hatch_gws_cli returned unparseable JSON: %s" % exc)


def list_accounts():
    """Return [(account_id, display_name)] for connected Gmail accounts."""
    data = gws(["gmail", "accounts"], TIMEOUT_LIST)
    accounts = []
    for acct in data.get("accounts", []) or []:
        aid = acct.get("account_id")
        if aid:
            accounts.append((aid, acct.get("display_name") or aid))
    return accounts


def poll_account(account_id, days, max_n):
    """Run all POLL_QUERIES against one account. Return [(query_label, msg_id)]."""
    seen = {}
    for label, query in POLL_QUERIES:
        q = "%s newer_than:%dd" % (query, days)
        params = json.dumps({"userId": "me", "q": q, "maxResults": max_n})
        try:
            data = gws(["gmail", "--account", account_id, "users", "messages", "list",
                        "--params", params], TIMEOUT_LIST)
        except RuntimeError as exc:
            raise RuntimeError("poll failed for query %r: %s" % (label, exc))
        for m in data.get("messages", []) or []:
            mid = m.get("id")
            if mid and mid not in seen:
                seen[mid] = label
        if len(seen) >= max_n:
            break
    return [(label, mid) for mid, label in list(seen.items())[:max_n]]


def get_metadata(account_id, msg_id):
    """Fetch From/Subject/Date + internalDate for one message (read-only)."""
    params = json.dumps({"userId": "me", "id": msg_id, "format": "metadata",
                         "metadataHeaders": ["From", "Subject", "Date"]})
    data = gws(["gmail", "--account", account_id, "users", "messages", "get",
                "--params", params], TIMEOUT_GET)
    headers = {}
    for h in (data.get("payload", {}) or {}).get("headers", []) or []:
        headers[h.get("name", "")] = h.get("value", "")
    return {
        "from": headers.get("From", ""),
        "subject": headers.get("Subject", ""),
        "date": headers.get("Date", ""),
        "internal_date": data.get("internalDate"),
        "labels": data.get("labelIds", []) or [],
    }


def get_full_bytes(account_id, msg_id):
    """Fetch the full Gmail API response bytes (read-only). These bytes are
    the pipeline's Phase A evidence — identical to what `collect` acquires."""
    params = json.dumps({"userId": "me", "id": msg_id, "format": "full"})
    cmd = [GWS, "gmail", "--account", account_id, "users", "messages", "get",
           "--params", params]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=TIMEOUT_GET, check=False)
    except FileNotFoundError:
        raise RuntimeError("hatch_gws_cli was not found in PATH")
    except subprocess.TimeoutExpired:
        raise RuntimeError("hatch_gws_cli timed out after %ds fetching %s" % (TIMEOUT_GET, msg_id))
    if result.returncode != 0:
        raise RuntimeError("hatch_gws_cli failed: %s" % result.stderr[:1000].decode("utf-8", "replace"))
    return result.stdout


# ---------------------------------------------------------------------------
# pipeline reuse (same code path as email-phish-takedown-2.2.py collect)
# ---------------------------------------------------------------------------

_pipeline_module = None


def load_pipeline():
    """Load email-phish-takedown-2.2.py as a module (same pattern as
    termux-collect.py). process_message() IS the collect code path."""
    global _pipeline_module
    if _pipeline_module is not None:
        return _pipeline_module
    if not PIPELINE_SCRIPT.exists():
        raise RuntimeError("pipeline not found: %s" % PIPELINE_SCRIPT)
    spec = importlib.util.spec_from_file_location("ept_pipeline", str(PIPELINE_SCRIPT))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _pipeline_module = module
    return module


def b64url_decode(data):
    value = data or ""
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        return b""


def gmail_json_to_eml(raw_bytes):
    """Convert raw Gmail API full-response bytes into best-effort RFC 822.

    The authoritative evidence stays the raw JSON bytes (the pipeline saves
    them as evidence/raw_message.json). The .eml is a human- and
    cluster.py-readable convenience copy: original headers verbatim,
    decoded text bodies, attachments listed (not embedded).
    """
    message = json.loads(raw_bytes.decode("utf-8"))
    payload = message.get("payload", {}) or {}

    em = EmailMessage()
    # Copy original headers verbatim, except the body-describing ones:
    # we rebuild the MIME structure ourselves below, and a copied
    # multipart Content-Type makes the message multipart, on which
    # set_content() raises TypeError.
    _SKIP_HEADERS = {"content-type", "mime-version", "content-transfer-encoding"}
    for h in payload.get("headers", []) or []:
        name, value = h.get("name", ""), h.get("value", "")
        if not name or name.lower().startswith("x-gm-"):
            continue
        if name.lower() in _SKIP_HEADERS:
            continue
        try:
            em[name] = value
        except Exception:
            continue

    plain_parts, html_parts, attachments = [], [], []

    def walk(part):
        mime = part.get("mimeType", "") or ""
        body = part.get("body") or {}
        data = body.get("data")
        if data and mime.startswith("text/"):
            text = b64url_decode(data).decode("utf-8", "replace")
            if text:
                (html_parts if mime.lower() == "text/html" else plain_parts).append(text)
        filename = part.get("filename") or ""
        if filename:
            attachments.append(filename)
        for sub in part.get("parts", []) or []:
            walk(sub)

    walk(payload)

    if attachments:
        em["X-Ingest-Attachments"] = "; ".join(attachments)
    em["X-Ingest-Note"] = (
        "reconstructed from Gmail API payload by ingest.py; authoritative "
        "evidence is the pipeline case's evidence/raw_message.json"
    )

    plain = "\n".join(plain_parts)
    htmlp = "\n".join(html_parts)
    if plain:
        em.set_content(plain)
        if htmlp:
            em.add_alternative(htmlp, subtype="html")
    elif htmlp:
        em.set_content(htmlp, subtype="html")
    else:
        em.set_content("(no decodable text body in Gmail payload)")
    return em.as_bytes()


def save_eml(raw_bytes, msg_id, internal_date):
    """Write-once .eml to inbox/YYYY-MM-DD/<id>.eml. Return (path, saved_bool)."""
    try:
        day = datetime.fromtimestamp(int(internal_date) / 1000, tz=timezone.utc)
    except Exception:
        day = datetime.now(timezone.utc)
    day_dir = INBOX_DIR / day.strftime("%Y-%m-%d")
    day_dir.mkdir(parents=True, exist_ok=True)
    path = day_dir / ("%s.eml" % msg_id)
    if path.exists():
        return path, False
    tmp = path.with_suffix(".eml.tmp")
    tmp.write_bytes(gmail_json_to_eml(raw_bytes))
    os.replace(tmp, path)
    return path, True


# ---------------------------------------------------------------------------
# watermark state + run log
# ---------------------------------------------------------------------------

def load_state():
    if not STATE_PATH.exists():
        return {"tool": "ingest.py", "version": VERSION, "accounts": {}}
    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        log_err("state file %s unreadable (%s); starting fresh" % (STATE_PATH, exc))
        return {"tool": "ingest.py", "version": VERSION, "accounts": {}}


def save_state(state):
    tmp = STATE_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    os.replace(tmp, STATE_PATH)


def account_state(state, account_id, display_name):
    acct = state["accounts"].setdefault(account_id, {
        "display_name": display_name, "last_poll": None,
        "last_poll_candidates": 0, "processed": []})
    acct["display_name"] = display_name
    return acct


def append_run_log(entry):
    entry = dict(entry)
    entry["tool"] = "ingest.py"
    entry["version"] = VERSION
    entry["ts"] = utcnow_iso()
    with open(RUN_LOG, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")


# ---------------------------------------------------------------------------
# case lookup (dedupe against manually-built cases too)
# ---------------------------------------------------------------------------

_case_index = None


def build_case_index():
    """Map gmail message_id -> case dir path by scanning cases/*/case.json."""
    global _case_index
    if _case_index is not None:
        return _case_index
    index = {}
    if CASES_DIR.is_dir():
        for entry in sorted(CASES_DIR.iterdir()):
            cjson = entry / "case.json"
            if not (entry.is_dir() and cjson.is_file()):
                continue
            try:
                data = json.loads(cjson.read_text(encoding="utf-8"))
            except Exception:
                continue
            mid = data.get("message_id")
            if mid:
                index.setdefault(mid, str(entry))
    _case_index = index
    return index


def reset_case_index():
    global _case_index
    _case_index = None

# ---------------------------------------------------------------------------
# per-candidate processing
# ---------------------------------------------------------------------------

def process_candidate(account_id, display_name, msg_id, query_label, meta):
    """Acquire + analyze one new candidate. Returns a result dict.

    Any failure is contained: the exception is logged to stderr and
    returned in the result; the caller keeps going with the rest.
    """
    result = {"message_id": msg_id, "query": query_label, "account": display_name,
              "subject": meta.get("subject", ""), "status": "ok",
              "eml": None, "eml_saved": False, "case_dir": None, "error": None}
    try:
        raw_bytes = get_full_bytes(account_id, msg_id)

        eml_path, saved = save_eml(raw_bytes, msg_id, meta.get("internal_date"))
        result["eml"] = str(eml_path)
        result["eml_saved"] = saved

        slug = "ingest-%s-%s" % (slugify(meta.get("subject", "")), msg_id[:8])
        pipeline = load_pipeline()
        out_dir = pipeline.process_message(
            raw_message_bytes=raw_bytes,
            message_id=msg_id,
            slug=slug,
            output_root=CASES_DIR,
            account=account_id,
            network=False,
        )
        result["case_dir"] = str(out_dir)
        reset_case_index()  # new case dir exists now
    except Exception as exc:
        result["status"] = "error"
        result["error"] = "%s: %s" % (type(exc).__name__, exc)
        log_err("candidate %s failed: %s" % (msg_id, result["error"]))
    return result


# ---------------------------------------------------------------------------
# cluster / report-gen / track orchestration
# ---------------------------------------------------------------------------

def run_subprocess(cmd, timeout, what):
    """Run a tool script; return (exit_code, stdout_text). stderr goes to ours."""
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False,
                                cwd=str(SCRIPT_DIR))
    except subprocess.TimeoutExpired:
        log_err("%s timed out after %ds" % (what, timeout))
        return 124, ""
    if result.stderr:
        sys.stderr.write(result.stderr.decode("utf-8", "replace"))
    return result.returncode, result.stdout.decode("utf-8", "replace")


def build_cluster_input():
    """Recreate .cache/ingest-cluster/ as symlinks to every case dir and
    every inbox .eml, so cluster.py makes ONE pass over inbox + cases.

    Dedupe: a message that already has a case dir is represented ONLY by
    the case dir — feeding both the .eml and the case dir for the same
    message creates phantom duplicate-pair "clusters" and pollutes real
    ones. .eml files are included only for messages with no case dir
    (e.g. pipeline analysis failed but acquisition succeeded).
    """
    if CLUSTER_INPUT_DIR.exists():
        shutil.rmtree(CLUSTER_INPUT_DIR)
    CLUSTER_INPUT_DIR.mkdir(parents=True, exist_ok=True)
    n_cases = n_eml = 0
    cased_ids = set(build_case_index().keys())
    if CASES_DIR.is_dir():
        for entry in sorted(CASES_DIR.iterdir()):
            if entry.is_dir() and (entry / "case.json").is_file():
                (CLUSTER_INPUT_DIR / entry.name).symlink_to(entry.resolve())
                n_cases += 1
    if INBOX_DIR.is_dir():
        for day_dir in sorted(INBOX_DIR.iterdir()):
            if not day_dir.is_dir():
                continue
            for eml in sorted(day_dir.glob("*.eml")):
                if eml.stem in cased_ids:
                    continue  # already represented by its case dir
                (CLUSTER_INPUT_DIR / ("%s_%s" % (day_dir.name, eml.name))).symlink_to(eml.resolve())
                n_eml += 1
    return n_cases, n_eml


def run_cluster():
    """Run cluster.py over inbox + cases; return parsed cluster JSON."""
    n_cases, n_eml = build_cluster_input()
    print("[*] clustering: %d case dirs + %d inbox .eml files" % (n_cases, n_eml))
    code, out = run_subprocess(
        [sys.executable, str(CLUSTER_SCRIPT), str(CLUSTER_INPUT_DIR),
         "--json", str(CLUSTER_JSON)],
        TIMEOUT_CLUSTER, "cluster.py")
    if code != 0:
        raise RuntimeError("cluster.py exited %d" % code)
    sys.stdout.write(out)
    return json.loads(CLUSTER_JSON.read_text(encoding="utf-8"))


def run_report_gen(case_dir, cluster_json_path):
    """Draft all report targets for one case dir. Returns True on success."""
    code, out = run_subprocess(
        [sys.executable, str(REPORT_GEN_SCRIPT), case_dir,
         "--target", "all", "--cluster", str(cluster_json_path)],
        TIMEOUT_REPORT_GEN, "report-gen.py")
    sys.stdout.write(out)
    return code == 0


def tracking_file_exists(label):
    path = CASES_DIR / "_tracking" / (sanitize_label(label) + ".json")
    return path.is_file()


def queue_drafts(campaign_cases):
    """campaign_cases: {cluster_label: [case_dir, ...]}. init new campaigns,
    import reports; all queued as status=draft. Returns drafts-added count."""
    total_added = 0
    for label in sorted(campaign_cases):
        case_dirs = campaign_cases[label]
        if not tracking_file_exists(label):
            code, out = run_subprocess(
                [sys.executable, str(TRACK_SCRIPT), "init",
                 "--campaign", label, "--cluster", str(CLUSTER_JSON)],
                TIMEOUT_TRACK, "track.py init")
            sys.stdout.write(out)
            if code != 0:
                log_err("track init failed for campaign %r; skipping its drafts" % label)
                continue
        cmd = [sys.executable, str(TRACK_SCRIPT), "import-reports",
               "--campaign", label]
        for d in case_dirs:
            cmd += ["--case-dir", d]
        code, out = run_subprocess(cmd, TIMEOUT_TRACK, "track.py import-reports")
        sys.stdout.write(out)
        if code == 0:
            m = re.search(r"import-reports: (\d+) added", out)
            if m:
                total_added += int(m.group(1))
        else:
            log_err("track import-reports failed for campaign %r" % label)
    return total_added


# ---------------------------------------------------------------------------
# poll command
# ---------------------------------------------------------------------------

def cmd_poll(args):
    days, max_n, dry_run = args.days, args.max, args.dry_run
    state = load_state()

    try:
        accounts = list_accounts()
    except RuntimeError as exc:
        log_err("GMAIL POLL BLOCKED: %s" % exc)
        return 2
    if not accounts:
        log_err("no Gmail accounts connected; connect one before polling")
        return 2

    print("[*] ingest poll: %d account(s), last %d days, max %d/account%s"
          % (len(accounts), days, max_n, " (DRY RUN)" if dry_run else ""))
    own_addresses = [name for _, name in accounts if "@" in name]

    case_index = build_case_index()
    run = {"command": "poll", "days": days, "max": max_n, "dry_run": dry_run,
           "accounts_polled": 0, "candidates": 0, "already_processed": 0,
           "self_skipped": 0,
           "case_exists_skipped": 0, "new_cases": 0, "errors": 0,
           "clusters": 0, "cluster_members_new": 0, "singletons_new": 0,
           "drafts_queued": 0}
    new_message_ids = set()
    candidate_rows = []  # for dry-run display
    errors = []

    for account_id, display_name in accounts:
        acct = account_state(state, account_id, display_name)
        processed = set(acct.get("processed", []) or [])
        try:
            candidates = poll_account(account_id, days, max_n)
        except RuntimeError as exc:
            log_err("poll failed for %s: %s" % (display_name, exc))
            errors.append({"account": display_name, "error": str(exc)})
            run["errors"] += 1
            continue
        run["accounts_polled"] += 1
        run["candidates"] += len(candidates)
        acct["last_poll"] = utcnow_iso()
        acct["last_poll_candidates"] = len(candidates)

        for query_label, msg_id in candidates:
            if msg_id in processed:
                run["already_processed"] += 1
                if dry_run:
                    candidate_rows.append((display_name, msg_id, query_label, "already-processed", ""))
                continue
            if msg_id in case_index:
                run["case_exists_skipped"] += 1
                processed.add(msg_id)
                if dry_run:
                    candidate_rows.append((display_name, msg_id, query_label, "case-exists",
                                          case_index[msg_id]))
                continue
            try:
                meta = get_metadata(account_id, msg_id)
            except RuntimeError as exc:
                log_err("metadata fetch failed for %s: %s" % (msg_id, exc))
                errors.append({"account": display_name, "message_id": msg_id, "error": str(exc)})
                run["errors"] += 1
                continue
            # Triage: skip LT's own mail (abuse reports he filed himself match
            # lure words like "phishing" and "delivery"; they are not inbound
            # phish). Self-sent is detected by the SENT label or a From that
            # matches one of his connected account addresses.
            if is_self_mail(meta, own_addresses):
                run["self_skipped"] += 1
                processed.add(msg_id)
                if dry_run:
                    candidate_rows.append((display_name, msg_id, query_label, "self-mail-skip",
                                          meta.get("subject", "")[:70]))
                continue
            if dry_run:
                candidate_rows.append((display_name, msg_id, query_label, "WOULD-INGEST",
                                      meta.get("subject", "")[:70]))
                continue
            print("[*] new candidate %s (%s): %s" % (msg_id, query_label, meta.get("subject", "")[:80]))
            result = process_candidate(account_id, display_name, msg_id, query_label, meta)
            processed.add(msg_id)  # dedupe: never process an ID twice, whatever the outcome
            if result["status"] == "ok":
                run["new_cases"] += 1
                new_message_ids.add(msg_id)
            else:
                run["errors"] += 1
                errors.append({"account": display_name, "message_id": msg_id,
                               "error": result["error"]})
        # bound the processed list; drop oldest
        acct["processed"] = list(processed)[-PROCESSED_CAP:]

    if dry_run:
        print("\n%-28s %-18s %-22s %-16s %s" % ("ACCOUNT", "MESSAGE ID", "QUERY", "VERDICT", "SUBJECT"))
        for row in candidate_rows:
            print("%-28s %-18s %-22s %-16s %s" % row)
        print("\n[dry-run] %d candidates (%d would ingest, %d already processed, %d case-exists); "
              "nothing saved, no state changed." % (
                  run["candidates"], len([r for r in candidate_rows if r[3] == "WOULD-INGEST"]),
                  run["already_processed"], run["case_exists_skipped"]))
        return 0

    # ---- downstream orchestration: cluster, report, queue drafts ----
    clusters_json = None
    try:
        clusters_json = run_cluster()
    except RuntimeError as exc:
        log_err("clustering failed: %s; skipping report/track stages" % exc)
        run["errors"] += 1
    if clusters_json:
        run["clusters"] = len(clusters_json.get("clusters", []) or [])
        campaign_cases = {}
        case_index = build_case_index()  # rebuilt after new cases landed
        for cluster in clusters_json.get("clusters", []) or []:
            label = cluster.get("label", "unlabeled")
            for member in cluster.get("members", []) or []:
                mid = member.get("message_id")
                if mid in new_message_ids:
                    run["cluster_members_new"] += 1
                    cdir = case_index.get(mid)
                    if cdir:
                        campaign_cases.setdefault(label, []).append(cdir)
        for s in clusters_json.get("singletons", []) or []:
            if s.get("message_id") in new_message_ids:
                run["singletons_new"] += 1
                print("[*] new singleton (no reports drafted): %s" % s.get("message_id"))

        reported = set()
        for label, cdirs in campaign_cases.items():
            for cdir in cdirs:
                if cdir in reported:
                    continue
                print("[*] report-gen --target all: %s" % cdir)
                if run_report_gen(cdir, CLUSTER_JSON):
                    reported.add(cdir)
                else:
                    log_err("report-gen failed for %s" % cdir)
                    run["errors"] += 1
        # queue drafts per campaign (only for cases whose reports generated)
        to_queue = {}
        for label, cdirs in campaign_cases.items():
            ok = [d for d in cdirs if d in reported]
            if ok:
                to_queue[label] = ok
        if to_queue:
            run["drafts_queued"] = queue_drafts(to_queue)
            print("[*] drafts queued (status=draft, human review required): %d" % run["drafts_queued"])

    save_state(state)
    run["errors_detail"] = errors
    append_run_log(run)
    print("[*] poll done: %d candidates, %d new cases, %d clusters, %d drafts queued, %d errors"
          % (run["candidates"], run["new_cases"], run["clusters"],
             run["drafts_queued"], run["errors"]))
    return 0


# ---------------------------------------------------------------------------
# status command
# ---------------------------------------------------------------------------

def cmd_status(_args):
    state = load_state()
    print("ingest.py %s — watermark + last run" % VERSION)
    accounts = state.get("accounts", {})
    if not accounts:
        print("  no polls recorded yet (run: ingest.py poll)")
    for aid, acct in accounts.items():
        print("  %-30s last poll: %-22s candidates: %-4d processed IDs: %d" % (
            acct.get("display_name", aid)[:30],
            acct.get("last_poll") or "never",
            acct.get("last_poll_candidates", 0),
            len(acct.get("processed", []) or [])))
    if RUN_LOG.exists():
        lines = RUN_LOG.read_text(encoding="utf-8").strip().splitlines()
        if lines:
            last = json.loads(lines[-1])
            print("  last run %s: candidates=%d new_cases=%d clusters=%d "
                  "drafts_queued=%d errors=%d" % (
                      last.get("ts"), last.get("candidates"), last.get("new_cases"),
                      last.get("clusters"), last.get("drafts_queued"), last.get("errors")))
    return 0


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        description="ScamIntel TOOL 5/5: auto-ingest. Polls Gmail for likely "
                    "phish, runs the evidence pipeline, clusters, drafts abuse "
                    "reports, and queues them as DRAFTS for human review. "
                    "Read-only on the mailbox; never auto-sends.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("poll", help="poll Gmail and ingest new likely-phish")
    p.add_argument("--days", type=int, default=DEFAULT_DAYS,
                   help="look-back window in days (default %d)" % DEFAULT_DAYS)
    p.add_argument("--max", type=int, default=DEFAULT_MAX,
                   help="candidate cap per account (default %d)" % DEFAULT_MAX)
    p.add_argument("--dry-run", action="store_true",
                   help="list what would be ingested; change nothing")
    p.set_defaults(func=cmd_poll)

    s = sub.add_parser("status", help="show watermark and last run summary")
    s.set_defaults(func=cmd_status)
    return parser


def main():
    args = build_parser().parse_args()
    try:
        return args.func(args)
    except KeyboardInterrupt:
        log_err("interrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
