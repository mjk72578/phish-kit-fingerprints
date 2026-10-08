# Phishing Kit Fingerprints

Defensive threat-intel notes: coding and deployment fingerprints lifted from
real phishing lures during takedown operations. Published so other defenders
can correlate kits across campaigns.

Each file is a self-contained fingerprint record tied to a preserved evidence
case (SHA-256 hashes, acquisition timestamps). No victim data. No live
malicious URLs — IOCs are defanged.

## Contents

- `fingerprint-before-deletion-1007.md` — "Before Deletion" operation
  (2026-10-07): French-template kit marker (`<!-- Bouton bleu -->`),
  uppercase `.HTML` convention, double-base64 token fragments, Unicode
  lookalike display names, filter-evasion stuffing patterns.
- `email-phish-takedown-2.2.py` — the forensic phishing-intel tool (pure
  Python stdlib; runs anywhere).
- `termux-collect.py` — Termux front end: feeds a saved raw Gmail API
  response file into the full pipeline, since `hatch_gws_cli` doesn't exist
  on Android. `verify` works unchanged via the main tool.
