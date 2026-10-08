# Kit Fingerprints — "Before Deletion" phishing operation

Case: `before-deletion-eb3e1675cb5d2da9` (ScamIntel 2.2.0)
Message ID: `1a11770e7ee78a87` — received 2026-10-07 12:37:16 CDT
Attribution: evidence retained, not a new report (infrastructure already filed
2026-10-07: DigitalOcean #12886038, Safe Browsing, IC3 18b4cb528a0f402183d4379c459a9e0d,
AWS abuse vs 15.224.161.56).

## Coding fingerprints (lure HTML)

1. **`<!-- Bouton bleu -->`** — French HTML comment ("blue button") left in the
   template while the button itself is styled red (`#f52727`). Kit authored
   from a French template or by a French speaker; operator recolored without
   updating the comment. Strongest kit fingerprint in the sample.
2. **Mismatched tags**: `<h1>Before Deletion <h1>` — second tag not closed
   properly. Hand-edited / low-quality kit.
3. **Filter-evasion stuffing**:
   - Hidden `display:none !important` div containing the sender address plus
     two legitimate YouTube URLs — pads text-to-image ratio for Bayesian filters.
   - Legitimate nuclino.com URL stuffed inside `<title>`.
   - Plain-text MIME part is scraped Edmund Optics contact info (table rows) —
     stolen legitimate content to lower spam score.
4. **Image-as-lure**: the pitch is a 620x480 PNG; the HTML is only a wrapper.
   Text scanners see nothing of the actual lure.
5. **Mangled MIME boundary** leaking into the body
   (`---_----------=bollinvArW5xZ0jL5ugc9Hvj.hkc5IDUuehRQ--`) — sloppy builder artifact.

## Deployment fingerprints

1. **Stem pattern**: `9z888885aa` — 10-char lowercase alphanumeric, reused as the
   object prefix and both filenames. Uppercase **`.HTML`** extension is unusual
   and trackable.
2. **Hosting**: DigitalOcean Spaces, `atl1` (Atlanta) region endpoint.
3. **Token fragment**: `#<base64(base64(opaque-binary))>` — double-encoded,
   inner layer is binary (not a URL). Per-victim token, not a readable destination.
4. **Destination**: `bitlaunchy.com/<long-token-path>` — kit-generated per-victim path.
5. **Delivery**: compromised Gmail (`alexescarry18@gmail.com`, SPF/DKIM/DMARC all
   pass), sent via AWS `15.224.161.56` (eu-west-3), fabricated HELO
   `leadflowcollab.com` (unregistered).
6. **Display-name spoof**: Unicode small-caps lookalikes
   ("Cʟᴏᴜᴅ Bɪʟʟɪɴɢ Sᴜᴘᴘᴏʀᴛ").

## Cross-case value

- The `Bouton bleu` comment + uppercase `.HTML` + `9z888885aa`-style stems are
  searchable kit markers. Any future lure carrying the French comment or the
  uppercase-extension convention likely comes from the same kit author.
- The double-base64 opaque token suggests the kit binds lure URLs to a
  per-victim secret; the inner binary is worth comparing across samples if a
  second one surfaces.
