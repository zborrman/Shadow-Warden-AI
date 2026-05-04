# Obsidian Integration Guide

Shadow Warden provides a bidirectional Obsidian integration: scan your vault
for secrets, classify notes by data sensitivity, and share notes directly to
the Business Community — all without leaving Obsidian.

---

## Plugin Installation

1. Download `obsidian-plugin/main.js` and `manifest.json` from the repo
2. Copy to `.obsidian/plugins/shadow-warden-ai/` in your vault
3. Enable in Obsidian → Settings → Community Plugins
4. Configure: Settings → Shadow Warden AI → enter your `WARDEN_URL` and `API_KEY`

---

## Plugin Commands

| Command | What it does |
|---------|-------------|
| **Scan active note** | Runs `POST /obsidian/scan` on the current file |
| **Share to community** | Shares the note to Business Community (secret-gated) |
| **Vault scan** | Scans all `.md` files, shows summary |
| **Community feed** | Opens the approved post feed in a modal |
| **Ping Warden** | Health check |

The plugin also auto-scans on file modify (debounced 2s) and updates the
status bar badge: `🟢 SAFE` · `🟡 MEDIUM` · `🔴 HIGH` · `🔴 CLASSIFIED`.

---

## Note Scanner

```bash
POST /obsidian/scan
Content-Type: application/json

{
  "content":  "# My Note\nAPI_KEY=sk-abc123...",
  "filename": "my-note.md"
}
```

Response:

```json
{
  "data_class":    "CONFIDENTIAL",
  "secrets_found": [{ "type": "api_key", "redacted": "sk-***123" }],
  "redacted_body": "# My Note\nAPI_KEY=[REDACTED]",
  "word_count":    42,
  "tags":          ["security"]
}
```

### Data classification hierarchy

| Class | Trigger |
|-------|---------|
| `CLASSIFIED` | Frontmatter `data_class: CLASSIFIED` |
| `CONFIDENTIAL` | Secrets detected |
| `PHI` | HIPAA/medical keywords or tags |
| `PII` | Name/email/phone patterns |
| `FINANCIAL` | Payment card / bank account patterns |
| `GENERAL` | None of the above |

---

## Sharing to the Community

```bash
POST /community/posts/from-obsidian
Content-Type: application/json

{
  "author_id":      "user-123",
  "note_content":   "# Security Tip\nAlways rotate keys.",
  "filename":       "security-tip.md",
  "obsidian_ueciid": null
}
```

!!! danger "Blocked cases"
    - `secrets_found` is non-empty → `422 secrets_detected`
    - `data_class == CLASSIFIED` → `422 classified_content`

    The scanner runs `SecretRedactor` internally. Even if the secret is
    redacted in `redacted_body`, the original content is not logged (GDPR).

On success:

```json
{
  "id":             "post-uuid",
  "status":         "pending",
  "data_class":     "GENERAL",
  "obsidian_ueciid": null,
  "message":        "Note queued for moderation"
}
```

The post enters the NIM moderation pipeline and appears in the feed when approved.

---

## SEP UECIID

When the note has a `sep_ueciid` frontmatter key or is passed as
`obsidian_ueciid`, the resulting community post is linked to the SEP
entity. This enables cross-community transfer tracking and Causal Transfer
Proofs.
