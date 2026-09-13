# Airtable Integration Module for RailCall

Production-grade Airtable integration for AI agents. Free Tier optimized with automatic rate-limit backoff, auto-chunked batch operations, and capacity monitoring. Zero external dependencies.

**Publisher:** `smit-shah/airtable` | **Version:** `1.0.5` | **Commands:** 22  
**Contest:** `contest:round2` | `contest:2026Q3`

---

## Quick Setup

```bash
# 1. Install
railcall market install smit-shah/airtable

# 2. Create PAT at airtable.com/create/tokens with scopes:
#    data.records:read, data.records:write, schema.bases:read, schema.bases:write

# 3. Register secret
railcall secrets set AIRTABLE_PAT patXXXXXXXXXXXXXXX
```

---

## 22 Governed Commands

**Record CRUD** — `get_record`, `list_records`, `search_records`, `create_record`, `update_record`, `delete_record`

**Batch Operations (Up to 100 records, auto-chunked into 10-record pages)** — `batch_create_records`, `batch_update_records`, `batch_delete_records`, `batch_upsert_records`

**Schema & Base Management** — `list_bases`, `list_tables`, `create_table`, `update_table`, `create_field`, `update_field`

**Collaboration & Diagnostics** — `add_comment`, `list_comments`, `whoami`, `list_webhooks` *(webhook creation requires paid tier)*

**Free Tier Automations** — `count_records` *(monitors 1,000-record ceiling)*, `sync_and_notify` *(upsert + auto-comment audit trail)*

---

## Free Tier Optimizations

| Airtable Limit | Solution |
|---|---|
| 5 req/sec rate limit | Automatic 429 exponential backoff with jitter (3 retries) |
| 10 records/batch | Transparent auto-chunking up to 100 records |
| 1,000 records/base | `count_records` capacity gauge with threshold warnings |
| No webhooks on Free | `sync_and_notify` chains upsert → comment notifications |

---

## Security

- Secrets from `context["secrets"]` only — never `os.environ`
- PAT auto-redacted from all error messages (`[REDACTED_PAT]`)
- All write operations require Airlock human approval
- Ed25519 signed module (`module.sig`)
- Pure Python stdlib — zero supply-chain dependencies

---

## Testing

```bash
# 32 offline unit tests (0 credentials needed)
python tests/test_airtable.py -v

# Live integration test (self-cleaning)
python tests/test_airtable.py --live --pat <PAT> --base <BASE_ID> --table <TABLE>
```
