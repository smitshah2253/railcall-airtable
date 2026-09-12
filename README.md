# Airtable Integration Module for RailCall

> Connect AI agents to Airtable REST API. Full CRUD, batch operations, schemas, and comments with zero dependencies and airlock safety.  
> **Contest Tag:** `contest:round2` (`contest:2026Q3`) | **Publisher:** `smit-shah/airtable` | **Version:** `1.0.2`

---

## Overview

Enables RailCall agents to treat Airtable as a relational database. Automates CRM syncs, bulk data operations, schema migrations, and record collaboration with strict airlock boundaries.

---

## Commands (20 Total)

| Command | Side Effects | Airlock | Description |
| :--- | :--- | :--- | :--- |
| `get_record` / `list_records` | `none` | No | Fetch single record or list with sort/filter/view |
| `search_records` | `none` | No | Filter records using Airtable formula syntax |
| `create_record` / `update_record` | `external` | **Yes** | Add new record or modify fields (PATCH) |
| `delete_record` | `external` | **Yes** | Permanently remove a record |
| `batch_create_records` | `external` | **Yes** | Bulk create up to 10 records per request |
| `batch_update_records` | `external` | **Yes** | Bulk update up to 10 records per request |
| `batch_delete_records` | `external` | **Yes** | Bulk delete up to 10 records per request |
| `batch_upsert_records` | `external` | **Yes** | Insert or update up to 10 records matching on key fields |
| `list_bases` / `list_tables` | `none` | No | Discover accessible bases and table/field schemas |
| `create_table` / `update_table` | `external` | **Yes** | Create tables with fields or rename/describe tables |
| `create_field` / `update_field` | `external` | **Yes** | Add new column or update existing column config |
| `add_comment` | `external` | **Yes** | Post note or mention (`@[usrXXX]`) on record |
| `list_comments` | `none` | No | Retrieve comment history for a record |
| `whoami` / `list_webhooks` | `none` | No | Check token scopes/ID and active webhook status |

---

## Setup & Authentication

1. Create a Personal Access Token at [airtable.com/create/tokens](https://airtable.com/create/tokens) with scopes: `data.records:read`, `data.records:write`, `schema.bases:read`, `schema.bases:write`.
2. Grant base access to your token.
3. Set secret in RailCall workspace:
   ```bash
   railcall secrets set AIRTABLE_PAT patXXXXXXXXXXXXXX
   ```

*Security: Token injected strictly via execution context. Zero `os.environ` access, zero disk writes, credentials automatically redacted in logs and receipts.*

---

## Agent Usage Examples

### 1. Batch Lead Sync & Upsert
> *"Upsert 5 new leads into Airtable matching on Email. Leave a review note on high-priority leads."*

The agent executes `batch_upsert_records(fields_to_merge_on=["Email"])`. Airlock prompts human review before writes execute. The agent then calls `add_comment` on high-priority records.

### 2. Schema Discovery & Migration
> *"Check if 'Sprint Bugs' table has a 'Severity' column; add it if missing."*

The agent calls `list_tables`, confirms column absence, then requests airlock confirmation to invoke `create_field`.

---

## Testing

```bash
# Offline unit tests (26 tests, 0 credentials needed)
python tests/test_airtable.py

# Live integration test (self-cleaning)
python tests/test_airtable.py --live --pat <PAT> --base <BASE_ID> --table <TABLE_NAME>
```
