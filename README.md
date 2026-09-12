# Airtable Integration Module for RailCall

Connect AI agents to Airtable REST API. Full CRUD, batch operations, schemas, and comments with zero dependencies and airlock safety.

**Contest Tags:** `contest:round2` | `contest:2026Q3`  
**Publisher:** `smit-shah/airtable` | **Version:** `1.0.4`

---

## Overview

Enables RailCall agents to treat Airtable as a relational database. Automates CRM syncs, bulk data operations, schema migrations, and record collaboration with strict airlock boundaries.

Zero external dependencies (pure Python standard library `urllib.request`). Mutating operations require human airlock review before committing changes.

---

## 20 Governed Commands

### Core Record CRUD (Airlock on Writes)
- `get_record` — Fetch single record by ID (Side effects: none)
- `list_records` — Filter, sort, and paginate records with view support (Side effects: none)
- `search_records` — Search records using Airtable formula syntax (Side effects: none)
- `create_record` — Create a single record in a table (Side effects: external / Airlock)
- `update_record` — Update fields on an existing record via PATCH (Side effects: external / Airlock)
- `delete_record` — Permanently remove a record (Side effects: external / Airlock)

### High-Volume Batch Operations (Max 10 Records)
- `batch_create_records` — Bulk create records in a single request (Airlock)
- `batch_update_records` — Bulk update records in a single request (Airlock)
- `batch_delete_records` — Bulk delete up to 10 records (Airlock)
- `batch_upsert_records` — Upsert records matching on unique key fields (Airlock)

### Schema & Base Management
- `list_bases` — Discover all bases accessible to token
- `get_base_schema` — Inspect table schemas, fields, and views
- `create_table` — Programmatically create new table with schema (Airlock)
- `update_table` — Rename table or update table description (Airlock)
- `create_field` — Add new column to an existing table (Airlock)
- `update_field` — Rename or edit column configuration (Airlock)

### Collaboration & Webhooks
- `create_comment` — Post note or user mention (`@[usrXXX]`) on record (Airlock)
- `list_comments` — Read comment history and threads on a record
- `whoami` — Inspect active token permissions and user ID
- `list_webhooks` — Inspect active webhooks on a base

---

## Quick Setup

### 1. Install Module
> `railcall market install smit-shah/airtable`

### 2. Configure Airtable PAT
Generate a Personal Access Token at [airtable.com/create/tokens](https://airtable.com/create/tokens) with scopes: `data.records:read`, `data.records:write`, `schema.bases:read`, `schema.bases:write`.

Register the secret in your local vault:
> `railcall secrets set AIRTABLE_PAT patXXXXXXXXXXXXXXX`

---

## Enterprise Workflows

### 1. Batch Lead Sync & Upsert
*Upsert 5 new leads into Airtable matching on Email. Leave a review note on high-priority leads.*

The agent executes `batch_upsert_records` matching on Email. Airlock prompts human review before writes execute. The agent then calls `create_comment` on high-priority records.

### 2. Schema Discovery & Migration
*Check if Sprint Bugs table has a Severity column; add it if missing.*

The agent calls `get_base_schema`, confirms column absence, then requests airlock confirmation to invoke `create_field`.

---

## Verification & Testing

- **Offline Unit Tests (26 tests, 0 credentials needed):**  
  `python tests/test_airtable.py`
- **Live Integration Test (automated self-cleanup):**  
  `python tests/test_airtable.py --live --pat <PAT> --base <BASE_ID> --table <TABLE_NAME>`
