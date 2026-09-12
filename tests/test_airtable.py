"""Test suite for RailCall Airtable module (smitshah/airtable).

Supports two execution modes:
1. Offline Mock Tests (default): Unit tests using unittest & mocks. Validates schema,
   auth extraction, error sanitization, batch validations, and API formatting without any network/credentials.
2. Live Integration Tests: Run with `--live --pat <PAT> --base <BASE_ID> --table <TABLE_NAME>`
   Executes end-to-end lifecycle testing (CRUD, batch operations, comments, schema) and self-cleans.
"""

import argparse
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch
import urllib.error

# Add parent directory to path so handlers can be imported directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from handlers import handler


class TestAirtableOffline(unittest.TestCase):
    """Offline unit tests testing logic, validation, security, and response parsing."""

    def setUp(self):
        self.mock_context = {"secrets": {"AIRTABLE_PAT": "pat_test_secret_12345"}}

    # --- Security & Auth Tests ---

    def test_auth_extraction_from_secrets(self):
        ctx = {"secrets": {"AIRTABLE_PAT": "pat_abc123"}}
        self.assertEqual(handler._get_api_key(ctx), "pat_abc123")

    def test_auth_extraction_missing_raises(self):
        with self.assertRaises(ValueError):
            handler._get_api_key({})
        with self.assertRaises(ValueError):
            handler._get_api_key({"secrets": {}})

    def test_token_sanitization(self):
        secret = "pat_super_secret_key"
        msg = f"Failed request with token {secret} to server"
        sanitized = handler._sanitize_error_message(msg, secret)
        self.assertNotIn(secret, sanitized)
        self.assertIn("[REDACTED_PAT]", sanitized)

    # --- Input Validation Tests ---

    def test_input_validation_missing_fields(self):
        res = handler.create_record({}, self.mock_context)
        self.assertFalse(res["success"])
        self.assertEqual(res["error"]["code"], "INVALID_INPUT")

        res = handler.update_record({"base_id": "app123"}, self.mock_context)
        self.assertFalse(res["success"])
        self.assertEqual(res["error"]["code"], "INVALID_INPUT")

        res = handler.delete_record({"base_id": "app123"}, self.mock_context)
        self.assertFalse(res["success"])
        self.assertEqual(res["error"]["code"], "INVALID_INPUT")

    def test_batch_validation_size_limits(self):
        # Over 10 items should fail validation
        records_11 = [{"fields": {"Name": f"Item {i}"}} for i in range(11)]
        res = handler.batch_create_records(
            {"base_id": "app123", "table_name": "T", "records": records_11},
            self.mock_context,
        )
        self.assertFalse(res["success"])
        self.assertEqual(res["error"]["code"], "INVALID_INPUT")
        self.assertIn("maximum of 10 records", res["error"]["message"])

        # Empty array should fail validation
        res = handler.batch_create_records(
            {"base_id": "app123", "table_name": "T", "records": []},
            self.mock_context,
        )
        self.assertFalse(res["success"])
        self.assertEqual(res["error"]["code"], "INVALID_INPUT")

    # --- Single Record Mock Tests ---

    @patch("urllib.request.urlopen")
    def test_create_record_mock(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "id": "recTestRecord001",
            "createdTime": "2026-09-13T00:00:00.000Z",
            "fields": {"Name": "Test Task", "Status": "Todo"},
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        result = handler.create_record(
            {
                "base_id": "appTestBase",
                "table_name": "Tasks",
                "fields": {"Name": "Test Task", "Status": "Todo"},
            },
            self.mock_context,
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["record_id"], "recTestRecord001")
        self.assertEqual(result["fields"]["Name"], "Test Task")

    @patch("urllib.request.urlopen")
    def test_get_record_mock(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "id": "recTestRecord001",
            "createdTime": "2026-09-13T00:00:00.000Z",
            "fields": {"Name": "Test Task"},
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        result = handler.get_record(
            {
                "base_id": "appTestBase",
                "table_name": "Tasks",
                "record_id": "recTestRecord001",
            },
            self.mock_context,
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["record"]["id"], "recTestRecord001")

    @patch("urllib.request.urlopen")
    def test_update_record_mock(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "id": "recTestRecord001",
            "fields": {"Name": "Updated Task", "Status": "Done"},
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        result = handler.update_record(
            {
                "base_id": "appTestBase",
                "table_name": "Tasks",
                "record_id": "recTestRecord001",
                "fields": {"Status": "Done"},
            },
            self.mock_context,
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["fields"]["Status"], "Done")

    @patch("urllib.request.urlopen")
    def test_delete_record_mock(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "deleted": True,
            "id": "recTestRecord001",
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        result = handler.delete_record(
            {
                "base_id": "appTestBase",
                "table_name": "Tasks",
                "record_id": "recTestRecord001",
            },
            self.mock_context,
        )

        self.assertTrue(result["success"])
        self.assertTrue(result["deleted"])
        self.assertEqual(result["record_id"], "recTestRecord001")

    @patch("urllib.request.urlopen")
    def test_list_records_mock(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "records": [
                {"id": "rec1", "createdTime": "2026-09-13T00:00:00.000Z", "fields": {"Name": "Item 1"}},
                {"id": "rec2", "createdTime": "2026-09-13T00:00:00.000Z", "fields": {"Name": "Item 2"}},
            ],
            "offset": "itrNextPageToken",
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        result = handler.list_records(
            {"base_id": "appTestBase", "table_name": "Tasks", "max_records": 10},
            self.mock_context,
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["offset"], "itrNextPageToken")

    @patch("urllib.request.urlopen")
    def test_search_records_mock(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "records": [
                {"id": "rec1", "createdTime": "2026-09-13T00:00:00.000Z", "fields": {"Name": "Found Item"}},
            ]
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        result = handler.search_records(
            {
                "base_id": "appTestBase",
                "table_name": "Tasks",
                "filter_by_formula": "{Name}='Found Item'",
            },
            self.mock_context,
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["records"][0]["fields"]["Name"], "Found Item")

    @patch("urllib.request.urlopen")
    def test_list_tables_mock(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "tables": [
                {
                    "id": "tbl123",
                    "name": "Tasks",
                    "primaryFieldId": "fld1",
                    "fields": [{"id": "fld1", "name": "Name", "type": "singleLineText"}],
                    "views": [{"id": "viw1", "name": "Grid view", "type": "grid"}],
                }
            ]
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        result = handler.list_tables({"base_id": "appTestBase"}, self.mock_context)
        self.assertTrue(result["success"])
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["tables"][0]["name"], "Tasks")

    # --- Tier 1 Mock Tests: Batch Operations & Base Discovery ---

    @patch("urllib.request.urlopen")
    def test_batch_create_records_mock(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "records": [
                {"id": "rec01", "createdTime": "2026-09-13T00:00:00.000Z", "fields": {"Name": "Batch 1"}},
                {"id": "rec02", "createdTime": "2026-09-13T00:00:00.000Z", "fields": {"Name": "Batch 2"}},
            ]
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        result = handler.batch_create_records(
            {
                "base_id": "appTestBase",
                "table_name": "Tasks",
                "records": [{"fields": {"Name": "Batch 1"}}, {"fields": {"Name": "Batch 2"}}],
            },
            self.mock_context,
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["records"][0]["id"], "rec01")

    @patch("urllib.request.urlopen")
    def test_batch_update_records_mock(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "records": [
                {"id": "rec01", "fields": {"Name": "Batch 1 Updated"}},
                {"id": "rec02", "fields": {"Name": "Batch 2 Updated"}},
            ]
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        result = handler.batch_update_records(
            {
                "base_id": "appTestBase",
                "table_name": "Tasks",
                "records": [
                    {"id": "rec01", "fields": {"Name": "Batch 1 Updated"}},
                    {"id": "rec02", "fields": {"Name": "Batch 2 Updated"}},
                ],
            },
            self.mock_context,
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["records"][0]["fields"]["Name"], "Batch 1 Updated")

    @patch("urllib.request.urlopen")
    def test_batch_delete_records_mock(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "records": [
                {"deleted": True, "id": "rec01"},
                {"deleted": True, "id": "rec02"},
            ]
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        result = handler.batch_delete_records(
            {
                "base_id": "appTestBase",
                "table_name": "Tasks",
                "record_ids": ["rec01", "rec02"],
            },
            self.mock_context,
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["count"], 2)
        self.assertTrue(result["records"][0]["deleted"])

    @patch("urllib.request.urlopen")
    def test_batch_upsert_records_mock(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "createdRecords": ["rec03"],
            "updatedRecords": ["rec01"],
            "records": [
                {"id": "rec01", "fields": {"Email": "user1@example.com", "Score": 10}},
                {"id": "rec03", "fields": {"Email": "user3@example.com", "Score": 5}},
            ],
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        result = handler.batch_upsert_records(
            {
                "base_id": "appTestBase",
                "table_name": "Users",
                "fields_to_merge_on": ["Email"],
                "records": [
                    {"fields": {"Email": "user1@example.com", "Score": 10}},
                    {"fields": {"Email": "user3@example.com", "Score": 5}},
                ],
            },
            self.mock_context,
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["created_records"], ["rec03"])
        self.assertEqual(result["updated_records"], ["rec01"])

    @patch("urllib.request.urlopen")
    def test_list_bases_mock(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "bases": [
                {"id": "appBase1", "name": "CRM Base", "permissionLevel": "create"},
                {"id": "appBase2", "name": "Sprint Base", "permissionLevel": "edit"},
            ],
            "offset": "nextPage",
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        result = handler.list_bases({}, self.mock_context)
        self.assertTrue(result["success"])
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["bases"][0]["id"], "appBase1")

    # --- Tier 2 Mock Tests: Comments, Schema & Auth ---

    @patch("urllib.request.urlopen")
    def test_add_comment_mock(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "id": "com01",
            "text": "Needs review @[usr123]",
            "createdTime": "2026-09-13T00:00:00.000Z",
            "author": {"id": "usr123", "email": "dev@test.com", "name": "Dev User"},
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        result = handler.add_comment(
            {
                "base_id": "appTestBase",
                "table_name": "Tasks",
                "record_id": "rec01",
                "text": "Needs review @[usr123]",
            },
            self.mock_context,
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["comment"]["id"], "com01")
        self.assertEqual(result["comment"]["text"], "Needs review @[usr123]")

    @patch("urllib.request.urlopen")
    def test_list_comments_mock(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "comments": [
                {
                    "id": "com01",
                    "text": "Hello comment",
                    "createdTime": "2026-09-13T00:00:00.000Z",
                    "author": {"name": "Alice"},
                }
            ],
            "offset": "nextOffsetToken",
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        result = handler.list_comments(
            {
                "base_id": "appTestBase",
                "table_name": "Tasks",
                "record_id": "rec01",
            },
            self.mock_context,
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["comments"][0]["id"], "com01")

    @patch("urllib.request.urlopen")
    def test_create_table_mock(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "id": "tblNew123",
            "name": "Projects",
            "primaryFieldId": "fldP1",
            "description": "Project tracker",
            "fields": [{"id": "fldP1", "name": "Title", "type": "singleLineText"}],
            "views": [{"id": "viwP1", "name": "Grid view", "type": "grid"}],
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        result = handler.create_table(
            {
                "base_id": "appTestBase",
                "name": "Projects",
                "description": "Project tracker",
                "fields": [{"name": "Title", "type": "singleLineText"}],
            },
            self.mock_context,
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["table"]["id"], "tblNew123")
        self.assertEqual(result["table"]["name"], "Projects")

    @patch("urllib.request.urlopen")
    def test_create_field_mock(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "id": "fldPriority",
            "name": "Priority",
            "type": "singleSelect",
            "description": "Task priority",
            "options": {"choices": [{"name": "High"}, {"name": "Low"}]},
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        result = handler.create_field(
            {
                "base_id": "appTestBase",
                "table_name": "Tasks",
                "name": "Priority",
                "type": "singleSelect",
                "description": "Task priority",
                "options": {"choices": [{"name": "High"}, {"name": "Low"}]},
            },
            self.mock_context,
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["field"]["id"], "fldPriority")
        self.assertEqual(result["field"]["name"], "Priority")

    @patch("urllib.request.urlopen")
    def test_whoami_mock(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "id": "usrTestUser",
            "scopes": ["data.records:read", "data.records:write", "schema.bases:read"],
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        result = handler.whoami({}, self.mock_context)
        self.assertTrue(result["success"])
        self.assertEqual(result["id"], "usrTestUser")
        self.assertIn("data.records:write", result["scopes"])

    # --- Tier 3 Mock Tests: Updates & Webhooks ---

    @patch("urllib.request.urlopen")
    def test_update_table_mock(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "id": "tbl123",
            "name": "Renamed Tasks",
            "description": "Updated description",
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        result = handler.update_table(
            {
                "base_id": "appTestBase",
                "table_name": "Tasks",
                "name": "Renamed Tasks",
                "description": "Updated description",
            },
            self.mock_context,
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["table"]["name"], "Renamed Tasks")

    @patch("urllib.request.urlopen")
    def test_update_field_mock(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "id": "fld1",
            "name": "Task Title",
            "type": "singleLineText",
            "description": "Renamed field",
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        result = handler.update_field(
            {
                "base_id": "appTestBase",
                "table_name": "Tasks",
                "field_id": "fld1",
                "name": "Task Title",
            },
            self.mock_context,
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["field"]["name"], "Task Title")

    @patch("urllib.request.urlopen")
    def test_list_webhooks_mock(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "webhooks": [
                {"id": "ach123", "areNotificationDeliveriesEnabled": True, "cursorForNextPayload": 1}
            ]
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        result = handler.list_webhooks({"base_id": "appTestBase"}, self.mock_context)
        self.assertTrue(result["success"])
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["webhooks"][0]["id"], "ach123")

    # --- HTTP Error Handling & Redaction Tests ---

    @patch("urllib.request.urlopen")
    def test_http_error_redaction_and_mapping(self, mock_urlopen):
        secret = self.mock_context["secrets"]["AIRTABLE_PAT"]
        error_json = json.dumps({
            "error": {
                "type": "AUTHENTICATION_REQUIRED",
                "message": f"Token {secret} is invalid or has expired",
            }
        }).encode("utf-8")

        mock_err = urllib.error.HTTPError(
            url="https://api.airtable.com/v0/meta/whoami",
            code=401,
            msg="Unauthorized",
            hdrs={},
            fp=MagicMock(read=MagicMock(return_value=error_json)),
        )
        mock_urlopen.side_effect = mock_err

        result = handler.whoami({}, self.mock_context)
        self.assertFalse(result["success"])
        self.assertEqual(result["error"]["code"], "UNAUTHORIZED")
        self.assertNotIn(secret, result["error"]["message"])
        self.assertIn("[REDACTED_PAT]", result["error"]["message"])


def run_live_tests(pat: str, base_id: str, table_name: str, field_name: str = "Name"):
    """Executes end-to-end integration tests against real Airtable base."""
    print("=" * 60)
    print("STARTING LIVE INTEGRATION TESTS AGAINST AIRTABLE")
    print(f"Base ID: {base_id} | Table: {table_name}")
    print("=" * 60)

    context = {"secrets": {"AIRTABLE_PAT": pat}}
    passed = 0
    total = 0

    def check(step_name: str, result: dict) -> bool:
        nonlocal passed, total
        total += 1
        if result.get("success"):
            print(f"  [PASS] {step_name}")
            passed += 1
            return True
        else:
            err = result.get("error", {})
            print(f"  [FAIL] {step_name}: {err.get('code')} - {err.get('message')}")
            return False

    # 1. whoami (token diagnostics)
    print("\n[1/10] Testing whoami...")
    res = handler.whoami({}, context)
    check("whoami", res)

    # 2. list_bases
    print("\n[2/10] Testing list_bases...")
    res = handler.list_bases({}, context)
    check("list_bases", res)

    # 3. list_tables (schema inspection)
    print("\n[3/10] Testing list_tables...")
    res = handler.list_tables({"base_id": base_id}, context)
    check("list_tables", res)

    # 4. create_record
    print("\n[4/10] Testing create_record...")
    test_val = f"RailCall Test Record {os.getpid()}"
    res = handler.create_record(
        {"base_id": base_id, "table_name": table_name, "fields": {field_name: test_val}},
        context,
    )
    created_id = res.get("record_id")
    check("create_record", res)

    if not created_id:
        print("\nCannot continue lifecycle without created record_id. Exiting.")
        return

    # 5. get_record
    print(f"\n[5/10] Testing get_record ({created_id})...")
    res = handler.get_record(
        {"base_id": base_id, "table_name": table_name, "record_id": created_id},
        context,
    )
    check("get_record", res)

    # 6. add_comment
    print(f"\n[6/10] Testing add_comment on {created_id}...")
    res = handler.add_comment(
        {
            "base_id": base_id,
            "table_name": table_name,
            "record_id": created_id,
            "text": "Automated verification comment by RailCall module",
        },
        context,
    )
    check("add_comment", res)

    # 7. list_comments
    print(f"\n[7/10] Testing list_comments on {created_id}...")
    res = handler.list_comments(
        {"base_id": base_id, "table_name": table_name, "record_id": created_id},
        context,
    )
    check("list_comments", res)

    # 8. update_record
    print(f"\n[8/10] Testing update_record ({created_id})...")
    updated_val = f"{test_val} [UPDATED]"
    res = handler.update_record(
        {
            "base_id": base_id,
            "table_name": table_name,
            "record_id": created_id,
            "fields": {field_name: updated_val},
        },
        context,
    )
    check("update_record", res)

    # 9. search_records
    print(f"\n[9/10] Testing search_records...")
    formula = f"{{{field_name}}} = '{updated_val}'"
    res = handler.search_records(
        {"base_id": base_id, "table_name": table_name, "filter_by_formula": formula},
        context,
    )
    check("search_records", res)

    # 10. delete_record (clean up)
    print(f"\n[10/10] Testing delete_record (cleanup {created_id})...")
    res = handler.delete_record(
        {"base_id": base_id, "table_name": table_name, "record_id": created_id},
        context,
    )
    check("delete_record (self-cleanup)", res)

    print("\n" + "=" * 60)
    print(f"INTEGRATION TEST COMPLETE: {passed}/{total} PASSED")
    print("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RailCall Airtable Test Runner")
    parser.add_argument("--live", action="store_true", help="Run live integration tests against Airtable API")
    parser.add_argument("--pat", help="Airtable Personal Access Token")
    parser.add_argument("--base", help="Airtable Base ID (appXXXXXXXXXXXXXX)")
    parser.add_argument("--table", help="Airtable Table Name")
    parser.add_argument("--field-name", default="Name", help="Field name to use for test record (default: Name)")

    args, unknown = parser.parse_known_args()

    if args.live:
        if not args.pat or not args.base or not args.table:
            print("Error: --pat, --base, and --table are required when running with --live")
            sys.exit(1)
        run_live_tests(args.pat, args.base, args.table, args.field_name)
    else:
        # Run standard unittest offline suite
        unittest.main(argv=[sys.argv[0]] + unknown)
