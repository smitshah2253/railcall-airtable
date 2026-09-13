"""RailCall Marketplace Module: smitshah/airtable
Integrates with the Airtable REST API.
"""

import json
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

AIRTABLE_API_BASE = "https://api.airtable.com/v0"
MAX_RETRIES = 3
INITIAL_BACKOFF = 1.0  # seconds
BATCH_CHUNK_SIZE = 10
MAX_BATCH_TOTAL = 100
FREE_TIER_LIMIT = 1000


def _get_api_key(context: Optional[Dict[str, Any]]) -> str:
    """Safely extract the Airtable Personal Access Token (PAT) from the execution context.
    
    RailCall injects secrets directly into context. Accessing os.environ for secrets is
    strictly prohibited by RailCall security policies.
    """
    if not isinstance(context, dict):
        raise ValueError("Execution context must be a dictionary")

    secrets = context.get("secrets", {})
    if isinstance(secrets, dict) and secrets.get("AIRTABLE_PAT"):
        return secrets["AIRTABLE_PAT"]
    if isinstance(secrets, dict) and secrets.get("api_key"):
        return secrets["api_key"]
    if context.get("AIRTABLE_PAT"):
        return context["AIRTABLE_PAT"]

    raise ValueError(
        "Missing Airtable PAT. Please configure AIRTABLE_PAT in RailCall module settings."
    )


def _sanitize_error_message(msg: str, pat: str) -> str:
    """Ensure no secret PAT tokens leak into error messages or receipts."""
    if pat and pat in msg:
        return msg.replace(pat, "[REDACTED_PAT]")
    return msg


def _chunk_list(items: list, chunk_size: int = BATCH_CHUNK_SIZE):
    """Yield successive chunks of items with size chunk_size."""
    for i in range(0, len(items), chunk_size):
        yield items[i : i + chunk_size]


def _make_request(
    endpoint: str,
    method: str,
    pat: str,
    data: Optional[Dict[str, Any]] = None,
    query_params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Execute an HTTP request to the Airtable REST API using Python stdlib.
    
    Includes automatic exponential backoff retry with jitter on HTTP 429
    (Rate Limit Exceeded), designed for Airtable's 5 req/sec free-tier limit.
    Returns a standardized dictionary response.
    """
    url = f"{AIRTABLE_API_BASE}/{endpoint.lstrip('/')}"
    if query_params:
        encoded_params = urllib.parse.urlencode(query_params, doseq=True)
        url = f"{url}?{encoded_params}"

    headers = {
        "Authorization": f"Bearer {pat}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "RailCall-Module-Airtable/1.0.5",
    }

    body = json.dumps(data).encode("utf-8") if data is not None else None

    for attempt in range(MAX_RETRIES + 1):
        req = urllib.request.Request(url, data=body, headers=headers, method=method.upper())
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                status_code = resp.status
                content = resp.read().decode("utf-8")
                parsed = json.loads(content) if content else {}
                return {
                    "success": True,
                    "status_code": status_code,
                    "data": parsed,
                }
        except urllib.error.HTTPError as err:
            # Handle rate limiting (429) with exponential backoff & Retry-After header
            if err.code == 429 and attempt < MAX_RETRIES:
                retry_after = None
                if hasattr(err, "headers") and err.headers:
                    retry_header = err.headers.get("Retry-After")
                    if retry_header:
                        try:
                            retry_after = float(retry_header)
                        except (ValueError, TypeError):
                            pass
                if retry_after is None:
                    # Exponential backoff with jitter: 1s, 2s, 4s + jitter
                    retry_after = INITIAL_BACKOFF * (2 ** attempt) + random.uniform(0.1, 0.5)
                time.sleep(retry_after)
                continue

            error_body = ""
            try:
                error_body = err.read().decode("utf-8")
                error_json = json.loads(error_body)
                err_details = error_json.get("error", {})
            except Exception:
                err_details = {"message": error_body or str(err)}

            status = err.code
            code_map = {
                401: "UNAUTHORIZED",
                403: "FORBIDDEN",
                404: "NOT_FOUND",
                422: "UNPROCESSABLE_ENTITY",
                429: "RATE_LIMIT_EXCEEDED",
            }
            error_code = code_map.get(status, f"HTTP_{status}")

            if isinstance(err_details, dict):
                raw_msg = err_details.get("message") or err_details.get("type") or str(err)
            else:
                raw_msg = str(err_details)

            safe_msg = _sanitize_error_message(str(raw_msg), pat)
            return {
                "success": False,
                "status_code": status,
                "error": {
                    "code": error_code,
                    "message": safe_msg,
                    "details": err_details if isinstance(err_details, dict) else {},
                },
            }
        except urllib.error.URLError as err:
            safe_msg = _sanitize_error_message(str(err.reason), pat)
            return {
                "success": False,
                "status_code": None,
                "error": {
                    "code": "NETWORK_ERROR",
                    "message": f"Network error connecting to Airtable: {safe_msg}",
                },
            }
        except Exception as exc:
            safe_msg = _sanitize_error_message(str(exc), pat)
            return {
                "success": False,
                "status_code": None,
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": f"Unexpected execution error: {safe_msg}",
                },
            }

    return {
        "success": False,
        "status_code": 429,
        "error": {
            "code": "RATE_LIMIT_EXCEEDED",
            "message": f"Request failed after {MAX_RETRIES} retry attempts due to rate limiting.",
        },
    }


# --- Command Handlers ---


def create_record(inputs: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Create a new record in the specified Airtable table.
    
    Mutating action: Requires external side_effects declaration and airlock approval.
    """
    try:
        pat = _get_api_key(context)
    except ValueError as e:
        return {"success": False, "error": {"code": "AUTH_ERROR", "message": str(e)}}

    base_id = inputs.get("base_id", "").strip()
    table_name = inputs.get("table_name", "").strip()
    fields = inputs.get("fields")
    typecast = bool(inputs.get("typecast", False))

    if not base_id:
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "base_id is required"}}
    if not table_name:
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "table_name is required"}}
    if not isinstance(fields, dict):
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "fields must be a dictionary"}}

    encoded_table = urllib.parse.quote(table_name, safe="")
    endpoint = f"{base_id}/{encoded_table}"
    payload: Dict[str, Any] = {"fields": fields}
    if typecast:
        payload["typecast"] = True

    resp = _make_request(endpoint, "POST", pat, data=payload)
    if not resp["success"]:
        return resp

    record = resp["data"]
    return {
        "success": True,
        "record_id": record.get("id"),
        "created_time": record.get("createdTime"),
        "fields": record.get("fields", {}),
    }


def update_record(inputs: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Update fields of an existing record (PATCH) in an Airtable table.
    
    Mutating action: Requires external side_effects declaration and airlock approval.
    """
    try:
        pat = _get_api_key(context)
    except ValueError as e:
        return {"success": False, "error": {"code": "AUTH_ERROR", "message": str(e)}}

    base_id = inputs.get("base_id", "").strip()
    table_name = inputs.get("table_name", "").strip()
    record_id = inputs.get("record_id", "").strip()
    fields = inputs.get("fields")
    typecast = bool(inputs.get("typecast", False))

    if not base_id or not table_name or not record_id:
        return {
            "success": False,
            "error": {
                "code": "INVALID_INPUT",
                "message": "base_id, table_name, and record_id are all required",
            },
        }
    if not isinstance(fields, dict):
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "fields must be a dictionary"}}

    encoded_table = urllib.parse.quote(table_name, safe="")
    encoded_record = urllib.parse.quote(record_id, safe="")
    endpoint = f"{base_id}/{encoded_table}/{encoded_record}"
    payload: Dict[str, Any] = {"fields": fields}
    if typecast:
        payload["typecast"] = True

    resp = _make_request(endpoint, "PATCH", pat, data=payload)
    if not resp["success"]:
        return resp

    record = resp["data"]
    return {
        "success": True,
        "record_id": record.get("id"),
        "fields": record.get("fields", {}),
    }


def delete_record(inputs: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Permanently delete a record from an Airtable table.
    
    Mutating action: Requires external side_effects declaration and airlock approval.
    """
    try:
        pat = _get_api_key(context)
    except ValueError as e:
        return {"success": False, "error": {"code": "AUTH_ERROR", "message": str(e)}}

    base_id = inputs.get("base_id", "").strip()
    table_name = inputs.get("table_name", "").strip()
    record_id = inputs.get("record_id", "").strip()

    if not base_id or not table_name or not record_id:
        return {
            "success": False,
            "error": {
                "code": "INVALID_INPUT",
                "message": "base_id, table_name, and record_id are all required",
            },
        }

    encoded_table = urllib.parse.quote(table_name, safe="")
    encoded_record = urllib.parse.quote(record_id, safe="")
    endpoint = f"{base_id}/{encoded_table}/{encoded_record}"

    resp = _make_request(endpoint, "DELETE", pat)
    if not resp["success"]:
        return resp

    data = resp["data"]
    return {
        "success": True,
        "deleted": data.get("deleted", True),
        "record_id": data.get("id", record_id),
    }


def get_record(inputs: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Retrieve a single record by its record ID.
    
    Read-only action (side_effects: "none").
    """
    try:
        pat = _get_api_key(context)
    except ValueError as e:
        return {"success": False, "error": {"code": "AUTH_ERROR", "message": str(e)}}

    base_id = inputs.get("base_id", "").strip()
    table_name = inputs.get("table_name", "").strip()
    record_id = inputs.get("record_id", "").strip()

    if not base_id or not table_name or not record_id:
        return {
            "success": False,
            "error": {
                "code": "INVALID_INPUT",
                "message": "base_id, table_name, and record_id are all required",
            },
        }

    encoded_table = urllib.parse.quote(table_name, safe="")
    encoded_record = urllib.parse.quote(record_id, safe="")
    endpoint = f"{base_id}/{encoded_table}/{encoded_record}"

    resp = _make_request(endpoint, "GET", pat)
    if not resp["success"]:
        return resp

    record = resp["data"]
    return {
        "success": True,
        "record": {
            "id": record.get("id"),
            "created_time": record.get("createdTime"),
            "fields": record.get("fields", {}),
        },
    }


def list_records(inputs: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """List records from a table with optional filtering, sorting, and pagination.
    
    Read-only action (side_effects: "none").
    """
    try:
        pat = _get_api_key(context)
    except ValueError as e:
        return {"success": False, "error": {"code": "AUTH_ERROR", "message": str(e)}}

    base_id = inputs.get("base_id", "").strip()
    table_name = inputs.get("table_name", "").strip()

    if not base_id or not table_name:
        return {
            "success": False,
            "error": {"code": "INVALID_INPUT", "message": "base_id and table_name are required"},
        }

    encoded_table = urllib.parse.quote(table_name, safe="")
    endpoint = f"{base_id}/{encoded_table}"

    params: Dict[str, Any] = {}
    if "max_records" in inputs and inputs["max_records"] is not None:
        params["maxRecords"] = int(inputs["max_records"])
    if "page_size" in inputs and inputs["page_size"] is not None:
        params["pageSize"] = int(inputs["page_size"])
    if inputs.get("offset"):
        params["offset"] = inputs["offset"]
    if inputs.get("view"):
        params["view"] = inputs["view"]

    # Handle fields projection
    if isinstance(inputs.get("fields"), list):
        for idx, f in enumerate(inputs["fields"]):
            params[f"fields[{idx}]"] = f

    # Handle sorting
    if isinstance(inputs.get("sort"), list):
        for idx, sort_item in enumerate(inputs["sort"]):
            if isinstance(sort_item, dict) and "field" in sort_item:
                params[f"sort[{idx}][field]"] = sort_item["field"]
                params[f"sort[{idx}][direction]"] = sort_item.get("direction", "asc")

    resp = _make_request(endpoint, "GET", pat, query_params=params)
    if not resp["success"]:
        return resp

    data = resp["data"]
    raw_records = data.get("records", [])
    formatted_records = [
        {
            "id": r.get("id"),
            "created_time": r.get("createdTime"),
            "fields": r.get("fields", {}),
        }
        for r in raw_records
    ]

    return {
        "success": True,
        "count": len(formatted_records),
        "offset": data.get("offset"),
        "records": formatted_records,
    }


def search_records(inputs: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Search and filter records using an Airtable formula expression.
    
    Read-only action (side_effects: "none").
    """
    try:
        pat = _get_api_key(context)
    except ValueError as e:
        return {"success": False, "error": {"code": "AUTH_ERROR", "message": str(e)}}

    base_id = inputs.get("base_id", "").strip()
    table_name = inputs.get("table_name", "").strip()
    formula = inputs.get("filter_by_formula", "").strip()

    if not base_id or not table_name:
        return {
            "success": False,
            "error": {"code": "INVALID_INPUT", "message": "base_id and table_name are required"},
        }
    if not formula:
        return {
            "success": False,
            "error": {
                "code": "INVALID_INPUT",
                "message": "filter_by_formula expression is required",
            },
        }

    encoded_table = urllib.parse.quote(table_name, safe="")
    endpoint = f"{base_id}/{encoded_table}"

    params: Dict[str, Any] = {"filterByFormula": formula}
    if "max_records" in inputs and inputs["max_records"] is not None:
        params["maxRecords"] = int(inputs["max_records"])

    resp = _make_request(endpoint, "GET", pat, query_params=params)
    if not resp["success"]:
        return resp

    data = resp["data"]
    raw_records = data.get("records", [])
    formatted_records = [
        {
            "id": r.get("id"),
            "created_time": r.get("createdTime"),
            "fields": r.get("fields", {}),
        }
        for r in raw_records
    ]

    return {
        "success": True,
        "count": len(formatted_records),
        "records": formatted_records,
    }


def list_tables(inputs: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Retrieve base schema metadata and table definitions.
    
    Read-only action (side_effects: "none").
    Requires Airtable PAT with `schema.bases:read` scope.
    """
    try:
        pat = _get_api_key(context)
    except ValueError as e:
        return {"success": False, "error": {"code": "AUTH_ERROR", "message": str(e)}}

    base_id = inputs.get("base_id", "").strip()
    if not base_id:
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "base_id is required"}}

    endpoint = f"meta/bases/{base_id}/tables"
    resp = _make_request(endpoint, "GET", pat)
    if not resp["success"]:
        return resp

    tables = resp["data"].get("tables", [])
    summary = [
        {
            "id": t.get("id"),
            "name": t.get("name"),
            "primary_field_id": t.get("primaryFieldId"),
            "description": t.get("description", ""),
            "fields": [
                {
                    "id": f.get("id"),
                    "name": f.get("name"),
                    "type": f.get("type"),
                }
                for f in t.get("fields", [])
            ],
            "views": [
                {
                    "id": v.get("id"),
                    "name": v.get("name"),
                    "type": v.get("type"),
                }
                for v in t.get("views", [])
            ],
        }
        for t in tables
    ]

    return {
        "success": True,
        "count": len(summary),
        "tables": summary,
    }


# --- Tier 1 Commands: Batch Operations & Base Discovery ---


def batch_create_records(inputs: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Create records in batch in the specified Airtable table.
    
    Automatically chunks payloads into batches of 10 (Airtable REST limit) up to
    100 total records per invocation.
    Mutating action: Requires external side_effects declaration and airlock approval.
    """
    try:
        pat = _get_api_key(context)
    except ValueError as e:
        return {"success": False, "error": {"code": "AUTH_ERROR", "message": str(e)}}

    base_id = inputs.get("base_id", "").strip()
    table_name = inputs.get("table_name", "").strip()
    records = inputs.get("records")
    typecast = bool(inputs.get("typecast", False))

    if not base_id:
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "base_id is required"}}
    if not table_name:
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "table_name is required"}}
    if not isinstance(records, list) or len(records) == 0:
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "records must be a non-empty array of objects"}}
    if len(records) > MAX_BATCH_TOTAL:
        return {
            "success": False,
            "error": {
                "code": "INVALID_INPUT",
                "message": f"Maximum allowed batch size is {MAX_BATCH_TOTAL} records across chunked operations (received {len(records)})",
            },
        }

    for idx, item in enumerate(records):
        if not isinstance(item, dict) or "fields" not in item or not isinstance(item["fields"], dict):
            return {
                "success": False,
                "error": {
                    "code": "INVALID_INPUT",
                    "message": f"Record at index {idx} must be an object with a 'fields' dictionary",
                },
            }

    encoded_table = urllib.parse.quote(table_name, safe="")
    endpoint = f"{base_id}/{encoded_table}"

    all_formatted = []
    for chunk in _chunk_list(records, BATCH_CHUNK_SIZE):
        payload: Dict[str, Any] = {"records": chunk}
        if typecast:
            payload["typecast"] = True

        resp = _make_request(endpoint, "POST", pat, data=payload)
        if not resp["success"]:
            if not all_formatted:
                return resp
            return {
                "success": False,
                "partial": True,
                "count": len(all_formatted),
                "records": all_formatted,
                "error": resp.get("error", {}),
            }

        created_records = resp["data"].get("records", [])
        for r in created_records:
            all_formatted.append({
                "id": r.get("id"),
                "created_time": r.get("createdTime"),
                "fields": r.get("fields", {}),
            })

    return {
        "success": True,
        "count": len(all_formatted),
        "records": all_formatted,
    }


def batch_update_records(inputs: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Update records in batch in the specified Airtable table (PATCH).
    
    Automatically chunks payloads into batches of 10 (Airtable REST limit) up to
    100 total records per invocation.
    Mutating action: Requires external side_effects declaration and airlock approval.
    """
    try:
        pat = _get_api_key(context)
    except ValueError as e:
        return {"success": False, "error": {"code": "AUTH_ERROR", "message": str(e)}}

    base_id = inputs.get("base_id", "").strip()
    table_name = inputs.get("table_name", "").strip()
    records = inputs.get("records")
    typecast = bool(inputs.get("typecast", False))

    if not base_id:
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "base_id is required"}}
    if not table_name:
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "table_name is required"}}
    if not isinstance(records, list) or len(records) == 0:
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "records must be a non-empty array of objects"}}
    if len(records) > MAX_BATCH_TOTAL:
        return {
            "success": False,
            "error": {
                "code": "INVALID_INPUT",
                "message": f"Maximum allowed batch size is {MAX_BATCH_TOTAL} records across chunked operations (received {len(records)})",
            },
        }

    for idx, item in enumerate(records):
        if not isinstance(item, dict) or not item.get("id") or not isinstance(item.get("fields"), dict):
            return {
                "success": False,
                "error": {
                    "code": "INVALID_INPUT",
                    "message": f"Record at index {idx} must be an object with 'id' and 'fields' properties",
                },
            }

    encoded_table = urllib.parse.quote(table_name, safe="")
    endpoint = f"{base_id}/{encoded_table}"

    all_formatted = []
    for chunk in _chunk_list(records, BATCH_CHUNK_SIZE):
        payload: Dict[str, Any] = {"records": chunk}
        if typecast:
            payload["typecast"] = True

        resp = _make_request(endpoint, "PATCH", pat, data=payload)
        if not resp["success"]:
            if not all_formatted:
                return resp
            return {
                "success": False,
                "partial": True,
                "count": len(all_formatted),
                "records": all_formatted,
                "error": resp.get("error", {}),
            }

        updated_records = resp["data"].get("records", [])
        for r in updated_records:
            all_formatted.append({
                "id": r.get("id"),
                "created_time": r.get("createdTime"),
                "fields": r.get("fields", {}),
            })

    return {
        "success": True,
        "count": len(all_formatted),
        "records": all_formatted,
    }


def batch_delete_records(inputs: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Delete records in batch in the specified Airtable table.
    
    Automatically chunks IDs into batches of 10 (Airtable REST limit) up to
    100 total records per invocation.
    Mutating action: Requires external side_effects declaration and airlock approval.
    """
    try:
        pat = _get_api_key(context)
    except ValueError as e:
        return {"success": False, "error": {"code": "AUTH_ERROR", "message": str(e)}}

    base_id = inputs.get("base_id", "").strip()
    table_name = inputs.get("table_name", "").strip()
    record_ids = inputs.get("record_ids")

    if not base_id:
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "base_id is required"}}
    if not table_name:
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "table_name is required"}}
    if not isinstance(record_ids, list) or len(record_ids) == 0:
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "record_ids must be a non-empty array of record IDs"}}
    if len(record_ids) > MAX_BATCH_TOTAL:
        return {
            "success": False,
            "error": {
                "code": "INVALID_INPUT",
                "message": f"Maximum allowed batch size is {MAX_BATCH_TOTAL} records across chunked operations (received {len(record_ids)})",
            },
        }

    encoded_table = urllib.parse.quote(table_name, safe="")
    endpoint = f"{base_id}/{encoded_table}"

    all_deleted = []
    for chunk in _chunk_list(record_ids, BATCH_CHUNK_SIZE):
        params = {"records[]": chunk}
        resp = _make_request(endpoint, "DELETE", pat, query_params=params)
        if not resp["success"]:
            if not all_deleted:
                return resp
            return {
                "success": False,
                "partial": True,
                "count": len(all_deleted),
                "records": all_deleted,
                "error": resp.get("error", {}),
            }

        deleted_records = resp["data"].get("records", [])
        all_deleted.extend(deleted_records)

    return {
        "success": True,
        "count": len(all_deleted),
        "records": all_deleted,
    }


def batch_upsert_records(inputs: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Perform upsert (insert-or-update) matching on specified key fields.
    
    Automatically chunks payloads into batches of 10 (Airtable REST limit) up to
    100 total records per invocation.
    Mutating action: Requires external side_effects declaration and airlock approval.
    """
    try:
        pat = _get_api_key(context)
    except ValueError as e:
        return {"success": False, "error": {"code": "AUTH_ERROR", "message": str(e)}}

    base_id = inputs.get("base_id", "").strip()
    table_name = inputs.get("table_name", "").strip()
    fields_to_merge_on = inputs.get("fields_to_merge_on")
    records = inputs.get("records")
    typecast = bool(inputs.get("typecast", False))

    if not base_id:
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "base_id is required"}}
    if not table_name:
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "table_name is required"}}
    if not isinstance(fields_to_merge_on, list) or len(fields_to_merge_on) == 0:
        return {
            "success": False,
            "error": {
                "code": "INVALID_INPUT",
                "message": "fields_to_merge_on must be a non-empty array of field names to match on",
            },
        }
    if not isinstance(records, list) or len(records) == 0:
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "records must be a non-empty array of objects"}}
    if len(records) > MAX_BATCH_TOTAL:
        return {
            "success": False,
            "error": {
                "code": "INVALID_INPUT",
                "message": f"Maximum allowed batch size is {MAX_BATCH_TOTAL} records across chunked operations (received {len(records)})",
            },
        }

    for idx, item in enumerate(records):
        if not isinstance(item, dict) or "fields" not in item or not isinstance(item["fields"], dict):
            return {
                "success": False,
                "error": {
                    "code": "INVALID_INPUT",
                    "message": f"Record at index {idx} must be an object with a 'fields' dictionary",
                },
            }

    encoded_table = urllib.parse.quote(table_name, safe="")
    endpoint = f"{base_id}/{encoded_table}"

    all_formatted = []
    all_created = []
    all_updated = []

    for chunk in _chunk_list(records, BATCH_CHUNK_SIZE):
        payload: Dict[str, Any] = {
            "performUpsert": {"fieldsToMergeOn": fields_to_merge_on},
            "records": chunk,
        }
        if typecast:
            payload["typecast"] = True

        resp = _make_request(endpoint, "PATCH", pat, data=payload)
        if not resp["success"]:
            if not all_formatted:
                return resp
            return {
                "success": False,
                "partial": True,
                "count": len(all_formatted),
                "created_records": all_created,
                "updated_records": all_updated,
                "records": all_formatted,
                "error": resp.get("error", {}),
            }

        data = resp["data"]
        all_created.extend(data.get("createdRecords", []))
        all_updated.extend(data.get("updatedRecords", []))
        raw_records = data.get("records", [])
        for r in raw_records:
            all_formatted.append({
                "id": r.get("id"),
                "created_time": r.get("createdTime"),
                "fields": r.get("fields", {}),
            })

    return {
        "success": True,
        "count": len(all_formatted),
        "created_records": all_created,
        "updated_records": all_updated,
        "records": all_formatted,
    }


def list_bases(inputs: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """List all Airtable bases accessible by the authenticated token.
    
    Read-only action (side_effects: "none").
    Requires Airtable PAT with `bases:read` or `schema.bases:read` scope.
    """
    try:
        pat = _get_api_key(context)
    except ValueError as e:
        return {"success": False, "error": {"code": "AUTH_ERROR", "message": str(e)}}

    params: Dict[str, Any] = {}
    if inputs.get("offset"):
        params["offset"] = inputs["offset"]

    endpoint = "meta/bases"
    resp = _make_request(endpoint, "GET", pat, query_params=params)
    if not resp["success"]:
        return resp

    data = resp["data"]
    raw_bases = data.get("bases", [])
    bases = [
        {
            "id": b.get("id"),
            "name": b.get("name"),
            "permission_level": b.get("permissionLevel"),
        }
        for b in raw_bases
    ]

    return {
        "success": True,
        "count": len(bases),
        "offset": data.get("offset"),
        "bases": bases,
    }


# --- Tier 2 Commands: Comments, Schema Creation, Token Diagnostics ---


def add_comment(inputs: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Add a comment to an Airtable record.
    
    Mutating action: Requires external side_effects declaration and airlock approval.
    """
    try:
        pat = _get_api_key(context)
    except ValueError as e:
        return {"success": False, "error": {"code": "AUTH_ERROR", "message": str(e)}}

    base_id = inputs.get("base_id", "").strip()
    table_name = inputs.get("table_name", "").strip()
    record_id = inputs.get("record_id", "").strip()
    text = inputs.get("text", "").strip()

    if not base_id or not table_name or not record_id:
        return {
            "success": False,
            "error": {
                "code": "INVALID_INPUT",
                "message": "base_id, table_name, and record_id are all required",
            },
        }
    if not text:
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "text is required for a comment"}}

    encoded_table = urllib.parse.quote(table_name, safe="")
    encoded_record = urllib.parse.quote(record_id, safe="")
    endpoint = f"{base_id}/{encoded_table}/{encoded_record}/comments"

    payload = {"text": text}
    resp = _make_request(endpoint, "POST", pat, data=payload)
    if not resp["success"]:
        return resp

    c = resp["data"]
    return {
        "success": True,
        "comment": {
            "id": c.get("id"),
            "text": c.get("text"),
            "created_time": c.get("createdTime"),
            "author": c.get("author", {}),
        },
    }


def list_comments(inputs: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """List comments on an Airtable record with pagination support.
    
    Read-only action (side_effects: "none").
    """
    try:
        pat = _get_api_key(context)
    except ValueError as e:
        return {"success": False, "error": {"code": "AUTH_ERROR", "message": str(e)}}

    base_id = inputs.get("base_id", "").strip()
    table_name = inputs.get("table_name", "").strip()
    record_id = inputs.get("record_id", "").strip()

    if not base_id or not table_name or not record_id:
        return {
            "success": False,
            "error": {
                "code": "INVALID_INPUT",
                "message": "base_id, table_name, and record_id are all required",
            },
        }

    params: Dict[str, Any] = {}
    if inputs.get("offset"):
        params["offset"] = inputs["offset"]
    if inputs.get("page_size"):
        params["pageSize"] = int(inputs["page_size"])

    encoded_table = urllib.parse.quote(table_name, safe="")
    encoded_record = urllib.parse.quote(record_id, safe="")
    endpoint = f"{base_id}/{encoded_table}/{encoded_record}/comments"

    resp = _make_request(endpoint, "GET", pat, query_params=params)
    if not resp["success"]:
        return resp

    data = resp["data"]
    raw_comments = data.get("comments", [])
    comments = [
        {
            "id": c.get("id"),
            "text": c.get("text"),
            "created_time": c.get("createdTime"),
            "last_updated_time": c.get("lastUpdatedTime"),
            "author": c.get("author", {}),
        }
        for c in raw_comments
    ]

    return {
        "success": True,
        "count": len(comments),
        "offset": data.get("offset"),
        "comments": comments,
    }


def create_table(inputs: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Create a new table in a base with specified fields.
    
    Mutating action: Requires external side_effects declaration and airlock approval.
    Requires Airtable PAT with `schema.bases:write` scope.
    """
    try:
        pat = _get_api_key(context)
    except ValueError as e:
        return {"success": False, "error": {"code": "AUTH_ERROR", "message": str(e)}}

    base_id = inputs.get("base_id", "").strip()
    name = inputs.get("name", "").strip()
    fields = inputs.get("fields")
    description = inputs.get("description", "")

    if not base_id:
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "base_id is required"}}
    if not name:
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "name is required for the new table"}}
    if not isinstance(fields, list) or len(fields) == 0:
        return {
            "success": False,
            "error": {
                "code": "INVALID_INPUT",
                "message": "fields must be a non-empty array of field definition objects (name, type required)",
            },
        }

    endpoint = f"meta/bases/{base_id}/tables"
    payload: Dict[str, Any] = {"name": name, "fields": fields}
    if description:
        payload["description"] = description

    resp = _make_request(endpoint, "POST", pat, data=payload)
    if not resp["success"]:
        return resp

    data = resp["data"]
    return {
        "success": True,
        "table": {
            "id": data.get("id"),
            "name": data.get("name"),
            "primary_field_id": data.get("primaryFieldId"),
            "description": data.get("description", ""),
            "fields": data.get("fields", []),
            "views": data.get("views", []),
        },
    }


def create_field(inputs: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Add a new field (column) to an existing table.
    
    Mutating action: Requires external side_effects declaration and airlock approval.
    Requires Airtable PAT with `schema.bases:write` scope.
    """
    try:
        pat = _get_api_key(context)
    except ValueError as e:
        return {"success": False, "error": {"code": "AUTH_ERROR", "message": str(e)}}

    base_id = inputs.get("base_id", "").strip()
    table_name = inputs.get("table_name", "").strip()
    name = inputs.get("name", "").strip()
    field_type = inputs.get("type", "").strip()
    description = inputs.get("description")
    options = inputs.get("options")

    if not base_id:
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "base_id is required"}}
    if not table_name:
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "table_name is required"}}
    if not name:
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "name is required for the new field"}}
    if not field_type:
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "type is required (e.g. singleLineText, number)"}}

    encoded_table = urllib.parse.quote(table_name, safe="")
    endpoint = f"meta/bases/{base_id}/tables/{encoded_table}/fields"

    payload: Dict[str, Any] = {"name": name, "type": field_type}
    if description is not None:
        payload["description"] = description
    if isinstance(options, dict):
        payload["options"] = options

    resp = _make_request(endpoint, "POST", pat, data=payload)
    if not resp["success"]:
        return resp

    data = resp["data"]
    return {
        "success": True,
        "field": {
            "id": data.get("id"),
            "name": data.get("name"),
            "type": data.get("type"),
            "description": data.get("description", ""),
            "options": data.get("options", {}),
        },
    }


def whoami(inputs: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Retrieve the current user ID and token permissions/scopes for diagnostics.
    
    Read-only action (side_effects: "none").
    """
    try:
        pat = _get_api_key(context)
    except ValueError as e:
        return {"success": False, "error": {"code": "AUTH_ERROR", "message": str(e)}}

    endpoint = "meta/whoami"
    resp = _make_request(endpoint, "GET", pat)
    if not resp["success"]:
        return resp

    data = resp["data"]
    return {
        "success": True,
        "id": data.get("id"),
        "scopes": data.get("scopes", []),
    }


# --- Tier 3 Commands: Schema Updates & Webhooks ---


def update_table(inputs: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Update table name and/or description.
    
    Mutating action: Requires external side_effects declaration and airlock approval.
    Requires Airtable PAT with `schema.bases:write` scope.
    """
    try:
        pat = _get_api_key(context)
    except ValueError as e:
        return {"success": False, "error": {"code": "AUTH_ERROR", "message": str(e)}}

    base_id = inputs.get("base_id", "").strip()
    table_name = inputs.get("table_name", "").strip()
    name = inputs.get("name")
    description = inputs.get("description")

    if not base_id:
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "base_id is required"}}
    if not table_name:
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "table_name is required"}}
    if name is None and description is None:
        return {
            "success": False,
            "error": {"code": "INVALID_INPUT", "message": "At least one of 'name' or 'description' must be provided"},
        }

    encoded_table = urllib.parse.quote(table_name, safe="")
    endpoint = f"meta/bases/{base_id}/tables/{encoded_table}"

    payload: Dict[str, Any] = {}
    if name is not None:
        payload["name"] = name
    if description is not None:
        payload["description"] = description

    resp = _make_request(endpoint, "PATCH", pat, data=payload)
    if not resp["success"]:
        return resp

    data = resp["data"]
    return {
        "success": True,
        "table": {
            "id": data.get("id"),
            "name": data.get("name"),
            "description": data.get("description", ""),
        },
    }


def update_field(inputs: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Update field name and/or description.
    
    Mutating action: Requires external side_effects declaration and airlock approval.
    Requires Airtable PAT with `schema.bases:write` scope.
    """
    try:
        pat = _get_api_key(context)
    except ValueError as e:
        return {"success": False, "error": {"code": "AUTH_ERROR", "message": str(e)}}

    base_id = inputs.get("base_id", "").strip()
    table_name = inputs.get("table_name", "").strip()
    field_id = inputs.get("field_id", "").strip()
    name = inputs.get("name")
    description = inputs.get("description")

    if not base_id or not table_name or not field_id:
        return {
            "success": False,
            "error": {
                "code": "INVALID_INPUT",
                "message": "base_id, table_name, and field_id are all required",
            },
        }
    if name is None and description is None:
        return {
            "success": False,
            "error": {"code": "INVALID_INPUT", "message": "At least one of 'name' or 'description' must be provided"},
        }

    encoded_table = urllib.parse.quote(table_name, safe="")
    encoded_field = urllib.parse.quote(field_id, safe="")
    endpoint = f"meta/bases/{base_id}/tables/{encoded_table}/fields/{encoded_field}"

    payload: Dict[str, Any] = {}
    if name is not None:
        payload["name"] = name
    if description is not None:
        payload["description"] = description

    resp = _make_request(endpoint, "PATCH", pat, data=payload)
    if not resp["success"]:
        return resp

    data = resp["data"]
    return {
        "success": True,
        "field": {
            "id": data.get("id"),
            "name": data.get("name"),
            "type": data.get("type"),
            "description": data.get("description", ""),
        },
    }


def list_webhooks(inputs: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """List all active webhooks for an Airtable base.
    
    Read-only action (side_effects: "none").
    Requires Airtable PAT with `webhook:manage` scope.
    """
    try:
        pat = _get_api_key(context)
    except ValueError as e:
        return {"success": False, "error": {"code": "AUTH_ERROR", "message": str(e)}}

    base_id = inputs.get("base_id", "").strip()
    if not base_id:
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "base_id is required"}}

    endpoint = f"bases/{base_id}/webhooks"
    resp = _make_request(endpoint, "GET", pat)
    if not resp["success"]:
        return resp

    data = resp["data"]
    webhooks = data.get("webhooks", [])
    return {
        "success": True,
        "count": len(webhooks),
        "webhooks": webhooks,
    }


def count_records(inputs: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Count total records in an Airtable table and monitor Free Tier limit capacity.
    
    Airtable Free Tier enforces a strict hard ceiling of 1,000 records per base.
    This helper paginates with minimal payload (empty fields parameter) to efficiently
    gauge current base usage and capacity remaining before writes fail.
    Read-only action (side_effects: "none").
    """
    try:
        pat = _get_api_key(context)
    except ValueError as e:
        return {"success": False, "error": {"code": "AUTH_ERROR", "message": str(e)}}

    base_id = inputs.get("base_id", "").strip()
    table_name = inputs.get("table_name", "").strip()
    view = inputs.get("view")
    filter_by_formula = inputs.get("filter_by_formula")

    if not base_id:
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "base_id is required"}}
    if not table_name:
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "table_name is required"}}

    encoded_table = urllib.parse.quote(table_name, safe="")
    endpoint = f"{base_id}/{encoded_table}"

    total_count = 0
    offset = None

    while True:
        params: Dict[str, Any] = {
            "pageSize": 100,
            "fields[]": "",
        }
        if view:
            params["view"] = view
        if filter_by_formula:
            params["filterByFormula"] = filter_by_formula
        if offset:
            params["offset"] = offset

        resp = _make_request(endpoint, "GET", pat, query_params=params)
        if not resp["success"]:
            return resp

        records = resp["data"].get("records", [])
        total_count += len(records)
        offset = resp["data"].get("offset")
        if not offset:
            break

    remaining = max(0, FREE_TIER_LIMIT - total_count)
    percent_used = round((total_count / FREE_TIER_LIMIT) * 100, 1)
    at_capacity = total_count >= FREE_TIER_LIMIT
    warning = None
    if at_capacity:
        warning = f"Table has reached or exceeded the 1,000 record Free Tier ceiling ({total_count} records). Writes may fail with 422 errors."
    elif total_count >= 850:
        warning = f"Table is nearing the 1,000 record Free Tier ceiling ({total_count}/1,000 records used - {remaining} remaining)."

    return {
        "success": True,
        "count": total_count,
        "table_name": table_name,
        "free_tier_limit": FREE_TIER_LIMIT,
        "remaining": remaining,
        "percent_used": percent_used,
        "at_capacity": at_capacity,
        "warning": warning,
    }


def sync_and_notify(inputs: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Compound automation: Upsert records matching on unique keys and attach audit comments.
    
    Perfect for Free Tier teams lacking paid webhooks or enterprise automation runs.
    Upserts up to 100 records and optionally leaves audit trail comments on created/updated
    records so teammates see agent changes directly in Airtable.
    Mutating action: Requires external side_effects declaration and airlock approval.
    """
    base_id = inputs.get("base_id", "").strip()
    table_name = inputs.get("table_name", "").strip()
    notify_text = inputs.get("notify_text")
    max_comments = inputs.get("max_comments", 10)

    # 1. Perform batch upsert
    upsert_res = batch_upsert_records(inputs, context)
    if not upsert_res.get("success"):
        return upsert_res

    comments_added = 0
    comment_errors = []

    # 2. If notification text provided, annotate newly created and updated records
    if notify_text:
        target_record_ids = []
        created_ids = upsert_res.get("created_records", [])
        updated_ids = upsert_res.get("updated_records", [])

        for item in created_ids + updated_ids:
            rec_id = item if isinstance(item, str) else (item.get("id") if isinstance(item, dict) else None)
            if rec_id and rec_id not in target_record_ids:
                target_record_ids.append(rec_id)

        if not target_record_ids:
            for r in upsert_res.get("records", []):
                rec_id = r.get("id")
                if rec_id and rec_id not in target_record_ids:
                    target_record_ids.append(rec_id)

        for rec_id in target_record_ids[:max_comments]:
            comment_res = add_comment(
                {
                    "base_id": base_id,
                    "table_name": table_name,
                    "record_id": rec_id,
                    "text": str(notify_text),
                },
                context,
            )
            if comment_res.get("success"):
                comments_added += 1
            else:
                comment_errors.append({
                    "record_id": rec_id,
                    "error": comment_res.get("error"),
                })

    return {
        "success": True,
        "count": upsert_res["count"],
        "created_records": upsert_res.get("created_records", []),
        "updated_records": upsert_res.get("updated_records", []),
        "comments_added": comments_added,
        "comment_errors": comment_errors,
        "records": upsert_res.get("records", []),
    }


