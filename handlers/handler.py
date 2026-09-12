"""RailCall Marketplace Module: smitshah/airtable
Integrates with the Airtable REST API.
"""

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

AIRTABLE_API_BASE = "https://api.airtable.com/v0"


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


def _make_request(
    endpoint: str,
    method: str,
    pat: str,
    data: Optional[Dict[str, Any]] = None,
    query_params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Execute an HTTP request to the Airtable REST API using Python stdlib.
    
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
        "User-Agent": "RailCall-Module-Airtable/1.0.0",
    }

    body = json.dumps(data).encode("utf-8") if data is not None else None
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
    """Create up to 10 records in a single batch request.
    
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
    if len(records) > 10:
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "Airtable allows a maximum of 10 records per batch request"}}

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
    payload: Dict[str, Any] = {"records": records}
    if typecast:
        payload["typecast"] = True

    resp = _make_request(endpoint, "POST", pat, data=payload)
    if not resp["success"]:
        return resp

    created_records = resp["data"].get("records", [])
    formatted = [
        {
            "id": r.get("id"),
            "created_time": r.get("createdTime"),
            "fields": r.get("fields", {}),
        }
        for r in created_records
    ]

    return {
        "success": True,
        "count": len(formatted),
        "records": formatted,
    }


def batch_update_records(inputs: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Update up to 10 records in a single batch request (PATCH).
    
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
    if len(records) > 10:
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "Airtable allows a maximum of 10 records per batch request"}}

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
    payload: Dict[str, Any] = {"records": records}
    if typecast:
        payload["typecast"] = True

    resp = _make_request(endpoint, "PATCH", pat, data=payload)
    if not resp["success"]:
        return resp

    updated_records = resp["data"].get("records", [])
    formatted = [
        {
            "id": r.get("id"),
            "created_time": r.get("createdTime"),
            "fields": r.get("fields", {}),
        }
        for r in updated_records
    ]

    return {
        "success": True,
        "count": len(formatted),
        "records": formatted,
    }


def batch_delete_records(inputs: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Delete up to 10 records in a single batch request.
    
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
    if len(record_ids) > 10:
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "Airtable allows a maximum of 10 records per batch delete"}}

    encoded_table = urllib.parse.quote(table_name, safe="")
    endpoint = f"{base_id}/{encoded_table}"
    params = {"records[]": record_ids}

    resp = _make_request(endpoint, "DELETE", pat, query_params=params)
    if not resp["success"]:
        return resp

    deleted_records = resp["data"].get("records", [])
    return {
        "success": True,
        "count": len(deleted_records),
        "records": deleted_records,
    }


def batch_upsert_records(inputs: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Perform upsert (insert-or-update) matching on specified key fields for up to 10 records.
    
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
    if len(records) > 10:
        return {"success": False, "error": {"code": "INVALID_INPUT", "message": "Airtable allows a maximum of 10 records per batch upsert"}}

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
    payload: Dict[str, Any] = {
        "performUpsert": {"fieldsToMergeOn": fields_to_merge_on},
        "records": records,
    }
    if typecast:
        payload["typecast"] = True

    resp = _make_request(endpoint, "PATCH", pat, data=payload)
    if not resp["success"]:
        return resp

    data = resp["data"]
    raw_records = data.get("records", [])
    formatted = [
        {
            "id": r.get("id"),
            "created_time": r.get("createdTime"),
            "fields": r.get("fields", {}),
        }
        for r in raw_records
    ]

    return {
        "success": True,
        "count": len(formatted),
        "created_records": data.get("createdRecords", []),
        "updated_records": data.get("updatedRecords", []),
        "records": formatted,
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

