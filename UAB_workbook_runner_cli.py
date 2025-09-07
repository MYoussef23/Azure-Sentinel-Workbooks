#!/usr/bin/env python3
"""
Sentinel Workbook KQL Runner (Azure Log Analytics via REST + AZ CLI auth)

- Reads a Sentinel workbook JSON, selects a query by index, substitutes placeholders,
  and executes the KQL against your Log Analytics workspace using the provided
  azure_monitor_logs_run_query module (REST API + az CLI token).

Requirements:
  pip install fire requests

Notes:
- AZ CLI must be installed and logged in (e.g., `az account show` works).
- The user's token acquisition path is handled by `azure_monitor_logs_run_query`.
- Placeholders like {UserPrincipalName}, {AccountUPN}, etc. are replaced with CLI kwargs.
- {Operation} can be "value::all" (treat as All) OR a comma list like "A,B,C".
- You can export results via --output csv/json and --outfile path.
"""

from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# External dependency provided by the user
import azure_monitor_logs_run_query  # noqa: F401

# supress warnings from requests about unverified HTTPS requests
import warnings
from urllib3.exceptions import InsecureRequestWarning
warnings.simplefilter('ignore', InsecureRequestWarning)

# --------------------------
# Placeholder / substitution
# --------------------------

# Matches {Param} or {Param:label} (label part optional)
PLACEHOLDER_RE = re.compile(r"\{([A-Za-z0-9_]+)(?::[^}]*)?\}")

def _sanitize_filename(name: str) -> str:
    name = name.strip().replace(" ", "_")
    return re.sub(r"[^-_.A-Za-z0-9]+", "", name) or "query"

def _coerce_operations(value: Optional[str]) -> Dict[str, Any]:
    if not value:
        return {"operations_all": True, "ops": []}
    v = value.strip()
    if v.lower() in ("value::all", "all", "any", "*"):
        return {"operations_all": True, "ops": []}
    ops = [o.strip() for o in v.split(",") if o.strip()]
    return {"operations_all": False, "ops": ops}

def _format_operations_for_kql(ops: List[str]) -> str:
    # In KQL, single quotes are escaped by doubling them ('')
    escaped = [o.replace("'", "''") for o in ops]
    return ", ".join(f"'{e}'" for e in escaped)

def _substitute_placeholders(raw_query: str, params: Dict[str, Any]) -> str:
    """
    Substitute placeholders:
      - {Operation}, {Operation:label}/{Operation:lable}
      - {TimeRange}, {TimeRange:ago}, {TimeFrom}, {TimeTo}, {TimeRange:where}
      - Any other {Param} via params
    """
    op_meta = _coerce_operations(params.get("Operation"))
    q = str(raw_query)

    # ---- TimeRange support ----
    time_field = params.get("TimeField") or "TimeGenerated"
    tr_value = params.get("TimeRange") or params.get("timespan")
    tr = _coerce_timerange(tr_value, time_field=time_field)

    # Tokens you can use in titles or KQL
    q = q.replace("{TimeRange}", tr["label"])
    # {TimeRange:ago} prints ago(X) for durations, or 'datetime(start) .. datetime(end)' for absolute
    q = q.replace("{TimeRange:ago}", tr["pretty_span"])
    q = q.replace("{TimeFrom}", tr["from_expr"])
    q = q.replace("{TimeTo}", tr["to_expr"])
    q = q.replace("{TimeRange:where}", tr["where_fragment"])

    # ---- Operation handling (as you had) ----
    all_branch_regex = re.compile(
        r"""
        \|\s*where\s*
        "?\{Operation:(?:label|lable)\}"?\s*==\s*"All"
        \s*or\s*
        Operation\s*in\s*\(\s*\{Operation\}\s*\)
        \s*\n?
        """,
        re.IGNORECASE | re.VERBOSE,
    )
    if op_meta["operations_all"]:
        q = all_branch_regex.sub("", q)
    else:
        q = q.replace("{Operation}", _format_operations_for_kql(op_meta["ops"]))
        lbl = ", ".join(op_meta["ops"]) or "Selected"
        q = q.replace("{Operation:label}", lbl)
        q = q.replace("{Operation:lable}", lbl)

    # ---- Generic replacement ----
    def _repl(m: re.Match) -> str:
        key = m.group(1)
        if key in {"Operation", "TimeRange", "TimeFrom", "TimeTo"}:
            return m.group(0)  # already handled
        val = params.get(key)
        return m.group(0) if val is None else str(val)

    q = PLACEHOLDER_RE.sub(_repl, q)
    return q

# --------------------------
# Workbook parsing
# --------------------------

def _load_queries(workbook_path: str) -> List[Dict[str, Any]]:
    """
    Extract queries from a Sentinel/Monitor workbook JSON.

    Tolerates multiple shapes:
      - item.type == 3 with content.query
      - content.serialData.query (when present)
      - content.queryData.query (some exports)
      - content.kql or content.customQuery (rare)
      - content as a raw string (treat as query)
    """
    p = Path(workbook_path)
    if not p.exists():
        raise FileNotFoundError(f"Workbook JSON not found: {p}")

    try:
        text = p.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        # Fallback for odd encodings/BOMs
        text = p.read_text(encoding="utf-8-sig")

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in workbook: {e}") from e

    queries: List[Dict[str, Any]] = []

    # Common locations for items
    items = data.get("items")
    if not isinstance(items, list):
        items = data.get("properties", {}).get("items", [])
    if not isinstance(items, list):
        items = []

    def _extract_query_from_content(content: Any) -> str:
        """Best-effort query extraction from a content payload."""
        if isinstance(content, str):
            return content  # raw KQL string
        if not isinstance(content, dict):
            return ""

        # Primary
        q = content.get("query")
        if isinstance(q, str) and q.strip():
            return q

        # Variants occasionally seen in exports
        for key in ("serialData", "queryData"):
            node = content.get(key)
            if isinstance(node, dict):
                q2 = node.get("query")
                if isinstance(q2, str) and q2.strip():
                    return q2

        # Other rare keys
        for key in ("kql", "customQuery"):
            q3 = content.get(key)
            if isinstance(q3, str) and q3.strip():
                return q3

        return ""

    for item in items:
        if not isinstance(item, dict):
            continue

        # Only consider visual type 3 (query control) if present; otherwise try anyway.
        content = item.get("content")
        title = (
            (isinstance(content, dict) and content.get("title"))
            or item.get("name")
            or "Untitled Query"
        )

        query_text = _extract_query_from_content(content)

        # Some workbook exports put the KQL directly under item["query"]
        if not query_text and isinstance(item.get("query"), str):
            query_text = item["query"]

        # Only append entries that actually have a query string
        if isinstance(query_text, str) and query_text.strip():
            queries.append({
                "title": title,
                "query": query_text,
                "name": item.get("name", ""),
            })

    return queries

# --------------------------
# Output helpers
# --------------------------

ISO_RANGE_RE = re.compile(r"^\s*(?P<start>[^/]+)\s*/\s*(?P<end>.+)\s*$", re.I)

def _coerce_timerange(time_range: str | None, time_field: str = "TimeGenerated") -> dict:
    if not time_range:
        return {"label": "", "from_expr": "", "to_expr": "", "where_fragment": "", "pretty_span": ""}

    tr = time_range.strip()

    # Absolute: start/end
    m = ISO_RANGE_RE.match(tr)
    if m:
        start, end = m.group("start"), m.group("end")
        frm, to = f"datetime({start})", f"datetime({end})"
        where = f"| where {time_field} between ({frm} .. {to})"
        return {"label": tr, "from_expr": frm, "to_expr": to, "where_fragment": where, "pretty_span": f"{frm} .. {to}"}

    # Relative: duration -> ago(span)
    if tr.upper().startswith("P"):
        span = _iso8601_to_kql_ago(tr)       # e.g., '1d 6h'
        frm, to = f"> ago({span})", "now()"
        where = f"| where {time_field} >= {frm}"
        return {"label": tr, "from_expr": frm, "to_expr": to, "where_fragment": where, "pretty_span": frm}

    # Fallback
    return {"label": tr, "from_expr": "", "to_expr": "", "where_fragment": tr, "pretty_span": tr}

def _iso8601_to_kql_ago(iso: str) -> str:
    """
    Convert ISO-8601 durations (P1D, PT6H, PT1H30M) to a compact span string: '1d', '6h', '1h 30m'.
    """
    m = re.fullmatch(r"P(?:(?P<d>\d+)D)?(?:T(?:(?P<h>\d+)H)?(?:(?P<m>\d+)M)?)?", iso, re.I)
    if not m:
        return iso  # pass through unknown formats

    d = int(m.group("d") or 0)
    h = int(m.group("h") or 0)
    mi = int(m.group("m") or 0)
    parts = []
    if d: parts.append(f"{d}d")
    if h: parts.append(f"{h}h")
    if mi: parts.append(f"{mi}m")
    return " ".join(parts) if parts else iso

def _coerce_table(result: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[List[Any]]]:
    """
    Accept either:
      - {"columns":[{"name":"A"},...], "rows":[[...], ...]}
      - {"tables":[{"columns":[...], "rows":[...]}]}
    Returns (columns, rows) where columns is a list of {"name": colname}
    """
    if not result:
        return [], []

    if "columns" in result and "rows" in result:
        return result.get("columns", []), result.get("rows", [])

    # Log Analytics REST default
    tables = result.get("tables") or []
    if tables and isinstance(tables, list):
        t0 = tables[0] if tables else {}
        return t0.get("columns", []), t0.get("rows", [])

    # Some wrappers return {"error": ...}
    if "error" in result:
        raise RuntimeError(json.dumps(result["error"], indent=2))

    return [], []

def _print_table(cols: List[Dict[str, Any]], rows: List[List[Any]], limit: Optional[int] = None) -> None:
    if not cols:
        print("No data returned.")
        return

    col_names = [c.get("name", f"col{i}") for i, c in enumerate(cols)]
    data = rows[: (limit or len(rows))]

    # Compute column widths (soft cap at 60 chars)
    max_width = 60
    widths = [min(len(name), max_width) for name in col_names]
    for row in data:
        for i, cell in enumerate(row):
            text = str(cell)
            widths[i] = min(max(widths[i], len(text)), max_width)

    # Header
    header = " | ".join(name.ljust(widths[i]) for i, name in enumerate(col_names))
    sep = "-+-".join("-" * widths[i] for i in range(len(widths)))
    print(header)
    print(sep)

    # Rows
    for row in data:
        line = " | ".join(str(cell)[:widths[i]].ljust(widths[i]) for i, cell in enumerate(row))
        print(line)

    if limit and len(rows) > limit:
        print(f"\n... {len(rows) - limit} more rows omitted (use --limit to adjust).")

def _export_results(cols: List[Dict[str, Any]], rows: List[List[Any]], fmt: str, outfile: Path) -> None:
    outfile.parent.mkdir(parents=True, exist_ok=True)
    col_names = [c.get("name", f"col{i}") for i, c in enumerate(cols)]

    if fmt.lower() == "csv":
        with outfile.open("w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(col_names)
            writer.writerows(rows)
    elif fmt.lower() == "json":
        as_dicts = [dict(zip(col_names, r)) for r in rows]
        with outfile.open("w", encoding="utf-8") as f:
            json.dump(as_dicts, f, ensure_ascii=False, indent=2)
    else:
        raise ValueError("Unsupported output format. Use csv or json.")

    print(f"Saved results to: {outfile}")

# --------------------------
# CLI
# --------------------------

class Runner:
    def list(self, workbook_path: str = "User_Analytics_Behaviour.json") -> None:
        """List all KQL queries (index + title)."""
        qs = _load_queries(workbook_path)
        if not qs:
            print("No queries found.")
            return
        for i, q in enumerate(qs, 1):
            title = q.get("title") or q.get("name") or "Untitled Query"
            empty = " (EMPTY)" if not (q.get("query") or "").strip() else ""
            print(f"[{i:02d}] {title}{empty}")

    def run(
        self,
        index: int,
        workspace_id: str,
        timespan: str,
        workbook_path: str = "User_Analytics_Behaviour.json",
        output: Optional[str] = None,               # csv|json
        outfile: Optional[str] = None,              # path for export
        limit: Optional[int] = 200,                 # preview row limit for console
        save_rendered_kql: bool = False,            # save rendered KQL to file
        quiet_kql: bool = False,                    # don't print KQL
        **kwargs,
    ) -> None:
        """
        Execute the specified workbook query by index against the given workspace.

        Args:
          index: 1-based index of the query from `list`
          workspace_id: Log Analytics Workspace ID (GUID)
          timespan: ISO8601 duration (e.g., P1D) or absolute range(s)
          workbook_path: path to the Sentinel workbook JSON
          output: csv or json to export results
          outfile: path to write exported file
          limit: max rows printed to console (export always writes all rows)
          save_rendered_kql: write the rendered KQL to a .kql file
          quiet_kql: suppress KQL printout
          **kwargs: placeholder values (e.g., --UserPrincipalName, --AccountUPN, --Operation)
        """
        qs = _load_queries(workbook_path)
        if index < 1 or index > len(qs):
            raise IndexError(f"Index out of range. 1..{len(qs)}")

        q = qs[index - 1]
        raw = q.get("query") or ""
        title = q.get("title") or q.get("name") or f"Query_{index:02d}"
        if not raw.strip():
            raise ValueError("Selected query is empty in the workbook.")

        rendered = _substitute_placeholders(raw, kwargs)
        kwargs.setdefault("TimeRange", timespan)
        vtitle = _substitute_placeholders(title, kwargs).strip()

        if save_rendered_kql:
            kql_path = Path(f"{_sanitize_filename(title)}.kql")
            kql_path.write_text(rendered, encoding="utf-8")
            print(f"Saved rendered KQL to: {kql_path}")

        if not quiet_kql:
            print(f"-- Executing: {vtitle} --\n")
            print("---- KQL ----")
            print(rendered)
            print("-------------\n")

        # Run the query
        try:
            table = azure_monitor_logs_run_query._query_log_analytics(workspace_id, rendered, timespan, verify_tls=False)
        except Exception as e:
            print("Failed to execute query via azure_monitor_logs_run_query._query_log_analytics()", file=sys.stderr)
            raise

        cols, rows = _coerce_table(table)

        # Print a simple, readable table
        _print_table(cols, rows, limit=limit)

        # Optional export
        if output:
            if outfile:
                out_path = Path(outfile)
            else:
                base = _sanitize_filename(title)
                out_path = Path(f"{base}.{output.lower()}")
            _export_results(cols, rows, output, out_path)

if __name__ == "__main__":
    try:
        import fire  # type: ignore
    except ImportError as e:
        raise SystemExit("Please install Python Fire first: pip install fire") from e
    fire.Fire(Runner)

# -------------------------- Example usage --------------------------
#   python sentinel_workbook_runner.py run <index> <workspace_ID> P1D --UserPrincipalName <UPN> --limit 5
#   python sentinel_workbook_runner.py list
#   python sentinel_workbook_runner.py run <id> P1D --UserPrincipalName <UPN> --Operation <Operation> --limit 10