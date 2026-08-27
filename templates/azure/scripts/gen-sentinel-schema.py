#!/usr/bin/env python3
"""
Generate a Log Analytics / DCR-ready column schema from Abstract's canonical ACS
field catalog (solution/schema/all_fields.json, sourced from GET /v1/acs/fields).

Why this exists
---------------
Abstract's "Azure Sentinel Destination" doc has you upload an all_fields schema to
the custom DCR-based table so every Abstract Common Schema (ACS) field lands in an
explicit column. This script turns the authoritative ACS catalog into a valid
Log Analytics `tableColumns` array (the sentinel-destination template's parameter),
handling the three things you cannot do by hand safely:

  1. Log Analytics column names allow only [A-Za-z0-9_], must start with a letter,
     and cannot contain dots — so ACS dotted names (cloud.account_id) are flattened
     to underscores (cloud_account_id). '@'-prefixed fields (@timestamp) are dropped
     from explicit columns (they map to TimeGenerated).
  2. Abstract data types are mapped to Log Analytics column types.
  3. The huge ext.* vendor-extension namespace (~1,399 fields) is collapsed into a
     single `ext` dynamic column instead of 1,399 columns (LA caps custom tables at
     ~500 columns). Set --explode-ext to emit them individually anyway.

Usage
-----
  python3 scripts/gen-sentinel-schema.py \
      --catalog solution/schema/all_fields.json \
      --out parameters/sentinel-destination.full-schema.parameters.json \
      [--static-only] [--explode-ext] [--print-columns]

Abstract type -> Log Analytics type
  String, Ipv4, Ipv6                        -> string
  Float64                                   -> real
  Date                                      -> datetime
  Boolean                                   -> boolean
  List(*), StringifyJSON, JSON, Nested,
  Coordinate                                -> dynamic
"""
import argparse, json, re, sys

TYPE_MAP = {
    "String": "string", "Ipv4": "string", "Ipv6": "string",
    "Float64": "real", "Date": "datetime", "Boolean": "boolean",
}
# everything else (List(...), StringifyJSON, JSON, Nested, Coordinate) -> dynamic
def la_type(abstract_type: str) -> str:
    return TYPE_MAP.get(abstract_type, "dynamic")

def flatten(name: str) -> str:
    """ACS field name -> valid LA column name, or None if it can't be a column."""
    if name.startswith("@"):
        return None                      # @timestamp etc. -> TimeGenerated
    col = re.sub(r"[^A-Za-z0-9_]", "_", name)
    if not re.match(r"^[A-Za-z]", col):
        col = "f_" + col
    return col[:45]                      # LA column-name max length

def build(catalog, static_only, explode_ext):
    cols = [{"name": "TimeGenerated", "type": "datetime"}]
    seen = {"timegenerated"}
    ext_present = False
    for f in catalog:
        name = f.get("field", "")
        if name.startswith("ext.") and not explode_ext:
            ext_present = True
            continue
        if static_only and name.startswith("ext."):
            continue
        col = flatten(name)
        if not col or col.lower() in seen:
            continue
        seen.add(col.lower())
        cols.append({"name": col, "type": la_type(f.get("data_type", "String"))})
    # single dynamic catch-all for the vendor extension namespace
    if ext_present and "ext" not in seen:
        cols.append({"name": "ext", "type": "dynamic"})
    # keep the raw event too, so nothing is ever lost even in explicit mode
    if "abstractevent" not in seen:
        cols.append({"name": "AbstractEvent", "type": "dynamic"})
    return cols

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--catalog", default="solution/schema/all_fields.json")
    ap.add_argument("--out", default="parameters/sentinel-destination.full-schema.parameters.json")
    ap.add_argument("--static-only", action="store_true", help="Exclude ext.* entirely (no ext dynamic column).")
    ap.add_argument("--explode-ext", action="store_true", help="Emit every ext.* field as its own column (may exceed LA limits).")
    ap.add_argument("--print-columns", action="store_true", help="Print the column count and first 20 columns, don't write.")
    a = ap.parse_args()

    doc = json.load(open(a.catalog))
    catalog = doc["fields"] if isinstance(doc, dict) and "fields" in doc else doc
    cols = build(catalog, a.static_only, a.explode_ext)

    if len(cols) > 500:
        print(f"WARNING: {len(cols)} columns exceeds the Log Analytics ~500-column "
              f"custom-table limit; use --static-only or curate.", file=sys.stderr)
    if a.print_columns:
        print(f"{len(cols)} columns")
        for c in cols[:20]:
            print(" ", c["name"], c["type"])
        return

    params = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
        "contentVersion": "3.0.0.0",
        "metadata": {
            "description": ("EXPLICIT-COLUMN schema for the Sentinel Destination template, generated "
                            "by scripts/gen-sentinel-schema.py from solution/schema/all_fields.json "
                            "(Abstract ACS catalog, GET /v1/acs/fields). ACS dotted names are flattened "
                            "to underscores; the ext.* vendor namespace is collapsed to one dynamic "
                            "'ext' column; 'AbstractEvent' is kept as a raw dynamic catch-all. Use ONLY "
                            "if your Abstract mapper emits explicit per-field columns; otherwise the "
                            "default 3-column wrapped-dynamic schema is recommended. Deploy: az deployment "
                            "group create -g <rg> --template-file templates/destinations/"
                            "sentinel-destination.azuredeploy.json --parameters @<this file> "
                            "--parameters principalId=<sp-object-id>."),
            "generatedColumnCount": len(cols),
        },
        "parameters": {
            "createWorkspace": {"value": True},
            "customTableName": {"value": "AbstractEventLogs_CL"},
            "principalId": {"value": "<service-principal-OBJECT-id>"},
            "tableColumns": {"value": cols},
        },
    }
    json.dump(params, open(a.out, "w"), indent=2)
    print(f"wrote {a.out} with {len(cols)} columns")

if __name__ == "__main__":
    main()
