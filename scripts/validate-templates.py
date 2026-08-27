#!/usr/bin/env python3
"""
Abstract Security - template/UI contract validator.

Catches the class of bug that neither `az bicep build` nor `az deployment validate`
can see: a portal UI whose outputs do not line up with its template's parameters.
That failure only shows up when a customer clicks Deploy, which is the worst place
to find it.

Checks, per template:
  1. Every .bicep has a compiled .azuredeploy.json, and it is NOT STALE
     (recompile and diff - a hand-edited or forgotten ARM file is a silent
     divergence between what we review and what customers deploy).
  2. Every UI output maps to a real template parameter.
  3. Every REQUIRED template parameter (no defaultValue) is supplied by the UI.
  4. Every steps('x').y / basics('x') reference resolves to an element that exists.
  5. The UI model matches the template's deployment SCOPE:
       resourceGroup      -> createUiDefinition is fine
       subscription / managementGroup / tenant
                          -> MUST be uiFormDefinition with the matching
                             outputs.kind, because createUiDefinition cannot
                             bind a deployment to those scopes.
  6. Form view outputs.kind carries the fields that kind requires.

Usage:
  python3 scripts/validate-templates.py            # validate
  python3 scripts/validate-templates.py --fix      # also recompile stale ARM
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

# scripts/ lives inside solutions/, so the solution root is one level up.
SOLUTION_ROOT = Path(__file__).resolve().parent.parent
REPO = SOLUTION_ROOT

SCOPE_BY_SCHEMA = {
    "deploymentTemplate.json#": "resourceGroup",
    "subscriptionDeploymentTemplate.json#": "subscription",
    "managementGroupDeploymentTemplate.json#": "managementGroup",
    "tenantDeploymentTemplate.json#": "tenant",
}

# Form view outputs.kind -> fields that kind must carry.
FORM_KIND_REQUIRED = {
    "ResourceGroup": {"resourceGroupId", "location", "parameters"},
    "Subscription": {"subscriptionId", "location", "parameters"},
    "ManagementGroup": {"managementGroupId", "location", "parameters"},
    "Tenant": {"location", "parameters"},
}

FORM_KIND_FOR_SCOPE = {
    "resourceGroup": "ResourceGroup",
    "subscription": "Subscription",
    "managementGroup": "ManagementGroup",
    "tenant": "Tenant",
}

errors: list[str] = []
warnings: list[str] = []
checked = 0


def err(msg: str) -> None:
    errors.append(msg)


def warn(msg: str) -> None:
    warnings.append(msg)


def load_json(path: Path):
    """Parse JSON, tolerating // line comments (ARM parameter files allow them)."""
    raw = path.read_text()
    stripped = re.sub(r"^\s*//.*$", "", raw, flags=re.M)
    return json.loads(stripped)


def template_scope(arm: dict) -> str:
    schema = arm.get("$schema", "").rsplit("/", 1)[-1]
    return SCOPE_BY_SCHEMA.get(schema, f"unknown({schema})")


def collect_ui_elements(container: list) -> set[str]:
    """Element names in a basics array or a step's elements array."""
    return {e["name"] for e in container if isinstance(e, dict) and "name" in e}


def check_references(outputs: dict, steps: dict[str, set[str]],
                     basics: set[str], label: str) -> None:
    """Every steps('x').y and basics('x') in an outputs expression must resolve."""
    for key, value in outputs.items():
        if not isinstance(value, str):
            continue
        for m in re.finditer(r"steps\('([^']+)'\)\.([A-Za-z0-9_]+)", value):
            step, element = m.group(1), m.group(2)
            if step not in steps:
                err(f"{label}: output '{key}' references unknown step '{step}'")
            elif element not in steps[step]:
                err(f"{label}: output '{key}' references steps('{step}').{element} "
                    f"which is not an element of that step")
        for m in re.finditer(r"basics\('([^']+)'\)", value):
            if m.group(1) not in basics:
                err(f"{label}: output '{key}' references unknown basics element "
                    f"'{m.group(1)}'")


def check_param_contract(ui_params: set[str], arm: dict, label: str) -> None:
    """UI outputs must be real parameters; required parameters must be supplied."""
    declared = set(arm.get("parameters", {}))
    for extra in sorted(ui_params - declared):
        err(f"{label}: UI supplies '{extra}' which is not a template parameter")

    required = {
        name for name, spec in arm.get("parameters", {}).items()
        if isinstance(spec, dict) and "defaultValue" not in spec
    }
    for missing in sorted(required - ui_params):
        err(f"{label}: required parameter '{missing}' has no default and is NOT "
            f"supplied by the UI - the portal deployment will fail")

    optional_unset = declared - ui_params - required
    if optional_unset:
        warn(f"{label}: {len(optional_unset)} optional parameter(s) use defaults: "
             f"{', '.join(sorted(optional_unset))}")


def validate_create_ui(ui_path: Path, arm: dict, scope: str) -> None:
    label = str(ui_path.relative_to(REPO))
    ui = load_json(ui_path)
    params = ui.get("parameters", {})

    if ui.get("handler") != "Microsoft.Azure.CreateUIDef":
        err(f"{label}: handler must be 'Microsoft.Azure.CreateUIDef'")

    if scope != "resourceGroup":
        err(f"{label}: createUiDefinition cannot bind a portal deployment to "
            f"'{scope}' scope - its basics step always renders a resource-group "
            f"picker. Use a uiFormDefinition with outputs.kind "
            f"'{FORM_KIND_FOR_SCOPE.get(scope, '?')}' instead")

    basics = collect_ui_elements(params.get("basics", []))
    steps = {s["name"]: collect_ui_elements(s.get("elements", []))
             for s in params.get("steps", [])}
    outputs = params.get("outputs", {})

    check_references(outputs, steps, basics, label)
    check_param_contract(set(outputs), arm, label)


def validate_form_ui(ui_path: Path, arm: dict, scope: str) -> None:
    label = str(ui_path.relative_to(REPO))
    ui = load_json(ui_path)
    view = ui.get("view", {})

    if view.get("kind") != "Form":
        err(f"{label}: view.kind must be 'Form'")

    props = view.get("properties", {})
    if not props.get("title"):
        err(f"{label}: view.properties.title is required")

    steps = {s["name"]: collect_ui_elements(s.get("elements", []))
             for s in props.get("steps", [])}
    if not steps:
        err(f"{label}: view.properties.steps must contain at least one step")

    outputs = view.get("outputs", {})
    kind = outputs.get("kind")
    expected_kind = FORM_KIND_FOR_SCOPE.get(scope)
    if kind != expected_kind:
        err(f"{label}: outputs.kind is '{kind}' but the template's schema is "
            f"'{scope}' scope, which requires '{expected_kind}'")

    for field in FORM_KIND_REQUIRED.get(kind, set()):
        if field not in outputs:
            err(f"{label}: outputs.kind '{kind}' requires field '{field}'")

    # Form view has no legacy basics(), so pass an empty set.
    scope_exprs = {k: v for k, v in outputs.items() if k != "parameters"}
    check_references(scope_exprs, steps, set(), label)
    check_references(outputs.get("parameters", {}), steps, set(), label)
    check_param_contract(set(outputs.get("parameters", {})), arm, label)


def strip_generator(arm: dict) -> dict:
    """Drop metadata._generator before comparing two compiles.

    Bicep stamps its own version and a templateHash into every ARM file it emits:
        "metadata": {"_generator": {"name": "bicep", "version": "0.44.1.10279", ...}}

    CI installs the latest Bicep, which will rarely match the version an author had
    locally. Comparing raw JSON therefore reports EVERY template as stale on a
    version bump - a red build that says nothing about the templates. Compare the
    substance instead: parameters, variables, resources, outputs.
    """
    out = json.loads(json.dumps(arm))
    meta = out.get("metadata")
    if isinstance(meta, dict):
        meta.pop("_generator", None)
        if not meta:
            out.pop("metadata", None)
    return out


def check_arm_freshness(bicep: Path, arm_path: Path, fix: bool) -> None:
    """Recompile the bicep to a temp file and diff - catches a stale ARM file."""
    label = str(bicep.relative_to(REPO))
    tmp = arm_path.with_suffix(".freshness-check.json")
    proc = subprocess.run(
        ["az", "bicep", "build", "--file", str(bicep), "--outfile", str(tmp)],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        err(f"{label}: bicep build FAILED: {proc.stderr.strip()[:400]}")
        tmp.unlink(missing_ok=True)
        return
    # NOTE: az bicep writes upgrade notices and linter warnings to stderr while still
    # exiting 0. Only the exit code decides success - treating stderr as failure made
    # every template with a style warning look broken.
    for line in proc.stderr.splitlines():
        if ") : Warning " in line:
            warn(f"{label}: bicep linter: {line.split(') : ',1)[-1][:160]}")
    try:
        fresh = strip_generator(json.loads(tmp.read_text()))
        current = strip_generator(json.loads(arm_path.read_text()))
        if fresh != current:
            if fix:
                arm_path.write_text(tmp.read_text())
                warn(f"{label}: ARM was STALE - recompiled "
                     f"{arm_path.relative_to(REPO)}")
            else:
                err(f"{label}: {arm_path.relative_to(REPO)} is STALE - it does not "
                    f"match a fresh compile. Run with --fix, or "
                    f"`az bicep build --file {label} --outfile "
                    f"{arm_path.relative_to(REPO)}`")
    finally:
        tmp.unlink(missing_ok=True)


def main() -> int:
    global checked
    fix = "--fix" in sys.argv

    bicep_files = sorted(
        p for p in REPO.rglob("*.bicep")
        if ".git" not in p.parts and ".venv" not in p.parts
    )
    if not bicep_files:
        err("no .bicep files found - is this the right repo?")
        return 1

    print(f"{'template':60} {'scope':16} {'ui model':22} status")
    print("-" * 112)

    for bicep in bicep_files:
        checked += 1
        stem = bicep.with_suffix("")
        label = str(bicep.relative_to(REPO))

        # main.bicep historically compiles to ./azuredeploy.json at the repo root.
        arm_path = stem.with_name(stem.name + ".azuredeploy.json")
        if not arm_path.exists() and bicep.name == "main.bicep":
            arm_path = bicep.parent / "azuredeploy.json"

        if not arm_path.exists():
            err(f"{label}: no compiled ARM template found - customers deploying "
                f"from the portal need the JSON, not the Bicep")
            print(f"{label:60} {'?':16} {'-':22} NO ARM")
            continue

        check_arm_freshness(bicep, arm_path, fix)

        try:
            arm = load_json(arm_path)
        except json.JSONDecodeError as e:
            err(f"{arm_path.relative_to(REPO)}: invalid JSON: {e}")
            continue

        scope = template_scope(arm)

        create_ui = stem.with_name(stem.name + ".createUiDefinition.json")
        if not create_ui.exists() and bicep.name == "main.bicep":
            alt = bicep.parent / "createUiDefinition.json"
            if alt.exists():
                create_ui = alt
        form_ui = stem.with_name(stem.name + ".uiFormDefinition.json")

        model = "-"
        if create_ui.exists() and form_ui.exists():
            model = "BOTH"
            err(f"{label}: has BOTH a createUiDefinition and a uiFormDefinition. "
                f"Ship one - two portal experiences for one template will drift.")
        elif create_ui.exists():
            model = "createUiDefinition"
            validate_create_ui(create_ui, arm, scope)
        elif form_ui.exists():
            model = "uiFormDefinition"
            validate_form_ui(form_ui, arm, scope)
        else:
            needed = FORM_KIND_FOR_SCOPE.get(scope)
            warn(f"{label}: no portal UI - CLI-only. ({scope} scope would need a "
                 f"uiFormDefinition with kind '{needed}')")

        print(f"{label:60} {scope:16} {model:22} ok")

    print()
    for w in warnings:
        print(f"  warn: {w}")
    if errors:
        print()
        for e in errors:
            print(f"  ERROR: {e}")
        print(f"\n{len(errors)} error(s), {len(warnings)} warning(s) "
              f"across {checked} template(s)")
        return 1

    print(f"\nAll {checked} template(s) valid. {len(warnings)} warning(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
