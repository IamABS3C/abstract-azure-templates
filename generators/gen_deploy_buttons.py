#!/usr/bin/env python3
"""Generate verified Deploy-to-Azure button URLs from the Azure solution manifest.

Why this is its own generator: a Deploy-to-Azure button is a one-click production
deployment. If the URL 404s, the customer sees a portal error; far worse, if it
resolves to a STALE template the customer silently deploys a known-broken version.
That is not hypothetical -- on 2026-08-26 `main` was serving an Event Hub template
whose diagnostics rule requested Send-only rights, which Microsoft documents as
insufficient for Event Hubs streaming. Buttons published that day would have
handed customers one-click deployment of a template that creates the setting and
collects nothing.

So this generator VERIFIES before it emits: every raw URL must return 200.

GROUNDED 2026-08-26 against Microsoft's own "Deploy to Azure button" page. Two
things I had wrong and that are easy to get wrong:

  * The button URL takes ONLY the encoded ARM template URL:
        https://portal.azure.com/#create/Microsoft.Template/uri/<encoded>
    There is no documented `createUIDefinitionUri` parameter for this button, and
    no `uiFormDefinitionUri` parameter at all -- I had invented the latter.

  * **Deployment scope is determined by the template `$schema`, not by the URL.**
    So a subscription/managementGroup/tenant template works through the same
    plain button; nothing extra is appended.

  * `createUiDefinition.json` belongs to Azure **Managed Applications**;
    `uiFormDefinition.json` belongs to **template spec** portal forms. NEITHER is
    rendered by a plain Deploy-to-Azure button -- the portal auto-generates a
    parameter pane from the template's own parameters and their metadata. Our UI
    files are still worth shipping (they drive the template-spec and managed-app
    paths), but a button does not surface them, and claiming otherwise oversells it.
"""
import json
import pathlib
import subprocess
import sys
import urllib.parse

AZURE_REPO = pathlib.Path("<local-path> ")
RAW = "https://raw.githubusercontent.com/IamABS3C/Abstract-MS-Azure-/main/solutions/"
PORTAL = "https://portal.azure.com/#create/Microsoft.Template/uri/"

# Scope is carried by the template's own $schema, so the button is identical for
# every scope. Kept as an assertion target: a template whose declared scope does
# not match its $schema would deploy at the wrong level.
SCHEMA_FOR_SCOPE = {
    "resourceGroup":   "deploymentTemplate.json",
    "subscription":    "subscriptionDeploymentTemplate.json",
    "managementGroup": "managementGroupDeploymentTemplate.json",
    "tenant":          "tenantDeploymentTemplate.json",
}


def http_status(url: str) -> int:
    out = subprocess.run(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-L", url],
        capture_output=True, text=True, timeout=30)
    return int(out.stdout.strip() or 0)


def button_url(tpl_path: str) -> str:
    """The documented format -- encoded ARM URL and nothing else."""
    return PORTAL + urllib.parse.quote(f"{RAW}{tpl_path}.azuredeploy.json", safe="")


def main() -> int:
    manifest = json.loads((AZURE_REPO / "solutions" / "solution.manifest.json").read_text())
    rows, failures = [], []

    for t in sorted(manifest["templates"], key=lambda x: x.get("order", 999)):
        path, scope, ui = t["path"], t.get("scope", ""), t.get("ui", "createUiDefinition")

        # The template's own $schema is what decides where it deploys. If it
        # disagrees with the manifest, the button silently targets the wrong
        # scope -- so check the file rather than trusting the manifest.
        local_arm = AZURE_REPO / "solutions" / f"{path}.azuredeploy.json"
        want = SCHEMA_FOR_SCOPE.get(scope)
        if want and local_arm.exists():
            declared = json.loads(local_arm.read_text()).get("$schema", "")
            if want not in declared:
                failures.append(
                    f"{t['id']}: manifest says scope '{scope}' but $schema is "
                    f"{declared.rsplit('/', 1)[-1]} — the button would deploy at "
                    f"the wrong scope")
                continue

        arm_url = f"{RAW}{path}.azuredeploy.json"
        ui_url = f"{RAW}{path}.{ui}.json"
        arm_s, ui_s = http_status(arm_url), http_status(ui_url)
        if arm_s != 200 or ui_s != 200:
            failures.append(f"{t['id']}: ARM {arm_s}, UI {ui_s} — not published on main")
            continue

        rows.append({
            "id": t["id"], "title": t["title"], "scope": scope,
            "summary": t.get("summary", ""), "url": button_url(path),
            "deploy_first": bool(t.get("deployFirst")),
        })

    out = pathlib.Path("dist/deploy-buttons.json")
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({"buttons": rows, "failures": failures}, indent=2) + "\n")

    for f in failures:
        print(f"FAIL : {f}")
    for r in rows:
        print(f"ok   : {r['id']:<32} {r['scope']}")
    print(f"\n{len(rows)} button(s) verified, {len(failures)} failure(s) -> {out}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
