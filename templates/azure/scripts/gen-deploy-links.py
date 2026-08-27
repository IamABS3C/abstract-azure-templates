#!/usr/bin/env python3
"""
Abstract Security - deploy-link generator.

Deploy-to-Azure URLs embed the repo owner, repo name and branch. Hand-maintained,
they rot the moment the repo is renamed, forked or ported - and a rotted button is
a 404 in front of a customer, discovered by the customer.

This generates every button from solutions/solution.manifest.json, so porting the
solution to a new repo is: edit `repo` in the manifest, run this with --write.

  python3 scripts/gen-deploy-links.py            # print the tables
  python3 scripts/gen-deploy-links.py --write     # rewrite README + Pages markers
  python3 scripts/gen-deploy-links.py --check     # CI: fail if anything is stale

Markers in the target files delimit generated regions:
  <!-- BEGIN GENERATED: deploy-table -->  ... <!-- END GENERATED: deploy-table -->
Everything outside the markers is hand-written and never touched.

TWO PORTAL URL FORMATS, and why both appear:
  createUiDefinition -> /createUIDefinitionUri/   (documented by Microsoft)
  uiFormDefinition   -> /uiFormDefinitionUri/     (community-documented only)

Microsoft's own deploy-button doc covers the template URI form but does not spell
out uiFormDefinitionUri; the format is used in the wild and by the portal, but it
is NOT in the official docs. That is why every Form-view template ALSO ships a
template-spec command in the README - the fully documented path - so no customer
is stranded if the button form changes.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
from pathlib import Path

SOLUTION_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = SOLUTION_ROOT / "solution.manifest.json"

BEGIN = "<!-- BEGIN GENERATED: {name} -->"
END = "<!-- END GENERATED: {name} -->"

SCOPE_LABEL = {
    "resourceGroup": "resource group",
    "subscription": "subscription",
    "managementGroup": "management group",
    "tenant": "tenant",
}

CATEGORY_TITLE = {
    "source": "Sources — Abstract reads *from* Azure",
    "governance": "Governance — onboard the whole estate",
    "identity": "Identity — app registrations for Graph / M365 collection",
    "destination": "Destinations — Abstract writes *to* Azure",
}

CATEGORY_BLURB = {
    "source": "Get Microsoft telemetry into Abstract. Deploy the Event Hub source first — every other source template consumes its outputs.",
    "governance": "Stop configuring diagnostic settings one subscription at a time. Assign once at a management group; current and future subscriptions onboard themselves.",
    "identity": "Event Hub collection needs no app registration. These are for the other source set: Microsoft Graph and the Microsoft 365 unified audit log.",
    "destination": "Send Abstract's enriched, normalized output back into Azure.",
}


def load_manifest() -> dict:
    return json.loads(MANIFEST.read_text())


def raw_url(repo: dict, rel_path: str) -> str:
    return (f"https://raw.githubusercontent.com/{repo['owner']}/{repo['name']}/"
            f"{repo['branch']}/{repo['solutionPath']}/{rel_path}")


def enc(url: str) -> str:
    """Portal deep links need the raw URL percent-encoded, including the slashes."""
    return urllib.parse.quote(url, safe="")


def button(manifest: dict, tpl: dict, gov: bool = False) -> str:
    repo = manifest["repo"]
    portal = manifest["portal"]["government" if gov else "public"]
    img = ("https://aka.ms/deploytoazuregovbutton" if gov
           else "https://aka.ms/deploytoazurebutton")
    alt = "Deploy to Azure Gov" if gov else "Deploy to Azure"

    arm = enc(raw_url(repo, f"{tpl['path']}.azuredeploy.json"))
    if tpl["ui"] == "createUiDefinition":
        ui_seg = f"/createUIDefinitionUri/{enc(raw_url(repo, tpl['path'] + '.createUiDefinition.json'))}"
    elif tpl["ui"] == "uiFormDefinition":
        ui_seg = f"/uiFormDefinitionUri/{enc(raw_url(repo, tpl['path'] + '.uiFormDefinition.json'))}"
    else:
        ui_seg = ""

    return f"[![{alt}]({img})]({portal}/#create/Microsoft.Template/uri/{arm}{ui_seg})"


def template_spec_command(tpl: dict) -> str:
    """The FULLY DOCUMENTED way to deliver a Form-view wizard.

    `uiFormDefinitionUri` on a Deploy-to-Azure URL works and is widely used, but it is
    NOT in Microsoft's official deploy-button documentation - only the template-spec
    flow is. Every Form-view template therefore also gets this command, so a customer
    whose policy allows only documented paths (or who hits a portal change) has a
    supported route to the same wizard.
    """
    name = tpl["path"].split("/")[-1]
    return (f"az ts create --name {name} --version 1.0 -g <rg> -l <region> \\\n"
            f"  --template-file solutions/{tpl['path']}.azuredeploy.json \\\n"
            f"  --ui-form-definition solutions/{tpl['path']}.uiFormDefinition.json")


def cli_command(tpl: dict) -> str:
    """The fully documented fallback for every template."""
    scope = tpl["scope"]
    bicep = f"solutions/{tpl['path']}.bicep"
    if scope == "resourceGroup":
        return f"az deployment group create -g <rg> --template-file {bicep}"
    if scope == "subscription":
        return f"az deployment sub create -l <region> --template-file {bicep}"
    if scope == "managementGroup":
        return f"az deployment mg create -m <mg-id> -l <region> --template-file {bicep}"
    return f"az deployment tenant create -l <region> --template-file {bicep}"


def deploy_table(manifest: dict) -> str:
    lines: list[str] = []
    by_cat: dict[str, list[dict]] = {}
    for tpl in sorted(manifest["templates"], key=lambda t: t["order"]):
        by_cat.setdefault(tpl["category"], []).append(tpl)

    for cat in ("source", "governance", "identity", "destination"):
        if cat not in by_cat:
            continue
        lines.append(f"### {CATEGORY_TITLE[cat]}")
        lines.append("")
        lines.append(CATEGORY_BLURB[cat])
        lines.append("")
        lines.append("| Template | Scope | Deploy | Gov | CLI |")
        lines.append("| --- | --- | --- | --- | --- |")
        for tpl in by_cat[cat]:
            star = " ⭐" if tpl.get("recommended") else ""
            first = " **(deploy first)**" if tpl.get("deployFirst") else ""
            lines.append(
                f"| **{tpl['title']}**{star}{first} | {SCOPE_LABEL[tpl['scope']]} | "
                f"{button(manifest, tpl)} | {button(manifest, tpl, gov=True)} | "
                f"`{cli_command(tpl)}` |"
            )
        lines.append("")
    return "\n".join(lines).rstrip()


def template_detail(manifest: dict) -> str:
    lines: list[str] = []
    for tpl in sorted(manifest["templates"], key=lambda t: t["order"]):
        star = " ⭐ **recommended**" if tpl.get("recommended") else ""
        lines.append(f"#### {tpl['title']}{star}")
        lines.append("")
        lines.append(tpl["summary"])
        lines.append("")
        lines.append(f"- **Scope:** {SCOPE_LABEL[tpl['scope']]} "
                     f"· **Portal UI:** `{tpl['ui']}`")
        lines.append(f"- **Files:** `{tpl['path']}.bicep` · "
                     f"`{tpl['path']}.azuredeploy.json` · "
                     f"`{tpl['path']}.{tpl['ui']}.json`")
        if tpl.get("prerequisite"):
            lines.append(f"- **Prerequisite:** {tpl['prerequisite']}")
        if tpl.get("driver"):
            lines.append(f"- **Driver script:** `{tpl['driver']}`")
        if tpl.get("outputsNeededNext"):
            outs = ", ".join(f"`{o}`" for o in tpl["outputsNeededNext"])
            lines.append(f"- **Outputs you need next:** {outs}")
        if tpl.get("notes"):
            lines.append(f"- **Note:** {tpl['notes']}")
        lines.append("")
    return "\n".join(lines).rstrip()


def inventory_table(manifest: dict) -> str:
    lines = ["| Template | Scope | Bicep | ARM | Portal UI |",
             "| --- | --- | :-: | :-: | :-: |"]
    for tpl in sorted(manifest["templates"], key=lambda t: t["order"]):
        ui = "createUiDef" if tpl["ui"] == "createUiDefinition" else "Form view"
        lines.append(f"| `{tpl['path'].split('/')[-1]}` | {SCOPE_LABEL[tpl['scope']]} "
                     f"| ✅ | ✅ | ✅ {ui} |")
    return "\n".join(lines)


def replace_region(text: str, name: str, body: str) -> tuple[str, bool]:
    begin, end = BEGIN.format(name=name), END.format(name=name)
    if begin not in text or end not in text:
        return text, False
    head, rest = text.split(begin, 1)
    _, tail = rest.split(end, 1)
    new = f"{head}{begin}\n{body}\n{end}{tail}"
    return new, new != text


def template_spec_table(manifest: dict) -> str:
    """Documented-path instructions for every Form-view template."""
    forms = [t for t in sorted(manifest["templates"], key=lambda t: t["order"])
             if t["ui"] == "uiFormDefinition"]
    if not forms:
        return "_No Form-view templates in this solution._"

    lines = [
        "The buttons above use `uiFormDefinitionUri`, which the portal accepts but which",
        "Microsoft does **not** document for Deploy-to-Azure links. Template specs are the",
        "documented delivery path for the identical wizard — use these when a customer's",
        "policy allows only documented Microsoft flows, or if the button form ever changes:",
        "",
    ]
    for tpl in forms:
        lines.append(f"**{tpl['title']}** ({SCOPE_LABEL[tpl['scope']]} scope)")
        lines.append("")
        lines.append("```bash")
        lines.append(template_spec_command(tpl))
        lines.append("# then: portal → Template specs → "
                     f"{tpl['path'].split('/')[-1]} → Deploy")
        lines.append("```")
        lines.append("")
    return "\n".join(lines).rstrip()


REGIONS = {
    "deploy-table": deploy_table,
    "template-spec": template_spec_table,
    "template-detail": template_detail,
    "inventory-table": inventory_table,
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="rewrite generated regions")
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if any generated region is stale (for CI)")
    args = ap.parse_args()

    manifest = load_manifest()

    targets = [
        SOLUTION_ROOT / "README.md",
        SOLUTION_ROOT.parent / "README.md",
    ]

    if not args.write and not args.check:
        for name, fn in REGIONS.items():
            print(f"\n{'=' * 78}\n{name}\n{'=' * 78}\n")
            print(fn(manifest))
        return 0

    stale: list[str] = []
    for target in targets:
        if not target.exists():
            continue
        text = original = target.read_text()
        touched = []
        for name, fn in REGIONS.items():
            text, changed = replace_region(text, name, fn(manifest))
            if changed:
                touched.append(name)
        if text != original:
            if args.check:
                stale.append(f"{target.name}: {', '.join(touched)}")
            else:
                target.write_text(text)
                print(f"updated {target.relative_to(SOLUTION_ROOT.parent)}: "
                      f"{', '.join(touched)}")
        else:
            print(f"up to date: {target.relative_to(SOLUTION_ROOT.parent)}")

    if stale:
        print("\nSTALE generated content:", file=sys.stderr)
        for s in stale:
            print(f"  {s}", file=sys.stderr)
        print("\nRun: python3 solutions/scripts/gen-deploy-links.py --write",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
