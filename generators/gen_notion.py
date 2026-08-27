#!/usr/bin/env python3
"""Corpus -> Notion sync planner + registry.

WHY THIS IS A PLANNER AND NOT A CLIENT
--------------------------------------
This workspace forbids Notion integrations AND personal access tokens, so there
is no API path from Python. The MCP connector is the only write path, and it
lives in the assistant's tool layer, not here. So this script:

  1. renders each corpus node to Notion-flavored markdown,
  2. hashes it and diffs against notion-registry.json,
  3. emits dist/notion-plan.json saying exactly which pages to CREATE and which
     to UPDATE — and, critically, which to SKIP.

The assistant then executes that plan through the MCP tools and calls
`--record` to write the returned page IDs back into the registry.

THE REGISTRY IS THE WHOLE POINT. Without a node-id -> page-id map, the second
sync run creates a parallel universe of duplicate pages and there is no way
back. Never delete notion-registry.json. Never sync without consulting it.

Usage:
  python3 generators/gen_notion.py --plan
  python3 generators/gen_notion.py --plan --only azure
  python3 generators/gen_notion.py --record <node_id> <page_id> [--url URL]
  python3 generators/gen_notion.py --status
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import date
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("pyyaml required: pip3 install pyyaml")

REPO = Path(__file__).resolve().parent.parent
CORPUS = REPO / "corpus"
DIST = REPO / "dist"
REGISTRY = REPO / "generators" / "notion-registry.json"

TIER_BADGE = {
    "deployed": "🟢 **deployed** — executed against a real account",
    "planned": "🔵 **planned** — plan/what-if/changeset run against real credentials",
    "validated": "🟡 **validated** — compiler/linter passed locally, not executed",
    "schema-reviewed": "🟠 **schema-reviewed** — written to current schema, never executed",
    "cited": "⚪ **cited** — reproduced from vendor documentation",
}

# Notion silently rewrites an unrecognised code language to `javascript` — no error, no
# warning. Verified empirically 2026-08-26: `bicep` came back as `javascript`, while `hcl`,
# `json`, `powershell`, `bash` and `mermaid` survived and `text` normalised to `plain text`.
# So every value here must be a language Notion actually knows.
#
# `bicep` is NOT one of them. Mapping it to `typescript` is a deliberate choice, not a
# guess: Bicep borrows TS-ish syntax, so `//` comments, 'single-quoted strings' and `{}`
# objects all highlight correctly, and only the `param`/`resource` keywords go unstyled.
# That beats `plain text`, and it beats being silently mislabelled JavaScript.
LANG = {
    "bicep": "typescript", "arm-json": "json", "arm-ui": "json", "azure-policy": "json",
    "azure-cli": "bash", "powershell": "powershell", "az-deployment-script": "bash",
    "cloudformation": "yaml", "cfn-stackset": "bash", "cfn-changeset": "bash",
    "aws-cli": "bash", "cdk": "typescript", "sam": "yaml",
    "terraform": "hcl", "opentofu": "hcl", "pulumi": "typescript", "ansible": "yaml",
    "gcloud-cli": "bash", "deployment-manager": "yaml",
    "oci-cli": "bash", "oci-resource-manager": "hcl",
    "python": "python", "bash": "bash", "github-actions": "yaml",
}


def load_registry() -> dict:
    if REGISTRY.exists():
        return json.loads(REGISTRY.read_text())
    return {"version": 1, "hub_page_id": None, "database_id": None,
            "data_source_url": None, "nodes": {}}


def save_registry(reg: dict) -> None:
    REGISTRY.parent.mkdir(parents=True, exist_ok=True)
    REGISTRY.write_text(json.dumps(reg, indent=2, sort_keys=True) + "\n")


def content_hash(md: str) -> str:
    return hashlib.sha256(md.encode()).hexdigest()[:16]


# --------------------------------------------------------------------------- render


# A Notion page is delivered in ~100-block chunks through the MCP connector, so a page
# that inlines a 600-line Bicep file AND its compiled ARM JSON is unusable — the first
# render came out at 162 KB. Large artifacts are excerpted and linked instead. The full
# file always lives in the repo; the page exists to explain it, not to be it.
INLINE_MAX = 1600          # characters — a Notion page should EXPLAIN the artifact,
EXCERPT_LINES = 22         # not be it. The corpus link is on every database row.


def _excerpt(text: str, path: str) -> str:
    """Head of a file, cut at a blank line so it does not end mid-statement."""
    lines = text.splitlines()
    cut = EXCERPT_LINES
    for i in range(min(EXCERPT_LINES + 12, len(lines)) - 1, EXCERPT_LINES - 1, -1):
        if not lines[i].strip():
            cut = i
            break
    head = "\n".join(lines[:cut]).rstrip()
    return f"{head}\n\n# ... {len(lines) - cut} more lines — full file: {path}"


def _artifact_body(a: dict) -> tuple[str, str | None]:
    """Return (code body, note). The note explains any truncation."""
    if a.get("inline"):
        return a["inline"].rstrip(), None

    for key, base in (("path", REPO), ("external_path", None)):
        p = a.get(key)
        if not p:
            continue
        fp = (base / p) if base else Path(p)
        try:
            text = fp.read_text().rstrip()
        except OSError:
            return f"<!-- artifact file not readable at generation time: {p} -->", None

        if len(text) <= INLINE_MAX:
            return text, None
        ref = public_ref(p)
        where = f"[{ref}]({ref})" if ref.startswith("http") else f"`{ref}`"
        return (_excerpt(text, ref),
                f"*Excerpt — the full artifact is {len(text):,} characters "
                f"({len(text.splitlines()):,} lines). Full file: {where}. "
                f"Deploy from the file, not from this page.*")

    return "<!-- no inline content and no path -->", None



# --------------------------------------------------------------------------- notion blocks
#
# Notion-flavored Markdown does NOT support pipe tables — they render as literal text.
# Tables must be <table> XML, callouts <callout>, toggles <details>. This was found by
# authoring one page by hand and comparing: the generator's pipe tables would have
# shipped seven pages of plaintext that looked like a formatting bug.

def esc(s) -> str:
    """Escape the characters Notion-flavored Markdown treats as delimiters.

    Deliberately NOT escaping inside code spans or code blocks — callers pass already-
    fenced content there, and escaping it would corrupt the code.
    """
    s = "" if s is None else str(s)
    return s.replace("|", "\\|")


def ntable(rows, header_row=False, header_column=False, fit=True) -> list[str]:
    """Emit a Notion <table>. rows = list of lists of cell strings."""
    attrs = [f'fit-page-width="{str(fit).lower()}"']
    if header_row:
        attrs.append('header-row="true"')
    if header_column:
        attrs.append('header-column="true"')
    out = [f"<table {' '.join(attrs)}>"]
    for r in rows:
        out.append("\t<tr>" + "".join(f"<td>{esc(c)}</td>" for c in r) + "</tr>")
    out.append("</table>")
    return out


def toggle(summary: str, body_lines: list[str]) -> list[str]:
    """A <details> toggle. Body must be flat blocks, one per line."""
    out = ["<details>", f"<summary>{summary}</summary>", ""]
    out.extend(body_lines)
    out.append("</details>")
    return out


def callout(lines: list[str], icon: str = "", color: str = "") -> list[str]:
    attrs = []
    if icon:
        attrs.append(f'icon="{icon}"')
    if color:
        attrs.append(f'color="{color}"')
    out = [f"<callout {' '.join(attrs)}>" if attrs else "<callout>"]
    # Split embedded newlines. A multi-paragraph review lens arrives as ONE string
    # containing "\n", and indenting only the first line silently breaks out of the
    # callout -- the remainder renders as loose page-level blocks. Blank lines are
    # dropped because Notion supplies block spacing itself.
    for ln in lines:
        for part in str(ln).split("\n"):
            if part.strip():
                out.append("\t" + part)
    out.append("</callout>")
    return out


def columns(cols: list[list[str]], ratios: list[int] | None = None) -> list[str]:
    """Two-up (or n-up) layout.

    The generator could not produce <columns> at all, while the live pages used it
    for the Review section -- so a re-sync would have FLATTENED a side-by-side
    layout into a single stack. Every page footer says "edit the corpus and
    re-sync", which made that instruction actively destructive.
    """
    ratios = ratios or [round(100 / len(cols))] * len(cols)
    out = ["<columns>"]
    for body, ratio in zip(cols, ratios):
        out.append(f'\t<column ratio="{ratio}">')
        out.extend("\t\t" + ln for ln in body)
        out.append("\t</column>")
    out.append("</columns>")
    return out



# Public repo roots, so an artifact reference becomes a URL a customer can actually open
# instead of a path on somebody's laptop. Verified public 2026-08-26: the Abstract-MS-Azure
# raw URLs return 200, which is also what makes the Deploy-to-Azure buttons work.
# NOTE the trailing space in the local directory name — it is real and it was being
# published verbatim.
PUBLIC_REPOS = {
    "<local-path> /":
        "https://github.com/IamABS3C/Abstract-MS-Azure-/blob/main/",
}


def public_ref(path: str) -> str:
    """Turn a local artifact path into something publishable.

    Absolute local paths must never reach a customer-visible page. Where the file lives in a
    known public repo we emit a real URL; otherwise we emit the basename only, because a
    truncated path is still a leak.
    """
    for local, url in PUBLIC_REPOS.items():
        if path.startswith(local):
            return url + path[len(local):]
    if path.startswith("/"):
        return path.rsplit("/", 1)[-1]          # basename only — never the full local path
    return path                                  # already repo-relative


def covers_future(node: dict) -> tuple[str, str]:
    """Return (label, mechanism) for covers_future_accounts.

    ONE implementation, used by both the page body and the database property. They previously
    disagreed on the same field: the page rendered "Yes" while the row computed "Conditional",
    on the same screen, for azure.policy.log-streams.
    """
    fut = node.get("covers_future_accounts")
    note = (node.get("mechanism_note") or "")
    if not fut:
        return "No", note
    if any(w in note.lower() for w in ("unless", "depends", "provided that", "only if")):
        return "Conditional", note
    return "Yes", note



# Licences that oblige the credit line to travel WITH the image, on the page,
# every time it renders. A footnote at the bottom of a long page does not
# discharge the obligation, and a reader who copies the image out takes the
# credit with them only if it is adjacent.
_ATTRIB_LICENSES = {"ms-screenshot-permission", "cc-by-4.0"}


def image_block(img: dict) -> str:
    """Render one walkthrough image with its attribution attached."""
    # Notion's image block has ONE text slot -- the caption. There is no separate
    # alt attribute, so the caption has to carry the description AND any credit
    # the licence obliges us to display. Putting the credit in a page footer
    # instead would not travel with the image when a reader copies it out.
    parts = [img.get("caption") or img["alt"]]
    if img.get("license") in _ATTRIB_LICENSES and img.get("credit"):
        parts.append(img["credit"])
    caption = " — ".join(parts).replace("]", "\\]").replace("[", "\\[")
    return f"![{caption}]({notion_asset_url(img['path'])})"


def preflight_assets(nodes: list) -> None:
    """Fail before writing anything if an image has not been uploaded.

    notion_asset_url() raises mid-render. On a multi-page plan that would abort
    partway through a sync -- some pages updated, some not, registry hashes
    half-written -- which is exactly the inconsistent state the registry exists
    to prevent. Collect every missing asset up front instead.
    """
    reg = load_registry().get("assets", {})
    missing = []
    for node in nodes:
        for step in node.get("console_walkthrough") or []:
            img = step.get("image")
            if img and img["path"] not in reg:
                missing.append(f"{node['id']}: {img['path']}")
    if missing:
        raise SystemExit(
            "these images are referenced but not uploaded to Notion yet:\n  "
            + "\n  ".join(missing)
            + "\nRun: python3 generators/upload_assets.py <path>\n"
            "Nothing was written -- fix these and re-run."
        )


def notion_asset_url(path: str) -> str:
    """Resolve a repo-relative asset path to whatever Notion can actually render.

    Uploaded assets are recorded in the registry under 'assets' by the upload
    step; until an asset has been uploaded there is no URL for it, and emitting
    a local path would render as a broken image on a customer-facing page.
    """
    uploaded = load_registry().get("assets", {}).get(path)
    if uploaded:
        # Defensive: the assets map briefly held non-asset keys, one of which was a
        # LOCAL path. Publishing that as an image src produces a broken image on a
        # customer-visible page and nothing errors, so refuse anything that is not
        # a resolvable source.
        if not uploaded.startswith(("file-upload://", "http://", "https://")):
            raise SystemExit(
                f"registry asset for {path} is not a publishable source: {uploaded!r}\n"
                f"Expected file-upload://<id> or an https URL."
            )
        return uploaded
    raise SystemExit(
        f"asset not uploaded to Notion yet: {path}\n"
        f"Run: python3 generators/upload_assets.py {path}\n"
        f"(a local filesystem path renders as a broken image on a shared page)"
    )


TIER_ICON  = {"deployed":"🟢","planned":"🔵","validated":"🟡",
              "schema-reviewed":"🟠","cited":"⚪"}
TIER_COLOR = {"deployed":"green_bg","planned":"blue_bg","validated":"yellow_bg",
              "schema-reviewed":"orange_bg","cited":"gray_bg"}


def render(node: dict) -> str:
    o: list[str] = []
    a = o.append

    _tier = node.get("provenance", "")
    # Strip the leading emoji: the callout already carries it as its icon.
    _badge = re.sub(r"^\S+\s+", "", TIER_BADGE.get(_tier, _tier))
    o.extend(callout([_badge],
                     icon=TIER_ICON.get(_tier, "🟠"), color=TIER_COLOR.get(_tier, "orange_bg")))
    a("")
    a(node["summary"])
    a("")

    # At-a-glance
    a("## At a glance")
    a("")
    rows = [
        ["Cloud", node["cloud"].upper()],
        ["Service", node["service"]],
        ["Transport", f"`{node['transport']}`"],
        ["Direction", node["direction"]],
    ]
    if node.get("scopes"):
        rows.append(["Deploys at", " · ".join(f"`{s}`" for s in node["scopes"])])
    if node.get("covers_future_accounts") is not None:
        label, note = covers_future(node)
        icon = {"Yes": "✅", "Conditional": "⚠️", "No": "❌"}[label]
        rows.append(["Covers future accounts",
                     f"{icon} **{label}**" + (f" — {note}" if note else "")])
    rows.append(["Status", node["status"]])
    ai = node.get("abstract_integration") or {}
    if ai.get("id"):
        rows.append(["Abstract integration",
                     f"`{ai['id']}`" + (f" ({ai['mode']})" if ai.get("mode") else "")])
    rows.append(["Available as",
                 " · ".join(f"`{x['kind']}`" for x in node.get("artifacts", []))])
    o.extend(ntable(rows, header_column=True))
    a("")

    if node.get("when_to_use"):
        a("### When to use this path")
        a("")
        a(node["when_to_use"])
        a("")
    if node.get("when_not_to_use"):
        a("### When NOT to use it")
        a("")
        a(node["when_not_to_use"])
        a("")

    if node.get("alternatives_rejected"):
        a("### Options considered and rejected")
        a("")
        o.extend(ntable([["Option", "Why not"]] +
                        [[x["option"], x["why_not"]] for x in node["alternatives_rejected"]],
                        header_row=True))
        a("")

    # Decision tree — the IP
    if node.get("decision"):
        a("## Decide before you build")
        a("")
        a("Answer these first. Every one of them changes what you deploy, and each is a "
          "question a specific human has to answer — identify that person before the call, "
          "not during it.")
        a("")
        for q in node["decision"]:
            a(f"### {q['question']}")
            a("")
            if q.get("ask_who"):
                a(f"**Who holds this answer:** {q['ask_who']}")
                a("")
            a(f"*Why it matters:* {q['why_it_matters']}")
            a("")
            for opt in q["options"]:
                tail = f" → `{opt['leads_to']}`"
                note = f" — {opt['note']}" if opt.get("note") else ""
                a(f"- **{opt['value']}**{tail}{note}")
            a("")

    # Prereqs
    pr = node.get("prereqs", {})
    a("## Prerequisites")
    a("")
    if pr.get("identity"):
        a("### Permissions — and the scope they are needed at")
        a("")
        o.extend(callout(["The single most common reason an onboarding stalls is a scope "
                          "mismatch: the person driving has rights on a project or resource "
                          "group, but the action needs rights at the organization, tenant or "
                          "management-group level. Check this first."],
                         icon="🔑", color="purple_bg"))
        a("")
        o.extend(ntable(
            [["Principal", "Role / permission", "At scope", "Why", "Least-privilege alternative"]] +
            [[i["principal"], f"`{i['role']}`", f"`{i['scope']}`", i["why"],
              i.get("least_privilege_alternative", "—")] for i in pr["identity"]],
            header_row=True))
        a("")
    for label, key in (("Resources that must exist", "resources"),
                       ("Settings that are OFF by default", "settings"),
                       ("Network", "network"),
                       ("Quotas and limits", "quotas_limits")):
        if pr.get(key):
            a(f"### {label}")
            a("")
            for x in pr[key]:
                a(f"- {x}")
            a("")
    if pr.get("lead_time"):
        o.extend(callout([f"**Lead time:** {pr['lead_time']}"], icon="⏱", color="gray_bg"))
        a("")

    # Console
    if node.get("console_walkthrough"):
        a("## Console walkthrough")
        a("")
        a("For operators who will not touch a CLI. This is how most teams do it the first time.")
        a("")
        for s in node["console_walkthrough"]:
            a(f"**{s['step']}. {s['action']}**")
            a("")
            if s.get("where"):
                a(f"- *Where:* {s['where']}")
            if s.get("expected"):
                a(f"- *You should see:* {s['expected']}")
            if s.get("gotcha"):
                a(f"- ⚠️ *Gotcha:* {s['gotcha']}")
            a("")
            if s.get("image"):
                a(image_block(s["image"]))
                a("")

    # Artifacts
    a("## Deploy it as code")
    a("")
    for art in node.get("artifacts", []):
        a(f"### {art['kind']}")
        a("")
        a(f"{TIER_BADGE.get(art['provenance'], art['provenance'])}")
        a("")
        if art.get("validation"):
            v = art["validation"]
            a(f"```text\n$ {v['command']}\n{v['result']}\n```")
            a(f"*Run {v['run_on']}"
              f"{' with ' + v['tool_version'] if v.get('tool_version') else ''}.*")
            a("")
        if art.get("scope"):
            a(f"*Deployment scope:* `{art['scope']}`")
            a("")
        if art.get("destructive_risk"):
            o.extend(callout([f"**Overwrite risk:** {art['destructive_risk']}"],
                             icon="⚠️", color="orange_bg"))
            a("")
        body, trunc = _artifact_body(art)
        if trunc:
            a(trunc)
            a("")
        a(f"```{LANG.get(art['kind'], 'text')}")
        a(body)
        a("```")
        a("")
        if art.get("note"):
            note_txt = art["note"]
            for local in PUBLIC_REPOS:
                note_txt = note_txt.replace(local, public_ref(local + "").rsplit("/blob/main/", 1)[0] + "/")
            a(note_txt)
            a("")

    if node.get("delivery_surfaces"):
        a("### Delivery surfaces")
        a("")
        a("How the artifact above gets *delivered* — a separate axis from how it is authored. "
          "Orchestrators run Terraform or CloudFormation; they do not replace them.")
        a("")
        a(", ".join(f"`{s}`" for s in node["delivery_surfaces"]))
        a("")

    # Verify
    a("## Verify it works")
    a("")
    a("In this order. Each check isolates one layer, so a failure tells you *where* the break is.")
    a("")
    for i, v in enumerate(node.get("verification", []), 1):
        a(f"**{i}. {v['check']}** *({v['where']})*")
        a("")
        if v.get("command"):
            a(f"```bash\n{v['command']}\n```")
        a(f"- ✅ Healthy: {v['healthy']}")
        if v.get("unhealthy_means"):
            a(f"- ❌ If not: {v['unhealthy_means']}")
        a("")

    # Troubleshooting
    if node.get("troubleshooting"):
        a("## Troubleshooting")
        a("")
        silent = [t for t in node["troubleshooting"] if t.get("silent")]
        if silent:
            o.extend(callout(["**Silent failures first.** These produce no error at all — "
                              "just zero events. They are the expensive ones because everyone "
                              "assumes the pipeline is fine."],
                             icon="🔇", color="red_bg"))
            a("")
        # Silent first — they are the expensive ones and burying them defeats the point.
        for ts in sorted(node["troubleshooting"], key=lambda x: not x.get("silent")):
            mark = "🔇 " if ts.get("silent") else ""
            body = [f"- **Likely cause:** {ts['likely_cause']}",
                    f"- **Check:** {ts['check']}",
                    f"- **Fix:** {ts['fix']}"]
            if ts.get("seen_on"):
                body.append(f"- *Observed: {ts['seen_on']}*")
            o.extend(toggle(f"{mark}**{ts['symptom']}**", body))
            a("")

    # Cost
    c = node.get("cost") or {}
    if c:
        a("## Cost")
        a("")
        if c.get("drivers"):
            o.extend(ntable([["Driver", "Charged on", "Whose bill", "Note"]] +
                            [[d["driver"], d["charged_on"], d["side"], d.get("note", "—")]
                             for d in c["drivers"]], header_row=True))
            a("")
        if c.get("surprise_line"):
            o.extend(callout([f"**The line nobody budgets for:** {c['surprise_line']}"],
                             icon="💸", color="yellow_bg"))
            a("")
        if c.get("volume_shape"):
            a(f"*Volume shape:* {c['volume_shape']}")
            a("")
        if c.get("savings"):
            a("**Savings this path creates:**")
            a("")
            for s in c["savings"]:
                a(f"- {s}")
            a("")

    # Detections
    if node.get("detections_unlocked"):
        a("## What this unlocks for the SOC")
        a("")
        o.extend(ntable([["Detection", "ACS fields", "MITRE"]] +
                        [[d["detection"],
                          " · ".join(f"`{f}`" for f in d.get("acs_fields", [])) or "—",
                          " · ".join(d.get("mitre", [])) or "—"]
                         for d in node["detections_unlocked"]], header_row=True))
        a("")

    # Reviews
    rv = node.get("reviews") or {}
    if any(rv.values()):
        a("## Review")
        a("")
        LENS = (("cloud_architect", "Cloud architect", "🏗️", "blue_bg"),
                ("devops", "DevOps / platform", "⚙️", "gray_bg"),
                ("security_iam", "Security / IAM", "🔐", "purple_bg"),
                ("finops", "FinOps", "💸", "yellow_bg"),
                ("soc", "SOC / detection", "🎯", "green_bg"))
        blocks = [callout([f"**{label}**", rv[key]], icon=icon, color=colour)
                  for key, label, icon, colour in LENS if rv.get(key)]
        # Two-up, pairing blocks left/right. Five lenses leave one full-width at the
        # end rather than a lopsided pair.
        for i in range(0, len(blocks) - 1, 2):
            o.extend(columns([blocks[i], blocks[i + 1]], [50, 50]))
            a("")
        if len(blocks) % 2:
            o.extend(blocks[-1])
            a("")

    # FAQ
    if node.get("faq"):
        a("## FAQ")
        a("")
        for fq in node["faq"]:
            body = [fq["a"]]
            if fq.get("asked_by"):
                body += ["", f"*Asked by: {fq['asked_by']}*"]
            o.extend(toggle(fq["q"], body))
            a("")

    # References
    a("## References")
    a("")
    o.extend(ntable([["Source", "Tier", "Supports", "Retrieved"]] +
                    [[f"[{r['title']}]({r['url']})", r["tier"], r.get("supports", "—"),
                      r.get("retrieved", "—")] for r in node.get("references", [])],
                    header_row=True))
    a("")

    a("---")
    a("")
    a(f"*Generated from `corpus/{node['cloud']}/{node['id']}.yml`. "
      f"Do not edit this page directly — edit the corpus and re-sync.*")
    if node.get("last_reviewed"):
        a(f"*Last reviewed {node['last_reviewed']}.*")

    return "\n".join(o)


CLOUD_LABEL = {"aws": "AWS", "azure": "Azure", "gcp": "GCP", "oci": "OCI", "multi": "Multi"}
STATUS_LABEL = {"ga": "GA", "preview": "Preview", "workaround": "Workaround", "gap": "Gap"}


def properties(node: dict) -> dict:
    """Row properties. Names must match the Notion database schema exactly — a mismatched
    key is silently dropped rather than erroring, so keep this in step with the DDL."""
    ts = node.get("troubleshooting") or []
    silent = sum(1 for x in ts if x.get("silent"))

    # Tri-state on purpose: a node claiming true whose mechanism_note admits a caveat (new
    # Azure subscriptions landing in the Tenant Root Group) is Conditional, not Yes. Shared
    # with the page body via covers_future() so the two can never disagree again.
    covers, _ = covers_future(node)

    return {
        "Path": node["title"],
        "Node ID": node["id"],
        "Cloud": CLOUD_LABEL.get(node["cloud"], node["cloud"]),
        "Service": node["service"],
        "Transport": node["transport"],
        "Direction": node["direction"],
        "Status": STATUS_LABEL.get(node["status"], node["status"]),
        "Provenance": node["provenance"],
        "Covers future accounts": covers,
        "IaC": [a["kind"] for a in node.get("artifacts", [])],
        "Scopes": node.get("scopes", []),
        "Silent failures": silent,
        "Decisions": len(node.get("decision") or []),
        "Detections": len(node.get("detections_unlocked") or []),
        "Abstract integration": (node.get("abstract_integration") or {}).get("id", ""),
        "Surprise cost line": ((node.get("cost") or {}).get("surprise_line") or "").strip()[:1800],
        "date:Last reviewed:start": node.get("last_reviewed", ""),
        "Corpus file": f"https://github.com/IamABS3C/abstract-cloud-onboarding/blob/main/corpus/{node['cloud']}/{node['id']}.yml",
    }


# --------------------------------------------------------------------------- commands


def cmd_plan(only: str | None) -> int:
    reg = load_registry()
    paths = sorted(p for p in CORPUS.rglob("*.yml") if "_schema" not in p.parts)
    if only:
        paths = [p for p in paths if f"/{only}/" in str(p)]
    if not paths:
        print("no corpus nodes to plan")
        return 0

    preflight_assets([yaml.safe_load(x.read_text()) for x in paths])

    plan = {"generated": date.today().isoformat(),
            "hub_page_id": reg.get("hub_page_id"),
            "data_source_url": reg.get("data_source_url"),
            "actions": []}

    for p in paths:
        node = yaml.safe_load(p.read_text())
        nid = node["id"]
        md = render(node)
        h = content_hash(md)
        known = reg["nodes"].get(nid)

        if not known:
            action = "create"
        elif known.get("hash") != h:
            action = "update"
        else:
            action = "skip"

        plan["actions"].append({
            "node_id": nid,
            "action": action,
            "page_id": (known or {}).get("page_id"),
            "title": node["title"],
            "hash": h,
            "previous_hash": (known or {}).get("hash"),
            "properties": properties(node),
            "supersedes_notion": node.get("supersedes_notion", []),
            "merges_notion": node.get("merges_notion", []),
            "content": md,
        })

    DIST.mkdir(parents=True, exist_ok=True)
    out = DIST / "notion-plan.json"
    out.write_text(json.dumps(plan, indent=2) + "\n")

    counts: dict[str, int] = {}
    for a in plan["actions"]:
        counts[a["action"]] = counts.get(a["action"], 0) + 1
    print(f"wrote {out}")
    for k in ("create", "update", "skip"):
        if counts.get(k):
            print(f"  {k:7}: {counts[k]}")
    for a in plan["actions"]:
        if a["action"] != "skip":
            print(f"  {a['action']:7} {a['node_id']}  ({a['title']})")
    return 0


def cmd_record(node_id: str, page_id: str, url: str | None) -> int:
    reg = load_registry()
    plan_path = DIST / "notion-plan.json"
    h = None
    if plan_path.exists():
        for a in json.loads(plan_path.read_text())["actions"]:
            if a["node_id"] == node_id:
                h = a["hash"]
                break
    if h is None:
        print(f"warn: {node_id} not in the current plan; recording without a hash. "
              f"Re-run --plan before the next sync.")
    reg["nodes"][node_id] = {"page_id": page_id, "url": url, "hash": h,
                             "synced": date.today().isoformat()}
    save_registry(reg)
    print(f"recorded {node_id} -> {page_id}")
    return 0


def cmd_status() -> int:
    reg = load_registry()
    print(f"hub page   : {reg.get('hub_page_id') or '(not created)'}")
    print(f"database   : {reg.get('database_id') or '(not created)'}")
    print(f"data source: {reg.get('data_source_url') or '(not created)'}")
    print(f"synced nodes: {len(reg['nodes'])}")
    for nid, v in sorted(reg["nodes"].items()):
        print(f"  {nid:44} {v['page_id']}  synced {v.get('synced')}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", action="store_true")
    ap.add_argument("--only", help="restrict to one cloud directory, e.g. azure")
    ap.add_argument("--record", nargs=2, metavar=("NODE_ID", "PAGE_ID"))
    ap.add_argument("--url")
    ap.add_argument("--status", action="store_true")
    args = ap.parse_args()

    if args.plan:
        return cmd_plan(args.only)
    if args.record:
        return cmd_record(args.record[0], args.record[1], args.url)
    if args.status:
        return cmd_status()
    ap.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
