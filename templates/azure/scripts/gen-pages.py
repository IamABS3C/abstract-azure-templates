#!/usr/bin/env python3
"""
Abstract Security - GitHub Pages generator.

Emits docs/index.html from solutions/solution.manifest.json. The site is therefore
never hand-maintained: adding a template or renaming the repo is a manifest edit
plus a re-run, and a stale deploy button on the public site becomes impossible.

  python3 scripts/gen-pages.py            # write ../docs/index.html
  python3 scripts/gen-pages.py --check    # CI: fail if the site is stale
  python3 scripts/gen-pages.py --out X    # write elsewhere

Design constraints, all deliberate:
  * ONE self-contained file. No build step, no bundler, no external JS. GitHub Pages
    serves it as-is and it works offline.
  * Brand-exact: Abstract colours (#FF216B pink, #01e69d teal), Barlow + Barlow Semi
    Condensed + JetBrains Mono.
  * Light AND dark. The previous site was dark-only; a customer projecting it in a
    bright room could not read it. prefers-color-scheme plus a manual toggle.
  * Accessible: semantic landmarks, visible focus rings, aria-pressed on filters,
    contrast that holds in both themes, and it degrades to a readable document with
    JavaScript disabled.
"""
from __future__ import annotations

import argparse
import html
import json
import sys
import urllib.parse
from pathlib import Path

SOLUTION_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = SOLUTION_ROOT / "solution.manifest.json"
DEFAULT_OUT = SOLUTION_ROOT.parent / "docs" / "index.html"

SCOPE_LABEL = {
    "resourceGroup": "Resource group",
    "subscription": "Subscription",
    "managementGroup": "Management group",
    "tenant": "Tenant",
}

CATEGORIES = [
    ("source", "Sources", "Abstract reads <em>from</em> Azure",
     "Get Microsoft telemetry into the pipeline. Deploy the Event Hub source first — every other source template consumes its outputs."),
    ("governance", "Governance", "Onboard the whole estate",
     "Stop configuring diagnostic settings one subscription at a time. Assign once at a management group; current and future subscriptions onboard themselves."),
    ("identity", "Identity", "App registrations for Graph &amp; M365",
     "Event Hub collection needs no app registration. These cover the other source set: Microsoft Graph and the Microsoft 365 unified audit log."),
    ("destination", "Destinations", "Abstract writes <em>to</em> Azure",
     "Send enriched, normalized, reduced output back into Azure."),
]

CLI_BY_SCOPE = {
    "resourceGroup": "az deployment group create -g &lt;rg&gt; \\\n  --template-file {bicep}",
    "subscription": "az deployment sub create -l &lt;region&gt; \\\n  --template-file {bicep}",
    "managementGroup": "az deployment mg create -m &lt;mg-id&gt; -l &lt;region&gt; \\\n  --template-file {bicep}",
    "tenant": "az deployment tenant create -l &lt;region&gt; \\\n  --template-file {bicep}",
}


def enc(url: str) -> str:
    return urllib.parse.quote(url, safe="")


def raw_url(repo: dict, rel: str) -> str:
    return (f"https://raw.githubusercontent.com/{repo['owner']}/{repo['name']}/"
            f"{repo['branch']}/{repo['solutionPath']}/{rel}")


def portal_url(manifest: dict, tpl: dict, gov: bool = False) -> str:
    repo = manifest["repo"]
    base = manifest["portal"]["government" if gov else "public"]
    arm = enc(raw_url(repo, f"{tpl['path']}.azuredeploy.json"))
    if tpl["ui"] == "createUiDefinition":
        seg = f"/createUIDefinitionUri/{enc(raw_url(repo, tpl['path'] + '.createUiDefinition.json'))}"
    elif tpl["ui"] == "uiFormDefinition":
        seg = f"/uiFormDefinitionUri/{enc(raw_url(repo, tpl['path'] + '.uiFormDefinition.json'))}"
    else:
        seg = ""
    return f"{base}/#create/Microsoft.Template/uri/{arm}{seg}"


def gh_url(repo: dict, rel: str) -> str:
    return (f"https://github.com/{repo['owner']}/{repo['name']}/blob/"
            f"{repo['branch']}/{repo['solutionPath']}/{rel}")


def esc(s: str) -> str:
    return html.escape(s, quote=True)


def card(manifest: dict, tpl: dict) -> str:
    repo = manifest["repo"]
    scope = tpl["scope"]
    ui_label = "Wizard" if tpl["ui"] == "createUiDefinition" else "Form&nbsp;view"
    badges = [f'<span class="badge scope-{scope}">{SCOPE_LABEL[scope]}</span>',
              f'<span class="badge ui">{ui_label}</span>']
    if tpl.get("recommended"):
        badges.insert(0, '<span class="badge rec">Recommended</span>')
    if tpl.get("deployFirst"):
        badges.insert(0, '<span class="badge first">Deploy first</span>')

    cli = CLI_BY_SCOPE[scope].format(bicep=f"solutions/{tpl['path']}.bicep")

    # Form-view buttons rely on uiFormDefinitionUri, which the portal accepts but
    # Microsoft does not document for Deploy-to-Azure links. Say so, and give the
    # documented template-spec route, rather than letting a customer discover it.
    spec_note = ""
    if tpl["ui"] == "uiFormDefinition":
        name = tpl["path"].split("/")[-1]
        spec_note = (
            '\n          <p class="specnote">The wizard button uses '
            '<code>uiFormDefinitionUri</code> — accepted by the portal but not in '
            "Microsoft's documented deploy-button format. The documented route to the "
            "same wizard is a template spec:</p>\n          <pre><code>"
            f"az ts create --name {name} --version 1.0 -g &lt;rg&gt; -l &lt;region&gt; \\\n"
            f"  --template-file solutions/{tpl['path']}.azuredeploy.json \\\n"
            f"  --ui-form-definition solutions/{tpl['path']}.uiFormDefinition.json"
            "</code></pre>")

    meta_rows = []
    if tpl.get("prerequisite"):
        meta_rows.append(
            f'<p class="prereq"><strong>Prerequisite</strong> {esc(tpl["prerequisite"])}</p>')
    if tpl.get("outputsNeededNext"):
        outs = ", ".join(f"<code>{esc(o)}</code>" for o in tpl["outputsNeededNext"])
        meta_rows.append(f'<p class="outs"><strong>Outputs you need next</strong> {outs}</p>')
    if tpl.get("notes"):
        meta_rows.append(f'<p class="note">{esc(tpl["notes"])}</p>')

    return f"""      <article class="card" data-category="{tpl['category']}" data-scope="{scope}">
        <div class="card-badges">{''.join(badges)}</div>
        <h3>{esc(tpl['title'])}</h3>
        <p class="summary">{esc(tpl['summary'])}</p>
        {''.join(meta_rows)}
        <div class="actions">
          <a class="btn primary" href="{portal_url(manifest, tpl)}" target="_blank" rel="noopener">
            Deploy to Azure
          </a>
          <a class="btn ghost" href="{portal_url(manifest, tpl, gov=True)}" target="_blank" rel="noopener">
            Azure&nbsp;Gov
          </a>
          <a class="btn ghost" href="{gh_url(repo, tpl['path'] + '.bicep')}" target="_blank" rel="noopener">
            Source
          </a>
        </div>
        <details class="cli">
          <summary>Deploy from the CLI instead</summary>
          <pre><code>{cli}</code></pre>{spec_note}
        </details>
      </article>
"""


def build(manifest: dict) -> str:
    repo = manifest["repo"]
    tpls = sorted(manifest["templates"], key=lambda t: t["order"])
    n_tpl = len(tpls)
    n_scopes = len({t["scope"] for t in tpls})

    sections = []
    for key, name, tagline, blurb in CATEGORIES:
        group = [t for t in tpls if t["category"] == key]
        if not group:
            continue
        cards = "".join(card(manifest, t) for t in group)
        sections.append(f"""    <section class="cat" id="{key}">
      <header class="cat-head">
        <h2>{name} <span class="tagline">{tagline}</span></h2>
        <p>{blurb}</p>
      </header>
      <div class="grid">
{cards}      </div>
    </section>
""")

    doc_cards = "".join(
        f"""        <a class="doc" href="{gh_url(repo, d['path'])}" target="_blank" rel="noopener">
          <h4>{esc(d['title'])}</h4>
          <p>{esc(d['summary'])}</p>
        </a>
""" for d in manifest.get("docs", []))

    script_rows = "".join(
        f"""          <tr>
            <td><code>{esc(s['path'])}</code></td>
            <td>{esc(s['summary'])}</td>
          </tr>
""" for s in manifest.get("scripts", []))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>{esc(manifest['name'])} · Deployment Console</title>
<meta name="description" content="{esc(manifest['description'])}" />
<meta name="color-scheme" content="dark light" />
<meta property="og:title" content="{esc(manifest['name'])}" />
<meta property="og:description" content="{esc(manifest['description'])}" />
<meta property="og:type" content="website" />
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link href="https://fonts.googleapis.com/css2?family=Barlow:ital,wght@0,400;0,500;0,600;1,500&amp;family=Barlow+Semi+Condensed:wght@500;600;700&amp;family=JetBrains+Mono:wght@400;500;700&amp;display=swap" rel="stylesheet" />
<!--
  GENERATED FILE - do not hand-edit.
  Source of truth : solutions/solution.manifest.json
  Generator       : solutions/scripts/gen-pages.py
  Regenerate      : python3 solutions/scripts/gen-pages.py
  CI fails if this file is stale, so edits here would be reverted anyway.
-->
<style>
  :root{{
    --pink:#FF216B; --mid:#E8005D; --deep:#C2004C;
    --teal:#01e69d; --amber:#f5c61e; --blue:#2e9bf0;
    --display:"Barlow Semi Condensed",system-ui,sans-serif;
    --body:"Barlow",system-ui,sans-serif;
    --mono:"JetBrains Mono",ui-monospace,monospace;
    --ease:cubic-bezier(.22,.61,.36,1);
    --radius:14px;
  }}
  /* Dark is the default (brand), light is a first-class alternative - the old site
     was dark-only and unreadable when projected in a lit room. */
  :root, :root[data-theme="dark"]{{
    --bg:#060608; --bg2:#0b0b10; --panel:#101016; --panel2:#15151d;
    --line:#24242f; --line2:#33333f;
    --text:#f4f4f7; --muted:#a4a4b2; --dim:#74748a;
    --shadow:0 18px 50px rgba(0,0,0,.55);
    --code-bg:rgba(1,230,157,.08);
  }}
  :root[data-theme="light"]{{
    --bg:#fbfbfd; --bg2:#f3f3f7; --panel:#ffffff; --panel2:#f7f7fb;
    --line:#e3e3ec; --line2:#cfcfdd;
    --text:#14141a; --muted:#55555f; --dim:#7b7b88;
    --shadow:0 14px 40px rgba(20,20,40,.10);
    --code-bg:rgba(0,120,80,.08);
  }}
  @media (prefers-color-scheme: light){{
    :root:not([data-theme]){{
      --bg:#fbfbfd; --bg2:#f3f3f7; --panel:#ffffff; --panel2:#f7f7fb;
      --line:#e3e3ec; --line2:#cfcfdd;
      --text:#14141a; --muted:#55555f; --dim:#7b7b88;
      --shadow:0 14px 40px rgba(20,20,40,.10);
      --code-bg:rgba(0,120,80,.08);
    }}
  }}

  *{{box-sizing:border-box}}
  html{{scroll-behavior:smooth}}
  body{{
    margin:0; background:var(--bg); color:var(--text);
    font-family:var(--body); line-height:1.62; -webkit-font-smoothing:antialiased;
  }}
  h1,h2,h3,h4{{font-family:var(--display); font-weight:700; letter-spacing:.3px; line-height:1.08; margin:0}}
  a{{color:var(--pink); text-decoration:none}}
  a:hover{{text-decoration:underline}}
  code{{font-family:var(--mono); font-size:.9em; color:var(--teal); background:var(--code-bg); padding:1px 6px; border-radius:5px}}
  :root[data-theme="light"] code{{color:#00694a}}
  @media (prefers-color-scheme: light){{ :root:not([data-theme]) code{{color:#00694a}} }}
  pre{{margin:0; overflow-x:auto}}
  pre code{{display:block; padding:12px 14px; background:var(--panel2); color:var(--text);
    border:1px solid var(--line); border-radius:10px; font-size:12.5px; line-height:1.7}}
  ::selection{{background:var(--pink); color:#fff}}
  /* Visible focus everywhere - keyboard users were previously stranded. */
  a:focus-visible, button:focus-visible, summary:focus-visible{{
    outline:2px solid var(--teal); outline-offset:3px; border-radius:6px}}
  .skip{{position:absolute; left:-9999px}}
  .skip:focus{{left:12px; top:12px; z-index:100; background:var(--panel);
    padding:10px 16px; border:1px solid var(--pink); border-radius:8px}}

  .wrap{{max-width:1180px; margin:0 auto; padding:0 22px}}

  header.site{{
    position:sticky; top:0; z-index:50;
    background:color-mix(in srgb, var(--bg) 88%, transparent);
    backdrop-filter:blur(12px); border-bottom:1px solid var(--line);
  }}
  .bar{{display:flex; align-items:center; gap:16px; height:62px}}
  .wordmark{{font-family:var(--display); font-weight:700; font-size:19px; letter-spacing:2.2px;
    text-transform:uppercase; color:var(--text); white-space:nowrap}}
  .wordmark b{{color:var(--pink)}}
  .bar nav{{margin-left:auto; display:flex; gap:6px; align-items:center; flex-wrap:wrap}}
  .bar nav a{{font-family:var(--mono); font-size:12px; color:var(--muted); padding:7px 11px;
    border-radius:8px; white-space:nowrap}}
  .bar nav a:hover{{color:var(--text); background:var(--panel2); text-decoration:none}}
  .theme{{font-family:var(--mono); font-size:12px; cursor:pointer;
    background:var(--panel2); color:var(--muted); border:1px solid var(--line2);
    padding:7px 12px; border-radius:8px}}
  .theme:hover{{color:var(--text); border-color:var(--pink)}}

  .hero{{padding:76px 0 44px; border-bottom:1px solid var(--line);
    background:radial-gradient(1000px 420px at 12% -12%, rgba(255,33,107,.13), transparent 62%),
               radial-gradient(760px 340px at 88% -18%, rgba(1,230,157,.09), transparent 60%)}}
  .eyebrow{{font-family:var(--mono); font-size:11.5px; letter-spacing:2.6px; text-transform:uppercase;
    color:var(--teal); margin-bottom:16px}}
  .hero h1{{font-size:clamp(36px,6.4vw,68px); max-width:20ch}}
  .hero h1 em{{font-style:normal; color:var(--pink)}}
  .lede{{font-size:clamp(16px,1.7vw,19.5px); color:var(--muted); max-width:66ch; margin:20px 0 0}}
  .stats{{display:flex; gap:36px; flex-wrap:wrap; margin-top:34px}}
  .stat b{{display:block; font-family:var(--display); font-size:34px; color:var(--text); line-height:1}}
  .stat span{{font-family:var(--mono); font-size:11px; letter-spacing:1.6px; text-transform:uppercase; color:var(--dim)}}

  .filters{{display:flex; gap:8px; flex-wrap:wrap; padding:26px 0 4px; align-items:center}}
  .filters .lbl{{font-family:var(--mono); font-size:11px; letter-spacing:1.6px;
    text-transform:uppercase; color:var(--dim); margin-right:4px}}
  .chip{{font-family:var(--mono); font-size:12px; cursor:pointer;
    background:transparent; color:var(--muted); border:1px solid var(--line2);
    padding:7px 13px; border-radius:999px; transition:all .18s var(--ease)}}
  .chip:hover{{color:var(--text); border-color:var(--pink)}}
  .chip[aria-pressed="true"]{{background:var(--pink); border-color:var(--pink); color:#fff}}

  .cat{{padding:44px 0 8px}}
  .cat-head{{margin-bottom:24px; max-width:78ch}}
  .cat-head h2{{font-size:clamp(24px,3vw,33px)}}
  .cat-head .tagline{{font-family:var(--body); font-weight:400; font-size:.56em;
    color:var(--dim); letter-spacing:0; margin-left:10px}}
  .cat-head p{{color:var(--muted); margin:10px 0 0; font-size:15px}}

  .grid{{display:grid; gap:20px; grid-template-columns:repeat(auto-fit,minmax(340px,1fr))}}
  .card{{background:var(--panel); border:1px solid var(--line); border-radius:var(--radius);
    padding:22px; display:flex; flex-direction:column; gap:12px;
    transition:transform .2s var(--ease), border-color .2s var(--ease), box-shadow .2s var(--ease)}}
  .card:hover{{transform:translateY(-3px); border-color:var(--line2); box-shadow:var(--shadow)}}
  .card h3{{font-size:20px}}
  .card-badges{{display:flex; gap:6px; flex-wrap:wrap}}
  .badge{{font-family:var(--mono); font-size:10px; letter-spacing:1.1px; text-transform:uppercase;
    padding:3px 9px; border-radius:999px; border:1px solid var(--line2); color:var(--muted)}}
  .badge.rec{{background:var(--pink); border-color:var(--pink); color:#fff}}
  .badge.first{{background:rgba(1,230,157,.14); border-color:var(--teal); color:var(--teal)}}
  .badge.ui{{color:var(--blue); border-color:rgba(46,155,240,.4)}}
  .badge.scope-tenant, .badge.scope-managementGroup{{color:var(--amber); border-color:rgba(245,198,30,.4)}}
  .summary{{color:var(--muted); font-size:14.5px; margin:0}}
  .card .note, .card .prereq, .card .outs{{
    font-size:13px; margin:0; color:var(--dim); border-left:2px solid var(--line2); padding-left:11px}}
  .card .prereq{{border-left-color:var(--amber)}}
  .card .prereq strong{{color:var(--amber); display:block; font-size:10.5px;
    font-family:var(--mono); letter-spacing:1.1px; text-transform:uppercase}}
  .card .outs strong{{color:var(--teal); display:block; font-size:10.5px;
    font-family:var(--mono); letter-spacing:1.1px; text-transform:uppercase}}

  .actions{{display:flex; gap:8px; flex-wrap:wrap; margin-top:auto; padding-top:6px}}
  .btn{{font-family:var(--mono); font-size:12px; padding:9px 15px; border-radius:9px;
    border:1px solid var(--line2); color:var(--text); transition:all .18s var(--ease)}}
  .btn:hover{{text-decoration:none}}
  .btn.primary{{background:var(--pink); border-color:var(--pink); color:#fff; font-weight:500}}
  .btn.primary:hover{{background:var(--mid); border-color:var(--mid)}}
  .btn.ghost:hover{{border-color:var(--pink); color:var(--pink)}}
  details.cli{{margin-top:2px}}
  details.cli summary{{font-family:var(--mono); font-size:11.5px; color:var(--dim);
    cursor:pointer; padding:4px 0}}
  details.cli summary:hover{{color:var(--text)}}
  details.cli pre{{margin-top:8px}}
  details.cli .specnote{{font-size:12.5px; color:var(--dim); margin:10px 0 0; line-height:1.55}}

  .band{{border-top:1px solid var(--line); background:var(--bg2); padding:52px 0}}
  .band h2{{font-size:clamp(22px,2.6vw,30px); margin-bottom:8px}}
  .band > .wrap > p{{color:var(--muted); max-width:74ch}}
  .docs{{display:grid; gap:16px; grid-template-columns:repeat(auto-fit,minmax(300px,1fr)); margin-top:26px}}
  .doc{{background:var(--panel); border:1px solid var(--line); border-radius:var(--radius);
    padding:20px; color:var(--text); transition:all .2s var(--ease)}}
  .doc:hover{{border-color:var(--pink); transform:translateY(-2px); text-decoration:none}}
  .doc h4{{font-size:17px; margin-bottom:8px}}
  .doc p{{color:var(--muted); font-size:14px; margin:0}}

  table{{width:100%; border-collapse:collapse; margin-top:22px; font-size:14px}}
  th,td{{text-align:left; padding:11px 12px; border-bottom:1px solid var(--line); vertical-align:top}}
  th{{font-family:var(--mono); font-size:10.5px; letter-spacing:1.4px; text-transform:uppercase; color:var(--dim)}}
  td:first-child{{white-space:nowrap}}
  .tablewrap{{overflow-x:auto}}

  .callout{{border:1px solid var(--line2); border-left:3px solid var(--amber);
    background:var(--panel); border-radius:10px; padding:18px 20px; margin-top:24px}}
  .callout h4{{font-size:15px; margin-bottom:8px; color:var(--amber)}}
  .callout p{{color:var(--muted); font-size:14px; margin:0 0 8px}}
  .callout p:last-child{{margin-bottom:0}}

  ol.steps{{counter-reset:s; list-style:none; padding:0; margin:26px 0 0; display:grid; gap:14px}}
  ol.steps li{{counter-increment:s; position:relative; padding-left:46px; color:var(--muted); font-size:14.5px}}
  ol.steps li::before{{content:counter(s); position:absolute; left:0; top:-2px;
    width:30px; height:30px; border-radius:50%; display:grid; place-items:center;
    font-family:var(--mono); font-size:12px; color:var(--pink);
    border:1px solid var(--pink); background:var(--panel)}}
  ol.steps strong{{color:var(--text); display:block; font-size:15px}}

  footer.site{{border-top:1px solid var(--line); padding:34px 0; color:var(--dim); font-size:13px}}
  footer.site .row{{display:flex; gap:18px; flex-wrap:wrap; align-items:center}}
  footer.site .row > :last-child{{margin-left:auto}}

  @media (max-width:720px){{
    .bar{{height:auto; padding:12px 0; flex-wrap:wrap}}
    .bar nav{{width:100%; margin-left:0}}
    .hero{{padding:52px 0 34px}}
    .stats{{gap:24px}}
  }}
  @media (prefers-reduced-motion: reduce){{
    *{{transition:none !important; animation:none !important}}
    html{{scroll-behavior:auto}}
  }}
</style>
</head>
<body>
<a class="skip" href="#main">Skip to content</a>

<header class="site">
  <div class="wrap bar">
    <span class="wordmark">Abstract<b>.</b>Security</span>
    <nav aria-label="Sections">
      <a href="#source">Sources</a>
      <a href="#governance">Governance</a>
      <a href="#identity">Identity</a>
      <a href="#destination">Destinations</a>
      <a href="#how">How to deploy</a>
      <a href="#docs">Docs</a>
      <button class="theme" id="theme" type="button" aria-label="Toggle light and dark theme">◐ Theme</button>
    </nav>
  </div>
</header>

<section class="hero">
  <div class="wrap">
    <p class="eyebrow">Azure &amp; Microsoft Sentinel · v{esc(manifest['version'])}</p>
    <h1>Deploy Abstract into Azure, <em>properly</em>.</h1>
    <p class="lede">{esc(manifest['description'])}</p>
    <div class="stats">
      <div class="stat"><b>{n_tpl}</b><span>Templates</span></div>
      <div class="stat"><b>{n_scopes}</b><span>Deployment scopes</span></div>
      <div class="stat"><b>100%</b><span>With a portal wizard</span></div>
      <div class="stat"><b>ARM + Bicep</b><span>Every template</span></div>
    </div>
  </div>
</section>

<main id="main">
  <div class="wrap">
    <div class="filters" role="group" aria-label="Filter templates by scope">
      <span class="lbl">Filter by scope</span>
      <button class="chip" type="button" data-filter="all" aria-pressed="true">All</button>
      <button class="chip" type="button" data-filter="resourceGroup" aria-pressed="false">Resource group</button>
      <button class="chip" type="button" data-filter="subscription" aria-pressed="false">Subscription</button>
      <button class="chip" type="button" data-filter="managementGroup" aria-pressed="false">Management group</button>
      <button class="chip" type="button" data-filter="tenant" aria-pressed="false">Tenant</button>
    </div>

{''.join(sections)}  </div>

  <section class="band" id="how">
    <div class="wrap">
      <h2>How to deploy</h2>
      <p>The shortest path from nothing to Azure telemetry flowing into Abstract. Every step
         has a button above and a CLI equivalent on each card.</p>
      <ol class="steps">
        <li><strong>Event Hub estate, first</strong>
            Everything else consumes its outputs — note <code>abstractDiagnosticsAuthRuleId</code>
            and <code>eventHubNames</code>. One namespace per region that holds regional resources.</li>
        <li><strong>Onboard the estate in report-only mode</strong>
            The governance pack starts as <code>AuditIfNotExists</code>: it changes nothing and
            tells you exactly which subscriptions and resources would be collected.</li>
        <li><strong>Grant, then backfill</strong>
            Give the policy identities access to the hub, then run a remediation task —
            <code>DeployIfNotExists</code> never touches resources you already own.</li>
        <li><strong>Identity telemetry</strong>
            One tenant-scope command covers the whole organisation. No Azure Policy can reach
            Entra ID, because there is no per-subscription object to evaluate.</li>
        <li><strong>Then destinations</strong>
            Route Abstract's enriched output to Sentinel, an Event Hub, or both.</li>
      </ol>

      <div class="callout">
        <h4>Three things that decide whether this works</h4>
        <p><strong>The region rule.</strong> Azure Monitor rejects a diagnostic setting whose
          Event Hub is in a different region from the monitored resource. One namespace per
          region. Activity Log, Defender for Cloud and Entra ID are exempt — they are not regional.</p>
        <p><strong>Remediation is not optional.</strong> Policy fires on create or update, so your
          existing estate stays dark until a remediation task backfills it.</p>
        <p><strong>New subscriptions must land in the right management group.</strong> They default
          to Tenant Root, not your group — set the tenant's default management group or they
          silently miss the policy.</p>
      </div>
    </div>
  </section>

  <section class="band" id="docs">
    <div class="wrap">
      <h2>Deep references</h2>
      <p>Both documents distinguish what was <em>tested against a live tenant</em> from what was
         read in documentation, and name the bugs that testing exposed.</p>
      <div class="docs">
{doc_cards}      </div>

      <h2 style="margin-top:44px">Scripts</h2>
      <p>The parts no template can do — and the guardrails that keep the templates honest.</p>
      <div class="tablewrap">
        <table>
          <thead><tr><th scope="col">Script</th><th scope="col">What it does</th></tr></thead>
          <tbody>
{script_rows}          </tbody>
        </table>
      </div>
    </div>
  </section>
</main>

<footer class="site">
  <div class="wrap row">
    <span>Abstract Security — the security data pipeline platform.</span>
    <a href="https://github.com/{repo['owner']}/{repo['name']}" target="_blank" rel="noopener">Repository</a>
    <a href="https://docs.abstractsecurity.app" target="_blank" rel="noopener">Documentation</a>
    <a href="https://abstract.security" target="_blank" rel="noopener">abstract.security</a>
  </div>
</footer>

<script>
  // Theme: honour the OS by default, remember an explicit choice.
  (function () {{
    var KEY = 'abstract-theme';
    var root = document.documentElement;
    try {{
      var saved = localStorage.getItem(KEY);
      if (saved) root.setAttribute('data-theme', saved);
    }} catch (e) {{ /* private browsing - fall back to prefers-color-scheme */ }}

    document.getElementById('theme').addEventListener('click', function () {{
      var current = root.getAttribute('data-theme');
      if (!current) {{
        current = window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
      }}
      var next = current === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      try {{ localStorage.setItem(KEY, next); }} catch (e) {{ /* ignore */ }}
    }});
  }})();

  // Scope filter. Cards are plain HTML, so with JS disabled everything stays visible.
  (function () {{
    var chips = Array.prototype.slice.call(document.querySelectorAll('.chip'));
    var cards = Array.prototype.slice.call(document.querySelectorAll('.card'));
    var cats  = Array.prototype.slice.call(document.querySelectorAll('.cat'));

    chips.forEach(function (chip) {{
      chip.addEventListener('click', function () {{
        var want = chip.getAttribute('data-filter');
        chips.forEach(function (c) {{
          c.setAttribute('aria-pressed', String(c === chip));
        }});
        cards.forEach(function (card) {{
          var show = want === 'all' || card.getAttribute('data-scope') === want;
          card.style.display = show ? '' : 'none';
        }});
        // Hide a category heading when it has nothing left to show.
        cats.forEach(function (cat) {{
          var visible = cat.querySelectorAll('.card:not([style*="none"])').length;
          cat.style.display = visible ? '' : 'none';
        }});
      }});
    }});
  }})();
</script>
</body>
</html>
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if the generated site differs from the file on disk")
    args = ap.parse_args()

    manifest = json.loads(MANIFEST.read_text())
    site = build(manifest)

    if args.check:
        if not args.out.exists():
            print(f"::error::{args.out} does not exist - run gen-pages.py", file=sys.stderr)
            return 1
        if args.out.read_text() != site:
            print(f"::error::{args.out} is STALE. "
                  f"Run: python3 solutions/scripts/gen-pages.py", file=sys.stderr)
            return 1
        print(f"up to date: {args.out}")
        return 0

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(site)
    print(f"wrote {args.out} ({len(site):,} bytes, {len(manifest['templates'])} templates)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
