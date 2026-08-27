#!/usr/bin/env python3
"""Corpus gate. Nothing reaches a generated surface without passing this.

Checks, in order of how badly each one bites if skipped:

  1. Schema      — every node validates against corpus/_schema/node.schema.json.
  2. Provenance  — every artifact carries a tier, and any artifact claiming
                   validated/planned/deployed carries the command that was
                   actually run. This is the anti-fabrication gate: it is the
                   difference between a knowledgebase and a plausible-sounding
                   pile of YAML.
  3. Tier match  — exactly one artifact is `recommended`, and node.provenance equals
                   ITS tier. The headline claim describes the path we actually tell
                   customers to use — not the best-evidenced artifact (overclaim) and
                   not the worst (a validated template dragged down by a CLI snippet).
  4. Links       — referenced file paths exist; related_nodes resolve; decision
                   options point at a real node, a real artifact kind, or stop:.
  5. Citations   — a claim supported ONLY by community sources is flagged.
  6. Gaps        — status: gap requires a feature_request, so a gap becomes a
                   roadmap item rather than a dead end.
  7. Silent      — every node must declare at least one silent troubleshooting
                   entry or explicitly assert there are none. Silent failures
                   (zero events, no error) are the expensive ones.

Usage:
  python3 ci/validate_corpus.py            # validate all
  python3 ci/validate_corpus.py --strict   # warnings become failures
  python3 ci/validate_corpus.py corpus/azure/foo.yml
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("pyyaml required: pip3 install pyyaml")
try:
    import jsonschema
except ImportError:
    sys.exit("jsonschema required: pip3 install jsonschema")

REPO = Path(__file__).resolve().parent.parent
SCHEMA = REPO / "corpus" / "_schema" / "node.schema.json"
CORPUS = REPO / "corpus"

# Ordered worst -> best. node.provenance tracks the `recommended` artifact.
TIERS = ["cited", "schema-reviewed", "validated", "planned", "deployed"]
EVIDENCE_REQUIRED = {"validated", "planned", "deployed"}

errors: list[str] = []
warnings: list[str] = []


def err(node: str, msg: str) -> None:
    errors.append(f"{node}: {msg}")


def warn(node: str, msg: str) -> None:
    warnings.append(f"{node}: {msg}")


def load_nodes(paths: list[Path]) -> dict[str, tuple[Path, dict]]:
    nodes: dict[str, tuple[Path, dict]] = {}
    for p in paths:
        try:
            doc = yaml.safe_load(p.read_text())
        except Exception as e:                      # noqa: BLE001
            errors.append(f"{p}: YAML parse failed: {e}")
            continue
        if not isinstance(doc, dict):
            errors.append(f"{p}: top level is not a mapping")
            continue
        nid = doc.get("id") or p.stem
        if nid in nodes:
            errors.append(f"{p}: duplicate node id '{nid}' (also {nodes[nid][0]})")
            continue
        nodes[nid] = (p, doc)
    return nodes


def check_schema(nid: str, doc: dict, validator: jsonschema.Draft202012Validator) -> None:
    for e in sorted(validator.iter_errors(doc), key=lambda e: list(e.path)):
        loc = "/".join(str(x) for x in e.path) or "(root)"
        err(nid, f"schema: {loc}: {e.message}")


def check_provenance(nid: str, doc: dict) -> None:
    arts = doc.get("artifacts") or []
    tiers = []
    for i, a in enumerate(arts):
        kind = a.get("kind", f"artifact[{i}]")
        tier = a.get("provenance")
        if tier not in TIERS:
            err(nid, f"{kind}: provenance '{tier}' is not a known tier")
            continue
        tiers.append(tier)
        if tier in EVIDENCE_REQUIRED:
            v = a.get("validation")
            if not v:
                err(nid, f"{kind}: provenance '{tier}' claims execution but carries no validation evidence "
                         f"(command/result/run_on). Downgrade to schema-reviewed or run the tool.")
            else:
                for f in ("command", "result", "run_on"):
                    if not v.get(f):
                        err(nid, f"{kind}: validation.{f} is empty but provenance is '{tier}'")
                # Word-boundary match, NOT substring. A naive `"n/a" in res` check flagged the
                # legitimate result string for templates/subscriptio(n/a)ctivitylog.bicep —
                # the path itself contained the token. Placeholder detection has to be
                # precise or it trains people to ignore the gate.
                res = str(v.get("result", "")).lower()
                hits = [w for w in ("todo", "tbd", "n/a", "pending", "assume", "placeholder")
                        if re.search(r"(?<![a-z0-9/])" + re.escape(w) + r"(?![a-z0-9])", res)]
                if hits:
                    err(nid, f"{kind}: validation.result looks like a placeholder "
                             f"(matched {hits}): {v.get('result')!r}")

    declared = doc.get("provenance")
    rec = [a for a in arts if a.get("recommended")]
    if len(rec) != 1:
        err(nid, f"exactly one artifact must set recommended:true (found {len(rec)}). "
                 f"Name the path we actually tell customers to use — node.provenance tracks it.")
    elif declared in TIERS:
        rt = rec[0].get("provenance")
        if rt != declared:
            err(nid, f"node provenance '{declared}' does not match the recommended "
                     f"{rec[0].get('kind')} artifact's tier '{rt}'. The headline claim must "
                     f"describe the recommended path, not the best or worst artifact.")

    floor = min(tiers, key=TIERS.index) if tiers else None
    if floor and declared in TIERS and TIERS.index(floor) < TIERS.index(declared):
        weak = [a.get("kind") for a in arts if a.get("provenance") == floor]
        warn(nid, f"recommended path is '{declared}' but these artifacts are only '{floor}': "
                  f"{', '.join(weak)} — each renders its own tier, so this is fine, but confirm "
                  f"the weaker ones are labelled clearly enough for a reader lifting them.")


def check_links(nid: str, doc: dict, path: Path, all_ids: set[str]) -> None:
    valid_kinds = {a.get("kind") for a in (doc.get("artifacts") or [])}

    for a in doc.get("artifacts") or []:
        p = a.get("path")
        if p and not (REPO / p).exists():
            err(nid, f"{a.get('kind')}: path does not exist: {p}")
        xp = a.get("external_path")
        if xp and not Path(xp).exists():
            warn(nid, f"{a.get('kind')}: external_path not found on this machine: {xp}")

    for rel in doc.get("related_nodes") or []:
        if rel not in all_ids:
            warn(nid, f"related_nodes -> unknown node id '{rel}'")

    for q in doc.get("decision") or []:
        for o in q.get("options") or []:
            t = o.get("leads_to", "")
            if t.startswith("stop:") or t in valid_kinds or t in all_ids:
                continue
            warn(nid, f"decision '{q.get('id')}' option '{o.get('value')}' leads_to '{t}' "
                      f"which is neither a node id, an artifact kind on this node, nor stop:<reason>")


def check_citations(nid: str, doc: dict) -> None:
    refs = doc.get("references") or []
    if not refs:
        err(nid, "no references")
        return
    tiers = [r.get("tier") for r in refs]
    hard = {"vendor-doc", "vendor-release-note", "reference-architecture", "internal-repo"}
    if not (set(tiers) & hard):
        warn(nid, "no vendor-doc / release-note / reference-architecture / internal-repo reference — "
                  "this node rests entirely on community or blog sources")
    for r in refs:
        if not r.get("supports"):
            warn(nid, f"reference '{r.get('title')}' does not say which claim it supports")


def check_gaps(nid: str, doc: dict) -> None:
    if doc.get("status") == "gap" and not doc.get("feature_request"):
        err(nid, "status is 'gap' but there is no feature_request — a gap must become a roadmap item, "
                 "not a dead end")
    if doc.get("covers_future_accounts") and not doc.get("mechanism_note"):
        err(nid, "covers_future_accounts is true but mechanism_note is empty — name the mechanism "
                 "(policy assignment / StackSet auto-deploy / aggregated sink) or set it false")


# Licences that oblige us to carry an attribution string with the image.
ATTRIBUTION_REQUIRED = {"ms-screenshot-permission", "cc-by-4.0"}
VENDOR_SOURCED = {"vendor-console", "vendor-doc"}
MS_CREDIT = "Used with permission from Microsoft"


def check_images(nid: str, doc: dict, root: Path) -> None:
    """Enforce the image licence obligations.

    These are not stylistic rules. Microsoft grants screenshot use in documentation
    only while the image stays unaltered, uncropped, free of third-party content and
    identifiable individuals, and carries its credit line. Google excludes images from
    the CC-BY licence covering its documentation text. Every one of those conditions is
    voided by exactly the edit someone will reach for first -- cropping to the relevant
    blade, or blurring a tenant name. So the gate refuses it rather than trusting memory.
    """
    steps = doc.get("console_walkthrough") or []
    with_img = 0

    for s in steps:
        img = s.get("image")
        if not img:
            continue
        with_img += 1
        where = f"console_walkthrough step {s.get('step')}"
        src_kind = img.get("source")
        lic = img.get("license")

        fp = root / img["path"]
        if not fp.exists():
            err(nid, f"{where}: image path does not exist: {img['path']}")

        if lic == "unlicensed":
            err(nid, f"{where}: license is 'unlicensed' -- it cannot be published. "
                     f"Replace it with an own-capture, a drawio render, or a deep link.")

        if src_kind in VENDOR_SOURCED:
            if img.get("altered"):
                err(nid, f"{where}: altered:true on a {src_kind} image. Cropping, blurring "
                         f"and de-branding all void the permission that makes the image "
                         f"usable at all. Resize only, or capture our own.")
            if img.get("tenant_safe") is not True:
                err(nid, f"{where}: {src_kind} image must set tenant_safe:true -- the frame "
                         f"must show no tenant/subscription/project/account name and no "
                         f"person. Vendor terms forbid third-party content and identifiable "
                         f"individuals, and our own rule forbids tenant identifiers in "
                         f"customer-facing output.")

        if lic in ATTRIBUTION_REQUIRED and not (img.get("credit") or "").strip():
            err(nid, f"{where}: license '{lic}' requires an attribution string but 'credit' "
                     f"is empty. The credit is a per-image obligation, not a page footer.")

        if lic == "ms-screenshot-permission" and MS_CREDIT not in (img.get("credit") or ""):
            err(nid, f"{where}: a Microsoft screenshot must carry the exact credit "
                     f"'{MS_CREDIT}'.")

    if steps and with_img == 0:
        warn(nid, f"console_walkthrough has {len(steps)} steps and no images -- a GUI "
                  f"walkthrough with no visuals is the weakest form of this section. "
                  f"See docs/IMAGE-SOURCING.md for the sources that carry no licence risk.")


def _readability(text: str) -> tuple[float, int]:
    # Split on line breaks as well as terminal punctuation. A markdown bullet
    # rarely ends in a full stop, so splitting on [.!?] alone treats an entire
    # list as ONE sentence -- which flagged a well-structured lens at 72 words
    # and would have had me "fix" prose that was already fine. Measure the
    # prose, not the formatting.
    lines = [ln for ln in text.split("\n") if ln.strip()]
    sents = [x for ln in lines for x in re.split(r"(?<=[.!?])\s+", ln) if x.strip()]
    words = re.findall(r"[A-Za-z']+", text)
    if not sents or not words:
        return 0.0, 0
    syl = sum(max(1, len(re.findall(r"[aeiouy]+", w.lower()))) for w in words)
    grade = 0.39 * len(words) / len(sents) + 11.8 * syl / len(words) - 15.59
    return grade, max(len(x.split()) for x in sents)


def check_readability(nid: str, doc: dict) -> None:
    """The review lenses were the least readable prose in the repo by a wide margin.

    Measured 2026-08-26: mean grade 15.2 across 35 lenses against 10.3 for
    troubleshooting, with three lenses over 20 and one 86-word sentence, every
    lens a single unbroken paragraph. Density is not the problem -- these carry
    the hardest-won facts in the corpus. Presenting them as a wall is.
    """
    for lens, txt in (doc.get("reviews") or {}).items():
        if not isinstance(txt, str) or len(txt.split()) < 40:
            continue
        grade, longest = _readability(txt)
        if grade > 17:
            warn(nid, f"reviews.{lens} reads at grade {grade:.1f} — the house standard is "
                      f"troubleshooting's ~10.3. Break the sentences, not the content.")
        if longest > 45:
            warn(nid, f"reviews.{lens} has a {longest}-word sentence. Split it.")
        if "\n" not in txt.strip():
            warn(nid, f"reviews.{lens} is one unbroken paragraph ({len(txt.split())} words). "
                      f"Lead with the claim, then break out the specifics.")


def check_silent(nid: str, doc: dict) -> None:
    ts = doc.get("troubleshooting") or []
    if not ts:
        warn(nid, "no troubleshooting entries")
        return
    if not any(t.get("silent") for t in ts):
        warn(nid, "no troubleshooting entry marked silent:true — confirm there really is no "
                  "zero-events-without-an-error failure mode for this path")
        return
    # A flag carried by most entries stops being a signal. Sorting silent-first only
    # helps a reader if it is a minority -- at 29 of 52 the sort discriminated nothing.
    n = sum(1 for t in ts if t.get("silent"))
    if n * 2 > len(ts):
        warn(nid, f"{n} of {len(ts)} troubleshooting entries are silent:true ({100*n//len(ts)}%). "
                  f"Above half the flag no longer sorts anything useful — re-check each against "
                  f"the rule: zero events AND no error signal anywhere. A wrong-but-discoverable "
                  f"result, a state the platform reports, or a cost surprise is not silent.")


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    strict = "--strict" in sys.argv

    if not SCHEMA.exists():
        sys.exit(f"schema not found: {SCHEMA}")
    schema = json.loads(SCHEMA.read_text())
    validator = jsonschema.Draft202012Validator(schema)

    paths = ([Path(a) for a in args] if args
             else sorted(p for p in CORPUS.rglob("*.yml") if "_schema" not in p.parts))
    if not paths:
        print("no corpus nodes yet — nothing to validate")
        return 0

    nodes = load_nodes(paths)
    all_ids = set(nodes)

    for nid, (path, doc) in sorted(nodes.items()):
        check_schema(nid, doc, validator)
        check_provenance(nid, doc)
        check_links(nid, doc, path, all_ids)
        check_citations(nid, doc)
        check_gaps(nid, doc)
        check_silent(nid, doc)
        check_images(nid, doc, REPO)
        check_readability(nid, doc)

    for w in warnings:
        print(f"warn : {w}")
    for e in errors:
        print(f"FAIL : {e}")

    print(f"\n{len(nodes)} node(s) checked, {len(errors)} error(s), {len(warnings)} warning(s)")
    if errors or (strict and warnings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
