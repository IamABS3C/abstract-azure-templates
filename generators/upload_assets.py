#!/usr/bin/env python3
"""Upload a repo asset to Notion and record its hosted URL in the registry.

Why this exists: `abstract-cloud-onboarding` has no git remote, so a local PNG has
no public URL, and Notion's `create-attachment` source_url path needs one. The
`create-file-upload` path takes a LOCAL file instead, which is why images are
possible here at all.

This script prepares the upload and prints the exact multipart POST to run. The
POST itself is executed by the caller (the MCP connector mints the short-lived
upload URL), then `--record` writes the resulting URL into the registry so
`gen_notion.py` can resolve `assets/...` paths to something that actually renders.
"""
import json
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
REGISTRY = REPO / "generators" / "notion-registry.json"


def load() -> dict:
    return json.loads(REGISTRY.read_text()) if REGISTRY.exists() else {}


def save(reg: dict) -> None:
    REGISTRY.write_text(json.dumps(reg, indent=2, sort_keys=True) + "\n")


def record(rel: str, url: str) -> None:
    reg = load()
    reg.setdefault("assets", {})[rel] = url
    save(reg)
    print(f"recorded {rel}\n      -> {url}")


def main() -> int:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        print("usage: upload_assets.py <asset-path> [--record <notion-url>]")
        print("       upload_assets.py --list")
        return 2

    if args[0] == "--list":
        for k, v in sorted(load().get("assets", {}).items()):
            print(f"{k}\n  -> {v}")
        return 0

    rel = args[0]
    if "--record" in args:
        record(rel, args[args.index("--record") + 1])
        return 0

    fp = REPO / rel
    if not fp.exists():
        print(f"no such asset: {fp}")
        return 1
    mib = fp.stat().st_size / 1024 / 1024
    if mib > 20:
        print(f"{rel} is {mib:.1f} MiB — over the 20 MiB single-part upload limit")
        return 1
    already = load().get("assets", {}).get(rel)
    print(f"asset    : {rel}  ({mib:.2f} MiB)")
    print(f"absolute : {fp}")
    print(f"status   : {'already uploaded -> ' + already if already else 'NOT uploaded'}")
    print(f"\nnext: notion-create-file-upload(filename='{fp.name}')")
    print(f"then POST the file to the returned upload_url,")
    print(f"then: python3 generators/upload_assets.py {rel} --record <markdown_source>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
