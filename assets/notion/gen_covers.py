#!/usr/bin/env python3
"""Render Abstract-branded Notion cover images. SVG -> PNG at 1500x600.

Usage:  python3 assets/notion/gen_covers.py      (from the repo root)
Requires: rsvg-convert  (brew install librsvg)

See README.md in this directory for the design rules these encode.
"""
import pathlib, subprocess, sys

MARK = pathlib.Path.home() / ".claude/projects/-Users-mherbert/memory/assets/abstract-logo-mark.svg"
OUT = pathlib.Path(__file__).parent
W, H = 1500, 600

# title, subtitle, accent, source-count for the pipeline motif, title font size
COVERS = {
    # 80px, not the 62px this used to carry. That downscale was a workaround for a bug, not a
    # design decision: the title was colliding with the motif because Helvetica was being
    # substituted for Barlow, and Barlow Semi Condensed sets ~0.78x the width. With the real
    # font installed there is no collision, so the workaround only made the hub inconsistent
    # with the other four covers.
    "hub":   ("CLOUD ONBOARDING", "Every path into Abstract \u00b7 AWS \u00b7 Azure \u00b7 GCP \u00b7 OCI", "#FF216B", 4, 80),
    "azure": ("AZURE",            "Event Hubs \u00b7 Policy at scale \u00b7 Entra ID",                        "#2e9bf0", 5, 80),
    "aws":   ("AWS",              "S3 + SQS \u00b7 Organizations \u00b7 StackSets",                           "#f5c61e", 4, 80),
    "gcp":   ("GOOGLE CLOUD",     "Log Router \u00b7 Pub/Sub \u00b7 Aggregated sink",                         "#01e69d", 6, 80),
    "oci":   ("ORACLE CLOUD",     "Service Connector Hub \u00b7 Streaming",                                    "#E8005D", 2, 80),
}


def pipeline_motif(accent, n):
    """Sources fanning into one pipe into one destination — the product, as a mark."""
    parts, join, dst = [], 150, 250
    for i in range(n):
        y = i * 34 - (n - 1) * 17
        parts.append(f'<path d="M0 {y} C 70 {y}, {join-60} 0, {join} 0" fill="none" '
                     f'stroke="{accent}" stroke-opacity="0.5" stroke-width="2"/>')
        parts.append(f'<circle cx="0" cy="{y}" r="5" fill="{accent}" fill-opacity="0.85"/>')
    parts.append(f'<path d="M{join} 0 L{dst-16} 0" stroke="{accent}" stroke-width="3.5"/>')
    parts.append(f'<circle cx="{join}" cy="0" r="7.5" fill="{accent}"/>')
    parts.append(f'<rect x="{dst-14}" y="-15" width="30" height="30" rx="8" fill="none" '
                 f'stroke="{accent}" stroke-width="3.5"/>')
    parts.append(f'<circle cx="{dst+1}" cy="0" r="5" fill="{accent}"/>')
    return "".join(parts)


def build(title, sub, accent, n, size):
    mark = MARK.read_text().split(">", 1)[1].rsplit("</svg>", 1)[0]
    dy = 0 if size >= 80 else -8
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#060608"/><stop offset="0.5" stop-color="#0e0a11"/>
      <stop offset="1" stop-color="#1a0a16"/></linearGradient>
    <radialGradient id="glow" cx="16%" cy="46%" r="60%">
      <stop offset="0" stop-color="{accent}" stop-opacity="0.30"/>
      <stop offset="0.45" stop-color="#E8005D" stop-opacity="0.12"/>
      <stop offset="1" stop-color="#060608" stop-opacity="0"/></radialGradient>
    <radialGradient id="glow2" cx="84%" cy="52%" r="42%">
      <stop offset="0" stop-color="{accent}" stop-opacity="0.14"/>
      <stop offset="1" stop-color="#060608" stop-opacity="0"/></radialGradient>
    <linearGradient id="rule" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="{accent}"/><stop offset="1" stop-color="{accent}" stop-opacity="0"/></linearGradient>
    <linearGradient id="base" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="#FF216B"/><stop offset="0.5" stop-color="{accent}"/>
      <stop offset="1" stop-color="#C2004C"/></linearGradient>
    <pattern id="grid" width="48" height="48" patternUnits="userSpaceOnUse">
      <path d="M48 0 L0 0 0 48" fill="none" stroke="#FF216B" stroke-opacity="0.10" stroke-width="1"/></pattern>
  </defs>
  <rect width="{W}" height="{H}" fill="url(#bg)"/>
  <rect width="{W}" height="{H}" fill="url(#grid)"/>
  <rect width="{W}" height="{H}" fill="url(#glow)"/>
  <rect width="{W}" height="{H}" fill="url(#glow2)"/>
  <g transform="translate(92,182) scale(1.22)">{mark}</g>
  <text x="318" y="{272+dy}" font-family="Barlow Semi Condensed, Barlow, Helvetica Neue, Arial, sans-serif"
        font-size="{size}" font-weight="700" letter-spacing="{4 if size < 80 else 6}" fill="#FFFFFF">{title}</text>
  <rect x="320" y="{294+dy}" width="{240 if size < 80 else 286}" height="3" fill="url(#rule)"/>
  <text x="320" y="{338+dy}" font-family="Barlow, Helvetica Neue, Arial, sans-serif"
        font-size="27" letter-spacing="2.2" fill="#FFE3EE" opacity="0.80">{sub}</text>
  <g transform="translate(1178,300)">{pipeline_motif(accent, n)}</g>
  <rect x="0" y="{H-5}" width="{W}" height="5" fill="url(#base)" opacity="0.9"/>
</svg>'''


def check_fonts():
    """Refuse to render without the brand fonts.

    This function exists because of a real failure: all five covers shipped set in
    Helvetica Neue. Neither Barlow face was installed, and the "responsible" fallback stack
    (`Barlow Semi Condensed, Barlow, Helvetica Neue, Arial, sans-serif`) meant rsvg-convert
    substituted silently and exited 0. The output looked deliberate and was off-brand.

    A fallback stack is correct for a WEB page, where you cannot control the client. It is
    wrong for a BUILD step, where you can and must — there the only safe behaviour is to
    fail. Verified by a pixel-identical probe against a Helvetica control.
    """
    try:
        listed = subprocess.run(["fc-list"], capture_output=True, text=True, check=True).stdout
    except (FileNotFoundError, subprocess.CalledProcessError):
        print("warn: fc-list unavailable — cannot verify fonts. Inspect the output by eye.",
              file=sys.stderr)
        return
    missing = [f for f in ("Barlow Semi Condensed", "Barlow") if f not in listed]
    if missing:
        sys.exit(
            f"brand font(s) not installed: {', '.join(missing)}\n"
            "Renders would silently substitute Helvetica and look plausible while being\n"
            "off-brand. Install the Barlow family (https://fonts.google.com/specimen/Barlow\n"
            "and /Barlow+Semi+Condensed) into ~/Library/Fonts, then re-run."
        )


def main():
    if not MARK.exists():
        sys.exit(f"official mark not found at {MARK} - do not redraw it, find it")
    check_fonts()
    for key, args in COVERS.items():
        svg = OUT / f"cover-{key}.svg"
        svg.write_text(build(*args))
        png = OUT / f"cover-{key}.png"
        subprocess.run(["rsvg-convert", "-w", str(W), "-h", str(H), str(svg), "-o", str(png)], check=True)
        print("wrote", png.name)


if __name__ == "__main__":
    main()
