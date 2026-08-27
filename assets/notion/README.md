# Notion visual assets

Generated, not hand-drawn. `gen_covers.py` renders SVG → PNG at 1500×600, Notion's cover
dimension. Re-run it rather than editing the PNGs.

**Design rules, learned by looking at the output rather than assuming:**

- **Composition sits in the middle ~55% of the height.** Notion crops covers to a shallow band
  and lets the user reposition, so anything near the top or bottom edge gets decapitated. The
  first draft put content at a natural vertical centre and lost it.
- **The pipeline motif on the right is the product, drawn.** N sources fanning into one pipe into
  one destination. An earlier draft used per-vendor geometric glyphs, which read as random noise —
  meaningless decoration is worse than none.
- **Titles are downscaled when long.** A character-count estimate under-counts wide glyphs
  (C, O, D, B, G), so "CLOUD ONBOARDING" collided with the motif twice before landing at 62px.
  Check the render; do not trust the estimate.
- **No vendor logos.** The per-cloud accent colour carries the identity — `#2e9bf0` Azure,
  `#f5c61e` AWS, `#01e69d` GCP, `#E8005D` OCI. Reproducing vendor marks in a customer-facing
  asset is a trademark question nobody needs.
- **The brand fonts must be installed, and the generator now refuses to run without them.**
  All five covers originally shipped set in **Helvetica Neue**: neither Barlow face was
  present, and the "responsible" fallback stack meant `rsvg-convert` substituted silently and
  exited 0. The output looked deliberate. A fallback stack is right for a *web page*, where
  you cannot control the client — it is wrong for a *build step*, where you can, and where the
  only safe behaviour is to fail. `check_fonts()` now does that, and it has a negative control.
- **The hub title is 80px like every other cover.** It briefly carried a 62px downscale to
  stop it colliding with the motif — that was a workaround for the font bug, not a design
  decision. Barlow Semi Condensed sets ~0.78× the width of Helvetica, so with the correct
  font there is no collision and the workaround only made the hub inconsistent.
- Brand colours only: `#FF216B` `#E8005D` `#C2004C` on `#060608`, accents `#01e69d` `#f5c61e`
  `#2e9bf0`. Barlow Semi Condensed for the wordmark, Barlow for body, with real fallback stacks
  because the renderer may not have the font.

The official mark is read from the canonical SVG in memory assets and embedded — never redrawn.
