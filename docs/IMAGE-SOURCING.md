# Image sourcing for console and GUI guides

**Written 2026-08-26.** Every GUI walkthrough in this corpus needs visuals — 43 console
steps across 7 nodes currently have none. This is where the visuals may come from, and
the one edit that must never be made to them.

---

## The rule that inverts the obvious instinct

The instinct, when putting a vendor's console into our own guide, is to tidy it up:
crop to the relevant blade, blur the tenant name, maybe drop the vendor's logo so the
page looks like ours.

**Every one of those edits is what makes the image unusable.**

| Vendor | What they grant | The conditions |
|---|---|---|
| **Microsoft** | Screenshots of Microsoft software may be used "in advertising, in documentation (including educational brochures), in tutorial books, in videos, or on websites" | Do **not** "alter the screenshot except to resize it" · do **not** "use portions of screenshots" · no third-party content · no identifiable individual · no boot/splash/beta screens · credit **"Used with permission from Microsoft"** |
| **Google** | Documentation **text** is CC-BY-4.0 | **"Images, audio, video ... are not covered by the license, unless specifically noted."** Trademarks and brand features are excluded entirely. So Google doc images carry **no reuse licence at all** |

So de-branding does not reduce risk. It converts a licensed use into an unlicensed one,
and it does it in the one direction that is hard to argue afterwards — an unaltered
screenshot with a credit line is plainly a citation, while a cropped and de-logoed one
is plainly a copy.

**Attribution is the price of the permission, not a courtesy.** `ci/validate_corpus.py`
enforces it per image, because a page-footer credit does not travel with an image when a
reader copies it out.

## What the gate refuses

`check_images()` fails the build on:

- `altered: true` on any `vendor-console` or `vendor-doc` image
- a vendor-sourced image without `tenant_safe: true`
- `license: unlicensed`
- an attribution-requiring licence with an empty `credit`
- an `ms-screenshot-permission` image whose credit omits the exact required string
- an image `path` that does not exist

Verified by negative control on 2026-08-26: a de-branded, cropped, mis-credited image
produced three distinct failures. A compliant one passes.

## Sources, best first

### 1. draw.io from the verified stencil catalog — **preferred**
Official AWS/Azure/GCP icon sets, licensed for architecture diagrams, rendered by
`skills/abstract-integrations-grandmaster/scripts/drawio_gen.py` against a
1,288-stencil verified catalog. Customer-editable `.drawio` source ships alongside.
No licence conditions to track, no identity leakage, and it shows the *whole path* —
which a console screenshot never can.

`source: drawio` · `license: vendor-icon-set`

### 2. Our own terminal output
`gcloud`, `az`, `tofu plan`. Our bytes, zero licence surface, and for a DevOps
audience often more useful than a portal shot. Redact nothing — run it against a
scratch project so there is nothing to redact.

`source: own-terminal` · `license: abstract-owned`

### 3. Our own `createUiDefinition` deployment form
The Deploy-to-Azure form is authored by us and rendered in the portal. The form is our
content. This is the strongest "guided GUI" asset available and it has no vendor-IP
surface of its own.

`source: own-ui-definition` · `license: abstract-owned`

### 4. Vendor console, captured by us — **gated, not blocked**
Permitted for Microsoft under the conditions above. **Two hard blockers today:**

1. **No authenticated capture path.** There is no stored Playwright session for the
   Azure portal or the GCP console, and login is interactive.
2. **A real tenant fails the conditions.** Portal chrome shows the signed-in account
   name and avatar — an *identifiable individual* — plus directory, subscription and
   resource names, which are both *third-party content* and a breach of our own rule
   that customer-facing output carries no tenant identifiers.

And these cannot be fixed by editing the image, because editing is the prohibited act.

**The unblock is a purpose-built demo tenant with a generic service account**, captured
full-window at a fixed viewport. That is a human setup step, not something a session can
do for itself.

### 5. Vendor documentation images — **do not use**
No reuse licence from Google. For Microsoft, screenshots of the *software* are covered
but images *authored for* their docs (diagrams, illustrations) are not. Deep-link to the
vendor page instead; a link is always safe and always current.

## Where the interactive builder changes the answer

Microsoft's terms also say: do **not** "include screenshots in your product user
interface." A Notion knowledge base is documentation and is squarely inside the grant.
The **interactive builder** on the roadmap is closer to product UI.

**Decide the sourcing rule before screenshots are embedded there** — the builder should
use categories 1–3 only. Reclassifying later means finding and replacing every image.

## Getting an image onto a Notion page

This repo has no git remote, so local files have no public URL — which rules out
`create-attachment`'s `source_url` path. Use `create-file-upload`, which takes a **local
file**:

```bash
python3 generators/upload_assets.py assets/diagrams/<name>.png     # prints the steps
# → notion-create-file-upload(filename=...) → POST the file to upload_url
python3 generators/upload_assets.py assets/diagrams/<name>.png --record file-upload://<id>
```

Record the `file-upload://<id>`, **not** the URL Notion returns when reading the page
back — that is a short-lived presigned S3 link. The `file-upload://` id is stable and
re-usable across pages.

Notion's image syntax is `![Caption](URL)`. There is **no separate alt attribute** — the
caption is the only text slot, so it carries both the description and any required
credit. `image_block()` in `gen_notion.py` does this.

## References

- [Use of Microsoft Copyrighted Content](https://www.microsoft.com/en-us/legal/intellectualproperty/copyright/permissions) — screenshot permissions and conditions
- [Microsoft Trademark and Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks) — no alteration of brand assets
- [Google Site Policies](https://developers.google.com/terms/site-policies) — CC-BY-4.0 on text, images excluded, trademarks excluded
