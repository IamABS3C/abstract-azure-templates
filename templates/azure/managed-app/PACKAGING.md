# Packaging the Abstract Security solution for Content Hub

This folder is a deployable, self-contained approximation. To produce an
**official** Microsoft Sentinel Content Hub / commercial-marketplace solution
(verified badge, `contentTemplates`-wrapped `mainTemplate`, automated tests),
run Microsoft's packaging + validation tooling against this source — it can't be
run here (proprietary .NET/PowerShell tooling in the Azure-Sentinel repo).

## Steps

1. **Lay the source out** in the Azure-Sentinel `Solutions/AbstractSecurity/`
   convention (this repo's `solution/` maps 1:1):
   - `Data Connectors/` ← `solution/connector/`
   - `Parsers/` ← `solution/parsers/`
   - `Analytic Rules/` ← `solution/analytics/` (YAML)
   - `Hunting Queries/` ← `solution/hunting/`
   - `Workbooks/` ← `solution/workbooks/`
   - `Playbooks/` ← `solution/playbooks/` (enrich, verdict, tune-at-source)
   - `SolutionMetadata.json`, `ReleaseNotes.md` ← `solution/`
2. **Logo**: use `abstract-logo.svg` (vector is required for certification; the
   PNG used in READMEs/landing page is fine for marketing but not the package).
3. **Generate the package**:
   ```powershell
   # from a clone of github.com/Azure/Azure-Sentinel
   pwsh ./Tools/Create-Azure-Sentinel-Solution/V3/createSolutionV4.ps1
   ```
   This emits `Package/mainTemplate.json` + `createUiDefinition.json` with the
   `contentPackages` + per-item `contentTemplates` wrappers Content Hub expects.
4. **Validate**:
   ```powershell
   pwsh ./Tools/Create-Azure-Sentinel-Solution/V3/Test-CreateSolutionV4.ps1
   # plus arm-ttk over the generated Package/
   ```
5. **Submit** via Partner Center (commercial marketplace) for the in-product
   Content Hub listing, or open a PR to Azure/Azure-Sentinel for community.

## Playbooks as embedded solution content

The three Logic App playbooks (`solution/playbooks/*.json`) are listed in
`SolutionMetadata.json` and should be added under `Playbooks/` so the packaging
tool embeds them as `contentTemplates` of kind `Playbook` and they install with
the solution. Keep the API key out of the package — playbooks take it as a
`securestring`/Key Vault reference at install time.

## What this repo's `Package/mainTemplate.json` does today

Registers the solution `contentPackages` record and deploys the connector tile,
ASIM parser (savedSearch), analytics rule, and workbook with linked `metadata`,
so the solution shows as installed and the content appears in the workspace.
Sufficient for a lab / private install; not a substitute for the certified
package above.
