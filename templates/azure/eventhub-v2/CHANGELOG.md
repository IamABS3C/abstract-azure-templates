# Changelog

## 2.0.0 — 2026-06-11

Aligned with the official Abstract Security "Azure Event Hub" documentation and
made portal-deployable.

### Added
- **Checkpoint Storage Account stack** (required by Abstract): StorageV2 account
  (TLS 1.2, public blob access off, optional shared-key disable), private blob
  container `abstract-checkpoints`, `Storage Blob Data Contributor` role
  assignment, optional blob private endpoint + `privatelink.blob` DNS group,
  optional mirroring of the namespace IP allowlist to the storage firewall.
- **createUiDefinition.json** — 6-step portal wizard (basics, hubs, auth,
  networking, storage, monitoring) for the Deploy to Azure button.
- **Deploy to Azure buttons** (public + Azure Gov) in the README.
- **templates/subscription/activitylog** (Bicep + ARM) — subscription-scope
  diagnostic setting streaming the Azure Activity Log to the hub, with its own
  Deploy button.
- `defaultPartitionCount` (default 4 per Abstract guidance) and
  `defaultRetentionDays` parameters for generated hubs.
- `abstractOnboarding` output object mapping field-for-field to the Abstract
  integration modal for both auth methods (no secrets — pointers only).
- Script v2: `-AuthMethod ConnectionString|ServicePrincipal|Both`,
  `-CreateServicePrincipal` (creates `abstract-eventhub-ingestion` app +
  secret), checkpoint-storage parameters, `-ExportActivityLogs`,
  `-ExportEntraLogs` (best effort via microsoft.aadiam), and a Credentials
  action that prints the exact Abstract modal fields for both methods
  (storage connection string included).
- Repo scaffolding: LICENSE (MIT), CHANGELOG, .gitignore, GitHub Actions
  validation workflow (JSON checks + arm-ttk).

### Changed
- **Basic SKU removed** — Abstract requires Standard tier or above.
- Default SAS rights now **Listen-only** (least privilege for a consumer);
  the Send-capable `abstract-diagnostics-send` rule covers log producers.
- Default hub sources now `activity, entra, defender`; default hub prefix
  `evh-abstract`; environment token optional (empty by default).
- Hub-source and IP-range inputs are trimmed and empty entries filtered, so
  CSV-driven portal inputs cannot produce empty hub names or invalid IP rules.
- Default capacity 2 TU; sizing table from the Abstract docs embedded in the
  template metadata and README.

## 1.0.0 — 2026-06-11

Initial release: namespace, auto-named hubs, consumer group, SAS + RBAC auth,
SafeMode/IpAllowlist/PrivateOnly/Hybrid networking profiles, Log Analytics
diagnostics, four parameter profiles, guided PowerShell deployer. Fixed ten
defects found in a prior hand-written draft (wrong Service Bus role GUIDs,
invalid conditional-loop syntax, networkRuleSet placement, maximumThroughputUnits
handling, Basic-SKU guards, PrincipalNotFound races, allLogs category group,
secrets leaking into outputs, and more).
