# Abstract Security — Azure Templates

Everything needed to stream Azure telemetry into Abstract Security: Event Hubs, Azure
Policy at scale, Entra ID identity logs, Activity Log, pipeline health alerts, and
destinations back out to Event Hub or Microsoft Sentinel.

Every template ships in **both Bicep and ARM**, at the deployment scope it actually
belongs to.

---

## Deploy first, then everything else

> **Deploy the Event Hub (Source) template first.** Every other source template consumes
> its outputs, and **Azure Policy never creates hubs** — any hub name passed elsewhere must
> already exist.

## One-click deploy, by scope

The button opens the Azure portal with the template loaded. The portal builds the parameter
pane from the template's own parameters and their `metadata.description`, which is why
those descriptions are written for a customer to read.

**Scope is carried by the template's `$schema`, not by the URL.** A
`subscriptionDeploymentTemplate` targets a subscription automatically; nothing extra is
appended to the button.

### Resource group

| Template | What it does | Deploy |
|---|---|---|
| **Event Hub (Source)** ⭐ | Namespace, one hub per log source, consumer group, checkpoint storage, SAS and/or Entra RBAC auth | [Deploy](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2Fabstract-azure-templates%2Fmain%2Ftemplates%2Fazure%2Fbicep%2Fsource%2Feventhub-source.azuredeploy.json) |
| **Pipeline health alerts** | Catches the stalled consumer Standard tier cannot see — a scheduled query rule, because a metric alert on sparse data may never fire | [Deploy](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2Fabstract-azure-templates%2Fmain%2Ftemplates%2Fazure%2Fbicep%2Fmonitoring%2Fpipeline-health-alerts.azuredeploy.json) |
| **App registration (automation)** | Creates the Entra app registration Abstract authenticates with, via a deployment script | [Deploy](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2Fabstract-azure-templates%2Fmain%2Ftemplates%2Fazure%2Fbicep%2Fautomation%2Fabstract-appreg-automation.azuredeploy.json) |
| **Event Hub (Destination)** | The reverse direction — Abstract writing to a customer Event Hub | [Deploy](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2Fabstract-azure-templates%2Fmain%2Ftemplates%2Fazure%2Fbicep%2Fdestinations%2Feventhub-destination.azuredeploy.json) |
| **Sentinel destination** | Abstract → Microsoft Sentinel, for customers keeping Sentinel as the SIEM | [Deploy](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2Fabstract-azure-templates%2Fmain%2Ftemplates%2Fazure%2Fbicep%2Fdestinations%2Fsentinel-destination.azuredeploy.json) |
| **Sentinel destination + app** | Same, bundled with the app registration for teams who want one pass | [Deploy](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2Fabstract-azure-templates%2Fmain%2Ftemplates%2Fazure%2Fbicep%2Fdestinations%2Fsentinel-destination-with-app.azuredeploy.json) |

### Subscription

| Template | What it does | Deploy |
|---|---|---|
| **Activity Log export** | One subscription's Activity Log to the Event Hub. For the whole estate, use the management-group policy instead | [Deploy](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2Fabstract-azure-templates%2Fmain%2Ftemplates%2Fazure%2Fbicep%2Fsubscription%2Factivitylog.azuredeploy.json) |

### Management group — current *and future* subscriptions

| Template | What it does | Deploy |
|---|---|---|
| **Log streams policy** | `DeployIfNotExists` across every subscription in the management group, and it **self-heals a deleted diagnostic setting** | [Deploy](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2Fabstract-azure-templates%2Fmain%2Ftemplates%2Fazure%2Fbicep%2Fpolicy%2Fabstract-logstreams-policy.azuredeploy.json) |
| **App registration policy** | The same `DeployIfNotExists` shape for the app registration | [Deploy](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2Fabstract-azure-templates%2Fmain%2Ftemplates%2Fazure%2Fbicep%2Fpolicy%2Fabstract-appreg-policy.azuredeploy.json) |

> **Read this before promising "future subscriptions are automatic."** New subscriptions
> land in the **Tenant Root Group** by default. A child-management-group assignment covers
> them only if the customer's subscription-vending process places them there. The claim is
> unconditionally true only at root scope.

### Tenant

| Template | What it does | Deploy |
|---|---|---|
| **Entra ID diagnostics** | Tenant-wide identity logs to the Event Hub, set once | [Deploy](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FIamABS3C%2Fabstract-azure-templates%2Fmain%2Ftemplates%2Fazure%2Fbicep%2Ftenant%2Fentra-diagnostics.azuredeploy.json) |

> Requires a role very few people hold — **confirm who before the call.** This is the most
> common place an Azure onboarding stalls. First data takes **24 hours to 3 days**; do not
> declare it broken on day one.

---

## Deploying from Bicep instead

Every ARM template above is generated from the Bicep beside it. If you prefer Bicep, or
want to review before deploying:

```bash
az login

# resource group scope
az deployment group create -g <rg> \
  --template-file templates/azure/bicep/source/eventhub-source.bicep

# subscription scope
az deployment sub create -l <region> \
  --template-file templates/azure/bicep/subscription/activitylog.bicep

# management group scope
az deployment mg create -m <mg-id> -l <region> \
  --template-file templates/azure/bicep/policy/abstract-logstreams-policy.bicep

# tenant scope
az deployment tenant create -l <region> \
  --template-file templates/azure/bicep/tenant/entra-diagnostics.bicep
```

Preview any of them first by swapping `create` for `what-if`.

## Deploying from Azure Cloud Shell

No local tooling, and `az` is already authenticated:

```bash
git clone https://github.com/IamABS3C/abstract-azure-templates
cd abstract-azure-templates
az deployment group create -g <rg> \
  --template-file templates/azure/bicep/source/eventhub-source.bicep
```

Cloud Shell is the better path when the person deploying has portal access but no local
Azure CLI, which is common for the tenant- and management-group-scoped templates.

---

## About the UI definition files

`createUiDefinition.json` and `uiFormDefinition.json` are in this repo, and it is worth
being precise about what they do, because it is easy to assume otherwise:

| File | Belongs to | Rendered by a plain Deploy-to-Azure button? |
|---|---|---|
| `createUiDefinition.json` | Azure **Managed Applications** | **No** |
| `uiFormDefinition.json` | **Template spec** portal forms | **No** |

A plain Deploy-to-Azure button takes **only** the encoded template URL. There is no
`createUIDefinitionUri` parameter for it, and no `uiFormDefinitionUri` parameter at all.
The portal auto-generates the parameter pane from the template's own parameters.

To get the richer guided experience, the template must be published as a **Managed
Application** or a **template spec** — see `templates/azure/managed-app/`, which contains a
Sentinel Content Hub solution package (`mainTemplate.json`, `createUiDefinition.json`,
logos) and `PACKAGING.md` describing what Microsoft's own tooling needs to certify it.

---

## The Azure fact that changes how you scope an engagement

**NSG and VNet flow logs cannot reach an Event Hub at all.** The `flowLogs` resource has a
required `storageId` and no Event Hub property. Azure's highest-volume source is
structurally unreachable by the streaming path — plan for a storage-based collection for
that data, and do not promise it over Event Hubs.

## A silent failure worth knowing before it costs you a week

Event Hubs publishes **no consumer-lag metric on Standard tier**. A stalled consumer looks
perfectly healthy while retention quietly expires. `ConsumerLag` exists only in
`ApplicationMetricsLogs` on Premium/Dedicated — which is a genuine argument for Premium.
The pipeline health alert template above exists specifically to catch this.

---

## Layout

```text
templates/azure/
  bicep/
    source/         Event Hub namespace and hubs — deploy first
    subscription/   Activity Log export
    policy/         Management-group DeployIfNotExists, at scale
    tenant/         Entra ID diagnostics
    destinations/   Event Hub and Sentinel, outbound
    monitoring/     Pipeline health alerts
    automation/     App registration via deployment script
  managed-app/      Sentinel Content Hub solution package
  scripts/          PowerShell and bash drivers
  parameters/       Worked parameter files
corpus/azure/       When and why to use each path
```

## Provenance

Every artifact declares how well it is evidenced — `deployed`, `planned`, `validated`,
`schema-reviewed`, or `cited`. A path never claims a tier higher than its weakest artifact.
Run `python3 ci/validate_corpus.py` to check.

Licensed under Apache 2.0.
