# Workbooks

Ten workbooks for Microsoft Sentinel. Seven are the SOC set that goes with the
[detection rules](../Detection-rules/); three are the earlier cost and ingestion workbooks.

## SOC workbooks

| Workbook | What it answers | Tables |
|---|---|---|
| [Identity Sign-ins](IdentitySignIns.json) | Who is signing in, from where, what fails and why. Password spray candidates, risky sign-ins, legacy authentication, accounts seen in more than one country. | `SigninLogs` |
| [Privileged Access Changes](PrivilegedAccessChanges.json) | Who granted power in Entra ID: role assignments (direct and through PIM), application secrets and permissions, Conditional Access edits, MFA method changes, admin password resets. | `AuditLogs` |
| [Endpoint Threats](EndpointThreats.json) | What Defender for Endpoint blocked, and the behaviour it only recorded: Windows tools that download or run code, new autorun entries, remote logon failures, SSH failures and sudo on Linux. | `DeviceEvents`, `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceRegistryEvents`, `DeviceLogonEvents`, optional `Syslog` |
| [Email and Phishing](EmailAndPhishing.json) | Threat mail from arrival to clean-up: what was caught, what was delivered anyway and which policy allowed it, who clicked, what was removed afterwards, inbox rules. | `EmailEvents`, `UrlClickEvents`, `EmailPostDeliveryEvents`, `CloudAppEvents` |
| [Azure Control Plane Activity](AzureControlPlaneActivity.json) | Who changed what in Azure: operations that change access, logging or exposure, deletions, callers being refused, callers using several addresses. | `AzureActivity` |
| [Insider Risk and Data Exfiltration](InsiderRiskDataExfiltration.json) | Data leaving by network, by USB and by cloud: top uploaders and destinations, files written to removable media, transfer tools, bulk downloads, sharing links. | `CommonSecurityLog`, `DeviceEvents`, `DeviceFileEvents`, `DeviceProcessEvents`, `DeviceNetworkEvents`, `CloudAppEvents` |
| [SOC Operations and Agent Performance](SocOperationsAgentPerformance.json) | Whether the queue is keeping up: time to acknowledge and close, classifications, noisy rules, what the Autonomous SOC Analyst decided, table freshness and rule failures. | `SecurityIncident`, `SecurityAlert`, `Usage`, optional `SentinelHealth` |

Every one of them has the same layout:

- A **time range** picker at the top (default 7 days; 14 for privileged access, 30 for SOC
  operations). Every tile, chart and table follows it.
- **Tabs**. The first is an overview with headline numbers and trends; the middle ones are for
  investigating; the last is always **Detections**.
- The **Detections** tab lists the detection rules of that area with the number of alerts each
  raised, a chart of alerts over time, the latest alerts with their details, and the incidents they
  created with status, owner and what the Autonomous SOC Analyst decided. A rule showing 0 alerts
  is not deployed, not enabled, or has had nothing to report.

The SOC Operations workbook reads the labels the
[Autonomous SOC Analyst](../Agents/Autonomous_SOC_Analyst/) writes on incidents (`soc-agent`,
`soc-agent:page`, `soc-agent:queue`, `soc-agent:auto_close`, `soc-agent:pending`,
`soc-agent:class:<alert class>`), so its Agent tab fills in as soon as the agent is running.

## Cost and ingestion workbooks

| Workbook | Purpose |
|---|---|
| [AzureCost.json](AzureCost.json) | Azure cost for the Sentinel workspace |
| [DataConnectorCost.json](DataConnectorCost.json) | Tables with data; multi-select sources to show combined cost |
| [DataIngestionLatency.json](DataIngestionLatency.json) | Potential latency of data ingested into the workspace |

## How to add a workbook to Sentinel

**One at a time, in the portal.** Microsoft Sentinel, **Workbooks**, **Add workbook**, **Edit**,
then the **Advanced editor** button (`</>`). Replace everything in the editor with the contents of
the `.json` file, choose **Apply**, then **Done editing** and **Save**. Give it the workspace's
resource group and region.

**All seven SOC workbooks at once.** Deploy the template to the resource group of the Sentinel
workspace (it must be that resource group, because the workbooks are attached to the workspace):

```bash
az deployment group create \
  --resource-group <resource-group> \
  --template-file Microsoft_Sentinel/Workbooks/deploy/all-workbooks.json \
  --parameters workspace=<workspace-name>
```

They appear under **Workbooks**, **My workbooks**. Deploying again updates the same seven
workbooks; it does not add copies, and it replaces any edits made to them in the portal.

A part of a workbook that reads a table you do not collect shows an error for that part only. The
optional tables (`Syslog`, `SentinelHealth`) show an empty table instead.

## How to change a SOC workbook

The seven SOC workbooks are generated. Their sources are the `.toml` files in [src/](src/): a
title, an introduction, and a list of tabs with the tiles, charts and tables on each and the KQL
behind them.

```toml
[[tab.item]]
kind = "table"                # text, tiles, table, timechart, areachart, barchart or piechart
title = "Addresses that fail for many accounts"
width = 50                    # per cent of the page; items share a row until it is full
bars = ["Accounts"]           # show these columns as bars
heat = ["Successful"]         # shade these columns by value
query = '''
SigninLogs
| summarize ...
'''
```

Other table settings: `severity = "Column"` colours High, Medium, Low and Informational;
`link = "Column"` with `link_label` turns a URL column into a link; `hide = [...]` hides columns;
`rows` limits the rows shown; `palette` sets the colour of bars and shading. Tiles need `label`
and `value` (the columns holding the tile name and number). Charts accept
`colours = { SeriesName = "colour" }`. Inside a query, `{TimeRange:grain}` is the bucket size the
workbook picks for the selected time range; the time range itself is applied for you.

After editing, run `python -m sentinel_content build` from [../Content_Build](../Content_Build/)
and commit the `.toml` file together with the regenerated `.json` files. The Detections tab is not
in the `.toml` file: it is produced from the rules in [../Detection-rules](../Detection-rules/), so
adding a rule there adds it to the workbook.

## How these workbooks were checked, and what was not

Checked: every query against the published table schemas and with Microsoft's KQL parser on every
push (see [../Content_Build](../Content_Build/)); the workbook JSON against Microsoft's workbook
schema; the structure (time range parameter, tabs, tiles, grid formatting) against the workbook
templates Microsoft publishes for Sentinel.

**Not checked: the workbooks have not been opened in a portal by the author.** The queries are
valid KQL for the documented schemas, but layout and formatting are only known to be well formed,
not known to look right, and values inside your data (operation names, action types) may differ
from the documented ones. If a tile is empty where you expect data, run its query in **Logs**
(open the workbook in edit mode and choose the part) and compare the filter values with what your
tables contain.
