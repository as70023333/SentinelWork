# Detection rules

28 scheduled analytics rules for Microsoft Sentinel in seven areas, four rules per area. Each area
has a workbook in [../Workbooks](../Workbooks/) whose **Detections** tab shows the alerts and
incidents these rules produce.

| Area | Rules | Reads | Workbook |
|---|---|---|---|
| [Identity sign-ins](CATALOGUE.md#identity-sign-ins) | ID-001 to ID-004: password spray, MFA fatigue, new country, legacy authentication | `SigninLogs` | Identity Sign-ins |
| [Privileged access changes](CATALOGUE.md#privileged-access-changes) | PA-001 to PA-004: privileged role assigned, credential added to an application, high-privilege permission granted, Conditional Access policy changed | `AuditLogs` | Privileged Access Changes |
| [Endpoint threats](CATALOGUE.md#endpoint-threats) | EP-001 to EP-004: credential dumping, recovery options deleted, Office starting a script host, encoded or download PowerShell | `DeviceProcessEvents` | Endpoint Threats |
| [Email and phishing](CATALOGUE.md#email-and-phishing) | EM-001 to EM-004: malicious URL clicked, phishing delivered to several people, inbox rule that forwards or hides, click before the mail was removed | `EmailEvents`, `UrlClickEvents`, `EmailPostDeliveryEvents`, `CloudAppEvents` | Email and Phishing |
| [Azure activity](CATALOGUE.md#azure-activity) | AZ-001 to AZ-004: diagnostic settings deleted, privileged Azure role assigned, mass deletion, Run Command on a VM | `AzureActivity` | Azure Control Plane Activity |
| [Insider risk and data exfiltration](CATALOGUE.md#insider-risk-and-data-exfiltration) | EX-001 to EX-004: large upload to one address, mass copy to USB, mass download from SharePoint or OneDrive, transfer tool executed | `CommonSecurityLog`, `DeviceEvents`, `DeviceFileEvents`, `DeviceProcessEvents`, `CloudAppEvents` | Insider Risk and Data Exfiltration |
| [SOC operations](CATALOGUE.md#soc-operations) | SO-001 to SO-004: log source went silent, rule failing, high severity incident not picked up, rule creating too many incidents | `Usage`, `SentinelHealth`, `SecurityIncident` | SOC Operations and Agent Performance |

**[CATALOGUE.md](CATALOGUE.md)** describes every rule in full: what it finds, what else triggers
it, how to tune it and what to do when it fires.

## Who this is for

A SOC that runs Microsoft Sentinel with Entra ID, Defender XDR, Azure activity and a firewall
connected, and wants a small set of rules it can read, understand and tune, instead of several
hundred templates nobody has opened. It is also the rule set the
[Autonomous SOC Analyst](../Agents/Autonomous_SOC_Analyst/) in this repository is meant to triage:
the rules map entities (account, host, address, URL, file hash) so the agent has something to
enrich and contain.

## Why these 28

Each rule covers a step that real intrusions and real insider cases go through, and that the
connected data shows clearly:

- **Getting in**: password spray, MFA fatigue, a phishing link that was clicked.
- **Staying in**: a new role, a new application secret, a consent grant, a weakened Conditional
  Access policy, an inbox rule.
- **Acting on a device**: credential dumping, script hosts started by Office, PowerShell that hides
  what it runs, backups deleted before encryption.
- **Acting in the cloud**: Run Command, mass deletion, logging switched off.
- **Taking data out**: by network, by USB, by cloud download, by transfer tool.
- **Keeping the SOC itself working**: a silent data source, a failing rule, an incident nobody
  picked up, a rule drowning the queue.

Rules that only repeat an alert a Microsoft product already raises were left out on purpose.

## What you need

| Rule group | Data connector | Table must exist |
|---|---|---|
| ID, PA | Microsoft Entra ID (sign-in logs and audit logs) | `SigninLogs`, `AuditLogs` |
| EP, EX-002, EX-004 | Microsoft Defender XDR (device events) | `DeviceProcessEvents`, `DeviceEvents`, `DeviceFileEvents` |
| EM, EX-003 | Microsoft Defender XDR (email, URL click and cloud app events) | `EmailEvents`, `UrlClickEvents`, `EmailPostDeliveryEvents`, `CloudAppEvents` |
| AZ | Azure Activity | `AzureActivity` |
| EX-001 | A firewall or proxy that sends CEF (Common Event Format) | `CommonSecurityLog` |
| SO-002 | Sentinel health monitoring switched on (Settings, then Auditing and health monitoring) | `SentinelHealth` |
| SO-001, SO-003, SO-004 | Nothing extra | `Usage`, `SecurityIncident` |

Sentinel checks a rule's query when the rule is created. A rule that reads a table your workspace
does not have is rejected, which is why there is one template per area: deploy the areas you
collect data for.

## How to deploy

The templates are in [deploy/](deploy/): `all-rules.json` has all 28 rules, and there is one file
per area. **Every rule is deployed disabled**, so nothing starts raising incidents until you have
looked at it.

1. Deploy to the resource group of the Sentinel workspace:

   ```bash
   az deployment group create \
     --resource-group <resource-group> \
     --template-file Microsoft_Sentinel/Detection-rules/deploy/all-rules.json \
     --parameters workspace=<workspace-name>
   ```

   Without the CLI: in the Azure portal search for **Deploy a custom template**, choose **Build
   your own template in the editor**, load the file, and enter the workspace name. The templates
   have the same shape as the files Sentinel's own **Export** produces, which is the shape
   **Analytics, Import** reads.

2. In Sentinel open **Analytics**, filter **Status: Disabled**, and for each rule run its query in
   **Logs** over the last week or two. You are checking two things: that it returns what the
   description says, and how often it would have fired.

3. Tune (see below), then select the rules and choose **Enable**.

Deploying again updates the same 28 rules; it never creates duplicates, because each rule has a
fixed identifier derived from its Id. It also puts back the repository's version of the query, so
keep your tuning in the `.kql` file (see [How to change a rule](#how-to-change-a-rule)) rather than
only in the portal.

To build templates whose rules start enabled, for a workspace where you have already done the
review: `python -m sentinel_content build --enabled --out <folder>` from
[../Content_Build](../Content_Build/).

## When the rules run

Most rules run every hour and read the hour that has just ended. Rules that compare with history
(new country, mass download) read 14 days; rules that join to earlier events (a click on mail
delivered days ago) read 7. `SO-003` runs every 30 minutes, `SO-001` every 6 hours and `SO-004`
once a day. The catalogue lists the schedule of every rule.

An alert becomes an incident. Alerts from the same rule that share their entities within five
hours join the same incident, so one password spray is one incident and not one per run.

## How a rule is written

A rule is one `.kql` file: a comment header with the settings, then the query.

```kql
// Title: Password spray from a single IP address
// Id: ID-001
// Severity: Medium
// Tactics: CredentialAccess
// Techniques: T1110
// Sub-techniques: T1110.003
// Tables: SigninLogs
// Frequency: PT1H
// Period: PT1H
// Entities: IP(Address=IPAddress)
// Custom details: TargetAccounts, FailedAttempts, SuccessfulSignIns, Outcome
// Description: ...
// False positives: ...
// Tuning: ...
// Response: ...
// References: https://...
let MinAccounts = 15;
let ExcludedIPs = dynamic([]);
SigninLogs
| where ...
```

| Field | Meaning |
|---|---|
| `Title` | The rule name in Sentinel, and the name of its alerts and incidents. |
| `Id` | Area prefix and number. Never reuse one: the rule's identifier in Sentinel is derived from it. |
| `Severity` | `High`, `Medium`, `Low` or `Informational`. |
| `Tactics`, `Techniques` | MITRE ATT&CK, as Sentinel names them. A technique must belong to a listed tactic. Operational rules have none. |
| `Sub-techniques` | Recorded in the description and the catalogue. |
| `Tables` | The tables the query reads. Checked against the query. |
| `Frequency`, `Period` | How often the rule runs and how far back it reads, as ISO 8601 durations (`PT30M`, `PT1H`, `P1D`). |
| `Entities` | `Type(Identifier=Column, ...)`, separated by `;`. The columns must be in the query result. |
| `Custom details` | Result columns shown on the alert, as `Name` or `Name=Column`. |
| `Incidents` | Optional. `AllEntities, PT5H` (the default), `Entities(Account, IP), PT5H`, `CustomDetails(Name), P1D`, or `none`. |
| `Alerts` | Optional. `AlertPerResult` (the default: one alert per result row) or `SingleAlert`. |
| `Trigger` | Optional. Default `GreaterThan 0`: alert when the query returns any row. |
| `Description`, `False positives`, `Tuning`, `Response` | Required. They become the rule description in Sentinel and the catalogue entry. |

## How to tune

Every threshold and every exclusion list is a `let` line at the top of the query, with a name that
says what it is: `MinAccounts`, `ExcludedIPs`, `AllowedActors`, `ManagementParents`, `MinBytes`,
`WatchedTables`. The `Tuning` field of each rule says which ones matter. The usual first changes:

- **ID-001, ID-004**: add your egress addresses and the service accounts that still need legacy
  protocols.
- **PA-001, PA-002, PA-004, AZ-***: add the identities that make approved changes
  (lower-case, as the lists are compared in lower case).
- **EP-004**: add the parent process of your management tooling.
- **EX-001**: add your backup provider and other expected destinations.
- **SO-001**: set `WatchedTables` to the tables your enabled rules read.

## How to change a rule

1. Edit the `.kql` file, or add a new one next to it (next free number in the area).
2. From [../Content_Build](../Content_Build/) run `python -m sentinel_content build`. It refuses to
   build if anything is wrong and says what; otherwise it rewrites the templates, the catalogue and
   the workbooks.
3. Commit the source and the generated files together. CI fails if they do not match.

## How these rules were checked, and what was not

Checked:

- Every table and column name against the Microsoft Learn table reference (copied into
  [../Content_Build/schema/tables.json](../Content_Build/schema/tables.json), October 2026).
- Every query parsed and analysed with Microsoft's own KQL parser (Kusto.Language) against those
  schemas, on every push. This catches syntax errors, unknown columns and functions, wrong argument
  counts, and columns used after the stage that removed them.
- The columns each rule maps to entities and custom details exist in the query result.
- Rule settings against the Sentinel alert rules API (version 2024-03-01) and the entity mapping
  reference: severities, tactics, technique and tactic pairs, durations, entity identifiers.

**Not checked: nothing here has been run in a live workspace.** No query was executed against real
data and no rule was deployed by the author. That matters in three places:

- **Values inside the data.** Operation names, result codes and action types (for example the
  Entra audit operation names, the PIM record layout in PA-001, `UsbDriveMounted` fields in EX-002)
  come from Microsoft's documentation and field experience. A tenant can differ. Step 2 of the
  deployment exists to find those cases.
- **Thresholds.** They are reasonable starting points, not measurements of your environment.
- **Deployment.** The templates follow the documented API and the export format; the first
  deployment is the real test.

## Limits

- Scheduled rules only. No near-real-time rules, no anomaly or Fusion rules, no automation rules.
- Interactive sign-ins only (`SigninLogs`). Non-interactive sign-ins, where legacy authentication
  and token replay also show up, are not read.
- `EX-001` understands IPv4 addresses. IPv6 traffic is not evaluated.
- `EM-*` rules need the Defender for Office 365 tables in the workspace. Whether URL click and
  post-delivery events are produced at all depends on your Defender for Office 365 licence.
- Alerts are matched to rules by name in the workbooks. Renaming a rule in the portal removes it
  from its workbook's Detections tab.
