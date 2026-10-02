# Microsoft Sentinel

Workbooks, cost monitoring and the **Autonomous SOC Analyst** multi-agent build-out for Microsoft Sentinel.

| Folder | Contents |
|---|---|
| [Agents](Agents/) | The Autonomous SOC Analyst: runnable project ([Autonomous_SOC_Analyst](Agents/Autonomous_SOC_Analyst/)), Tier-1 core agents (built) and Tier-2 advanced agents (planned) |
| [Detection Rules](Detection-rules/) | 28 scheduled analytics rules in seven areas (identity, privileged access, endpoint, email, Azure activity, data exfiltration, SOC operations), with deployable templates and a [catalogue](Detection-rules/CATALOGUE.md) |
| [Deployment](Deployment/) | Logic App playbooks, Azure Automation runbooks, infrastructure and app-registration setup |
| [Workbooks](Workbooks/) | Seven SOC workbooks, one per detection area, each showing its own rules' alerts; plus Azure cost, data connector cost and ingestion latency |
| [Content_Build](Content_Build/) | The tool that builds the rule templates and workbooks from their sources and checks every query |
| [Cost_Monitoring](Cost_Monitoring/) | Cost and volume canary definitions |
| [Docs](Docs/) | Architecture and the agent ideas document |

## Goal

When an alert fires in Defender or Sentinel, the agent does the Tier-1 ground work (detection,
analysis, response) in 28 seconds or less: contains the threat, gathers preliminary evidence, and
delivers a concise report. The human is no longer the first responder; they are the strategic overseer.
