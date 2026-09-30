# Autonomous SOC Analyst: agents

A multi-agent system: one orchestrator owns each incident and calls specialist agents, each with a
narrow job and a narrow set of permissions.

## Runnable project

**[Autonomous_SOC_Analyst](Autonomous_SOC_Analyst/)** implements all ten Tier-1 agents as one
deployable service (dashboard, API, CLI, demo mode, live Microsoft connectors, 59 tests).
Quick start and the full go-live guide are in its [README](Autonomous_SOC_Analyst/README.md):

```bash
cd Microsoft_Sentinel/Agents/Autonomous_SOC_Analyst
pip install -r requirements.txt
cp .env.example .env
python -m soc_agent serve      # http://localhost:8080
```

## Phase 1: Tier-1 core

| # | Agent | Status |
|---|---|---|
| 01 | [Triage Orchestrator (Flow State agent)](01_Tier1_Core/01_Triage_Orchestrator/) | Built (v1) |
| 02 | [Threat Intel Enrichment](01_Tier1_Core/02_Threat_Intel_Enrichment/) | Built (v1) |
| 03 | [Malware Analysis (slow path)](01_Tier1_Core/03_Malware_Analysis/) | Built (v1) |
| 04 | [User Activity](01_Tier1_Core/04_User_Activity/) | Built (v1) |
| 05 | [Endpoint & Network Traffic](01_Tier1_Core/05_Endpoint_Network_Traffic/) | Built (v1) |
| 06 | [Endpoint Containment](01_Tier1_Core/06_Endpoint_Containment/) | Built (v1) |
| 07 | [Network Block](01_Tier1_Core/07_Network_Block/) | Built (v1) |
| 08 | [Identity Containment](01_Tier1_Core/08_Identity_Containment/) | Built (v1) |
| 09 | [IR Report](01_Tier1_Core/09_IR_Report/) | Built (v1) |
| 10 | [Policy & Guardrail](01_Tier1_Core/10_Policy_Guardrail/) | Built (v1) |

## Phase 2: Tier-2 advanced

| # | Agent | Status |
|---|---|---|
| 11 | [Phishing Triage](02_Tier2_Advanced/11_Phishing_Triage/) | Planned |
| 12 | [False Positive Learning](02_Tier2_Advanced/12_False_Positive_Learning/) | Planned |
| 13 | [Threat Hunting](02_Tier2_Advanced/13_Threat_Hunting/) | Planned |
| 14 | [Detection Engineering](02_Tier2_Advanced/14_Detection_Engineering/) | Planned |
| 15 | [Incident Correlation](02_Tier2_Advanced/15_Incident_Correlation/) | Planned |
| 16 | [Vulnerability Context](02_Tier2_Advanced/16_Vulnerability_Context/) | Planned |
| 17 | [Cloud Posture](02_Tier2_Advanced/17_Cloud_Posture/) | Planned |
| 18 | [Insider Risk / Data Exfiltration](02_Tier2_Advanced/18_Insider_Risk_Data_Exfil/) | Planned |
| 19 | [Shift Handoff](02_Tier2_Advanced/19_Shift_Handoff/) | Planned |
| 20 | [Playbook Validation](02_Tier2_Advanced/20_Playbook_Validation/) | Planned |

## Shared

* [Shared/Connectors](Shared/Connectors/): clients for Sentinel, Defender, Graph, Log Analytics, threat-intel feeds, notifications
* [Shared/IR_Policy](Shared/IR_Policy/): the machine-readable IR policy (autonomy, guardrails, escalation)
* [Shared/Demo_Data](Shared/Demo_Data/): simulated tenant data and demo scenarios
* [Shared/Tests](Shared/Tests/): tests for detection logic, guardrails and connectors

## Rollout

Build agents 01, 02, 09 and 10 first with containment in recommend-only mode. Once the verdicts are
trusted, switch agents 06-08 to autonomous for specific alert classes.
