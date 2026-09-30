# Autonomous SOC Analyst: agents

A multi-agent system: one orchestrator owns each incident and calls specialist agents, each with a
narrow job and a narrow set of permissions.

## Phase 1: Tier-1 core

| # | Agent | Phase |
|---|---|---|
| 01 | [Triage Orchestrator (Flow State agent)](01_Tier1_Core/01_Triage_Orchestrator/) | Phase 1 |
| 02 | [Threat Intel Enrichment](01_Tier1_Core/02_Threat_Intel_Enrichment/) | Phase 1 |
| 03 | [Malware Analysis (slow path)](01_Tier1_Core/03_Malware_Analysis/) | Phase 1 |
| 04 | [User Activity](01_Tier1_Core/04_User_Activity/) | Phase 1 |
| 05 | [Endpoint & Network Traffic](01_Tier1_Core/05_Endpoint_Network_Traffic/) | Phase 1 |
| 06 | [Endpoint Containment](01_Tier1_Core/06_Endpoint_Containment/) | Phase 1 |
| 07 | [Network Block](01_Tier1_Core/07_Network_Block/) | Phase 1 |
| 08 | [Identity Containment](01_Tier1_Core/08_Identity_Containment/) | Phase 1 |
| 09 | [IR Report](01_Tier1_Core/09_IR_Report/) | Phase 1 |
| 10 | [Policy & Guardrail](01_Tier1_Core/10_Policy_Guardrail/) | Phase 1 |

## Phase 2: Tier-2 advanced

| # | Agent | Phase |
|---|---|---|
| 11 | [Phishing Triage](02_Tier2_Advanced/11_Phishing_Triage/) | Phase 2 |
| 12 | [False Positive Learning](02_Tier2_Advanced/12_False_Positive_Learning/) | Phase 2 |
| 13 | [Threat Hunting](02_Tier2_Advanced/13_Threat_Hunting/) | Phase 2 |
| 14 | [Detection Engineering](02_Tier2_Advanced/14_Detection_Engineering/) | Phase 2 |
| 15 | [Incident Correlation](02_Tier2_Advanced/15_Incident_Correlation/) | Phase 2 |
| 16 | [Vulnerability Context](02_Tier2_Advanced/16_Vulnerability_Context/) | Phase 2 |
| 17 | [Cloud Posture](02_Tier2_Advanced/17_Cloud_Posture/) | Phase 2 |
| 18 | [Insider Risk / Data Exfiltration](02_Tier2_Advanced/18_Insider_Risk_Data_Exfil/) | Phase 2 |
| 19 | [Shift Handoff](02_Tier2_Advanced/19_Shift_Handoff/) | Phase 2 |
| 20 | [Playbook Validation](02_Tier2_Advanced/20_Playbook_Validation/) | Phase 2 |

## Shared

* [Shared/Connectors](Shared/Connectors/): clients for Sentinel, Defender, Graph, Log Analytics, threat-intel feeds, notifications
* [Shared/IR_Policy](Shared/IR_Policy/): the machine-readable IR policy (autonomy, guardrails, escalation)
* [Shared/Demo_Data](Shared/Demo_Data/): simulated tenant data and demo scenarios
* [Shared/Tests](Shared/Tests/): tests for detection logic, guardrails and connectors

## Rollout

Build agents 01, 02, 09 and 10 first with containment in recommend-only mode. Once the verdicts are
trusted, switch agents 06-08 to autonomous for specific alert classes.
