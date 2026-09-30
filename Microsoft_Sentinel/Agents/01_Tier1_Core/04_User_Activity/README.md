# 04. User Activity

**Phase:** 1 (Tier-1 core) | **Status:** built (v1), demo + live connectors

## Purpose

Reviews 24-72h of sign-ins and audit activity: impossible travel, MFA fatigue, password attacks, risky sign-ins, inbox rules, role changes, Entra risk, privileged roles.

| | |
|---|---|
| Trigger | Called by the orchestrator |
| Data sources | SigninLogs, AuditLogs, OfficeActivity (Log Analytics), Microsoft Graph (user, directory roles, Entra ID Protection risk) |
| Actions | None (read-only) |

## Implementation

Part of the runnable [Autonomous SOC Analyst](../../Autonomous_SOC_Analyst/) project:

* [`soc_agent/agents/investigate.py`](../../Autonomous_SOC_Analyst/soc_agent/agents/investigate.py)
* [`soc_agent/agents/analysis.py`](../../Autonomous_SOC_Analyst/soc_agent/agents/analysis.py)
* [`soc_agent/connectors/hunting.py`](../../Autonomous_SOC_Analyst/soc_agent/connectors/hunting.py)
* [`soc_agent/connectors/identity.py`](../../Autonomous_SOC_Analyst/soc_agent/connectors/identity.py)

## Build checklist

- [x] Design and interfaces
- [x] Implementation
- [x] Tests
- [x] Demo scenario
- [x] Live permissions documented
