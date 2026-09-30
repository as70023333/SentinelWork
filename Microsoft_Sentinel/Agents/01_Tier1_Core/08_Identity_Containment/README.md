# 08. Identity Containment

**Phase:** 1 (Tier-1 core) | **Status:** built (v1), demo + live connectors

## Purpose

Disables the account in Entra ID and/or on-prem AD, and revokes sessions and refresh tokens. Tier-0 and admin-role accounts always go through approval. Password reset and MFA re-registration are recommended next steps in the report (planned as an action).

| | |
|---|---|
| Trigger | Approved by the Policy & Guardrail agent |
| Data sources | Microsoft Graph, Azure Automation Hybrid Runbook Worker (AD) |
| Actions | Disable / enable / revoke sessions (with rollback) |

## Implementation

Part of the runnable [Autonomous SOC Analyst](../../Autonomous_SOC_Analyst/) project:

* [`soc_agent/agents/response.py`](../../Autonomous_SOC_Analyst/soc_agent/agents/response.py)
* [`soc_agent/connectors/identity.py`](../../Autonomous_SOC_Analyst/soc_agent/connectors/identity.py)
* [`deploy/runbooks/Invoke-SocADUserAction.ps1`](../../Autonomous_SOC_Analyst/deploy/runbooks/Invoke-SocADUserAction.ps1)

## Build checklist

- [x] Design and interfaces
- [x] Implementation
- [x] Tests
- [x] Demo scenario
- [x] Live permissions documented
