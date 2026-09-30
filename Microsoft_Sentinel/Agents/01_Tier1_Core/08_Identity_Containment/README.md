# 08. Identity Containment

**Phase:** 1 (Tier-1 core)

## Purpose

Disables the account in Entra ID and on-prem AD, revokes sessions and refresh tokens, forces password reset. Privileged accounts always go through approval.

| | |
|---|---|
| Trigger | Approved by the Policy & Guardrail agent |
| Data sources | Microsoft Graph, Azure Automation Hybrid Runbook Worker (AD) |
| Actions | Disable / enable / revoke sessions (with rollback) |

## Build checklist

- [ ] Design and interfaces
- [ ] Implementation
- [ ] Tests
- [ ] Demo scenario
- [ ] Live permissions documented
