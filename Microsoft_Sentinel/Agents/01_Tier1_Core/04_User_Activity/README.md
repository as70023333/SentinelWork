# 04. User Activity

**Phase:** 1 (Tier-1 core)

## Purpose

Reviews 24-72h of sign-ins and audit activity: impossible travel, MFA fatigue, password attacks, risky sign-ins, inbox rules, role changes, Entra risk, privileged roles.

| | |
|---|---|
| Trigger | Called by the orchestrator |
| Data sources | SigninLogs, AuditLogs, OfficeActivity, IdentityLogonEvents, Microsoft Graph |
| Actions | None (read-only) |

## Build checklist

- [ ] Design and interfaces
- [ ] Implementation
- [ ] Tests
- [ ] Demo scenario
- [ ] Live permissions documented
