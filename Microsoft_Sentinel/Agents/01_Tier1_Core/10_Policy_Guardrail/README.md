# 10. Policy & Guardrail

**Phase:** 1 (Tier-1 core)

## Purpose

Encodes the IR policy as rules every action must pass: protected hosts, tier-0 accounts, confidence threshold, rate limits, kill switch, allowlists, audit log and rollback.

| | |
|---|---|
| Trigger | Every proposed action |
| Data sources | config/ir_policy.yaml |
| Actions | Gates actions: autonomous / approval / recommend / deny |

## Build checklist

- [ ] Design and interfaces
- [ ] Implementation
- [ ] Tests
- [ ] Demo scenario
- [ ] Live permissions documented
