# 01. Triage Orchestrator (Flow State agent)

**Phase:** 1 (Tier-1 core)

## Purpose

Owns the incident lifecycle and the 28-second budget. Runs the specialist agents in parallel, merges results, applies the IR policy, and decides severity, verdict, status, alert class, and page vs. queue.

| | |
|---|---|
| Trigger | Sentinel incident created (automation rule + Logic App, or polling) |
| Data sources | Sentinel REST API |
| Actions | Updates incident status, severity, labels, comments |

## Build checklist

- [ ] Design and interfaces
- [ ] Implementation
- [ ] Tests
- [ ] Demo scenario
- [ ] Live permissions documented
