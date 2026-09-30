# 09. IR Report

**Phase:** 1 (Tier-1 core)

## Purpose

Writes the human-readable report: executive summary, timeline, IOCs, actions with timestamps, confidence and next steps. Delivers to Teams/email/ticketing and the Sentinel incident.

| | |
|---|---|
| Trigger | End of the fast path; updated by the slow path |
| Data sources | Claude (Anthropic API) for narrative; facts rendered from the incident record |
| Actions | Teams, pager, webhook, Sentinel comment |

## Build checklist

- [ ] Design and interfaces
- [ ] Implementation
- [ ] Tests
- [ ] Demo scenario
- [ ] Live permissions documented
