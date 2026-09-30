# 01. Triage Orchestrator (Flow State agent)

**Phase:** 1 (Tier-1 core) | **Status:** built (v1), demo + live connectors

## Purpose

Owns the incident lifecycle and the 28-second budget. Runs the specialist agents in parallel, merges results, applies the IR policy, and decides severity, verdict, status, alert class, and page vs. queue.

| | |
|---|---|
| Trigger | Sentinel incident created (automation rule + Logic App, or polling) |
| Data sources | Sentinel REST API |
| Actions | Updates incident status, severity, labels, comments |

## Implementation

Part of the runnable [Autonomous SOC Analyst](../../Autonomous_SOC_Analyst/) project:

* [`soc_agent/orchestrator.py`](../../Autonomous_SOC_Analyst/soc_agent/orchestrator.py)
* [`soc_agent/scoring.py`](../../Autonomous_SOC_Analyst/soc_agent/scoring.py)
* [`soc_agent/api.py`](../../Autonomous_SOC_Analyst/soc_agent/api.py)

## Build checklist

- [x] Design and interfaces
- [x] Implementation
- [x] Tests
- [x] Demo scenario
- [x] Live permissions documented
