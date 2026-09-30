# 06. Endpoint Containment

**Phase:** 1 (Tier-1 core) | **Status:** built (v1), demo + live connectors

## Purpose

Isolates the device (full isolation), runs a quick AV scan, and verifies isolation actually succeeded (confirmation continues in the background if the device is slow). Release from isolation is one-click rollback. Planned: selective isolation, stop-and-quarantine file.

| | |
|---|---|
| Trigger | Approved by the Policy & Guardrail agent |
| Data sources | Defender for Endpoint API |
| Actions | Isolate / release / scan (with rollback) |

## Implementation

Part of the runnable [Autonomous SOC Analyst](../../Autonomous_SOC_Analyst/) project:

* [`soc_agent/agents/response.py`](../../Autonomous_SOC_Analyst/soc_agent/agents/response.py)
* [`soc_agent/connectors/defender.py`](../../Autonomous_SOC_Analyst/soc_agent/connectors/defender.py)

## Build checklist

- [x] Design and interfaces
- [x] Implementation
- [x] Tests
- [x] Demo scenario
- [x] Live permissions documented
