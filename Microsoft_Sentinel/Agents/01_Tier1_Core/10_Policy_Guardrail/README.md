# 10. Policy & Guardrail

**Phase:** 1 (Tier-1 core) | **Status:** built (v1), demo + live connectors

## Purpose

Encodes the IR policy as rules every action must pass: protected hosts, tier-0 accounts, confidence threshold, rate limits, kill switch, allowlists, audit log and rollback.

| | |
|---|---|
| Trigger | Every proposed action |
| Data sources | config/ir_policy.yaml |
| Actions | Gates actions: autonomous / approval / recommend / deny |

## Implementation

Part of the runnable [Autonomous SOC Analyst](../../Autonomous_SOC_Analyst/) project:

* [`soc_agent/policy.py`](../../Autonomous_SOC_Analyst/soc_agent/policy.py)
* [`config/ir_policy.yaml`](../../Autonomous_SOC_Analyst/config/ir_policy.yaml)

## Build checklist

- [x] Design and interfaces
- [x] Implementation
- [x] Tests
- [x] Demo scenario
- [x] Live permissions documented
