# 09. IR Report

**Phase:** 1 (Tier-1 core) | **Status:** built (v1), demo + live connectors

## Purpose

Writes the human-readable report: executive summary, timeline, IOCs, actions with timestamps, confidence and next steps. Delivers to Teams (Adaptive Card), a pager webhook, a generic webhook (ticketing/SOAR/email bridge) and as a comment on the Sentinel incident.

| | |
|---|---|
| Trigger | End of the fast path; updated by the slow path |
| Data sources | Claude (Anthropic API) for narrative; facts rendered from the incident record |
| Actions | Teams, pager, webhook, Sentinel comment |

## Implementation

Part of the runnable [Autonomous SOC Analyst](../../Autonomous_SOC_Analyst/) project:

* [`soc_agent/agents/report.py`](../../Autonomous_SOC_Analyst/soc_agent/agents/report.py)
* [`soc_agent/connectors/notify.py`](../../Autonomous_SOC_Analyst/soc_agent/connectors/notify.py)
* [`soc_agent/connectors/llm.py`](../../Autonomous_SOC_Analyst/soc_agent/connectors/llm.py)
* [`soc_agent/render.py`](../../Autonomous_SOC_Analyst/soc_agent/render.py)

## Build checklist

- [x] Design and interfaces
- [x] Implementation
- [x] Tests
- [x] Demo scenario
- [x] Live permissions documented
