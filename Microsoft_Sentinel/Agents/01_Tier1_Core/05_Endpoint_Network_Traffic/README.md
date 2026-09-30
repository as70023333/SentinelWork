# 05. Endpoint & Network Traffic

**Phase:** 1 (Tier-1 core) | **Status:** built (v1), demo + live connectors

## Purpose

Builds the process tree and outbound-connection timeline, detects behaviors (shadow copy deletion, LSASS dumping, encoded PowerShell, beaconing) and hunts for the same IOC on other hosts.

| | |
|---|---|
| Trigger | Called by the orchestrator |
| Data sources | DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents (Defender XDR advanced hunting via Graph) |
| Actions | None (read-only) |

## Implementation

Part of the runnable [Autonomous SOC Analyst](../../Autonomous_SOC_Analyst/) project:

* [`soc_agent/agents/investigate.py`](../../Autonomous_SOC_Analyst/soc_agent/agents/investigate.py)
* [`soc_agent/agents/analysis.py`](../../Autonomous_SOC_Analyst/soc_agent/agents/analysis.py)
* [`soc_agent/connectors/hunting.py`](../../Autonomous_SOC_Analyst/soc_agent/connectors/hunting.py)

## Build checklist

- [x] Design and interfaces
- [x] Implementation
- [x] Tests
- [x] Demo scenario
- [x] Live permissions documented
