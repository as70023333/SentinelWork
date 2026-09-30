# 07. Network Block

**Phase:** 1 (Tier-1 core) | **Status:** built (v1), demo + live connectors

## Purpose

Blocks IPs, domains, URLs and hashes with an automatic expiry.

| | |
|---|---|
| Trigger | Approved by the Policy & Guardrail agent |
| Data sources | Defender for Endpoint custom indicators; perimeter firewalls (Palo Alto, Fortinet, Check Point, Azure Firewall) through a generic block/unblock webhook |
| Actions | Block / unblock (with rollback) |

## Implementation

Part of the runnable [Autonomous SOC Analyst](../../Autonomous_SOC_Analyst/) project:

* [`soc_agent/agents/response.py`](../../Autonomous_SOC_Analyst/soc_agent/agents/response.py)
* [`soc_agent/connectors/defender.py`](../../Autonomous_SOC_Analyst/soc_agent/connectors/defender.py)
* [`soc_agent/connectors/firewall.py`](../../Autonomous_SOC_Analyst/soc_agent/connectors/firewall.py)

## Build checklist

- [x] Design and interfaces
- [x] Implementation
- [x] Tests
- [x] Demo scenario
- [x] Live permissions documented
