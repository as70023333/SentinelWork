# 02. Threat Intel Enrichment

**Phase:** 1 (Tier-1 core) | **Status:** built (v1), demo + live connectors

## Purpose

Checks every hash, IP, domain and URL against every configured feed in parallel and returns a normalized reputation, malware family and first-seen date.

| | |
|---|---|
| Trigger | Called by the orchestrator |
| Data sources | Sentinel ThreatIntelIndicators (Defender TI), VirusTotal, AbuseIPDB, AlienVault OTX, GreyNoise, MalwareBazaar, URLhaus |
| Actions | None (read-only) |

## Implementation

Part of the runnable [Autonomous SOC Analyst](../../Autonomous_SOC_Analyst/) project:

* [`soc_agent/agents/investigate.py`](../../Autonomous_SOC_Analyst/soc_agent/agents/investigate.py)
* [`soc_agent/connectors/threat_intel.py`](../../Autonomous_SOC_Analyst/soc_agent/connectors/threat_intel.py)

## Build checklist

- [x] Design and interfaces
- [x] Implementation
- [x] Tests
- [x] Demo scenario
- [x] Live permissions documented
