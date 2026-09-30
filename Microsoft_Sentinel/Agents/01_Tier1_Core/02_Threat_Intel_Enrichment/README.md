# 02. Threat Intel Enrichment

**Phase:** 1 (Tier-1 core)

## Purpose

Checks every hash, IP, domain and URL against every configured feed in parallel and returns a normalized reputation, malware family and first-seen date.

| | |
|---|---|
| Trigger | Called by the orchestrator |
| Data sources | Sentinel ThreatIntelIndicators (Defender TI), VirusTotal, AbuseIPDB, AlienVault OTX, GreyNoise, MalwareBazaar, URLhaus |
| Actions | None (read-only) |

## Build checklist

- [ ] Design and interfaces
- [ ] Implementation
- [ ] Tests
- [ ] Demo scenario
- [ ] Live permissions documented
