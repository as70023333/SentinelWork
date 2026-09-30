# 05. Endpoint & Network Traffic

**Phase:** 1 (Tier-1 core)

## Purpose

Builds the process tree and outbound-connection timeline, detects behaviors (shadow copy deletion, LSASS dumping, encoded PowerShell, beaconing) and hunts for the same IOC on other hosts.

| | |
|---|---|
| Trigger | Called by the orchestrator |
| Data sources | DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, CommonSecurityLog (advanced hunting) |
| Actions | None (read-only) |

## Build checklist

- [ ] Design and interfaces
- [ ] Implementation
- [ ] Tests
- [ ] Demo scenario
- [ ] Live permissions documented
