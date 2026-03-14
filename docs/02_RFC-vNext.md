
# BannKenn vNext Upgrade Proposal

Behavior-Based Containment for Ransomware and Data Exfiltration

## 1. Overview

BannKenn currently operates as a behavior-based Intrusion Prevention System (IPS) with lightweight agents, centralized aggregation, and firewall enforcement. The system focuses primarily on detecting malicious network behavior and automatically blocking offending IP addresses.

While this approach is effective for many external threats, modern attacks increasingly involve valid credentials, internal lateral movement, and abuse of legitimate connections. In these cases, simple IP blocking may not be sufficient.

This document proposes an upgrade to BannKenn that introduces behavior-based containment mechanisms designed to mitigate:
- Ransomware attacks
- Mass file modification or encryption
- Data exfiltration through legitimate connections
- Insider misuse of data access

The key design principle is staged response, allowing the system to slow down or contain suspicious activity rather than immediately blocking access.

---

2. Design Goals

The vNext upgrade aims to expand BannKenn into a host-level behavioral protection platform with the following capabilities:
 1. Detect abnormal filesystem activity.
 2. Correlate file events with process and network behavior.
 3. Apply staged containment responses.
 4. Slow down suspicious activity before damage escalates.
 5. Provide administrators with time to investigate and respond.

The system should remain:
- Lightweight
- Self-hosted
- Container-friendly
- Suitable for small organizations and home labs

---

## 3. Threat Model

The upgrade specifically targets modern threat patterns such as:

Ransomware Behavior

Typical ransomware activity includes:
- Rapid file reads
- File renaming
- File overwriting
- High entropy output
- Mass changes across directories

Indicators:
- Hundreds of file modifications within seconds
- Suspicious extension changes
- High write throughput

---

Data Exfiltration

Data theft often follows a pattern:
 1. File enumeration
 2. Bulk reading
 3. Compression
 4. Network upload

Indicators:
- Sudden large read activity
- High outbound traffic
- Access to sensitive directories
- Unknown processes performing large transfers

---

Abuse of Legitimate Connections

Many modern attacks occur through:
- Valid user sessions
- Authorized applications
- Internal services

Because of this, IP blocking alone is insufficient.

---

## 4. Core Concept: Staged Containment

Instead of binary decisions (allow vs block), BannKenn vNext introduces graded containment levels.

This allows the system to delay attacker progress while preserving legitimate operations.

---

Level 0 — Normal Operation

System operates normally.

Agent responsibilities:
- Collect baseline metrics
- Track file activity patterns
- Monitor network throughput
- Observe process activity

No restrictions applied.

---

Level 1 — Suspicious Activity

Triggered when anomaly score exceeds a low threshold.

Actions:
- Increase event logging
- Capture detailed process metadata
- Notify central server
- Alert administrators

No containment actions yet.

Purpose:
Reduce false positives.

---

Level 2 — Throttling Mode

Triggered when suspicious behavior intensifies.

Containment actions may include:
- Network bandwidth throttling
- Disk I/O rate limiting
- File operation slowdown
- Restrict access to sensitive paths

Example effects:
- Large uploads slowed significantly
- Mass file encryption delayed
- Suspicious processes limited in write speed

This stage buys time for investigation.

---

Level 3 — Emergency Fuse

Triggered when strong evidence of attack exists.

Actions:
- Block write access to protected directories
- Suspend suspicious processes
- Stop data transfer services
- Isolate host network access
- Maintain management channel for investigation

Manual administrator intervention is required to restore full operation.

---

## 5. Behavior Scoring Engine

The containment system relies on a scoring model rather than single-event triggers.

Example indicators:

Event Score
Mass file rename +20
High write frequency +25
Abnormal file entropy +25
Large outbound transfer +20
Unknown process activity +15
Sensitive directory access +10
Off-hours activity +5

Thresholds:

Score Response
30 Suspicious
60 Throttling
90 Fuse

This reduces false positives and improves resilience.

---

## 6. Architecture Changes

BannKenn’s existing architecture already contains the core components required for this upgrade.

Current structure:

agent/
server/
dashboard/
docker/

vNext introduces additional modules inside the agent.

---

## 7. Agent Module Expansion

New modules proposed:

File Guard

Monitors filesystem activity.

Tracks:
- rename
- delete
- create
- modify
- read frequency

Detects abnormal file operations.

---

Process Correlator

Links file activity with process information.

Tracks:
- PID
- command
- user
- executable path

Helps identify the origin of suspicious behavior.

---

Network Volume Monitor

Tracks large outbound data transfers.

Collects:
- destination IP
- port
- transfer size
- protocol

Used to detect data exfiltration.

---

Containment Engine

Applies staged responses:
- throttle
- restrict
- fuse

Implements system-level actions such as:
- bandwidth shaping
- I/O limitation
- service suspension
- access control changes

---

## 8. Central Server Enhancements

The server component will gain new responsibilities:
- Event correlation across agents
- Global anomaly scoring
- Threat timeline reconstruction
- Containment orchestration
- Administrator alerts

The central server will also provide:
- incident summaries
- affected host visibility
- recovery controls

---

## 9. Dashboard Improvements

The web dashboard will visualize:
- containment status
- threat levels
- suspicious hosts
- activity timelines
- active throttling events

Administrators should be able to:
- review incidents
- release throttling
- trigger fuse actions manually

---

## 10. Deployment Model

Typical deployment:

             BannKenn Server
                  │
        ┌─────────┴─────────┐
        │                   │
    Agent Host         Agent Host

Agents perform local detection and containment, while the server provides central coordination and visibility.

Local containment ensures fast reaction without network latency.

---

## 11. Implementation Phases

Recommended roadmap:

Phase 1 — File Activity Detection

Add:
- filesystem monitoring
- rename/write counters
- anomaly scoring

---

Phase 2 — Throttling Engine

Implement:
- network bandwidth control
- disk I/O limits
- containment triggers

---

Phase 3 — Fuse Mode

Add:
- service isolation
- write protection
- network quarantine

---

Phase 4 — Dashboard Integration

Add visualization and administrative controls.

---

## 12. Long-Term Vision

With these upgrades, BannKenn evolves from a network-focused IPS into a self-hosted behavioral protection platform capable of:
- detecting ransomware
- slowing data exfiltration
- containing suspicious activity
- protecting internal resources

The system remains lightweight, open source, and suitable for environments where traditional enterprise EDR solutions are too heavy or expensive.

---

If you’d like, I can also help you write:
- a shorter GitHub RFC version
- a README upgrade section
- or a technical design spec for the Rust agent modules.