# BannKenn v2 Detection Design Review

## Overview

This document reviews the current BannKenn behavior-detection results and proposes a practical v2 design for improving accuracy, reducing false positives, and lowering CPU usage. The analysis is based on the observed event output, process list, shell history, and recent system logs.

The current conclusion is that the host does not show strong evidence of active compromise. The suspicious events were most likely triggered by legitimate system activity and by BannKenn itself running with overly aggressive behavior analysis. In other words, the main issue is not an attacker, but a detection architecture that is currently too sensitive and not yet context-aware.

## Current Findings

### Environment Summary

The system shows the following active processes of interest:

* `/usr/local/bin/bannkenn-agent run`
* `/usr/libexec/fwupd/fwupd`
* `/usr/lib/snapd/snapd`
* `unattended-upgrade-shutdown`
* Oracle Cloud agent components

The command history shows that BannKenn was manually downloaded, installed, initialized, and started as a system service shortly before the suspicious behavior events appeared.

### Event Pattern Observed

The dashboard reported events such as:

* rename burst
* delete burst
* write burst
* protected path touched
* unknown process activity

The affected paths included:

* `/usr/bin`
* `/etc/profile.d`
* `/usr/lib/systemd/system`

These paths are sensitive, but they are also commonly touched during package installation, service updates, firmware updates, unattended upgrades, and snap-related changes.

### Most Likely Explanation

The most likely explanation is a combination of the following:

1. Legitimate system maintenance activity was occurring.
2. BannKenn detected burst-style file operations in protected paths.
3. BannKenn could not reliably attribute the responsible process, so it labeled them as `unknown`.
4. BannKenn likely contributed additional noise through its own scanning, syncing, and monitoring behavior.

## Root Problems in the Current Design

### 1. Weak Process Attribution

The most important weakness is incomplete process attribution. The system appears to detect low-level file behavior but does not consistently map the activity to a trusted executable, service, or parent process.

As a result, legitimate processes may appear as `unknown process activity`, which greatly increases false positives and reduces operator trust.

### 2. Overly Sensitive Burst Heuristics

Rules such as small rename bursts or delete bursts are being scored too aggressively. Modern Linux systems often perform clustered file operations during package upgrades, service reloads, firmware tasks, and snap refreshes.

A low threshold may be useful for early experimentation, but it is not stable enough for real-world deployment.

### 3. Self-Noise From the Agent

The monitoring agent may be observing its own actions, or indirectly triggering additional events through sync operations, log access attempts, policy reconciliation, and firewall updates.

This creates feedback loops where the defense tool increases the volume of suspicious telemetry.

### 4. Polling and Resource Usage

The agent consumed very high CPU usage, indicating that parts of the watcher or correlation pipeline may be polling too frequently, retrying excessively, or processing too much raw event volume without backpressure.

### 5. Linux Logging Assumptions

The repeated failure to open `/var/log/auth.log` suggests that the watcher assumes a traditional auth log layout. On many Ubuntu systems, especially those using systemd-journald, authentication data may instead be accessed through the journal. This is not a security breach by itself, but it creates noise and unnecessary work.

## BannKenn v2 Design Goals

BannKenn v2 should target the following goals:

* Reduce false positives from normal operating system activity
* Improve process attribution and event explainability
* Prevent self-generated monitoring noise
* Lower CPU usage significantly
* Detect ransomware-like behavior more accurately
* Support both host and container-aware monitoring
* Produce events that an operator can trust

## Proposed v2 Architecture

### A. Event Collection Layer

The event collection layer should continue using eBPF and low-level telemetry where possible, but it must collect richer process context at the moment of observation.

Recommended metadata per event:

* PID
  n- PPID
* executable path
* command line
* UID and GID
* cgroup or container identifier
* mount namespace identifier
* timestamp
* operation type
* target path
* file extension before and after rename
* bytes written

The design should prefer capturing enough context once rather than performing repeated expensive lookups later.

### B. Process Identity and Trust Layer

Every event should be enriched with a process identity profile.

Suggested process attributes:

* executable absolute path
* package owner, if available
* digital signature or package verification state where possible
* parent process chain
* service unit name, if launched by systemd
* container source, if inside Docker or another runtime
* known-good classification
* first-seen timestamp

The system should maintain a trust model such as:

* trusted system process
* trusted package-managed process
* allowed local process
* unknown process
* suspicious process

This single improvement would eliminate a large portion of current false positives.

### C. Baseline and Allowlist Layer

BannKenn v2 should introduce explicit baseline handling for common Linux maintenance operations.

Examples of processes and paths that should often be allowlisted or scored much lower:

* `apt`
* `dpkg`
* `snapd`
* `systemd`
* `fwupd`
* `unattended-upgrades`
* package post-install scripts
* known deployment tooling

The allowlist should be policy-driven, not hardcoded. A deployment should be able to define trust by executable path, package name, systemd unit, or container image.

Example policy model:

* trusted paths
* trusted process names
* trusted package managers
* maintenance windows
* trusted service units

### D. Correlation Engine

BannKenn should stop treating small isolated events as strong indicators by themselves. Instead, it should correlate them into behavior chains.

Examples:

#### Low-risk pattern

* small rename burst
* trusted package manager
* system path affected
* maintenance window active

Result: informational only

#### Medium-risk pattern

* repeated deletes
* unknown process
* user-writable directories affected
* no matching package manager activity

Result: suspicious

#### High-risk ransomware pattern

* large rename burst
* write burst
* extension changes across many files
* entropy increase or file unreadability indicators
* same unknown process across many directories
* process not tied to package operations

Result: high confidence ransomware candidate

This correlation model is much more stable than threshold-only detection.

### E. Scoring Model

BannKenn v2 should move to weighted scoring instead of simple rule-trigger classification.

Example scoring dimensions:

* path sensitivity
* process trust level
* burst size
* write volume
* rename extension anomaly
* entropy change
* spread across directories
* parent process reputation
* container escape relevance
* recurrence frequency

Example severity bands:

* 0 to 19: observed
* 20 to 49: suspicious
* 50 to 79: high risk
* 80 and above: containment candidate

This scoring should be tunable by environment profile.

### F. Self-Noise Suppression

The agent must be prevented from generating or amplifying its own detections.

Recommended protections:

* ignore BannKenn's own executable path
* ignore BannKenn-managed state directories
* suppress known sync and policy reconciliation operations
* tag internal operations explicitly as `agent_internal`
* exclude internal telemetry loops from security scoring

Without self-noise suppression, operators will quickly lose confidence in the product.

### G. Performance Controls

To reduce CPU usage, BannKenn v2 should introduce the following performance mechanisms:

* event batching
* ring buffer backpressure handling
* bounded queues between collection and scoring stages
* rate limits for repeated identical warnings
* cached process enrichment
* adaptive sampling for low-risk paths
* journald integration instead of repeated missing-file polling
* debounce windows for repetitive filesystem actions

A high-volume event storm should never cause the agent itself to become the most resource-intensive process on the host.

### H. Journald-Aware Logging Integration

Instead of assuming `/var/log/auth.log` exists, BannKenn should support both legacy log files and systemd journal sources.

Recommended behavior:

1. Detect whether journald is available.
2. Prefer journal subscriptions on systemd-based distributions.
3. Fall back to traditional log files only when needed.
4. Avoid repeated warning spam for missing paths.

This improves portability and reduces unnecessary noise.

### I. Container Awareness

If BannKenn is expected to monitor modern servers, container context is essential.

The v2 design should attribute events to:

* host process
* Docker container ID
* container image name
* orchestrator metadata where available
* mapped bind mounts or volumes

This allows the system to distinguish a trusted package update on the host from a suspicious file operation inside an application container.

## Suggested Detection Logic for Ransomware-Like Behavior

A more realistic ransomware-oriented rule should require multiple signals.

### Candidate signals

* burst renames above a meaningful threshold
* extension replacement across many files
* repeated writes after rename
* high write throughput to many documents
* entropy increase in rewritten files
* unknown or newly seen process
* activity across multiple user data directories
* rapid delete or shadow-copy style cleanup attempts

### Example decision model

Trigger a high-risk ransomware alert only when all of the following are broadly true:

* the process is unknown or untrusted
* rename burst exceeds a threshold such as 20 or more
* writes occur across many files in a short time window
* path targets include user or application data rather than only package-managed system paths
* no package-manager or maintenance context matches the activity

This would be more accurate than flagging rename burst x3 in isolation.

## Practical Policy Recommendations

### Default Trust Seeds

Initial trust seeds for Linux hosts should include:

* package managers
* systemd-managed update mechanisms
* firmware update services
* cloud-agent components from the platform provider
* standard shell startup scripts during package installation

### Protected Path Strategy

Protected paths are still valuable, but touching them should not automatically imply maliciousness. Protected-path access should increase score only when combined with weak trust or anomalous behavior.

### Maintenance Window Awareness

Many servers perform noisy but legitimate changes during update windows. BannKenn should support scheduled maintenance windows during which system-package behaviors are scored more leniently.

## Suggested Engineering Roadmap

### Phase 1: Stabilization

* reduce CPU usage
* disable repeated missing-file polling
* ignore BannKenn self-events
* improve warning deduplication
* add explicit process path logging to every event

### Phase 2: Attribution and Trust

* enrich events with executable path and parent process
* add trust classification
* add allowlist policy system
* identify package-manager and systemd contexts

### Phase 3: Correlation and Scoring

* replace simplistic thresholds with weighted scoring
* implement event chain correlation
* introduce directory spread and extension anomaly logic
* add confidence-based severity output

### Phase 4: Advanced Detection

* add entropy-based ransomware indicators
* add container context
* add optional containment actions with stronger confidence requirements
* support fleet-wide baseline sharing

## Immediate Short-Term Fixes

Before building the full v2 design, the following quick fixes are recommended immediately:

1. Stop repeated polling of `/var/log/auth.log` on systems that use journald.
2. Lower the sensitivity of rename and delete burst scoring.
3. Exclude `bannkenn-agent` from behavioral scoring.
4. Record executable path and parent process for every flagged event.
5. Add trust exceptions for `fwupd`, `snapd`, `apt`, `dpkg`, and `systemd`-related processes.
6. Add event deduplication so the same root cause does not flood the dashboard.

## Conclusion

The recent events do not primarily indicate a successful intrusion. Instead, they show that BannKenn already has a promising behavioral detection foundation, but it still needs stronger process attribution, policy-aware trust modeling, self-noise suppression, and more mature correlation logic.

This is a good sign from an engineering perspective. The system is already observing meaningful low-level behavior, which is one of the hardest parts to build. The next step is to improve interpretation quality so that the product can distinguish legitimate Linux maintenance from genuinely harmful activity.

With these improvements, BannKenn v2 can evolve from an experimental detector into a much more reliable host security platform with practical ransomware and abnormal-change detection capabilities.
