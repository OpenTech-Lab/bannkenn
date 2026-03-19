# Technical Investigation Report: eBPF EDR Alert Review and False-Positive Analysis

## 1. Purpose

This document summarizes the investigation of several suspicious file activity alerts detected by BannKenn Agent on Linux hosts. The goal was to determine whether the events indicated an active compromise, malware execution, crypto-mining, or whether they were caused by legitimate system and application behavior.

The investigation focused on repeated alerts involving temporary paths such as `/tmp` and `/var/tmp`, especially patterns labeled as write burst, delete burst, rename burst, protected path touched, and unknown process activity.

## 2. Executive Summary

The investigation found no confirmed evidence of malware, miner execution, persistence, or unauthorized binary drops on the analyzed systems.

Most alerts were caused by legitimate software performing temporary file operations that resemble malicious behavior at the filesystem event level. These included:

- Wazuh Indexer / OpenSearch Java runtime extracting and deleting native JNI libraries in `/tmp`
- Uptime Kuma launching an internal MariaDB process inside a container
- System package installation and post-install hooks invoking tools such as `depmod` and `cryptroot`
- High-throughput copy operations during package or container-related tasks
- Short-lived processes that exited before metadata could be fully resolved by the eBPF pipeline

The core issue identified is not a host compromise, but a detection-tuning problem. BannKenn is successfully capturing low-level behavior, but it currently lacks enough execution context to distinguish benign temporary file patterns from actual malicious staging or fileless execution.

## 3. Investigation Scope and Method

The investigation covered the following areas:

- Shell history review for suspicious commands
- Process lineage inspection
- Command-line inspection through `/proc/<pid>/cmdline`
- Executable path validation through `/proc/<pid>/exe`
- Open file analysis with `lsof`
- Systemd and cron persistence review
- Docker container attribution
- Temporary file inspection under `/tmp` and `/var/tmp`
- Package installation timeline analysis using `dpkg.log`

The working question for each alert was whether the observed behavior met the threshold for a likely compromise, rather than whether it merely looked unusual in isolation. An alert was only treated as a high-confidence malicious candidate if the investigation could support at least one of the following:

- execution of a temp-written payload
- unexpected outbound connectivity following temp staging
- persistence creation
- process-name and executable-path mismatch
- untrusted lineage with no legitimate package, service, or container explanation

This matters because low-level file bursts, rapid deletes, and short-lived helper processes are common in both malicious and benign Linux activity. The investigation therefore emphasized corroborating context and negative findings, not just anomaly labels.

## 4. Initial Alert Themes

Several alerts had similar characteristics:

- Process wrote to `/tmp` or `/var/tmp`
- Process deleted the same file shortly after writing it
- Alerts were labeled with reasons such as:

  - write burst xN
  - delete burst xN
  - rename burst xN
  - protected path touched
  - unknown process activity
  - write throughput anomaly

At first glance, this pattern resembled loader behavior, miner staging, or short-lived fileless malware. However, deeper analysis showed that these patterns were also produced by normal applications and system maintenance operations.

## 5. Case Disposition Summary

| Alert case | Key validation points | Disposition | Confidence |
| --- | --- | --- | --- |
| `java` write/delete bursts under `/tmp` | OpenSearch command line, expected temp dir, JNI `.so` extraction, deleted-but-open files | Legitimate Wazuh/OpenSearch runtime behavior | High |
| `mariadbd` on a host where MariaDB was not expected | Legitimate `/usr/sbin/mariadbd`, Docker/container lineage, Uptime Kuma attribution | Legitimate embedded container dependency | High |
| `depmod`, `cryptroot`, `cp`, and `unknown` temp activity | `dpkg.log` timing, maintenance tooling, no suspicious temp payloads recovered | Legitimate package-management or maintenance activity | Moderate to high |

## 6. Findings by Case

### 6.1 Java Process on `/tmp`: Wazuh Indexer / OpenSearch

One host generated alerts involving `java` with repeated write/delete activity under `/tmp`.

**Observed Process**  
`/usr/share/wazuh-indexer/jdk/bin/java ... org.opensearch.bootstrap.OpenSearch`

**Key Evidence**  
The full Java command line matched a legitimate Wazuh Indexer / OpenSearch deployment, including expected options such as:

- `-Djava.io.tmpdir=/tmp/opensearch-...`
- `-cp /usr/share/wazuh-indexer/lib/*`
- `org.opensearch.bootstrap.OpenSearch`

Open file inspection showed entries such as:

- `libzstd-jni-...so`
- randomly named deleted files under `/tmp`
- deleted-but-still-open file descriptors

**Interpretation**  
This behavior is consistent with standard JVM native library extraction and loading. A typical Java/JNI pattern is:

1. Extract native library from JAR into `/tmp`
2. Load it into memory
3. Delete the file from the filesystem while keeping the file descriptor open

This creates exactly the type of sequence that EDR systems often flag:

- write
- delete
- file still in use
- temporary path involvement

**Conclusion**  
This was legitimate Wazuh/OpenSearch runtime behavior and not an intrusion.

### 6.2 `mariadbd` Detected on a Host Where MariaDB Was Not Expected

A separate host generated alerts involving `mariadbd` touching `/tmp`. At first this appeared highly suspicious because only PostgreSQL was expected on that host.

**Initial Concern**  
The appearance of a database daemon that was not knowingly installed suggested two possibilities:

- disguised malware using a trusted process name
- a hidden or embedded application dependency

**Key Evidence**  
Process inspection showed:

- Executable path: `/usr/sbin/mariadbd`
- Command line: `mariadbd --user=node --datadir=/app/data/mariadb --socket=/app/data/run/mariadb.sock --pid-file=/app/data/run/mysqld.pid`

Process lineage showed:  
`systemd -> containerd-shim -> dumb-init -> node server/server.js -> mariadbd`

Docker inspection then confirmed that the process was inside:  
`louislam/uptime-kuma:2`

Container process listing showed:

- `/usr/bin/dumb-init -- node server/server.js`
- `node server/server.js`
- `mariadbd ...`

**Interpretation**  
The MariaDB process was not part of the user’s Sync Server project. It was launched by the Uptime Kuma container. The binary was legitimate, the parent process chain was legitimate, and the process was contained inside Docker.

**Conclusion**  
This was not malware and not related to the user’s own application stack. It was a legitimate service process inside the Uptime Kuma container.

### 6.3 Alerts Involving `depmod`, `cryptroot`, `cp`, and `unknown`

Another alert set involved:

- `depmod`
- `cryptroot`
- `cp`
- `unknown`

with activity under `/var/tmp` and `/tmp`.

**Key Evidence**  
Package logs showed active software installation around the same time:

- `rkhunter`
- `libc-bin`
- `rsyslog`
- `ruby`
- `nginx`
- related package transitions

The alert timestamps closely matched the package installation period.

Only one recent temp file was found:  
`/tmp/start_...properties` owned by Solr

No suspicious ELF payloads, hidden binaries, or miner artifacts were found under `/tmp` or `/var/tmp`.

**Interpretation**  
This alert group is best explained by package installation and post-install behavior:

- `depmod` is commonly invoked during kernel/module dependency updates
- `cryptroot` may run during initramfs or encrypted-root related updates
- `cp` may produce very high write throughput during package extraction or copy operations
- `unknown` most likely reflects short-lived helper processes that exited before full metadata correlation was completed

**Conclusion**  
These alerts were consistent with package management and system maintenance activity, not malicious execution.

## 7. Shell History Review

Shell history was examined for suspicious commands such as:

- `curl | bash`
- `wget`
- `xmrig`
- `miner`
- `burst`
- `java.*burst`

There were several higher-risk administrative commands present, including remote install scripts and GitHub downloads. However, no command directly proved miner installation or malicious payload execution.

Instead, most of the history reflected:

- active investigation by the user
- API health checks
- Git cloning of legitimate repositories
- tool installations
- local service testing

This means shell history alone did not support a compromise conclusion.

## 8. Persistence Review

Persistence mechanisms were reviewed through:

- systemd service listing
- active service listing
- user and root cron inspection
- search across `/etc/cron*`, `/etc/systemd/system`, `~/.config/systemd`, `~/.config/autostart`

**Result**  
No malicious persistence mechanism was found.

Only expected services were present, including BannKenn and standard Ubuntu services.

## 9. Temporary Path Review

Repeated alerts targeted `/tmp` and `/var/tmp`, but direct file inspection did not reveal suspicious staged binaries.

**Observed Legitimate Temp Usage**

- OpenSearch Java temp directory under `/tmp/opensearch-*`
- JNI/native library extraction under `/tmp`
- Solr temporary properties file under `/tmp`
- package management temporary writes under `/var/tmp`
- MariaDB or application temporary usage patterns

**Not Observed**

- no dropped miner binary
- no hidden executable in `/tmp`
- no obvious malicious `.so` outside expected runtime behavior
- no residual staging artifacts consistent with compromise

## 10. Resource Usage Review

Resource usage analysis showed:

- highest CPU usage was BannKenn Agent itself, running under QEMU user emulation
- Redis, Solr, Node, Docker, and MariaDB processes appeared normal
- no miner-like CPU consumer was present

**Important Note**  
BannKenn Agent was running via:  
`/usr/libexec/qemu-binfmt/x86_64-binfmt-P /usr/local/bin/bannkenn-agent ...`

This indicates the agent binary was x86_64 and was being emulated on a different architecture, likely ARM. This explains the unusually high CPU usage for the security agent itself.

**Conclusion**  
The top CPU consumer was the monitoring agent, not a malicious process.

## 11. Negative Findings That Weighed Against Compromise

Across the reviewed systems, the investigation did not find the kinds of corroborating signals that would normally elevate these alerts into a likely incident:

- no recovered executable payload from `/tmp` or `/var/tmp`
- no observed `execve` chain from a temp-staged binary
- no persistence mechanism added through cron, systemd, or user autostart paths
- no process masquerading evidence where the process name and executable path materially disagreed
- no miner-like sustained CPU consumer besides the emulated BannKenn Agent itself
- no residual staging artifacts, hidden ELF payloads, or suspicious standalone `.so` files outside known runtime behavior

These absences do not prove a system can never be compromised, but they materially weaken the malware or cryptominer hypothesis for the specific alerts under review.

## 12. Confidence, Limitations, and Residual Risk

The confidence level is not identical across all cases.

- High confidence benign: the OpenSearch Java case and the containerized `mariadbd` case, because process identity, lineage, and execution context were directly validated
- Moderate-to-high confidence benign: the `depmod` / `cryptroot` / `cp` / `unknown` case, because timing and system-maintenance evidence lined up well, but some short-lived helper attribution remained incomplete

The report is also bounded by the evidence available at investigation time. In particular:

- very short-lived processes may exit before full eBPF attribution is captured
- deleted temp artifacts may no longer be recoverable after the fact
- this review relied on host inspection and operating-system telemetry, not full memory forensics or disk imaging

Residual risk therefore remains low but non-zero. The more accurate conclusion is not "nothing suspicious happened," but rather "the available evidence supports benign explanations more strongly than compromise."

## 13. Root Cause

The root cause of the observed alerts is an over-sensitive behavior-based detection model operating without sufficient runtime context.

BannKenn is correctly detecting low-level patterns such as:

- temp-file creation
- rapid delete-after-write behavior
- rename bursts
- transient process activity
- high-throughput file operations

However, these patterns also occur during normal operation of:

- JVM/JNI applications
- databases
- package managers
- initramfs or cryptroot tooling
- Dockerized applications
- short-lived helper processes

Without process lineage awareness, package-manager context, container context, and executable/path validation, these benign events are scored too aggressively.

## 14. Security Assessment

### Confirmed

- No confirmed malware
- No confirmed cryptominer
- No confirmed persistence
- No confirmed unauthorized binary drop
- No confirmed malicious Java or MariaDB impersonation

### Noteworthy

- Multiple legitimate behaviors strongly resembled malware at the filesystem event level
- Some process attribution gaps remain, especially for short-lived processes labeled as `unknown`

### Overall Assessment

The systems investigated appear clean based on currently available evidence. The primary problem is false positives caused by context-poor detection logic.

## 15. Recommended Improvements for BannKenn

### 15.1 Add Context-Aware Scoring

A simple rule such as:

`/tmp write + delete = suspicious`

should be replaced with context-aware logic such as:

- temp write + delete
- plus executable content
- plus network activity
- plus non-whitelisted parent process
- plus persistence attempt

Only when multiple suspicious dimensions overlap should severity be elevated.

### 15.2 Add Executable and Lineage Validation

Examples of useful validation:

- `mariadbd` is acceptable when:
  - executable is `/usr/sbin/mariadbd`
  - parent is `node server/server.js`
  - process is inside container lineage

- Java temp extraction is acceptable when:
  - process command line matches known OpenSearch/Solr runtime
  - file activity is limited to expected temp directories
  - opened files are JNI `.so` libraries

### 15.3 Add Package-Manager Awareness

Alerts during active package installation should be downgraded or grouped differently.

Signals to use:

- recent `dpkg` or `apt` activity
- post-install execution windows
- known package helper tools such as:
  - `depmod`
  - `cryptroot`
  - `update-initramfs`
  - `ldconfig`

### 15.4 Improve Unknown Process Resolution

`unknown process activity` should not immediately imply suspicion. It should be treated as incomplete attribution until correlated with:

- short process lifetime
- container namespace boundaries
- cgroup/container identity
- concurrent network activity
- repeated recurrence

Unknown events without supporting malicious context should default to lower severity.

### 15.5 Add Container-Aware Detection

Container lineage should be incorporated into scoring. For example:

- `containerd-shim -> dumb-init -> node -> mariadbd`  
  should be treated differently from:  
- `bash -> mariadbd` from an unexpected host path

This reduces noise from self-contained application stacks.

### 15.6 Add Stronger Malware-Specific Triggers

Instead of relying primarily on temp-file burst patterns, prioritize signals such as:

- executable writes to `/tmp` or `/var/tmp` followed by `execve`
- temp writes followed by outbound network connections
- process masquerading where executable path does not match process name
- persistence creation after temp staging
- suspicious parent chains such as:
  - `curl | bash`
  - `sh -c`
  - shell spawned from temp path
- miner-like command lines, pools, or stratum connections

### 15.7 Prioritize the Detection v2 Rollout

The implementation order matters. The fastest path to materially better triage is:

1. Add trusted lineage, executable-path validation, and package-manager windows so obviously benign activity stops escalating immediately.
2. Improve attribution for `unknown` and containerized processes so analysts get better context with the existing telemetry.
3. Reserve high-severity scoring for strong malicious combinations such as temp-write-plus-exec, temp-write-plus-network, persistence creation, or path/name mismatch.

This keeps BannKenn useful during the transition: false positives fall first, while truly high-signal detections become easier to trust.

## 16. Suggested Rule Direction

A stronger high-confidence detection model would look like this:

Raise high severity only when one or more of the following are true:

- a process writes an executable to `/tmp` or `/var/tmp` and then executes it
- a temp-written process immediately initiates outbound network communication
- the executable path does not match a trusted system location for the claimed process name
- the process attempts persistence after temp staging
- the process is not in an allowlist and has no trusted lineage
- repeated temp bursts occur together with CPU spikes and miner-like network behavior

Downgrade or suppress when:

- process lineage maps to known containerized application behavior
- package installation or upgrade is active
- JVM/JNI extraction patterns match known software
- database temp-file activity matches expected execution path
- system maintenance tools are involved

## 17. Final Conclusion

The investigation did not reveal a compromise. The alerts were generated because BannKenn is already effective at observing low-level file and process behavior, but it currently interprets many legitimate runtime patterns as suspicious.

In practical terms, this is a tuning problem, not an incident response failure. The agent is capturing useful telemetry. The next step is to improve scoring and attribution so that normal Java, database, package, and container workflows do not generate unnecessary alerts, while truly malicious staging and fileless execution still stand out clearly.

## 18. Recommended Next Step

The recommended next phase is to design BannKenn Detection v2 with:

- package-manager awareness
- container awareness
- process-lineage-based scoring
- executable-path validation
- unknown-process correlation
- stronger malware-specific triggers instead of temp-path behavior alone

This would move the system from broad anomaly detection toward production-grade Linux EDR triage. It also aligns the investigation findings with the broader scoring and correlation direction already outlined in [BannKenn vNext Upgrade Proposal](02_RFC-vNext.md).
