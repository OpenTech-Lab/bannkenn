# BannKenn vNext — Implementation Plan

## Deployment
- [x] Add eBPF build stage to Docker (linux-headers, clang, llvm)
- [x] Feature flags default: enabled=false, dry_run=true, fuse_enabled=false
- [x] Update installer for kernel version check (Linux 5.8+ required)
- [x] Rollback documentation

## Optional Deployment / Runtime Follow-Up
- [x] Teach `bannkenn-agent update` to fetch/install the matching `.bpf.o` release asset
- [x] Keep GitHub Releases + `sudo bannkenn-agent init` as the primary agent distribution path; no separate Dockerized agent package path is required
- [ ] Exercise real privileged eBPF attachment on a Linux host and document the exact runtime capability requirements
- [ ] Exercise real privileged cgroup/tc containment enforcement on a Linux host and document the exact runtime prerequisites/observed behavior

## tasks
