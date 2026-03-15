# BannKenn vNext — Implementation Plan

## Deployment
- [ ] Add eBPF build stage to Docker (linux-headers, clang, llvm)
- [x] Feature flags default: enabled=false, dry_run=true, fuse_enabled=false
- [x] Update installer for kernel version check (Linux 5.8+ required)
- [ ] Rollback documentation

## Optional Deployment / Runtime Follow-Up
- [ ] Teach `bannkenn-agent update` to fetch/install the matching `.bpf.o` release asset
- [ ] Add a Dockerized agent build/package path that includes the containment BPF object when containerized agent distribution is needed
- [ ] Exercise real privileged eBPF attachment on a Linux host and document the exact runtime capability requirements
- [ ] Exercise real privileged cgroup/tc containment enforcement on a Linux host and document the exact runtime prerequisites/observed behavior

## tasks
