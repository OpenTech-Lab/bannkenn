# tasks

## Done: Recreate follow-up tasks from `docs/05_Technical Investigation Report.md`

### Investigation-driven upgrade backlog
- [x] Recreate task inventory after manual cleanup of the old notes
- [x] Ship a concrete Detection v2 upgrade in the old containment scorer instead of leaving the report as documentation only
- [x] Reduce false positives for known benign temp-file activity described in the investigation report
- [x] Preserve genuinely suspicious temp-path behavior so the containment pipeline still escalates high-signal events
- [x] Add regression tests for the upgraded scorer behavior
- [x] Verify the agent crate still passes targeted tests after the scoring change

### Candidate follow-up tasks from the report
- [x] Package-manager awareness for `dpkg`/`apt` helper processes such as `depmod`, `cryptroot`, `update-initramfs`, and `ldconfig`
- [x] Known-runtime temp extraction downgrade for Java/OpenSearch/Solr JNI extraction patterns
- [x] Improve handling of `unknown process activity` so incomplete attribution is not treated as strong suspicion by itself
- [x] Add stronger malware-specific triggers such as temp-path executable or path/name mismatch weighting
- [ ] Evaluate future container-aware lineage enrichment beyond the current process snapshot model

### Current implementation target
- Upgrade the containment scorer to apply benign-context downgrades for package-maintenance helpers and known Java temp extraction patterns, and make `unknown process activity` require supporting suspicious signals before adding score.

### Review
- Implemented the upgrade in `agent/src/scorer.rs` rather than changing thresholds globally.
- Added temp-only benign-context downgrades for package-manager helpers and known Java/OpenSearch/Solr temp extraction behavior.
- Tightened `unknown process activity` so write-only unknown events no longer cross the suspicious threshold by bonus alone.
- Added a new high-signal boost for processes executing from `/tmp` or `/var/tmp`.
- Verification: `cargo test -p bannkenn-agent` passed after the change.
