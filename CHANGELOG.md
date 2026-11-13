# Packaging changelog

## 0.2.1 — 2026-11-13
- Missing pytest now exits 3 and reports FAIL / NOT_RUN, rather than a misleading full PASS.
- Explicit --release-only reports PARTIAL / SKIPPED; a failed release gate still fails.
- Preserve existing PYTHONPATH when adding src, and decode subprocess output as UTF-8.
- Rebuild installable wheel and update packaging metadata; add pinned test dependency.
- Frozen semantic sources, normative claims, release manifest and baseline ReleaseID are unchanged.
- Fresh Windows CPython 3.12.10: 92 regression tests, 30 oracles, 14 capabilities; installed wheel self-check passes.

The archived performance table is historical; it was not freshly benchmarked. Independent rigorous PDE backend replay remains OPEN.
