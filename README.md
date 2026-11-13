# Honeycomb Equation — Reference Executable Semantics (v0.2.1)

Reference executable semantics and conformance kernel for the **Honeycomb Equation (HE)** framework: query-scoped PDE certification, provenance, conformance and semantic regression checks.

## Records

| Item | DOI | Version | License |
|---|---|---|---|
| Preprint — *Honeycomb Equation Reference Executable Semantics for Query-Scoped PDE Certification* | [10.5281/zenodo.24189752](https://doi.org/10.5281/zenodo.24189752) | 1.0 | CC BY 4.0 |
| Software — this artifact | [10.5281/zenodo.24189825](https://doi.org/10.5281/zenodo.24189825) | 0.2.1 | MIT |

- Preprint record: https://zenodo.org/records/24189752
- Software record: https://zenodo.org/records/24189825

## Scope

This is a **reference semantics / conformance package**, not a general-purpose PDE solver. Packaging revision **0.2.1** fixes verification result reporting; the semantic baseline is unchanged.

Independent rigorous PDE backend replay remains **OPEN**.

## Contents

- `src/honeycomb_v0/` — reference kernel, DSL, assemblers, faces, checkers, conformance
- `examples/` — 13 example model / query / bundle / evidence JSON files
- `tests/` — 5 test modules
- `policy/`, `rules/`, `theorems/`, `manifests/` — trust policy, adapter rules, theorem fixtures, release manifest
- `dist/` — built wheel `honeycomb_v0_prototype-0.2.1-py3-none-any.whl`
- `reproducibility/` — HE Reproducibility v0.3 original package
- `verify_package.py`, `run_pde.py`, `run_release.py`, `run_weak_evidence.py`, `build_release_manifest.py`

## Citation

See `CITATION.cff`. Author: **Zhang, Bingchao** — ORCID [0009-0004-1160-2602](https://orcid.org/0009-0004-1160-2602), Huangshi Wuyu Structural Intelligence Technology Co., Ltd.

## License

MIT — see `LICENSE`.

## Checksums

`SHA256SUMS.txt` at this repository root lists SHA-256 values for every tracked file except the manifest itself. It is computed from the Git blob bytes of the commit that first added the manifest, so it describes that repository snapshot.

Three checksum contexts are distinct and should not be conflated:

- **Repository manifest** (this file, `SHA256SUMS.txt` at the repository root) — the current repository snapshot.
- **Archived manifest** (inside `HE_Software_v0.2.1.zip`) — the frozen packaging snapshot, unchanged.
- **Zenodo manifest** (`SHA256SUMS.txt` published in the Zenodo software record) — covers the full local handoff folder, including documents that were not uploaded; it does not verify against the Zenodo download directory alone.

Working trees on Windows may check out CRLF line endings while the stored blobs are LF. To reproduce the manifest, read the blob bytes (`git cat-file -p <blob>`) or download the raw file from GitHub, not a local working copy.

