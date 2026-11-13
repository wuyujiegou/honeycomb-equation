from __future__ import annotations
from dataclasses import dataclass
from typing import FrozenSet, Tuple
from .canonical import content_id
from .types import *

@dataclass(frozen=True)
class CanonicalReport:
    run_spec_id: str
    output_id: str
    face_vector: FaceVector
    support_refs: Tuple[str, ...]
    residuals: Tuple[Residual, ...]
    status: str

class ReportBuilder:
    builder_id = "report-builder"
    version = "0.3.0"
    def build(self, run: RunSpec, output: OutputArtifact, faces: FaceVector, active: FrozenSet[str], residuals: Tuple[Residual, ...]) -> CanonicalReport:
        exact = output.kind.startswith("EXACT_")
        run_id = content_id(run)
        if output.model_id != run.model_id or output.query_id != run.query_id or output.scope != run.scope:
            status = "INVALID_OUTPUT_BINDING"
        elif exact and not output.support_refs:
            status = "INVALID_UNSUPPORTED_EXACT"
        elif not output.support_refs.issubset(active):
            status = "STALE"
        elif exact and faces.H_O != FaceState.PASS:
            status = "INVALID_OUTPUT_FACE"
        elif faces.H_R != FaceState.PASS:
            status = "STALE"
        elif exact and any(r.affects_query and r.effect in {"BLOCKS_EXACT", "BOUNDED"} for r in residuals):
            status = "INVALID_AFFECTING_RESIDUAL"
        else:
            status = "CURRENT"
        supports = tuple(sorted(output.support_refs, key=lambda s: content_id(s)))
        return CanonicalReport(run_id, content_id(output), faces, supports, tuple(sorted(residuals, key=lambda r: content_id(r))), status)
