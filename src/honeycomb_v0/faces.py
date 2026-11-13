from __future__ import annotations
from dataclasses import dataclass
from typing import FrozenSet
from .canonical import content_id
from .types import *


@dataclass(frozen=True)
class FaceInputs:
    input_evidence: ObligationEvidence | None
    exactness_witness: ExactnessWitness | None
    output: OutputArtifact | None
    active: FrozenSet[str]
    verified_support: FrozenSet[str]
    dynamic_evidence: ObligationEvidence | None = None
    numerical_evidence: ObligationEvidence | None = None


class FaceEvaluator:
    evaluator_id = "face-evaluator"
    version = "0.5.0-reconstructed"

    @staticmethod
    def _obligation_state(run: RunSpec, evidence: ObligationEvidence | None,
                          obligation: str, active: FrozenSet[str]) -> FaceState:
        if evidence is None:
            return FaceState.OPEN
        if (evidence.model_id != run.model_id or evidence.query_id != run.query_id or
                evidence.scope != run.scope or evidence.obligation != obligation):
            return FaceState.FAIL
        eid = content_id(evidence)
        if eid not in active or not evidence.support_refs.issubset(active):
            return FaceState.OPEN
        return {
            "SATISFIED": FaceState.PASS,
            "VIOLATED": FaceState.FAIL,
            "CONDITIONAL": FaceState.CONDITIONAL,
        }.get(evidence.conclusion, FaceState.FAIL)

    @staticmethod
    def _exact_witness_valid(run: RunSpec, witness: ExactnessWitness | None,
                             output: OutputArtifact | None, active: FrozenSet[str]) -> bool:
        if witness is None or output is None:
            return False
        return (
            witness.model_id == run.model_id and witness.query_id == run.query_id and
            witness.scope == run.scope and witness.output_id == content_id(output) and
            witness.output_kind == output.kind and content_id(witness) in active and
            witness.support_refs and witness.support_refs.issubset(active)
        )

    def evaluate(self, run: RunSpec, x: FaceInputs) -> FaceVector:
        declared_na = set(run.declared_na)
        allowed_na = {"H_delta", "H_N"}
        manifest_invalid = bool(declared_na - allowed_na)
        if manifest_invalid:
            return FaceVector(FaceState.FAIL, FaceState.FAIL, FaceState.FAIL,
                              FaceState.FAIL, FaceState.OPEN, FaceState.FAIL)

        hi = self._obligation_state(run, x.input_evidence, "H_I", x.active)

        o = x.output
        if o is None:
            ho = FaceState.FAIL
            hr = FaceState.FAIL
        else:
            invalid_kind = o.kind.startswith("INVALID_") or o.kind in {"CONFLICT_LEAK", "UNVERIFIED_FACT"}
            output_bound = o.model_id == run.model_id and o.query_id == run.query_id and o.scope == run.scope
            exact_requires_support = (not o.kind.startswith("EXACT_")) or bool(o.support_refs)
            locally_verified = o.support_refs.issubset(x.verified_support)
            ho = FaceState.PASS if (output_bound and not invalid_kind and exact_requires_support and locally_verified) else FaceState.FAIL
            hr = FaceState.PASS if o.support_refs.issubset(x.active) else FaceState.FAIL

        if "H_delta" in declared_na:
            hd = FaceState.NA
        else:
            hd = self._obligation_state(run, x.dynamic_evidence, "H_delta", x.active)

        if "H_N" in declared_na:
            hn = FaceState.NA
        else:
            hn = self._obligation_state(run, x.numerical_evidence, "H_N", x.active)

        he = FaceState.PASS if (hi == FaceState.PASS and self._exact_witness_valid(
            run, x.exactness_witness, o, x.active)) else FaceState.OPEN
        return FaceVector(hi, ho, hd, hn, he, hr)
