from __future__ import annotations
from dataclasses import dataclass
from typing import FrozenSet, Iterable, Tuple
from .canonical import content_id
from .faces import FaceEvaluator, FaceInputs
from .kernel import CertifiedRoot, CertifiedSupportRule, RuntimeTrustPolicy, SupportKernel, TrustGate
from .report import CanonicalReport, ReportBuilder
from .types import ExactnessWitness, FaceVector, ObligationEvidence, OutputArtifact, Residual, RunSpec


@dataclass(frozen=True)
class ClosedLoopResult:
    active: FrozenSet[str]
    verified_support: FrozenSet[str]
    faces: FaceVector
    report: CanonicalReport


class ClosedLoopEvaluator:
    """Normative orchestration boundary for reconstructed HE closed-loop semantics.

    The caller supplies typed certified roots/rules and a frozen trust policy; this
    object performs the actual TrustGate + certified quarantine before face/report
    evaluation. A stage label named CHECK has no authority here.
    """
    evaluator_id = "he-closed-loop-evaluator"
    version = "0.1.0-reconstructed"

    def run(self, run: RunSpec, *, roots: Iterable[CertifiedRoot], rules: Iterable[CertifiedSupportRule],
            policy: RuntimeTrustPolicy, conflicts: Iterable[Tuple[str, str]], output: OutputArtifact,
            input_evidence: ObligationEvidence | None, exactness_witness: ExactnessWitness | None,
            dynamic_evidence: ObligationEvidence | None = None,
            numerical_evidence: ObligationEvidence | None = None,
            residuals: Tuple[Residual, ...] = tuple()) -> ClosedLoopResult:
        root_rows = tuple(roots); rule_rows = tuple(rules)
        gate = TrustGate()
        trusted_roots = gate.roots(root_rows, policy)
        trusted_rules = gate.rules(rule_rows, policy)
        verified_support = frozenset(set(trusted_roots) | {r.conclusion for r in trusted_rules})
        active = SupportKernel().quarantine(trusted_roots, trusted_rules, tuple(conflicts))
        face_inputs = FaceInputs(input_evidence, exactness_witness, output, active, verified_support,
                                 dynamic_evidence, numerical_evidence)
        faces = FaceEvaluator().evaluate(run, face_inputs)
        report = ReportBuilder().build(run, output, faces, active, residuals)
        return ClosedLoopResult(active, verified_support, faces, report)


def obligation_evidence(model_id: str, query_id: str, scope, obligation: str,
                        conclusion: str, support_refs: FrozenSet[str]) -> ObligationEvidence:
    return ObligationEvidence(model_id, query_id, scope, obligation, conclusion, support_refs)


def exactness_witness(output: OutputArtifact, support_refs: FrozenSet[str]) -> ExactnessWitness:
    return ExactnessWitness(output.model_id, output.query_id, output.scope, content_id(output), output.kind, support_refs)


def closed_loop_pass(run: RunSpec, result: ClosedLoopResult) -> bool:
    """Release-level closed-loop gate for the six frozen faces.

    Only H_delta and H_N may be predeclared N/A. Every other face must PASS;
    declared N/A faces must actually evaluate to N/A, and the report must be CURRENT.
    """
    allowed_na = {"H_delta", "H_N"}
    if set(run.declared_na) - allowed_na:
        return False
    rows = {
        "H_I": result.faces.H_I,
        "H_O": result.faces.H_O,
        "H_delta": result.faces.H_delta,
        "H_N": result.faces.H_N,
        "H_E": result.faces.H_E,
        "H_R": result.faces.H_R,
    }
    for name, state in rows.items():
        if name in run.declared_na:
            if state.value != "N/A":
                return False
        elif state.value != "PASS":
            return False
    return result.report.status == "CURRENT"
