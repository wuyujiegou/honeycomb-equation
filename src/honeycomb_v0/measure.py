from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import sys
from typing import FrozenSet, Tuple

from .assemblers import QueryAssembler, measure_projection_fact, query_fact_id
from .canonical import content_id, file_sha256
from .checkers import MeasureValuedQueryChecker
from .faces import FaceEvaluator, FaceInputs
from .kernel import CertifiedSupportRule, RuntimeTrustPolicy, SupportKernel, TrustGate
from .report import CanonicalReport, ReportBuilder
from .types import (
    CheckResult, FaceVector, MeasureValuedOuterRelation, MeasureValuedQueryProjection,
    OutputArtifact, QueryTransparencyClaim, Residual, RunSpec, ExactnessWitness, ObligationEvidence,
    WeakLimitClaim, WeakQueryProfile,
)


def _module_hash(obj: object) -> str:
    mod=sys.modules[obj.__module__]
    path=getattr(mod,"__file__",None)
    if not path:
        raise RuntimeError(f"module file unavailable: {obj.__module__}")
    return file_sha256(Path(path))


@dataclass(frozen=True)
class MeasureValuedQueryRunResult:
    status: str
    reason: str
    projection: MeasureValuedQueryProjection | None
    output: OutputArtifact | None
    exactness_witness: ExactnessWitness | None
    faces: FaceVector | None
    report: CanonicalReport | None
    residuals: Tuple[Residual, ...]
    active: FrozenSet[str]


class MeasureValuedQueryPipeline:
    """Certified projection of a measure-valued outer relation onto a typed query.

    Input `active` is the already-certified Ksafe slice containing the weak/measure
    claims. New projection/query-fact edges are verified, content-addressed, and
    signed by the pinned checker/assembler executables.
    """
    pipeline_id="measure-valued-query-pipeline"
    version="0.1.0"

    @staticmethod
    def _extend(active: FrozenSet[str], rule: CertifiedSupportRule, allowed: tuple[str,str,str]) -> FrozenSet[str]:
        policy=RuntimeTrustPolicy("measure-query-local",frozenset({allowed}))
        trusted=TrustGate().rules((rule,),policy)
        return SupportKernel().closure(active,trusted)

    def run(self, relation: MeasureValuedOuterRelation, query: WeakQueryProfile, active: FrozenSet[str], *,
            release_id: str="measure-valued-query",
            defect_annihilation: WeakLimitClaim | None=None,
            transparency: QueryTransparencyClaim | None=None) -> MeasureValuedQueryRunResult:
        checker=MeasureValuedQueryChecker()
        cr,projection=checker.check(relation,query,active,defect_annihilation,transparency)
        if cr!=CheckResult.VALID or projection is None:
            return MeasureValuedQueryRunResult("INVALID",f"measure-valued query check failed: {cr.value}",None,None,None,None,None,tuple(),active)

        checker_hash=_module_hash(MeasureValuedQueryChecker)
        projection_id=content_id(projection)
        prule=CertifiedSupportRule(projection.support_refs,projection_id,checker.checker_id,checker_hash,"MEASURE_QUERY_PROJECTION_DERIVATION")
        active=self._extend(active,prule,(checker.checker_id,checker_hash,"MEASURE_QUERY_PROJECTION_DERIVATION"))

        residuals=[]
        if projection.status=="OPEN_DEFECT":
            for kind in projection.missing_defects:
                residuals.append(Residual(f"missing-{kind.lower()}-representation","BLOCKS_EXACT",True))

        fact=measure_projection_fact(projection)
        if fact is None:
            return MeasureValuedQueryRunResult("INVALID","projection could not be converted to query fact",projection,None,None,None,None,tuple(),active)
        fact_id=query_fact_id(fact)
        assembler_hash=_module_hash(QueryAssembler)
        frule=CertifiedSupportRule(frozenset({projection_id}),fact_id,QueryAssembler.assembler_id,assembler_hash,"MEASURE_QUERY_FACT_BINDING")
        active=self._extend(active,frule,(QueryAssembler.assembler_id,assembler_hash,"MEASURE_QUERY_FACT_BINDING"))

        input_evidence=ObligationEvidence(query.model_id,query.query_id,query.scope,"H_I","SATISFIED",frozenset({projection_id}))
        irule=CertifiedSupportRule(input_evidence.support_refs,content_id(input_evidence),QueryAssembler.assembler_id,assembler_hash,"MEASURE_QUERY_INPUT_CLOSURE")
        active=self._extend(active,irule,(QueryAssembler.assembler_id,assembler_hash,"MEASURE_QUERY_INPUT_CLOSURE"))

        if projection.status=="CERTIFIED_OUTER_QUERY_RELATION":
            residuals.append(Residual("outer-relaxation-not-query-transparent","BLOCKS_EXACT",True))

        output=QueryAssembler().assemble(query.model_id,query.query_id,query.scope,"RELATION",(fact,),active)
        exact_witness=None
        if projection.status=="EXACT_QUERY_RELATION":
            exact_witness=ExactnessWitness(query.model_id,query.query_id,query.scope,content_id(output),output.kind,frozenset({fact_id}))
            wrule=CertifiedSupportRule(exact_witness.support_refs,content_id(exact_witness),QueryAssembler.assembler_id,assembler_hash,"MEASURE_QUERY_EXACTNESS_BINDING")
            active=self._extend(active,wrule,(QueryAssembler.assembler_id,assembler_hash,"MEASURE_QUERY_EXACTNESS_BINDING"))
            residuals.append(Residual("measure-defect-query-transparent","CERTIFIED_NONE",True))
        run=RunSpec(query.model_id,query.query_id,query.scope,release_id,frozenset({"H_delta","H_N"}))
        faces=FaceEvaluator().evaluate(run,FaceInputs(input_evidence,exact_witness,output,active,active,None,None))
        report=ReportBuilder().build(run,output,faces,active,tuple(residuals))
        ok=((projection.status=="EXACT_QUERY_RELATION" and output.kind=="EXACT_RELATION") or
            (projection.status=="CERTIFIED_OUTER_QUERY_RELATION" and output.kind=="CERTIFIED_OUTER_RELATION") or
            (projection.status=="OPEN_DEFECT" and output.kind=="OPEN")) and report.status=="CURRENT"
        out_status="OPEN" if projection.status=="OPEN_DEFECT" and ok else ("VALID" if ok else "INVALID")
        reason="required defect representation is missing" if out_status=="OPEN" else ("measure-valued query projection assembled" if ok else "measure-valued query assembly failed")
        return MeasureValuedQueryRunResult(out_status,reason,projection,output,exact_witness,faces,report,tuple(residuals),active)
