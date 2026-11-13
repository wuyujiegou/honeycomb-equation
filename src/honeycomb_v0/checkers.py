from __future__ import annotations
from dataclasses import dataclass
from fractions import Fraction
from typing import Dict, FrozenSet, Tuple
from .types import *
from .canonical import content_id

ZERO = "ZERO"

def projection_claim_semantic_id(model_id: str, reader_id: str, term_id: str, query_id: str, scope: Scope, projected_object: str, exact: bool=True) -> str:
    return content_id({"type":"ProjectionClaim","model_id":model_id,"reader_id":reader_id,"term_id":term_id,"query_id":query_id,"scope":scope,"projected_object":projected_object,"exact":exact})

def target_link_semantic_id(model_id: str, reader_id: str, storage_term_id: str, query_id: str, scope: Scope, target_derivative_object: str) -> str:
    return content_id({"type":"TargetDerivativeLink","model_id":model_id,"reader_id":reader_id,"storage_term_id":storage_term_id,"query_id":query_id,"scope":scope,"target_derivative_object":target_derivative_object})

def transport_claim_semantic_id(source_model_id: str, target_model_id: str, exact: bool=True) -> str:
    return content_id({"type":"RelationTransportClaim","source_model_id":source_model_id,"target_model_id":target_model_id,"exact":exact})


@dataclass(frozen=True)
class NormalizationManifest:
    source_relation_id: str
    ir_relation_id: str
    source_term_ids: Tuple[str, ...]
    mappings: Tuple[Tuple[str, str, int], ...]
    storage_mapping: Tuple[str, str] | None = None

class NormalizationValidator:
    checker_id = "normalization-validator"
    version = "0.3.0"
    def check(self, source: SourceBalanceSpec, ir: BalanceRelationIR, m: NormalizationManifest) -> CheckResult:
        if source.model_id != ir.model_id:
            return CheckResult.INVALID
        if m.source_relation_id != source.relation_id or m.ir_relation_id != ir.relation_id:
            return CheckResult.INVALID
        source_ids = [t.term_id for t in source.terms]
        if len(set(source_ids)) != len(source_ids):
            return CheckResult.INVALID
        if sorted(source_ids) != sorted(m.source_term_ids):
            return CheckResult.INVALID
        mapped_src = [a for a, _, _ in m.mappings]
        mapped_ir = [b for _, b, _ in m.mappings]
        ir_ids = [t.term_id for t in ir.terms]
        if sorted(source_ids) != sorted(mapped_src) or sorted(ir_ids) != sorted(mapped_ir):
            return CheckResult.INVALID
        if len(set(mapped_src)) != len(mapped_src) or len(set(mapped_ir)) != len(mapped_ir):
            return CheckResult.INVALID
        src_map = {t.term_id: t for t in source.terms}
        ir_map = {t.term_id: t for t in ir.terms}
        for a, b, sign in m.mappings:
            st, it = src_map[a], ir_map[b]
            if st.sign != sign or it.sign != sign:
                return CheckResult.INVALID
            if (st.role, st.expression, st.semantic_ref) != (it.role, it.expression, it.semantic_ref):
                return CheckResult.INVALID
        if source.storage_term_id:
            if source.scope != ir.scope:
                return CheckResult.INVALID
            if not m.storage_mapping or m.storage_mapping != (source.storage_term_id, ir.storage_term_id):
                return CheckResult.INVALID
            if source.storage_expression != ir.storage_expression:
                return CheckResult.INVALID
        return CheckResult.VALID

class ExactLinearAlgebraChecker:
    checker_id = "exact-linear-algebra"
    version = "0.2.0"
    @staticmethod
    def _exact_scalar(v) -> bool:
        return (isinstance(v, (int, Fraction)) and not isinstance(v, bool))
    @classmethod
    def row_times_matrix(cls, row: Tuple[Fraction, ...], mat: Tuple[Tuple[Fraction, ...], ...]) -> Tuple[Fraction, ...]:
        if not isinstance(row, tuple) or not isinstance(mat, tuple):
            raise ValueError("exact tuple carriers required")
        if any(not cls._exact_scalar(v) for v in row):
            raise ValueError("non-exact row scalar")
        if not mat:
            if row:
                raise ValueError("shape mismatch")
            return tuple()
        if len(row) != len(mat):
            raise ValueError("shape mismatch")
        if any(not isinstance(r, tuple) for r in mat):
            raise ValueError("matrix rows must be tuples")
        widths = {len(r) for r in mat}
        if len(widths) != 1:
            raise ValueError("ragged matrix")
        if any(not cls._exact_scalar(v) for r in mat for v in r):
            raise ValueError("non-exact matrix scalar")
        n = next(iter(widths))
        return tuple(sum(row[i] * mat[i][j] for i in range(len(row))) for j in range(n))
    def check_row_zero(self, row, mat) -> CheckResult:
        try:
            out = self.row_times_matrix(row, mat)
        except Exception:
            return CheckResult.INVALID
        return CheckResult.VALID if all(v == 0 for v in out) else CheckResult.INVALID

class BalanceReaderChecker:
    checker_id = "balance-reader"
    version = "0.4.0"
    def check(self, balance: BalanceRelationIR, ev: BalanceReaderEvidence, active: FrozenSet[str],
              projections: Dict[str, ProjectionClaim], target_links: Dict[str, TargetDerivativeLink]) -> tuple[CheckResult, BalanceLaw | None]:
        if ev.model_id != balance.model_id or ev.balance_ref != balance.relation_id or ev.scope != balance.scope:
            return CheckResult.INVALID, None
        if not ev.reader_admissibility_claims or not ev.reader_admissibility_claims.issubset(active):
            return CheckResult.INVALID, None
        link = target_links.get(ev.target_link_claim_id)
        if link is None or ev.target_link_claim_id not in active:
            return CheckResult.INVALID, None
        if link.claim_id != target_link_semantic_id(link.model_id,link.reader_id,link.storage_term_id,link.query_id,link.scope,link.target_derivative_object):
            return CheckResult.INVALID, None
        if (link.model_id, link.reader_id, link.storage_term_id, link.query_id, link.scope) != (ev.model_id, ev.reader_id, balance.storage_term_id, ev.query_id, ev.scope):
            return CheckResult.INVALID, None
        ir_ids = [t.term_id for t in balance.terms]
        evidence_ids = [x.term_id for x in ev.projected_terms]
        if sorted(ir_ids) != sorted(evidence_ids) or len(set(evidence_ids)) != len(evidence_ids):
            return CheckResult.INVALID, None
        tmap = {t.term_id: t for t in balance.terms}
        retained, defects, supports = [], [], set(ev.reader_admissibility_claims) | {link.claim_id}
        for pe in ev.projected_terms:
            pc = projections.get(pe.projection_claim_id)
            if pc is None or pc.claim_id not in active or not pc.exact:
                return CheckResult.INVALID, None
            if pc.claim_id != projection_claim_semantic_id(pc.model_id,pc.reader_id,pc.term_id,pc.query_id,pc.scope,pc.projected_object,pc.exact):
                return CheckResult.INVALID, None
            if (pc.model_id, pc.reader_id, pc.term_id, pc.query_id, pc.scope, pc.projected_object) != (ev.model_id, ev.reader_id, pe.term_id, ev.query_id, ev.scope, pe.projected_object):
                return CheckResult.INVALID, None
            supports.add(pc.claim_id)
            sign = tmap[pe.term_id].sign
            if pe.action == Action.ANNIHILATE:
                if pe.projected_object != ZERO:
                    return CheckResult.INVALID, None
            elif pe.action == Action.RETAIN:
                if pe.projected_object == ZERO:
                    return CheckResult.INVALID, None
                retained.append((sign, pe.projected_object))
            elif pe.action == Action.DEFECT:
                if pe.projected_object == ZERO:
                    return CheckResult.INVALID, None
                defects.append((sign, pe.projected_object))
            else:
                return CheckResult.UNSUPPORTED, None
        law = BalanceLaw(balance.model_id, balance.relation_id, ev.query_id, ev.scope, link.target_derivative_object,
                         tuple(retained), tuple(defects), frozenset(supports))
        return CheckResult.VALID, law

class IdentityTransportChecker:
    checker_id = "identity-transport"
    version = "0.1.0"
    def check(self, source_model_id: str, target_model_id: str,
              claim: RelationTransportClaim | None, active: FrozenSet[str]) -> CheckResult:
        if source_model_id == target_model_id:
            return CheckResult.VALID
        if claim is None or claim.claim_id not in active or not claim.exact:
            return CheckResult.INVALID
        if claim.claim_id != transport_claim_semantic_id(claim.source_model_id,claim.target_model_id,claim.exact):
            return CheckResult.INVALID
        if (claim.source_model_id, claim.target_model_id) != (source_model_id, target_model_id):
            return CheckResult.INVALID
        return CheckResult.VALID


def defect_bound_claim_semantic_id(owner_id: str, defect_id: str, scope: Scope, projected_object: str, epsilon: Fraction) -> str:
    return content_id({"type":"DefectBoundClaim","owner_id":owner_id,"defect_id":defect_id,"scope":scope,"projected_object":projected_object,"epsilon":epsilon})


def infinite_dual_claim_semantic_id(operator_id: str, target_id: str, scope: Scope, kind: str, witness_ref: str | None = None) -> str:
    return content_id({"type":"InfiniteDualClaim","operator_id":operator_id,"target_id":target_id,"scope":scope,"kind":kind,"witness_ref":witness_ref})


def weak_limit_claim_semantic_id(model_id: str, relation_id: str, sequence_id: str, query_id: str, scope: Scope, kind: str) -> str:
    return content_id({"type":"WeakLimitClaim","model_id":model_id,"relation_id":relation_id,"sequence_id":sequence_id,"query_id":query_id,"scope":scope,"kind":kind})


def query_transparency_claim_semantic_id(model_id: str, strong_relation_id: str, outer_relation_id: str, query_id: str, scope: Scope, theorem_fixture_id: str, theorem_fixture_content_id: str) -> str:
    return content_id({
        "type":"QueryTransparencyClaim",
        "model_id":model_id,
        "strong_relation_id":strong_relation_id,
        "outer_relation_id":outer_relation_id,
        "query_id":query_id,
        "scope":scope,
        "theorem_fixture_id":theorem_fixture_id,
        "theorem_fixture_content_id":theorem_fixture_content_id,
    })


class DefectPropagationChecker:
    """Exact rational v0 propagation: |sum a_j d_j| <= sum |a_j| epsilon_j."""
    checker_id = "defect-propagation"
    version = "0.1.0"

    def check(self, ev: DefectPropagationEvidence, active: FrozenSet[str]) -> tuple[CheckResult, DefectPropagationResult | None]:
        if ev.scope.level not in {ScopeLevel.CONTINUUM, ScopeLevel.DISCRETE}:
            return CheckResult.UNSUPPORTED, None
        supports=set()
        total=Fraction(0)
        if not ev.terms:
            return CheckResult.INVALID, None
        for coeff, claim in ev.terms:
            if not isinstance(coeff,int) or isinstance(coeff,bool):
                return CheckResult.INVALID, None
            if not isinstance(claim.epsilon,Fraction) or claim.epsilon < 0:
                return CheckResult.INVALID, None
            expected=defect_bound_claim_semantic_id(claim.owner_id,claim.defect_id,claim.scope,claim.projected_object,claim.epsilon)
            if claim.claim_id != expected or claim.claim_id not in active or claim.scope != ev.scope:
                return CheckResult.INVALID, None
            supports.add(claim.claim_id)
            total += abs(coeff)*claim.epsilon
        return CheckResult.VALID, DefectPropagationResult((-total,total),frozenset(supports))


class InfiniteDimensionalDualChecker:
    """Separates Hilbert-space uniqueness from an executable bounded adjoint witness."""
    checker_id = "infinite-dimensional-dual"
    version = "0.1.0"
    _KINDS=frozenset({"KERNEL_ANNIHILATION","ADJOINT_CLOSURE_MEMBERSHIP","CLOSED_RANGE","ADJOINT_WITNESS"})

    def check(self, claims: Tuple[InfiniteDualClaim,...], active: FrozenSet[str]) -> tuple[CheckResult, InfiniteDualAssessment | None]:
        if not claims:
            return CheckResult.INVALID, None
        base=(claims[0].operator_id,claims[0].target_id,claims[0].scope)
        kinds=set(); supports=set()
        for c in claims:
            if (c.operator_id,c.target_id,c.scope)!=base or c.kind not in self._KINDS:
                return CheckResult.INVALID, None
            if c.claim_id != infinite_dual_claim_semantic_id(c.operator_id,c.target_id,c.scope,c.kind,c.witness_ref):
                return CheckResult.INVALID, None
            if c.claim_id not in active:
                return CheckResult.INVALID, None
            if c.kind=="ADJOINT_WITNESS" and not c.witness_ref:
                return CheckResult.INVALID, None
            kinds.add(c.kind); supports.add(c.claim_id)
        uniqueness = "EXACT_UNIQUENESS" if kinds & {"KERNEL_ANNIHILATION","ADJOINT_CLOSURE_MEMBERSHIP","ADJOINT_WITNESS"} else "OPEN"
        if "ADJOINT_WITNESS" in kinds:
            range_credit="RANGE_WITH_BOUNDED_WITNESS"
            computational="BOUNDED_DUAL_CERTIFICATE"
        elif "ADJOINT_CLOSURE_MEMBERSHIP" in kinds and "CLOSED_RANGE" in kinds:
            range_credit="RANGE_EXISTENCE_NONCONSTRUCTIVE"
            computational="NO_EXECUTABLE_DUAL_WITNESS"
        elif "ADJOINT_CLOSURE_MEMBERSHIP" in kinds:
            range_credit="CLOSURE_ONLY"
            computational="NO_EXECUTABLE_DUAL_WITNESS"
        else:
            range_credit="UNESTABLISHED"
            computational="NO_EXECUTABLE_DUAL_WITNESS"
        return CheckResult.VALID, InfiniteDualAssessment(uniqueness,range_credit,computational,frozenset(supports))


class WeakLimitDefectChecker:
    """Typed weak-limit firewall; accounting a defect is not the same as strong/query exactness."""
    checker_id = "weak-limit-defect"
    version = "0.1.0"
    _KINDS=frozenset({"WEAK_STATE","YOUNG_MEASURE","CONCENTRATION_MEASURE","DEFECT_ANNIHILATION"})

    def check(self, observable_kind: str, claims: Tuple[WeakLimitClaim,...], active: FrozenSet[str]) -> tuple[CheckResult, WeakLimitAssessment | None]:
        if observable_kind not in {"LINEAR","NONLINEAR_OSCILLATION","CONCENTRATION_SENSITIVE"} or not claims:
            return CheckResult.INVALID, None
        base=(claims[0].model_id,claims[0].relation_id,claims[0].sequence_id,claims[0].query_id,claims[0].scope)
        kinds=set(); supports=set()
        for c in claims:
            if (c.model_id,c.relation_id,c.sequence_id,c.query_id,c.scope)!=base or c.kind not in self._KINDS:
                return CheckResult.INVALID, None
            if c.claim_id != weak_limit_claim_semantic_id(c.model_id,c.relation_id,c.sequence_id,c.query_id,c.scope,c.kind) or c.claim_id not in active:
                return CheckResult.INVALID, None
            kinds.add(c.kind); supports.add(c.claim_id)
        if "WEAK_STATE" not in kinds:
            return CheckResult.INVALID, None
        if "DEFECT_ANNIHILATION" in kinds:
            status="QUERY_EXACT_DEFECT_INVISIBLE"
        elif observable_kind=="LINEAR":
            status="QUERY_EXACT_WEAK_CONTINUITY"
        elif observable_kind=="NONLINEAR_OSCILLATION":
            status="DEFECT_ACCOUNTED" if "YOUNG_MEASURE" in kinds else "DEFECT_REQUIRED"
        else:
            if "YOUNG_MEASURE" not in kinds:
                status="DEFECT_REQUIRED"
            elif "CONCENTRATION_MEASURE" not in kinds:
                status="CONCENTRATION_DEFECT_REQUIRED"
            else:
                status="DEFECT_ACCOUNTED"
        return CheckResult.VALID, WeakLimitAssessment(status,frozenset(supports))


class MeasureValuedQueryChecker:
    """Projects a certified measure-valued outer relation onto a typed query without laundering outer credit into strong exactness."""
    checker_id = "measure-valued-query"
    version = "0.1.0"

    @staticmethod
    def _required_defects(observable_kind: str) -> tuple[str, ...]:
        if observable_kind == "LINEAR":
            return tuple()
        if observable_kind == "NONLINEAR_OSCILLATION":
            return ("OSCILLATION",)
        if observable_kind == "CONCENTRATION_SENSITIVE":
            return ("OSCILLATION","CONCENTRATION")
        raise ValueError("unsupported observable kind")

    def check(self, relation: MeasureValuedOuterRelation, query: WeakQueryProfile, active: FrozenSet[str],
              defect_annihilation: WeakLimitClaim | None = None,
              transparency: QueryTransparencyClaim | None = None) -> tuple[CheckResult, MeasureValuedQueryProjection | None]:
        if (relation.model_id, relation.relation_id, relation.scope) != (query.model_id, query.relation_id, query.scope):
            return CheckResult.INVALID, None
        if query.observable_kind not in {"LINEAR","NONLINEAR_OSCILLATION","CONCENTRATION_SENSITIVE"}:
            return CheckResult.INVALID, None
        claims=tuple(relation.weak_claims)
        if not claims or relation.support_refs != frozenset(c.claim_id for c in claims):
            return CheckResult.INVALID, None
        if len({c.kind for c in claims}) != len(claims):
            return CheckResult.INVALID, None
        if not relation.support_refs.issubset(active):
            return CheckResult.INVALID, None
        for c in claims:
            if c.model_id != relation.model_id or c.relation_id != relation.relation_id or c.sequence_id != relation.sequence_id or c.scope != relation.scope or c.query_id != query.query_id:
                return CheckResult.INVALID, None
            if c.kind == "DEFECT_ANNIHILATION":
                return CheckResult.INVALID, None
        query_claims=list(claims)
        supports=set(relation.support_refs)
        if defect_annihilation is not None:
            if (defect_annihilation.model_id,defect_annihilation.relation_id,defect_annihilation.sequence_id,defect_annihilation.query_id,defect_annihilation.scope,defect_annihilation.kind) != (relation.model_id,relation.relation_id,relation.sequence_id,query.query_id,query.scope,"DEFECT_ANNIHILATION"):
                return CheckResult.INVALID, None
            if defect_annihilation.claim_id != weak_limit_claim_semantic_id(defect_annihilation.model_id,defect_annihilation.relation_id,defect_annihilation.sequence_id,defect_annihilation.query_id,defect_annihilation.scope,defect_annihilation.kind) or defect_annihilation.claim_id not in active:
                return CheckResult.INVALID, None
            query_claims.append(defect_annihilation); supports.add(defect_annihilation.claim_id)
        cr,assessment=WeakLimitDefectChecker().check(query.observable_kind,tuple(query_claims),active)
        if cr != CheckResult.VALID or assessment is None:
            return cr, None
        kinds={c.kind for c in claims}
        if defect_annihilation is not None:
            expected_assessment="QUERY_EXACT_DEFECT_INVISIBLE"
        elif query.observable_kind=="LINEAR":
            expected_assessment="QUERY_EXACT_WEAK_CONTINUITY"
        elif query.observable_kind=="NONLINEAR_OSCILLATION":
            expected_assessment="DEFECT_ACCOUNTED" if "YOUNG_MEASURE" in kinds else "DEFECT_REQUIRED"
        else:
            expected_assessment=("DEFECT_REQUIRED" if "YOUNG_MEASURE" not in kinds else ("CONCENTRATION_DEFECT_REQUIRED" if "CONCENTRATION_MEASURE" not in kinds else "DEFECT_ACCOUNTED"))
        if assessment.status != expected_assessment:
            return CheckResult.INVALID, None
        required=set(self._required_defects(query.observable_kind))
        if defect_annihilation is not None:
            visible=set()
        else:
            visible=set(required)
        accounted=set()
        if "OSCILLATION" in visible and "YOUNG_MEASURE" in kinds:
            accounted.add("OSCILLATION")
        if "CONCENTRATION" in visible and "CONCENTRATION_MEASURE" in kinds:
            accounted.add("CONCENTRATION")
        missing=visible-accounted
        status="OPEN_DEFECT" if missing else "CERTIFIED_OUTER_QUERY_RELATION"
        if transparency is not None:
            expected=query_transparency_claim_semantic_id(transparency.model_id,transparency.strong_relation_id,transparency.outer_relation_id,transparency.query_id,transparency.scope,transparency.theorem_fixture_id,transparency.theorem_fixture_content_id)
            if transparency.claim_id != expected or transparency.claim_id not in active:
                return CheckResult.INVALID, None
            if not transparency.strong_relation_id or transparency.strong_relation_id==transparency.outer_relation_id:
                return CheckResult.INVALID, None
            if (transparency.model_id,transparency.outer_relation_id,transparency.query_id,transparency.scope)!=(relation.model_id,relation.relation_id,query.query_id,query.scope):
                return CheckResult.INVALID, None
            supports.add(transparency.claim_id)
            if not missing:
                status="EXACT_QUERY_RELATION"
        projection=MeasureValuedQueryProjection(relation.model_id,relation.relation_id,query.query_id,query.scope,query.observable_kind,status,tuple(sorted(visible)),tuple(sorted(accounted)),tuple(sorted(missing)),frozenset(supports))
        return CheckResult.VALID, projection
