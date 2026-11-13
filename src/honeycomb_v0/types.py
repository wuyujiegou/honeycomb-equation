from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from fractions import Fraction
from typing import FrozenSet, Tuple

class CheckResult(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    UNSUPPORTED = "UNSUPPORTED"

class FaceState(str, Enum):
    PASS = "PASS"
    CONDITIONAL = "CONDITIONAL"
    OPEN = "OPEN"
    FAIL = "FAIL"
    NA = "N/A"

class ScopeLevel(str, Enum):
    CONTINUUM = "CONTINUUM"
    DISCRETE = "DISCRETE"


class QueryFactType(str, Enum):
    MODEL_EMPTY = "MODEL_EMPTY"
    MODEL_NONEMPTY = "MODEL_NONEMPTY"
    OUTER_SET = "OUTER_SET"
    MEMBER = "MEMBER"
    EXACT_LAW = "EXACT_LAW"
    DEFECT_INTERVAL = "DEFECT_INTERVAL"
    DEFECT_LAW = "DEFECT_LAW"
    OUTER_RELATION = "OUTER_RELATION"
    EXACT_RELATION = "EXACT_RELATION"
    OPEN_RELATION = "OPEN_RELATION"

class Action(str, Enum):
    ANNIHILATE = "ANNIHILATE"
    RETAIN = "RETAIN"
    DEFECT = "DEFECT"

@dataclass(frozen=True)
class Scope:
    level: ScopeLevel
    tag: str = ""

@dataclass(frozen=True)
class Term:
    term_id: str
    sign: int
    role: str
    expression: str
    semantic_ref: str | None = None

@dataclass(frozen=True)
class SourceBalanceSpec:
    model_id: str
    relation_id: str
    terms: Tuple[Term, ...]
    storage_term_id: str = ""
    storage_expression: str = ""
    scope: Scope | None = None

@dataclass(frozen=True)
class BalanceRelationIR:
    model_id: str
    relation_id: str
    scope: Scope
    storage_term_id: str
    terms: Tuple[Term, ...]
    storage_expression: str = ""

@dataclass(frozen=True)
class ProjectionClaim:
    claim_id: str
    model_id: str
    reader_id: str
    term_id: str
    query_id: str
    scope: Scope
    projected_object: str
    exact: bool = True

@dataclass(frozen=True)
class TargetDerivativeLink:
    claim_id: str
    model_id: str
    reader_id: str
    storage_term_id: str
    query_id: str
    scope: Scope
    target_derivative_object: str

@dataclass(frozen=True)
class ProjectedTermEvidence:
    term_id: str
    action: Action
    projected_object: str
    projection_claim_id: str

@dataclass(frozen=True)
class BalanceReaderEvidence:
    model_id: str
    balance_ref: str
    query_id: str
    reader_id: str
    scope: Scope
    reader_admissibility_claims: FrozenSet[str]
    target_link_claim_id: str
    projected_terms: Tuple[ProjectedTermEvidence, ...]

@dataclass(frozen=True)
class BalanceLaw:
    model_id: str
    balance_ref: str
    query_id: str
    scope: Scope
    derivative_object: str
    retained_terms: Tuple[Tuple[int, str], ...]
    defect_terms: Tuple[Tuple[int, str], ...]
    support_refs: FrozenSet[str]



@dataclass(frozen=True)
class CouplingProjectionClaim:
    claim_id: str
    bundle_id: str
    coupling_id: str
    query_id: str
    scope: Scope
    projected_port_terms: Tuple[Tuple[str, str, int, str], ...]
    projected_object: str = "ZERO"
    exact: bool = True

@dataclass(frozen=True)
class CoupledBalanceLaw:
    bundle_id: str
    query_id: str
    scope: Scope
    local_derivatives: Tuple[Tuple[str, str], ...]
    retained_terms: Tuple[Tuple[str, int, str], ...]
    eliminated_couplings: Tuple[str, ...]
    support_refs: FrozenSet[str]



@dataclass(frozen=True)
class DefectBoundClaim:
    claim_id: str
    owner_id: str
    defect_id: str
    scope: Scope
    projected_object: str
    epsilon: Fraction


@dataclass(frozen=True)
class DefectPropagationEvidence:
    query_id: str
    scope: Scope
    terms: Tuple[Tuple[int, DefectBoundClaim], ...]


@dataclass(frozen=True)
class DefectPropagationResult:
    interval: Tuple[Fraction, Fraction]
    support_refs: FrozenSet[str]


@dataclass(frozen=True)
class CoupledDefectBalanceLaw:
    bundle_id: str
    query_id: str
    scope: Scope
    local_derivatives: Tuple[Tuple[str, str], ...]
    retained_terms: Tuple[Tuple[str, int, str], ...]
    defect_terms: Tuple[Tuple[str, int, str], ...]
    propagated_interval: Tuple[Fraction, Fraction]
    support_refs: FrozenSet[str]


@dataclass(frozen=True)
class InfiniteDualClaim:
    claim_id: str
    operator_id: str
    target_id: str
    scope: Scope
    kind: str  # KERNEL_ANNIHILATION | ADJOINT_CLOSURE_MEMBERSHIP | CLOSED_RANGE | ADJOINT_WITNESS
    witness_ref: str | None = None


@dataclass(frozen=True)
class InfiniteDualAssessment:
    uniqueness_credit: str
    range_credit: str
    computational_credit: str
    support_refs: FrozenSet[str]


@dataclass(frozen=True)
class WeakLimitClaim:
    claim_id: str
    model_id: str
    relation_id: str
    sequence_id: str
    query_id: str
    scope: Scope
    kind: str  # WEAK_STATE | YOUNG_MEASURE | CONCENTRATION_MEASURE | DEFECT_ANNIHILATION


@dataclass(frozen=True)
class WeakLimitEvidenceSubmission:
    submission_id: str
    model_id: str
    relation_id: str
    sequence_id: str
    query_id: str
    scope: Scope
    kind: str
    source_id: str
    source_content_id: str
    theorem_fixture_id: str
    theorem_fixture_content_id: str
    witness: Tuple[Tuple[str, object], ...]


@dataclass(frozen=True)
class WeakLimitEvidenceVerification:
    submission_id: str
    claim_id: str
    theorem_fixture_id: str
    theorem_fixture_content_id: str
    verifier_id: str
    verifier_content_id: str
    support_refs: FrozenSet[str]


@dataclass(frozen=True)
class WeakLimitAssessment:
    status: str
    support_refs: FrozenSet[str]




@dataclass(frozen=True)
class MeasureValuedOuterRelation:
    model_id: str
    relation_id: str
    sequence_id: str
    scope: Scope
    weak_claims: Tuple[WeakLimitClaim, ...]
    support_refs: FrozenSet[str]


@dataclass(frozen=True)
class WeakQueryProfile:
    model_id: str
    relation_id: str
    query_id: str
    scope: Scope
    observable_kind: str  # LINEAR | NONLINEAR_OSCILLATION | CONCENTRATION_SENSITIVE


@dataclass(frozen=True)
class QueryTransparencyClaim:
    claim_id: str
    model_id: str
    strong_relation_id: str
    outer_relation_id: str
    query_id: str
    scope: Scope
    theorem_fixture_id: str
    theorem_fixture_content_id: str


@dataclass(frozen=True)
class MeasureValuedQueryProjection:
    model_id: str
    outer_relation_id: str
    query_id: str
    scope: Scope
    observable_kind: str
    status: str  # OPEN_DEFECT | CERTIFIED_OUTER_QUERY_RELATION | EXACT_QUERY_RELATION
    visible_defects: Tuple[str, ...]
    accounted_defects: Tuple[str, ...]
    missing_defects: Tuple[str, ...]
    support_refs: FrozenSet[str]


@dataclass(frozen=True)
class OutputArtifact:
    model_id: str
    query_id: str
    scope: Scope
    kind: str
    value: object
    support_refs: FrozenSet[str]

@dataclass(frozen=True)
class RunSpec:
    model_id: str
    query_id: str
    scope: Scope
    release_id: str
    declared_na: FrozenSet[str]

@dataclass(frozen=True)
class FaceVector:
    H_I: FaceState
    H_O: FaceState
    H_delta: FaceState
    H_N: FaceState
    H_E: FaceState
    H_R: FaceState

@dataclass(frozen=True)
class Residual:
    residual_id: str
    effect: str  # CERTIFIED_NONE | BLOCKS_EXACT | BOUNDED
    affects_query: bool

@dataclass(frozen=True)
class ExactRational:
    value: Fraction

@dataclass(frozen=True)
class ApproxDisplay:
    value: float

@dataclass(frozen=True)
class RelationTransportClaim:
    claim_id: str
    source_model_id: str
    target_model_id: str
    exact: bool


@dataclass(frozen=True)
class QueryFact:
    model_id: str
    query_id: str
    scope: Scope
    fact_type: QueryFactType
    value: object = None


@dataclass(frozen=True)
class ObligationEvidence:
    model_id: str
    query_id: str
    scope: Scope
    obligation: str  # H_I | H_delta | H_N
    conclusion: str  # SATISFIED | VIOLATED | CONDITIONAL
    support_refs: FrozenSet[str]


@dataclass(frozen=True)
class ExactnessWitness:
    model_id: str
    query_id: str
    scope: Scope
    output_id: str
    output_kind: str
    support_refs: FrozenSet[str]

