from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from fractions import Fraction
from typing import Any, Tuple

from .canonical import content_id
from .types import Scope, ScopeLevel, SourceBalanceSpec, BalanceRelationIR, Term
from .checkers import NormalizationManifest


class PDESense(str, Enum):
    WEAK = "WEAK"
    DISTRIBUTIONAL = "DISTRIBUTIONAL"
    STRONG = "STRONG"


class BoundaryKind(str, Enum):
    DIRICHLET = "DIRICHLET"
    NEUMANN = "NEUMANN"
    ROBIN = "ROBIN"
    PERIODIC = "PERIODIC"
    ADMISSIBLE_SET = "ADMISSIBLE_SET"
    PORT = "PORT"


class ValidationSeverity(str, Enum):
    ERROR = "ERROR"
    WARNING = "WARNING"


@dataclass(frozen=True)
class GeometrySpec:
    domain_id: str
    dimension: int
    domain_class: str


@dataclass(frozen=True)
class TimeSpec:
    start: Any
    end: Any
    direction: str = "FORWARD"


@dataclass(frozen=True)
class FieldSpec:
    name: str
    role: str
    value_type: str
    spatial_space: str
    time_space: str
    time_derivative_order: int
    derivative_space: str


@dataclass(frozen=True)
class DataSpec:
    name: str
    role: str
    semantic: str
    value: Any


@dataclass(frozen=True)
class OperatorSpec:
    name: str
    domain: str
    codomain: str
    kind: str


@dataclass(frozen=True)
class WeakTermSpec:
    term_id: str
    sign: int
    role: str
    expression: str
    symbols: Tuple[str, ...]
    port_ref: str | None = None
    boundary_ref: str | None = None


@dataclass(frozen=True)
class EquationSpec:
    relation_name: str
    sense: PDESense
    test_symbol: str
    test_space: str
    storage_term_id: str
    storage_expression: str
    storage_symbols: Tuple[str, ...]
    terms: Tuple[WeakTermSpec, ...]


@dataclass(frozen=True)
class InitialSpec:
    field: str
    data_ref: str
    derivative_slot: int = 0


@dataclass(frozen=True)
class BoundarySpec:
    boundary_id: str
    field: str
    kind: BoundaryKind
    semantic: str
    value: Any = None
    admissible_set: str | None = None
    port_ref: str | None = None


@dataclass(frozen=True)
class SolutionClassSpec:
    equation_sense: PDESense
    regularity: Tuple[Tuple[str, str], ...]
    admissibility: Tuple[str, ...] = tuple()


@dataclass(frozen=True)
class PortSpec:
    port_id: str
    semantic_space: str
    orientation: str
    realization_kind: str
    field: str
    boundary_id: str


@dataclass(frozen=True)
class PDEProfile:
    name: str
    geometry: GeometrySpec
    time: TimeSpec
    fields: Tuple[FieldSpec, ...]
    data: Tuple[DataSpec, ...]
    operators: Tuple[OperatorSpec, ...]
    equations: Tuple[EquationSpec, ...]
    initial: Tuple[InitialSpec, ...]
    boundary: Tuple[BoundarySpec, ...]
    solution_class: SolutionClassSpec
    ports: Tuple[PortSpec, ...] = tuple()

    @property
    def model_id(self) -> str:
        # The declared name is included deliberately in v0. A rename is a new model identity.
        return content_id({"type": "PDEProfile", "profile": self})


@dataclass(frozen=True)
class CouplingPortRef:
    model_ref: str
    port_ref: str
    sign: int


@dataclass(frozen=True)
class CouplingDefectSpec:
    defect_id: str
    semantic_space: str
    projection_reader_id: str
    projected_abs_bound: Fraction


@dataclass(frozen=True)
class CouplingSpec:
    coupling_id: str
    kind: str
    terms: Tuple[CouplingPortRef, ...]
    equals: Any


@dataclass(frozen=True)
class PDEBundle:
    name: str
    models: Tuple[PDEProfile, ...]
    couplings: Tuple[CouplingSpec, ...]

    @property
    def bundle_id(self) -> str:
        return content_id({"type": "PDEBundle", "bundle": self})


@dataclass(frozen=True)
class ValidationIssue:
    code: str
    severity: ValidationSeverity
    path: str
    message: str


@dataclass(frozen=True)
class ValidationReport:
    issues: Tuple[ValidationIssue, ...]

    @property
    def valid(self) -> bool:
        return not any(i.severity == ValidationSeverity.ERROR for i in self.issues)

    @property
    def error_codes(self) -> frozenset[str]:
        return frozenset(i.code for i in self.issues if i.severity == ValidationSeverity.ERROR)


@dataclass(frozen=True)
class BoundPDE:
    profile: PDEProfile
    model_id: str
    scope: Scope
    source_balances: Tuple[SourceBalanceSpec, ...]
    ir_balances: Tuple[BalanceRelationIR, ...]
    normalization_manifests: Tuple[NormalizationManifest, ...]
    validation: ValidationReport


@dataclass(frozen=True)
class BoundPDEBundle:
    bundle: PDEBundle
    bound_models: Tuple[BoundPDE, ...]
    validation: ValidationReport


class PDEProfileValidator:
    version = "0.1.0"

    def validate(self, profile: PDEProfile) -> ValidationReport:
        issues: list[ValidationIssue] = []
        add = lambda code, path, msg, sev=ValidationSeverity.ERROR: issues.append(ValidationIssue(code, sev, path, msg))

        if profile.geometry.dimension <= 0:
            add("GEOMETRY_DIMENSION_INVALID", "geometry.dimension", "dimension must be positive")
        if not profile.geometry.domain_id or not profile.geometry.domain_class:
            add("GEOMETRY_UNDERDECLARED", "geometry", "domain id and class are required")
        if profile.time.direction != "FORWARD":
            add("UNSUPPORTED_TIME_DIRECTION", "time.direction", "v0 supports FORWARD time only")

        field_names = [f.name for f in profile.fields]
        data_names = [d.name for d in profile.data]
        op_names = [o.name for o in profile.operators]
        port_names = [p.port_id for p in profile.ports]
        eq_names = [e.relation_name for e in profile.equations]
        for label, rows in (("field", field_names), ("data", data_names), ("operator", op_names), ("port", port_names), ("equation", eq_names)):
            if len(set(rows)) != len(rows):
                add("DUPLICATE_SYMBOL", label, f"duplicate {label} identifier")

        declared = set(field_names) | set(data_names) | set(op_names) | set(port_names)
        field_map = {f.name: f for f in profile.fields}
        port_map = {p.port_id: p for p in profile.ports}
        boundary_ids = [b.boundary_id for b in profile.boundary]
        if len(set(boundary_ids)) != len(boundary_ids):
            add("DUPLICATE_BOUNDARY_ID", "boundary", "boundary identifiers must be unique")
        boundary_map = {b.boundary_id: b for b in profile.boundary}
        declared |= set(boundary_ids)

        for f in profile.fields:
            if f.time_derivative_order < 0:
                add("TEMPORAL_ORDER_INVALID", f"fields.{f.name}", "time derivative order must be nonnegative")
            if f.role.upper() == "STATE" and f.time_derivative_order == 0:
                add("TEMPORAL_CLOSURE_GAP", f"fields.{f.name}", "state field requires declared time derivative order")

        if profile.solution_class.equation_sense not in (PDESense.WEAK, PDESense.DISTRIBUTIONAL):
            add("UNSUPPORTED_SOLUTION_SENSE", "solution.equation_sense", "v0 binder supports weak/distributional solution classes only")

        for e in profile.equations:
            if e.sense != PDESense.WEAK:
                add("UNSUPPORTED_SEMANTIC_CONSTRUCT", f"equations.{e.relation_name}.sense", "v0 balance binder accepts explicit WEAK equations only")
            if e.sense != profile.solution_class.equation_sense:
                add("SOLUTION_SENSE_MISMATCH", f"equations.{e.relation_name}", "equation sense must match solution class")
            if not e.test_symbol or not e.test_space:
                add("TEST_SPACE_GAP", f"equations.{e.relation_name}.test", "test symbol and space are required")
            term_ids = [t.term_id for t in e.terms]
            if e.storage_term_id in term_ids or len(set(term_ids)) != len(term_ids):
                add("TERM_ID_COLLISION", f"equations.{e.relation_name}", "storage/term ids must be unique")
            allowed = declared | {e.test_symbol}
            for sym in e.storage_symbols:
                if sym not in allowed:
                    add("UNDECLARED_SYMBOL", f"equations.{e.relation_name}.storage", f"undeclared symbol: {sym}")
            for t in e.terms:
                if t.sign not in (-1, 1):
                    add("TERM_SIGN_INVALID", f"equations.{e.relation_name}.{t.term_id}", "term sign must be +1 or -1")
                for sym in t.symbols:
                    if sym not in allowed:
                        add("UNDECLARED_SYMBOL", f"equations.{e.relation_name}.{t.term_id}", f"undeclared symbol: {sym}")
                if t.role.upper() == "PORT":
                    if not t.port_ref or t.port_ref not in port_map:
                        add("PORT_TERM_UNBOUND", f"equations.{e.relation_name}.{t.term_id}", "PORT term must reference a declared port")
                    elif t.port_ref not in t.symbols:
                        add("PORT_SYMBOL_GAP", f"equations.{e.relation_name}.{t.term_id}", "PORT term symbols must include its port_ref")
                    if t.boundary_ref is not None:
                        add("BOUNDARY_REF_ON_PORT_TERM", f"equations.{e.relation_name}.{t.term_id}", "PORT term uses port_ref, not boundary_ref")
                elif t.role.upper() == "BOUNDARY":
                    if not t.boundary_ref or t.boundary_ref not in boundary_map:
                        add("BOUNDARY_TERM_UNBOUND", f"equations.{e.relation_name}.{t.term_id}", "BOUNDARY term must reference a declared boundary")
                    elif t.boundary_ref not in t.symbols:
                        add("BOUNDARY_SYMBOL_GAP", f"equations.{e.relation_name}.{t.term_id}", "BOUNDARY term symbols must include boundary_ref")
                    if t.port_ref is not None:
                        add("PORT_REF_ON_BOUNDARY_TERM", f"equations.{e.relation_name}.{t.term_id}", "BOUNDARY term uses boundary_ref, not port_ref")
                elif t.port_ref is not None or t.boundary_ref is not None:
                    add("SEMANTIC_REF_ON_PLAIN_TERM", f"equations.{e.relation_name}.{t.term_id}", "only PORT/BOUNDARY terms may carry semantic refs")

        for ini in profile.initial:
            if ini.field not in field_map:
                add("INITIAL_FIELD_UNKNOWN", f"initial.{ini.field}", "initial condition field is undeclared")
            if ini.data_ref not in data_names:
                add("INITIAL_DATA_UNKNOWN", f"initial.{ini.field}", "initial condition data_ref is undeclared")
            f = field_map.get(ini.field)
            if f and not (0 <= ini.derivative_slot < max(1, f.time_derivative_order)):
                add("INITIAL_SLOT_INVALID", f"initial.{ini.field}", "derivative slot outside declared time order")

        initial_slots = {}
        for ini in profile.initial:
            initial_slots.setdefault(ini.field, set()).add(ini.derivative_slot)
        for f in profile.fields:
            if f.role.upper() == "STATE" and f.time_derivative_order > 0:
                required = set(range(f.time_derivative_order))
                missing = required - initial_slots.get(f.name, set())
                if missing:
                    add("INITIAL_DATA_GAP", f"initial.{f.name}", f"missing derivative slots: {sorted(missing)}")

        state_fields = {f.name for f in profile.fields if f.role.upper() == "STATE"}
        boundary_fields = {b.field for b in profile.boundary}
        for f in sorted(state_fields - boundary_fields):
            add("BOUNDARY_GAP", f"boundary.{f}", "state field has no declared boundary semantics")

        for b in profile.boundary:
            if b.field not in field_map:
                add("BOUNDARY_FIELD_UNKNOWN", f"boundary.{b.boundary_id}", "boundary field is undeclared")
            if b.kind == BoundaryKind.PORT:
                if not b.port_ref or b.port_ref not in port_map:
                    add("BOUNDARY_PORT_UNKNOWN", f"boundary.{b.boundary_id}", "port boundary must reference a declared port")
                else:
                    p = port_map[b.port_ref]
                    if p.field != b.field or p.boundary_id != b.boundary_id:
                        add("BOUNDARY_PORT_BINDING_MISMATCH", f"boundary.{b.boundary_id}", "port field/boundary binding mismatch")
            elif b.kind == BoundaryKind.ADMISSIBLE_SET:
                if not b.admissible_set:
                    add("BOUNDARY_ADMISSIBLE_SET_GAP", f"boundary.{b.boundary_id}", "admissible-set boundary requires a set declaration")
            else:
                if b.semantic not in {"EXACT", "SYMBOLIC", "PERIODIC"}:
                    add("BOUNDARY_SEMANTIC_INVALID", f"boundary.{b.boundary_id}", "prescribed boundary requires explicit semantic")

        port_terms = {t.port_ref for e in profile.equations for t in e.terms if t.role.upper()=="PORT" and t.port_ref}
        boundary_terms = {t.boundary_ref for e in profile.equations for t in e.terms if t.role.upper()=="BOUNDARY" and t.boundary_ref}
        for b in profile.boundary:
            if b.kind == BoundaryKind.PORT and b.port_ref not in port_terms:
                add("PORT_UNUSED_BY_BALANCE", f"boundary.{b.boundary_id}", "declared open port is absent from every weak balance")
            if b.kind in {BoundaryKind.NEUMANN, BoundaryKind.ROBIN, BoundaryKind.ADMISSIBLE_SET}:
                zero_neumann = (b.kind == BoundaryKind.NEUMANN and b.semantic == "EXACT" and b.value == 0)
                if not zero_neumann and b.kind != BoundaryKind.PORT and b.boundary_id not in boundary_terms:
                    add("BOUNDARY_EFFECT_MISSING_FROM_BALANCE", f"boundary.{b.boundary_id}", "truth-relevant boundary effect is absent from weak balance")

        for p in profile.ports:
            if p.field not in field_map:
                add("PORT_FIELD_UNKNOWN", f"ports.{p.port_id}", "port field is undeclared")
            if p.boundary_id not in boundary_map:
                add("PORT_BOUNDARY_UNKNOWN", f"ports.{p.port_id}", "port boundary is undeclared")
            if p.orientation not in {"OUTWARD", "INWARD", "NONE"}:
                add("PORT_ORIENTATION_INVALID", f"ports.{p.port_id}", "invalid orientation")
            if not p.semantic_space:
                add("PORT_SPACE_GAP", f"ports.{p.port_id}", "semantic port space is required")

        regularity_fields = {k for k, _ in profile.solution_class.regularity}
        for f in state_fields - regularity_fields:
            add("SOLUTION_REGULARITY_GAP", f"solution.regularity.{f}", "state regularity is undeclared")

        return ValidationReport(tuple(issues))


class PDEBinder:
    version = "0.1.0"

    def __init__(self, validator: PDEProfileValidator | None = None):
        self.validator = validator or PDEProfileValidator()

    def bind(self, profile: PDEProfile) -> BoundPDE:
        report = self.validator.validate(profile)
        if not report.valid:
            return BoundPDE(profile, profile.model_id, Scope(ScopeLevel.CONTINUUM, "weak"), tuple(), tuple(), tuple(), report)
        scope = Scope(ScopeLevel.CONTINUUM, "weak")
        source_balances = []
        ir_balances = []
        manifests = []
        for e in profile.equations:
            src_relation_id = content_id({"type": "SourceBalanceRelation", "model_id": profile.model_id, "equation": e.relation_name})
            ir_relation_id = content_id({"type": "BalanceRelationIR", "model_id": profile.model_id, "equation": e.relation_name})
            src_terms = tuple(Term(f"src:{t.term_id}", t.sign, t.role.upper(), t.expression, t.port_ref or t.boundary_ref) for t in e.terms)
            ir_terms = tuple(Term(t.term_id, t.sign, t.role.upper(), t.expression, t.port_ref or t.boundary_ref) for t in e.terms)
            src_storage = f"src:{e.storage_term_id}"
            source = SourceBalanceSpec(profile.model_id, src_relation_id, src_terms, src_storage, e.storage_expression, scope)
            ir = BalanceRelationIR(profile.model_id, ir_relation_id, scope, e.storage_term_id, ir_terms, e.storage_expression)
            mappings = tuple((f"src:{t.term_id}", t.term_id, t.sign) for t in e.terms)
            manifest = NormalizationManifest(src_relation_id, ir_relation_id, tuple(x.term_id for x in src_terms), mappings, (src_storage, e.storage_term_id))
            source_balances.append(source); ir_balances.append(ir); manifests.append(manifest)
        return BoundPDE(profile, profile.model_id, scope, tuple(source_balances), tuple(ir_balances), tuple(manifests), report)


class PDEBundleValidator:
    version = "0.2.0"

    def validate(self, bundle: PDEBundle) -> ValidationReport:
        issues: list[ValidationIssue] = []
        pv = PDEProfileValidator()
        names = [m.name for m in bundle.models]
        if len(set(names)) != len(names):
            issues.append(ValidationIssue("DUPLICATE_MODEL_NAME", ValidationSeverity.ERROR, "models", "bundle model names must be unique"))
        by_name = {m.name: m for m in bundle.models}
        for m in bundle.models:
            issues.extend(pv.validate(m).issues)
        coupling_ids = [c.coupling_id for c in bundle.couplings]
        if len(set(coupling_ids)) != len(coupling_ids):
            issues.append(ValidationIssue("DUPLICATE_COUPLING_ID", ValidationSeverity.ERROR, "couplings", "coupling identifiers must be unique"))
        for c in bundle.couplings:
            if c.kind != "SIGNED_BALANCE":
                issues.append(ValidationIssue("UNSUPPORTED_COUPLING_KIND", ValidationSeverity.ERROR, f"couplings.{c.coupling_id}", "v0 supports SIGNED_BALANCE coupling only"))
                continue
            defect_rhs = c.equals if isinstance(c.equals, CouplingDefectSpec) else None
            if c.equals != 0 and defect_rhs is None:
                issues.append(ValidationIssue("COUPLING_RHS_UNSUPPORTED", ValidationSeverity.ERROR, f"couplings.{c.coupling_id}", "coupling RHS must be exact zero or a typed defect channel"))
            if defect_rhs is not None:
                if not defect_rhs.defect_id or not defect_rhs.semantic_space:
                    issues.append(ValidationIssue("COUPLING_DEFECT_UNDERDECLARED", ValidationSeverity.ERROR, f"couplings.{c.coupling_id}", "defect id and semantic space are required"))
                if defect_rhs.projection_reader_id != "trace(1)":
                    issues.append(ValidationIssue("COUPLING_DEFECT_READER_UNSUPPORTED", ValidationSeverity.ERROR, f"couplings.{c.coupling_id}", "v0 supports only the trace(1) projected defect bound"))
                if not isinstance(defect_rhs.projected_abs_bound, Fraction) or defect_rhs.projected_abs_bound < 0:
                    issues.append(ValidationIssue("COUPLING_DEFECT_BOUND_INVALID", ValidationSeverity.ERROR, f"couplings.{c.coupling_id}", "projected defect bound must be a nonnegative exact rational"))
            if len(c.terms) < 2:
                issues.append(ValidationIssue("COUPLING_ARITY_INVALID", ValidationSeverity.ERROR, f"couplings.{c.coupling_id}", "signed balance requires at least two port terms"))
            refs_key = [(r.model_ref, r.port_ref) for r in c.terms]
            if len(set(refs_key)) != len(refs_key):
                issues.append(ValidationIssue("COUPLING_DUPLICATE_PORT", ValidationSeverity.ERROR, f"couplings.{c.coupling_id}", "same port cannot appear twice in one coupling"))
            spaces = set()
            realizations = set()
            for ref in c.terms:
                model = by_name.get(ref.model_ref)
                if model is None:
                    issues.append(ValidationIssue("COUPLING_MODEL_UNKNOWN", ValidationSeverity.ERROR, f"couplings.{c.coupling_id}", ref.model_ref))
                    continue
                ports = {p.port_id: p for p in model.ports}
                p = ports.get(ref.port_ref)
                if p is None:
                    issues.append(ValidationIssue("COUPLING_PORT_UNKNOWN", ValidationSeverity.ERROR, f"couplings.{c.coupling_id}", f"{ref.model_ref}.{ref.port_ref}"))
                    continue
                if ref.sign not in (-1, 1):
                    issues.append(ValidationIssue("COUPLING_SIGN_INVALID", ValidationSeverity.ERROR, f"couplings.{c.coupling_id}", "sign must be +/-1"))
                if p.orientation != "OUTWARD":
                    issues.append(ValidationIssue("COUPLING_ORIENTATION_UNSAFE", ValidationSeverity.ERROR, f"couplings.{c.coupling_id}", "signed flux balance requires local outward orientation"))
                if p.realization_kind != "WEAK_CONORMAL":
                    issues.append(ValidationIssue("COUPLING_REALIZATION_UNSUPPORTED", ValidationSeverity.ERROR, f"couplings.{c.coupling_id}", "v0 signed interface balance requires WEAK_CONORMAL ports"))
                spaces.add(p.semantic_space)
                realizations.add(p.realization_kind)
            if len(spaces) > 1:
                issues.append(ValidationIssue("COUPLING_PORT_SPACE_MISMATCH", ValidationSeverity.ERROR, f"couplings.{c.coupling_id}", "coupled ports must have the same semantic space"))
            if defect_rhs is not None and spaces and defect_rhs.semantic_space not in spaces:
                issues.append(ValidationIssue("COUPLING_DEFECT_SPACE_MISMATCH", ValidationSeverity.ERROR, f"couplings.{c.coupling_id}", "defect channel must live in the common port semantic space"))
            if len(realizations) > 1:
                issues.append(ValidationIssue("COUPLING_PORT_REALIZATION_MISMATCH", ValidationSeverity.ERROR, f"couplings.{c.coupling_id}", "coupled ports must use the same realization kind"))
        return ValidationReport(tuple(issues))


class PDEBundleBinder:
    version = "0.2.0"

    def bind(self, bundle: PDEBundle) -> BoundPDEBundle:
        report = PDEBundleValidator().validate(bundle)
        if not report.valid:
            return BoundPDEBundle(bundle, tuple(PDEBinder().bind(m) for m in bundle.models), report)
        return BoundPDEBundle(bundle, tuple(PDEBinder().bind(m) for m in bundle.models), report)
