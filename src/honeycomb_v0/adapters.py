from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Tuple

from .assemblers import QueryAssembler, query_fact_id
from .canonical import canonical_data, content_id, file_sha256
from .checkers import (
    ZERO,
    BalanceReaderChecker,
    ExactLinearAlgebraChecker,
    NormalizationValidator,
    projection_claim_semantic_id,
    target_link_semantic_id,
)
from .dsl import UserQuerySpec
from .faces import FaceEvaluator, FaceInputs
from .kernel import CertifiedRoot, CertifiedSupportRule, RuntimeTrustPolicy, SupportKernel
from .pde import BoundPDE, BoundaryKind, PDESense, PDEBinder
from .report import CanonicalReport, ReportBuilder
from .types import (
    Action,
    BalanceLaw,
    BalanceReaderEvidence,
    CheckResult,
    FaceVector,
    OutputArtifact,
    ProjectedTermEvidence,
    ProjectionClaim,
    QueryFact,
    QueryFactType,
    RunSpec,
    TargetDerivativeLink,
    ExactnessWitness,
    ObligationEvidence,
)



@dataclass(frozen=True)
class TheoremFixtureRegistry:
    fixture_set_id: str
    version: str
    fixtures: Tuple[Mapping[str, Any], ...]

    @classmethod
    def from_path(cls, path: str | Path) -> "TheoremFixtureRegistry":
        obj = json.loads(Path(path).read_text(encoding="utf-8"))
        rows = obj.get("fixtures", [])
        if not isinstance(rows, list) or not all(isinstance(x, dict) for x in rows):
            raise ValueError("invalid theorem fixture registry")
        ids=[]
        for row in rows:
            required={"id","role","scope","claim","theorem_kind"}
            if not required.issubset(row) or any(not isinstance(row[k],str) or not row[k] for k in required):
                raise ValueError("invalid theorem fixture row")
            ids.append(row["id"])
        if len(set(ids))!=len(ids): raise ValueError("duplicate theorem fixture id")
        if not obj.get("fixture_set_id") or not obj.get("version"): raise ValueError("theorem fixture registry identity missing")
        return cls(str(obj.get("fixture_set_id", "")), str(obj.get("version", "")), tuple(rows))

    @property
    def ids(self) -> frozenset[str]:
        return frozenset(str(x.get("id")) for x in self.fixtures if x.get("id"))

    def row(self, fixture_id: str) -> Mapping[str, Any]:
        hits = [x for x in self.fixtures if x.get("id") == fixture_id]
        if len(hits) != 1:
            raise KeyError(fixture_id)
        return hits[0]

    def content_id_for(self, fixture_id: str) -> str:
        return content_id({"type": "TheoremFixture", "fixture": self.row(fixture_id)})

    def root_id_for(self, fixture_id: str) -> str:
        return content_id(
            {
                "type": "TheoremFixtureRoot",
                "fixture_id": fixture_id,
                "fixture_content_id": self.content_id_for(fixture_id),
            }
        )


@dataclass(frozen=True)
class ReaderAdmissibilityClaim:
    model_id: str
    relation_id: str
    query_id: str
    reader_id: str
    scope: object
    test_space: str
    fixture_id: str

    @property
    def claim_id(self) -> str:
        return content_id({"type": "ReaderAdmissibilityClaim", "claim": self})


@dataclass(frozen=True)
class AutoEvidenceResult:
    status: str
    reason: str
    model_id: str
    query_id: str
    relation_id: str | None
    fixture_ids: Tuple[str, ...]
    law: BalanceLaw | None
    output: OutputArtifact | None
    faces: FaceVector | None
    report: CanonicalReport | None
    active: frozenset[str]
    adapter_theorem_credit: str
    existence_credit: str
    rule_id: str | None = None
    rule_content_id: str | None = None


def _module_hash(obj: object) -> str:
    mod = sys.modules[obj.__module__]
    path = getattr(mod, "__file__", None)
    if not path:
        raise RuntimeError(f"module file unavailable: {obj.__module__}")
    return file_sha256(path)


def _unsupported(bound: BoundPDE, query: UserQuerySpec, reason: str, *, relation_id: str | None = None) -> AutoEvidenceResult:
    return AutoEvidenceResult(
        "UNSUPPORTED",
        reason,
        bound.model_id,
        query.query_id,
        relation_id,
        tuple(),
        None,
        None,
        None,
        None,
        frozenset(),
        "ZERO",
        "NONE",
    )


def _invalid(bound: BoundPDE, query: UserQuerySpec, reason: str, *, relation_id: str | None = None) -> AutoEvidenceResult:
    return AutoEvidenceResult(
        "INVALID",
        reason,
        bound.model_id,
        query.query_id,
        relation_id,
        tuple(),
        None,
        None,
        None,
        None,
        frozenset(),
        "ZERO",
        "NONE",
    )


# ---------------------------------------------------------------------------
# Declarative adapter-rule engine (v0.2)
# ---------------------------------------------------------------------------
# Named compatibility wrappers route through this finite declarative engine.
# There is one truth-bearing automatic-evidence implementation source.

from .rules import DeclarativeAdapterRuleRegistry, DeclarativeAdapterRule

OFFICIAL_ADAPTER_RULE_PATH = Path(__file__).resolve().parents[2] / "rules" / "adapter_rules.json"
PACKAGED_ADAPTER_RULE_PATH = Path(__file__).resolve().parent / "data" / "rules" / "adapter_rules.json"


def official_adapter_rule_registry() -> DeclarativeAdapterRuleRegistry:
    # Source releases use the root-level pinned rule file. Installed wheels fall back
    # to the byte-identical packaged resource copy used by he-selfcheck.
    path = OFFICIAL_ADAPTER_RULE_PATH if OFFICIAL_ADAPTER_RULE_PATH.exists() else PACKAGED_ADAPTER_RULE_PATH
    return DeclarativeAdapterRuleRegistry.from_path(path)


def _classify_state_boundary(bound: BoundPDE, state: str):
    """Return the single frozen boundary primitive and its active port, if any.

    This is intentionally strict.  A mixed or ambiguous boundary decomposition is not
    guessed into an existing automatic-evidence rule.
    """
    profile=bound.profile
    sb=tuple(b for b in profile.boundary if b.field==state)
    state_ports=tuple(p for p in profile.ports if p.field==state)
    if sb and not state_ports and all(b.kind==BoundaryKind.NEUMANN and b.semantic=="EXACT" and b.value==0 for b in sb):
        return "EXACT_ZERO_NEUMANN", None
    if len(sb)==1 and sb[0].kind==BoundaryKind.PORT and len(state_ports)==1:
        b=sb[0]; port=state_ports[0]
        if (b.port_ref==port.port_id and port.boundary_id==b.boundary_id and
            port.orientation=="OUTWARD" and port.realization_kind=="WEAK_CONORMAL" and
            port.semantic_space==f"H-1/2({b.boundary_id})"):
            return "SINGLE_WEAK_CONORMAL_PORT", port
    return None, None


class DeclarativeBalanceEvidenceAdapter:
    """Finite, audited rule interpreter for automatic balance-reader evidence.

    The registry may only select frozen primitives validated by rules.py.  No rule can
    carry Python code, an arbitrary expression evaluator, proof status, or a free-form
    claim.  Mathematical credit remains owned by theorem fixtures / exact checkers and
    by BalanceReaderChecker.
    """

    engine_id = "declarative-balance-evidence-engine"
    version = "0.2.0"
    _mean_re = re.compile(r"^mean\((?P<state>[A-Za-z_][A-Za-z0-9_]*)\)$")
    _vector_obs_re = re.compile(r"^int\((?P<reader>[A-Za-z_][A-Za-z0-9_]*)\^T (?P<state>[A-Za-z_][A-Za-z0-9_]*)\)$")

    def __init__(self, rule_id: str, rule_registry: DeclarativeAdapterRuleRegistry | None = None):
        self.rule_registry = rule_registry or official_adapter_rule_registry()
        self.rule = self.rule_registry.rule(rule_id)
        self.rule_id = self.rule.rule_id
        self.rule_content_id = self.rule.content_id

    @property
    def adapter_id(self) -> str:
        return f"{self.engine_id}:{self.rule_id}"

    @property
    def adapter_version(self) -> str:
        return self.rule.version

    def _retag(self, result: AutoEvidenceResult) -> AutoEvidenceResult:
        from dataclasses import replace
        return replace(result, rule_id=self.rule_id, rule_content_id=self.rule_content_id)

    def _unsupported(self, bound: BoundPDE, query: UserQuerySpec, reason: str, relation_id: str | None = None):
        return self._retag(_unsupported(bound, query, reason, relation_id=relation_id))

    def _invalid(self, bound: BoundPDE, query: UserQuerySpec, reason: str, relation_id: str | None = None):
        return self._retag(_invalid(bound, query, reason, relation_id=relation_id))

    @staticmethod
    def _fixture_refs(rule: DeclarativeAdapterRule) -> tuple[Mapping[str, str], ...]:
        raw=rule.raw
        refs=[raw["reader_admissibility_fixture"], raw["time_pairing_fixture"]]
        for t in raw["terms"]:
            sup=t["support"]
            if sup["kind"]=="THEOREM": refs.append(sup["fixture"])
        # Canonical unique order by fixture id.
        unique={r["id"]:r for r in refs}
        return tuple(unique[k] for k in sorted(unique))

    def _match_query(self, bound: BoundPDE, query: UserQuerySpec, relation_id: str):
        raw=self.rule.raw; qr=raw["query"]
        if query.kind != qr["kind"] or query.reader_kind != qr["reader_kind"]:
            return None, self._unsupported(bound,query,"query kind/reader kind is outside the selected declarative rule",relation_id)
        profile=bound.profile; data={d.name:d for d in profile.data}; fields={f.name:f for f in profile.fields}
        if qr["observable_primitive"]=="MEAN_STATE":
            m=self._mean_re.fullmatch(query.observable)
            if not m: return None,self._unsupported(bound,query,"observable does not match MEAN_STATE primitive",relation_id)
            state=m.group("state"); reader=query.reader_id
            if qr["reader_id_mode"]!="LITERAL" or reader!=qr["reader_id"]:
                return None,self._invalid(bound,query,"literal reader binding mismatch",relation_id)
            reader_value=None
        elif qr["observable_primitive"]=="VECTOR_INTEGRAL":
            m=self._vector_obs_re.fullmatch(query.observable)
            if not m: return None,self._unsupported(bound,query,"observable does not match VECTOR_INTEGRAL primitive",relation_id)
            reader,state=m.group("reader"),m.group("state")
            if qr["reader_id_mode"]!="DATA_REF" or query.reader_id!=reader:
                return None,self._invalid(bound,query,"reader id does not bind vector observable",relation_id)
            d=data.get(reader)
            if d is None or d.role.upper()!=qr["reader_data_role"] or d.semantic!="EXACT_VECTOR":
                return None,self._invalid(bound,query,"reader must be declared exact vector data with the required role",relation_id)
            reader_value=d.value
            if not isinstance(reader_value,tuple) or not reader_value:
                return None,self._invalid(bound,query,"reader vector carrier is invalid",relation_id)
        else:
            return None,self._unsupported(bound,query,"unknown observable primitive",relation_id)
        sf=fields.get(state)
        if sf is None or sf.role.upper()!="STATE":
            return None,self._invalid(bound,query,"observable state is undeclared",relation_id)
        return {"state":state,"reader":reader,"reader_value":reader_value,"state_field":sf,"data":data},None

    def adapt(self, bound: BoundPDE, query: UserQuerySpec, registry: TheoremFixtureRegistry, *, release_id: str | None = None) -> AutoEvidenceResult:
        release_id=release_id or self.adapter_id
        if not bound.validation.valid:
            return self._invalid(bound,query,"PDE binding is invalid")
        rebound=PDEBinder().bind(bound.profile)
        if content_id(rebound)!=content_id(bound):
            return self._invalid(bound,query,"BoundPDE provenance mismatch: object is not a reproducible PDEBinder result")
        if query.model_id!=bound.model_id or query.scope!=bound.scope:
            return self._invalid(bound,query,"query/model/scope binding mismatch")
        if len(bound.ir_balances)!=1 or len(bound.source_balances)!=1 or len(bound.normalization_manifests)!=1:
            return self._unsupported(bound,query,"selected declarative rule requires exactly one weak balance")
        source,ir,manifest=bound.source_balances[0],bound.ir_balances[0],bound.normalization_manifests[0]
        relation_id=ir.relation_id
        if NormalizationValidator().check(source,ir,manifest)!=CheckResult.VALID:
            return self._invalid(bound,query,"normalization validation failed",relation_id)

        ctx,err=self._match_query(bound,query,relation_id)
        if err is not None: return err
        assert ctx is not None
        raw=self.rule.raw; pr=raw["profile"]; profile=bound.profile; eq=profile.equations[0]
        if profile.geometry.domain_class!=pr["domain_class"] or profile.solution_class.equation_sense.value!=pr["solution_sense"]:
            return self._unsupported(bound,query,"domain/solution class is outside the declarative rule",relation_id)
        if eq.sense.value!=pr["solution_sense"]:
            return self._unsupported(bound,query,"equation sense is outside the declarative rule",relation_id)

        state=ctx["state"]; reader=ctx["reader"]; sf=ctx["state_field"]; data=ctx["data"]
        value_type=sf.value_type
        if pr["state_value_primitive"]=="SCALAR":
            if value_type!="scalar": return self._unsupported(bound,query,"state is not scalar",relation_id)
        elif pr["state_value_primitive"]=="FINITE_VECTOR":
            vm=re.fullmatch(r"R(?P<n>[1-9][0-9]*)",value_type)
            if not vm or len(ctx["reader_value"])!=int(vm.group("n")):
                return self._unsupported(bound,query,"finite-vector state/reader dimension mismatch",relation_id)
        else:
            return self._unsupported(bound,query,"unknown state value primitive",relation_id)

        fmt={"domain":profile.geometry.domain_id,"value_type":value_type,"state":state,"reader":reader,"test":eq.test_symbol}
        expected_test=pr["test_space_template"].format(**fmt)
        expected_spatial=pr["field_spatial_space_template"].format(**fmt)
        regularity=dict(profile.solution_class.regularity).get(state)
        if not (eq.test_space==expected_test and sf.spatial_space==expected_spatial and sf.time_space==pr["field_time_space"] and
                sf.derivative_space==pr["field_derivative_space"] and sf.time_derivative_order==pr["time_derivative_order"] and regularity==pr["regularity"]):
            return self._unsupported(bound,query,"weak-space/temporal regularity is outside the declarative rule",relation_id)
        expected_storage=raw["storage"]["template"].format(**fmt)
        if eq.storage_expression!=expected_storage or set(eq.storage_symbols)!={state,eq.test_symbol}:
            return self._unsupported(bound,query,"storage expression is outside the declarative rule",relation_id)
        actual_boundary, active_port = _classify_state_boundary(bound,state)
        if actual_boundary != pr["boundary_primitive"]:
            return self._unsupported(bound,query,"declared boundary semantics are outside the selected declarative rule",relation_id)
        ctx["active_port"]=active_port

        fixture_refs=self._fixture_refs(self.rule)
        for ref in fixture_refs:
            fid=ref["id"]
            if fid not in registry.ids:
                return self._unsupported(bound,query,f"required theorem fixture is missing: {fid}",relation_id)
            if registry.content_id_for(fid)!=ref["content_id"]:
                return self._unsupported(bound,query,f"theorem fixture semantic fingerprint mismatch: {fid}",relation_id)
            row=registry.row(fid)
            if row.get("role")!="trusted_theorem_fixture":
                return self._unsupported(bound,query,f"fixture is not theorem-credit eligible: {fid}",relation_id)
            if row.get("theorem_kind")!=ref["theorem_kind"]:
                return self._unsupported(bound,query,f"theorem fixture kind mismatch: {fid}",relation_id)

        eq_terms={t.term_id:t for t in eq.terms}
        ir_by_role={}
        for t in ir.terms: ir_by_role.setdefault(t.role,[]).append(t)
        if len(ir.terms)!=len(raw["terms"]):
            return self._unsupported(bound,query,"IR term count differs from declarative rule",relation_id)
        projection_claims: dict[str,ProjectionClaim]={}
        projected_terms=[]
        rule_specs=[]  # support kind, support id/claim, claim id, claim class
        algebra_roots=[]
        checker_hash=_module_hash(BalanceReaderChecker)
        algebra_hash=_module_hash(ExactLinearAlgebraChecker)
        operators={o.name:o for o in profile.operators}

        for tr in raw["terms"]:
            hits=ir_by_role.get(tr["role"],[])
            if len(hits)!=tr["count"]:
                return self._unsupported(bound,query,f"term cardinality mismatch for role {tr['role']}",relation_id)
            term=hits[0]; ets=eq_terms.get(term.term_id)
            if ets is None: return self._invalid(bound,query,"IR term has no source EquationSpec term",relation_id)
            primitive=tr["primitive"]; support=tr["support"]
            projected=None; support_token=None; claim_class=None

            if primitive=="SCALAR_DIFFUSION":
                coeffs=[x for x in ets.symbols if x in data and data[x].role.upper()=="COEFFICIENT"]
                if len(coeffs)!=1: return self._unsupported(bound,query,"scalar diffusion coefficient binding is ambiguous",relation_id)
                coef=coeffs[0]; expected=f"{coef}*int(grad({state}).grad({eq.test_symbol}))"
                if term.expression!=expected: return self._unsupported(bound,query,"scalar diffusion expression mismatch",relation_id)
                projected=ZERO; support_token=("THEOREM",support["fixture"]["id"]); claim_class="THEOREM_INSTANTIATION_BINDING"
            elif primitive=="SCALAR_SOURCE":
                srcs=[x for x in ets.symbols if x in data and data[x].role.upper()=="SOURCE"]
                if len(srcs)!=1: return self._unsupported(bound,query,"scalar source binding is ambiguous",relation_id)
                src=srcs[0]; expected=f"<{src},{eq.test_symbol}>"
                if term.expression!=expected: return self._unsupported(bound,query,"scalar source expression mismatch",relation_id)
                projected=f"<{src},1>"; support_token=("STRUCTURAL",None); claim_class="STRUCTURAL_READER_SUBSTITUTION"
            elif primitive=="SCALAR_WEAK_PORT":
                port=ctx.get("active_port")
                if port is None:
                    return self._unsupported(bound,query,"weak-port primitive requires one bound weak-conormal port",relation_id)
                expected=f"<{port.port_id},trace({eq.test_symbol})>"
                if (term.expression!=expected or ets.port_ref!=port.port_id or term.semantic_ref!=port.port_id or
                    set(ets.symbols)!={port.port_id,eq.test_symbol}):
                    return self._unsupported(bound,query,"weak boundary-port expression/binding mismatch",relation_id)
                projected=f"<{port.port_id},trace(1)>"; support_token=("THEOREM",support["fixture"]["id"]); claim_class="THEOREM_INSTANTIATION_BINDING"
            elif primitive=="VECTOR_DIFFUSION":
                coeffs=[x for x in ets.symbols if x in data and data[x].role.upper()=="COEFFICIENT"]
                if len(coeffs)!=1: return self._unsupported(bound,query,"vector diffusion coefficient binding is ambiguous",relation_id)
                coef=coeffs[0]; expected=f"int({coef} grad({state}):grad({eq.test_symbol}))"
                if term.expression!=expected: return self._unsupported(bound,query,"vector diffusion expression mismatch",relation_id)
                projected=ZERO; support_token=("THEOREM",support["fixture"]["id"]); claim_class="THEOREM_INSTANTIATION_BINDING"
            elif primitive=="VECTOR_REACTION":
                mats=[d for d in profile.data if d.role.upper()==support["matrix_data_role"]]
                if len(mats)!=1 or mats[0].semantic!="EXACT_MATRIX":
                    return self._unsupported(bound,query,"left-nullspace primitive requires one exact matrix datum",relation_id)
                md=mats[0]; ops=[x for x in ets.symbols if x in operators]
                if len(ops)!=1: return self._unsupported(bound,query,"reaction operator binding is ambiguous",relation_id)
                op=ops[0]; expected=f"int({eq.test_symbol}^T {md.name} {op}({state}))"
                if term.expression!=expected: return self._unsupported(bound,query,"vector reaction expression mismatch",relation_id)
                if ExactLinearAlgebraChecker().check_row_zero(ctx["reader_value"],md.value)!=CheckResult.VALID:
                    return self._unsupported(bound,query,"declared reader is not in the exact left nullspace of the required matrix",relation_id)
                algebra_claim_id=content_id({"type":"ExactRowZeroClaim","reader":ctx["reader_value"],"matrix":md.value,"reader_id":reader,"matrix_id":md.name,"result":"ZERO"})
                algebra_roots.append(algebra_claim_id)
                projected=ZERO; support_token=("ALGEBRA",algebra_claim_id); claim_class="ALGEBRA_TO_PROJECTION_BINDING"
            elif primitive=="VECTOR_SOURCE":
                srcs=[x for x in ets.symbols if x in data and data[x].role.upper()=="SOURCE"]
                if len(srcs)!=1: return self._unsupported(bound,query,"vector source binding is ambiguous",relation_id)
                src=srcs[0]; expected=f"int({eq.test_symbol}^T {src})"
                if term.expression!=expected: return self._unsupported(bound,query,"vector source expression mismatch",relation_id)
                projected=f"int({reader}^T {src})"; support_token=("STRUCTURAL",None); claim_class="STRUCTURAL_READER_SUBSTITUTION"
            else:
                return self._unsupported(bound,query,f"unsupported declarative term primitive: {primitive}",relation_id)

            action=Action(tr["action"])
            if (action==Action.ANNIHILATE)!=(projected==ZERO):
                return self._invalid(bound,query,"declarative action/projected-object invariant violated",relation_id)
            pc=ProjectionClaim(projection_claim_semantic_id(bound.model_id,reader,term.term_id,query.query_id,query.scope,projected),bound.model_id,reader,term.term_id,query.query_id,query.scope,projected)
            projection_claims[pc.claim_id]=pc
            projected_terms.append(ProjectedTermEvidence(term.term_id,action,projected,pc.claim_id))
            rule_specs.append((support_token,pc.claim_id,claim_class))

        rf=raw["reader_admissibility_fixture"]["id"]
        reader_claim=ReaderAdmissibilityClaim(bound.model_id,ir.relation_id,query.query_id,reader,query.scope,eq.test_space,rf)
        reader_claim_id=reader_claim.claim_id
        derivative_object=raw["derivative"]["template"].format(**fmt)
        link=TargetDerivativeLink(target_link_semantic_id(bound.model_id,reader,ir.storage_term_id,query.query_id,query.scope,derivative_object),bound.model_id,reader,ir.storage_term_id,query.query_id,query.scope,derivative_object)
        evidence=BalanceReaderEvidence(bound.model_id,ir.relation_id,query.query_id,reader,query.scope,frozenset({reader_claim_id}),link.claim_id,tuple(projected_terms))

        relation_root=content_id({"type":"VerifiedBoundRelationRoot","profile":profile,"source":source,"ir":ir,"normalization":manifest})
        query_root=query.query_id
        pde_hash=_module_hash(type(bound.profile)); adapter_code_hash=file_sha256(Path(__file__))
        issuer_cid=content_id({"type":"DeclarativeAdapterExecutable","engine_id":self.engine_id,"engine_version":self.version,"adapter_code_hash":adapter_code_hash,"rule_content_id":self.rule_content_id})
        issuer_id=self.adapter_id
        roots=[CertifiedRoot(relation_root,"pde-binder",pde_hash,"MODEL_RELATION_BINDING"),CertifiedRoot(query_root,issuer_id,issuer_cid,"QUERY_CONTRACT_BINDING")]
        allowed={("pde-binder",pde_hash,"MODEL_RELATION_BINDING"),(issuer_id,issuer_cid,"QUERY_CONTRACT_BINDING"),(issuer_id,issuer_cid,"THEOREM_INSTANTIATION_BINDING"),(issuer_id,issuer_cid,"STRUCTURAL_READER_SUBSTITUTION"),(issuer_id,issuer_cid,"ALGEBRA_TO_PROJECTION_BINDING"),(issuer_id,issuer_cid,"ADAPTER_QUERY_BINDING"),(issuer_id,issuer_cid,"INPUT_CLOSURE_BINDING"),(issuer_id,issuer_cid,"DYNAMIC_CLOSURE_BINDING"),(issuer_id,issuer_cid,"EXACTNESS_ASSEMBLY_BINDING"),(BalanceReaderChecker.checker_id,checker_hash,"BALANCE_LAW_DERIVATION"),(ExactLinearAlgebraChecker.checker_id,algebra_hash,"EXACT_ALGEBRA_IDENTITY")}
        fixture_root={}
        for ref in fixture_refs:
            fid=ref["id"]; cid=registry.content_id_for(fid); rid=registry.root_id_for(fid); fi=f"theorem-fixture:{fid}"
            roots.append(CertifiedRoot(rid,fi,cid,"THEOREM_FIXTURE_ROOT")); allowed.add((fi,cid,"THEOREM_FIXTURE_ROOT")); fixture_root[fid]=rid
        for aid in sorted(set(algebra_roots)):
            roots.append(CertifiedRoot(aid,ExactLinearAlgebraChecker.checker_id,algebra_hash,"EXACT_ALGEBRA_IDENTITY"))

        rules=[
            CertifiedSupportRule(frozenset({relation_root,query_root,fixture_root[rf]}),reader_claim_id,issuer_id,issuer_cid,"THEOREM_INSTANTIATION_BINDING"),
            CertifiedSupportRule(frozenset({relation_root,query_root,reader_claim_id,fixture_root[raw['time_pairing_fixture']['id']]}),link.claim_id,issuer_id,issuer_cid,"THEOREM_INSTANTIATION_BINDING"),
        ]
        for token,claim_id,klass in rule_specs:
            premises={relation_root,query_root,reader_claim_id}; kind,ref=token
            if kind=="THEOREM": premises.add(fixture_root[ref])
            elif kind=="ALGEBRA": premises.add(ref)
            rules.append(CertifiedSupportRule(frozenset(premises),claim_id,issuer_id,issuer_cid,klass))
        policy=RuntimeTrustPolicy(f"{issuer_id}:{query.query_id}",frozenset(allowed))
        try:
            active=SupportKernel().certified_closure(tuple(roots),tuple(rules),policy)
        except Exception as exc:
            return self._invalid(bound,query,f"trust closure failed: {exc}",relation_id)
        cr,law=BalanceReaderChecker().check(ir,evidence,active,projection_claims,{link.claim_id:link})
        if cr!=CheckResult.VALID or law is None:
            return self._invalid(bound,query,f"balance reader check failed: {cr.value}",relation_id)

        law_id=content_id({"type":"VerifiedBalanceLaw","law":law})
        law_rule=CertifiedSupportRule(law.support_refs,law_id,BalanceReaderChecker.checker_id,checker_hash,"BALANCE_LAW_DERIVATION")
        law_value={"type":"BALANCE_LAW","derivative":law.derivative_object,"retained_terms":tuple({"sign":s,"object":o} for s,o in law.retained_terms),"defect_terms":tuple({"sign":s,"object":o} for s,o in law.defect_terms),"equation_form":"derivative + signed_terms = 0"}
        fact=QueryFact(bound.model_id,query.query_id,query.scope,QueryFactType.EXACT_LAW,law_value); fact_id=query_fact_id(fact)
        fact_rule=CertifiedSupportRule(frozenset({law_id}),fact_id,issuer_id,issuer_cid,"ADAPTER_QUERY_BINDING")
        input_evidence=ObligationEvidence(bound.model_id,query.query_id,query.scope,"H_I","SATISFIED",frozenset({relation_root,query_root}))
        input_rule=CertifiedSupportRule(input_evidence.support_refs,content_id(input_evidence),issuer_id,issuer_cid,"INPUT_CLOSURE_BINDING")
        dynamic_evidence=ObligationEvidence(bound.model_id,query.query_id,query.scope,"H_delta","SATISFIED",frozenset({law_id}))
        dynamic_rule=CertifiedSupportRule(dynamic_evidence.support_refs,content_id(dynamic_evidence),issuer_id,issuer_cid,"DYNAMIC_CLOSURE_BINDING")
        base_final_rules=tuple(rules)+(law_rule,fact_rule,input_rule,dynamic_rule)
        try:
            active=SupportKernel().certified_closure(tuple(roots),base_final_rules,policy)
        except Exception as exc:
            return self._invalid(bound,query,f"final trust closure failed: {exc}",relation_id)
        output=QueryAssembler().assemble(bound.model_id,query.query_id,query.scope,"LAW",(fact,),active)
        exact_witness=ExactnessWitness(bound.model_id,query.query_id,query.scope,content_id(output),output.kind,frozenset({fact_id}))
        witness_rule=CertifiedSupportRule(exact_witness.support_refs,content_id(exact_witness),issuer_id,issuer_cid,"EXACTNESS_ASSEMBLY_BINDING")
        try:
            active=SupportKernel().certified_closure(tuple(roots),base_final_rules+(witness_rule,),policy)
        except Exception as exc:
            return self._invalid(bound,query,f"exactness witness closure failed: {exc}",relation_id)
        run=RunSpec(bound.model_id,query.query_id,query.scope,release_id,frozenset({"H_N"}))
        faces=FaceEvaluator().evaluate(run,FaceInputs(input_evidence,exact_witness,output,active,active,dynamic_evidence,None))
        report=ReportBuilder().build(run,output,faces,active,tuple())
        status="VALID" if output.kind=="EXACT_LAW" and report.status=="CURRENT" else "INVALID"
        result=AutoEvidenceResult(status,"declarative automatic balance evidence assembled" if status=="VALID" else "declarative automatic assembly failed",bound.model_id,query.query_id,relation_id,tuple(ref["id"] for ref in fixture_refs),law,output,faces,report,active,"ZERO","NONE",self.rule_id,self.rule_content_id)
        return result


class DeclarativeAutoEvidenceRouter:
    """Deterministically selects one declarative rule from query + bound semantics."""
    version="0.2.0"
    def __init__(self, rule_registry: DeclarativeAdapterRuleRegistry | None = None):
        self.rule_registry=rule_registry or official_adapter_rule_registry()

    def select_rule_id(self, bound: BoundPDE, query: UserQuerySpec) -> str:
        if not bound.validation.valid:
            raise ValueError("PDE binding is invalid")
        hits=[]
        mean=DeclarativeBalanceEvidenceAdapter._mean_re.fullmatch(query.observable)
        vector=DeclarativeBalanceEvidenceAdapter._vector_obs_re.fullmatch(query.observable)
        state=mean.group("state") if mean else (vector.group("state") if vector else None)
        actual_boundary,_=_classify_state_boundary(bound,state) if state else (None,None)
        for r in self.rule_registry.rules:
            q=r.raw["query"]
            if query.kind!=q["kind"] or query.reader_kind!=q["reader_kind"]: continue
            if q["reader_id_mode"]=="LITERAL" and query.reader_id!=q["reader_id"]: continue
            if q["reader_id_mode"]=="DATA_REF" and query.reader_id not in {d.name for d in bound.profile.data}: continue
            if r.raw["profile"]["boundary_primitive"]!=actual_boundary: continue
            hits.append(r.rule_id)
        if len(hits)!=1:
            raise ValueError("no unique declarative automatic-evidence rule")
        return hits[0]

    def adapt(self,bound:BoundPDE,query:UserQuerySpec,registry:TheoremFixtureRegistry,*,release_id:str="declarative-auto-evidence-router") -> AutoEvidenceResult:
        if not bound.validation.valid:
            return _invalid(bound,query,"PDE binding is invalid")
        try: rid=self.select_rule_id(bound,query)
        except Exception as exc: return _unsupported(bound,query,str(exc))
        return DeclarativeBalanceEvidenceAdapter(rid,self.rule_registry).adapt(bound,query,registry,release_id=release_id)


# Compatibility aliases preserve old API names while forcing execution through the
# single declarative rule interpreter.
class WeakConstantTestEvidenceAdapter(DeclarativeBalanceEvidenceAdapter):
    adapter_id = "weak-constant-test-evidence-adapter"
    version = "0.2.0"
    def __init__(self, rule_registry: DeclarativeAdapterRuleRegistry | None = None):
        super().__init__("heat-mean-constant-test-v1",rule_registry)
    @property
    def adapter_id(self):
        return "weak-constant-test-evidence-adapter"

class WeakConstantVectorInvariantAdapter(DeclarativeBalanceEvidenceAdapter):
    adapter_id = "weak-constant-vector-invariant-adapter"
    version = "0.2.0"
    def __init__(self, rule_registry: DeclarativeAdapterRuleRegistry | None = None):
        super().__init__("reaction-diffusion-constant-vector-invariant-v1",rule_registry)
    @property
    def adapter_id(self):
        return "weak-constant-vector-invariant-adapter"

# Ensure summaries emitted after the declarative transition expose the selected rule.
def auto_evidence_summary(result: AutoEvidenceResult) -> Mapping[str, Any]:
    return {
        "status": result.status,
        "reason": result.reason,
        "model_id": result.model_id,
        "query_id": result.query_id,
        "relation_id": result.relation_id,
        "fixture_ids": result.fixture_ids,
        "adapter_theorem_credit": result.adapter_theorem_credit,
        "existence_credit": result.existence_credit,
        "rule_id": result.rule_id,
        "rule_content_id": result.rule_content_id,
        "law": canonical_data(result.law) if result.law is not None else None,
        "output": canonical_data(result.output) if result.output is not None else None,
        "faces": canonical_data(result.faces) if result.faces is not None else None,
        "report": canonical_data(result.report) if result.report is not None else None,
        "active_id": content_id(result.active),
    }
