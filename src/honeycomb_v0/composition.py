from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Tuple

from .adapters import (
    AutoEvidenceResult,
    DeclarativeAutoEvidenceRouter,
    TheoremFixtureRegistry,
)
from .assemblers import QueryAssembler, query_fact_id
from .canonical import canonical_data, content_id, file_sha256
from .dsl import BundleLawQuerySpec, UserQuerySpec
from .faces import FaceEvaluator, FaceInputs
from .kernel import CertifiedRoot, CertifiedSupportRule, RuntimeTrustPolicy, SupportKernel
from .pde import BoundPDEBundle, PDEBundleBinder, CouplingDefectSpec
from .report import CanonicalReport, ReportBuilder
from .checkers import DefectPropagationChecker, defect_bound_claim_semantic_id
from .types import (
    CheckResult,
    CoupledBalanceLaw,
    CoupledDefectBalanceLaw,
    DefectBoundClaim,
    DefectPropagationEvidence,
    Residual,
    FaceState,
    CouplingProjectionClaim,
    FaceVector,
    OutputArtifact,
    QueryFact,
    QueryFactType,
    RunSpec,
    ExactnessWitness,
    ObligationEvidence,
)

COUPLING_FIXTURE_ID = "linear-functional-signed-balance-v1"
COUPLING_FIXTURE_KIND = "LINEAR_FUNCTIONAL_SIGNED_BALANCE"
COUPLING_FIXTURE_CONTENT_ID = "77baa42f6a005a917c211aff621f331a8c036ca341b620b3faed1f1c8bd70d3a"


def coupling_projection_claim_semantic_id(
    bundle_id: str,
    coupling_id: str,
    query_id: str,
    scope,
    projected_port_terms: Tuple[Tuple[str, str, int, str], ...],
    projected_object: str = "ZERO",
    exact: bool = True,
) -> str:
    return content_id(
        {
            "type": "CouplingProjectionClaim",
            "bundle_id": bundle_id,
            "coupling_id": coupling_id,
            "query_id": query_id,
            "scope": scope,
            "projected_port_terms": projected_port_terms,
            "projected_object": projected_object,
            "exact": exact,
        }
    )


@dataclass(frozen=True)
class CoupledEvidenceResult:
    status: str
    reason: str
    bundle_id: str
    query_id: str
    coupling_ids: Tuple[str, ...]
    local_rule_ids: Tuple[Tuple[str, str], ...]
    law: CoupledBalanceLaw | None
    output: OutputArtifact | None
    faces: FaceVector | None
    report: CanonicalReport | None
    active: frozenset[str]
    composition_theorem_credit: str = "ZERO"
    existence_credit: str = "NONE"


class CouplingCompositionChecker:
    checker_id = "coupling-composition-checker"
    version = "0.1.0"

    def check(
        self,
        bound: BoundPDEBundle,
        query: BundleLawQuerySpec,
        local_results: Mapping[str, AutoEvidenceResult],
        claim: CouplingProjectionClaim,
        active: frozenset[str],
    ) -> tuple[CheckResult, CoupledBalanceLaw | None]:
        if not bound.validation.valid or query.bundle_id != bound.bundle.bundle_id or query.scope.level.value != "CONTINUUM":
            return CheckResult.INVALID, None
        if query.kind != "LAW" or query.observable_primitive != "SUM_LOCAL_MEAN" or query.reader_kind != "CONSTANT_TEST" or query.reader_id != "one":
            return CheckResult.UNSUPPORTED, None
        if len(bound.bundle.couplings) != 1:
            return CheckResult.UNSUPPORTED, None
        coupling = bound.bundle.couplings[0]
        if coupling.kind != "SIGNED_BALANCE" or coupling.equals != 0:
            return CheckResult.INVALID, None
        if claim.claim_id not in active or not claim.exact or claim.projected_object != "ZERO":
            return CheckResult.INVALID, None
        expected_claim_id = coupling_projection_claim_semantic_id(
            claim.bundle_id, claim.coupling_id, claim.query_id, claim.scope,
            claim.projected_port_terms, claim.projected_object, claim.exact,
        )
        if claim.claim_id != expected_claim_id:
            return CheckResult.INVALID, None
        if (claim.bundle_id, claim.coupling_id, claim.query_id, claim.scope) != (bound.bundle.bundle_id, coupling.coupling_id, query.query_id, query.scope):
            return CheckResult.INVALID, None

        by_name = {m.profile.name: m for m in bound.bound_models}
        if set(local_results) != set(by_name):
            return CheckResult.INVALID, None
        if {r.model_ref for r in coupling.terms} != set(by_name):
            return CheckResult.INVALID, None
        if len(coupling.terms) != len(by_name):
            return CheckResult.INVALID, None

        claim_rows = {(mid, port): (sgn, obj) for mid, port, sgn, obj in claim.projected_port_terms}
        if len(claim_rows) != len(claim.projected_port_terms):
            return CheckResult.INVALID, None

        local_derivatives=[]
        retained=[]
        law_ids=[]
        multiplier=None
        for cref in coupling.terms:
            bm = by_name.get(cref.model_ref)
            if bm is None:
                return CheckResult.INVALID, None
            result = local_results.get(cref.model_ref)
            if result is None or result.status != "VALID" or result.law is None or result.output is None or result.report is None:
                return CheckResult.INVALID, None
            if result.rule_id != "heat-mean-open-port-constant-test-v1":
                return CheckResult.INVALID, None
            if result.report.status != "CURRENT" or result.output.kind != "EXACT_LAW":
                return CheckResult.INVALID, None
            law=result.law
            if law.model_id != bm.model_id or law.scope != query.scope or law.defect_terms:
                return CheckResult.INVALID, None
            law_id=content_id({"type":"VerifiedBalanceLaw","law":law})
            if law_id not in result.active:
                return CheckResult.INVALID, None
            law_ids.append(law_id)

            ports={p.port_id:p for p in bm.profile.ports}
            port=ports.get(cref.port_ref)
            if port is None or port.field != query.field or port.orientation != "OUTWARD" or port.realization_kind != "WEAK_CONORMAL":
                return CheckResult.INVALID, None
            ir_ports=[t for ir in bm.ir_balances for t in ir.terms if t.role=="PORT" and t.semantic_ref==cref.port_ref]
            if len(ir_ports)!=1:
                return CheckResult.INVALID, None
            expected_obj=f"<{cref.port_ref},trace(1)>"
            port_hits=[(s,o) for s,o in law.retained_terms if o==expected_obj]
            if len(port_hits)!=1:
                return CheckResult.INVALID, None
            local_sign=port_hits[0][0]
            if local_sign != ir_ports[0].sign:
                return CheckResult.INVALID, None
            row=claim_rows.get((bm.model_id,cref.port_ref))
            if row != (cref.sign,expected_obj):
                return CheckResult.INVALID, None
            ratio=local_sign*cref.sign  # signs are +/-1, so division equals multiplication
            if multiplier is None:
                multiplier=ratio
            elif ratio!=multiplier:
                return CheckResult.INVALID, None

            local_derivatives.append((bm.model_id,law.derivative_object))
            skipped=False
            for s,o in law.retained_terms:
                if not skipped and (s,o)==(local_sign,expected_obj):
                    skipped=True
                    continue
                retained.append((bm.model_id,s,o))

        if multiplier not in (-1,1):
            return CheckResult.INVALID, None
        expected_projected=tuple(
            (by_name[r.model_ref].model_id,r.port_ref,r.sign,f"<{r.port_ref},trace(1)>")
            for r in coupling.terms
        )
        if claim.projected_port_terms != expected_projected:
            return CheckResult.INVALID, None

        supports=frozenset(law_ids+[claim.claim_id])
        law=CoupledBalanceLaw(
            bound.bundle.bundle_id,
            query.query_id,
            query.scope,
            tuple(local_derivatives),
            tuple(retained),
            (coupling.coupling_id,),
            supports,
        )
        return CheckResult.VALID, law


class CoupledPortBalanceEvidenceAdapter:
    """Compose verified local open-port laws through an exact signed coupling relation."""
    adapter_id = "coupled-port-balance-evidence-adapter"
    version = "0.1.0"

    def _fail(self,bound,query,status,reason):
        return CoupledEvidenceResult(status,reason,bound.bundle.bundle_id,query.query_id,tuple(),tuple(),None,None,None,None,frozenset())

    def adapt(
        self,
        bound: BoundPDEBundle,
        query: BundleLawQuerySpec,
        registry: TheoremFixtureRegistry,
        *,
        release_id: str = "coupled-port-auto-evidence",
    ) -> CoupledEvidenceResult:
        if not bound.validation.valid:
            return self._fail(bound,query,"INVALID","bundle binding is invalid")
        try:
            rebound=PDEBundleBinder().bind(bound.bundle)
        except Exception as exc:
            return self._fail(bound,query,"INVALID",f"bundle rebind failed: {exc}")
        if rebound != bound:
            return self._fail(bound,query,"INVALID","BoundPDEBundle is not reproducible binder output")
        if (query.bundle_id,query.bundle_name)!=(bound.bundle.bundle_id,bound.bundle.name):
            return self._fail(bound,query,"INVALID","bundle query identity mismatch")
        if len(bound.bundle.couplings)!=1:
            return self._fail(bound,query,"UNSUPPORTED","v0 composition requires exactly one signed coupling")
        coupling=bound.bundle.couplings[0]
        try:
            row=registry.row(COUPLING_FIXTURE_ID)
            if row.get("role")!="trusted_theorem_fixture" or row.get("theorem_kind")!=COUPLING_FIXTURE_KIND:
                return self._fail(bound,query,"UNSUPPORTED","coupling theorem fixture semantic kind mismatch")
            if registry.content_id_for(COUPLING_FIXTURE_ID)!=COUPLING_FIXTURE_CONTENT_ID:
                return self._fail(bound,query,"UNSUPPORTED","coupling theorem fixture fingerprint mismatch")
        except Exception as exc:
            return self._fail(bound,query,"UNSUPPORTED",f"coupling theorem fixture unavailable: {exc}")

        router=DeclarativeAutoEvidenceRouter()
        local_results={}
        local_rule_ids=[]
        for bm in bound.bound_models:
            lq=UserQuerySpec(
                f"{query.name}:{bm.profile.name}",
                bm.profile.name,
                bm.model_id,
                "LAW",
                f"mean({query.field})",
                "CONSTANT_TEST",
                "one",
                query.scope,
            )
            lr=router.adapt(bm,lq,registry,release_id=f"{release_id}:{bm.profile.name}")
            if lr.status!="VALID":
                return self._fail(bound,query,lr.status,f"local law failed for {bm.profile.name}: {lr.reason}")
            local_results[bm.profile.name]=lr
            local_rule_ids.append((bm.profile.name,lr.rule_id or ""))

        by_name={m.profile.name:m for m in bound.bound_models}
        projected=[]
        for ref in coupling.terms:
            bm=by_name.get(ref.model_ref)
            if bm is None:
                return self._fail(bound,query,"INVALID","coupling references unknown model")
            projected.append((bm.model_id,ref.port_ref,ref.sign,f"<{ref.port_ref},trace(1)>"))
        projected=tuple(projected)
        claim=CouplingProjectionClaim(
            coupling_projection_claim_semantic_id(bound.bundle.bundle_id,coupling.coupling_id,query.query_id,query.scope,projected),
            bound.bundle.bundle_id,coupling.coupling_id,query.query_id,query.scope,projected,"ZERO",True,
        )

        adapter_hash=file_sha256(Path(__file__))
        checker_hash=adapter_hash
        binder_hash=file_sha256(Path(__file__).with_name("pde.py"))
        local_roots=[]
        allowed={(self.adapter_id,adapter_hash,"BUNDLE_QUERY_BINDING"),(self.adapter_id,adapter_hash,"VERIFIED_LOCAL_LAW_IMPORT"),(self.adapter_id,adapter_hash,"COMPOSED_QUERY_BINDING"),(self.adapter_id,adapter_hash,"INPUT_CLOSURE_BINDING"),(self.adapter_id,adapter_hash,"DYNAMIC_CLOSURE_BINDING"),(self.adapter_id,adapter_hash,"EXACTNESS_ASSEMBLY_BINDING"),("pde-bundle-binder",binder_hash,"BUNDLE_RELATION_BINDING"),("theorem-fixture:"+COUPLING_FIXTURE_ID,COUPLING_FIXTURE_CONTENT_ID,"THEOREM_FIXTURE_ROOT"),(CouplingCompositionChecker.checker_id,checker_hash,"COUPLING_PROJECTION_DERIVATION"),(CouplingCompositionChecker.checker_id,checker_hash,"RELATIONAL_COMPOSITION_DERIVATION")}
        roots=[]
        bundle_root=content_id({"type":"VerifiedBoundPDEBundleRoot","bundle":bound.bundle,"bound_models":bound.bound_models})
        roots.append(CertifiedRoot(bundle_root,"pde-bundle-binder",binder_hash,"BUNDLE_RELATION_BINDING"))
        roots.append(CertifiedRoot(query.query_id,self.adapter_id,adapter_hash,"BUNDLE_QUERY_BINDING"))
        fixture_root=registry.root_id_for(COUPLING_FIXTURE_ID)
        roots.append(CertifiedRoot(fixture_root,"theorem-fixture:"+COUPLING_FIXTURE_ID,COUPLING_FIXTURE_CONTENT_ID,"THEOREM_FIXTURE_ROOT"))
        for name,lr in sorted(local_results.items()):
            law_id=content_id({"type":"VerifiedBalanceLaw","law":lr.law})
            roots.append(CertifiedRoot(law_id,self.adapter_id,adapter_hash,"VERIFIED_LOCAL_LAW_IMPORT"))
            local_roots.append(law_id)
        claim_rule=CertifiedSupportRule(frozenset({bundle_root,query.query_id,fixture_root}),claim.claim_id,CouplingCompositionChecker.checker_id,checker_hash,"COUPLING_PROJECTION_DERIVATION")
        policy=RuntimeTrustPolicy(f"coupled:{query.query_id}",frozenset(allowed))
        try:
            active=SupportKernel().certified_closure(tuple(roots),(claim_rule,),policy)
        except Exception as exc:
            return self._fail(bound,query,"INVALID",f"composition trust closure failed: {exc}")
        cr,law=CouplingCompositionChecker().check(bound,query,local_results,claim,active)
        if cr!=CheckResult.VALID or law is None:
            return self._fail(bound,query,cr.value,f"coupling composition check failed: {cr.value}")

        law_id=content_id({"type":"VerifiedCoupledBalanceLaw","law":law})
        law_rule=CertifiedSupportRule(law.support_refs,law_id,CouplingCompositionChecker.checker_id,checker_hash,"RELATIONAL_COMPOSITION_DERIVATION")
        law_value={
            "type":"COUPLED_BALANCE_LAW",
            "local_derivatives":tuple({"model_id":mid,"object":obj} for mid,obj in law.local_derivatives),
            "retained_terms":tuple({"model_id":mid,"sign":s,"object":obj} for mid,s,obj in law.retained_terms),
            "eliminated_couplings":law.eliminated_couplings,
            "equation_form":"sum(local_derivatives) + signed retained terms = 0",
        }
        fact=QueryFact(bound.bundle.bundle_id,query.query_id,query.scope,QueryFactType.EXACT_LAW,law_value)
        fact_id=query_fact_id(fact)
        fact_rule=CertifiedSupportRule(frozenset({law_id}),fact_id,self.adapter_id,adapter_hash,"COMPOSED_QUERY_BINDING")
        input_evidence=ObligationEvidence(bound.bundle.bundle_id,query.query_id,query.scope,"H_I","SATISFIED",frozenset({bundle_root,query.query_id}))
        input_rule=CertifiedSupportRule(input_evidence.support_refs,content_id(input_evidence),self.adapter_id,adapter_hash,"INPUT_CLOSURE_BINDING")
        dynamic_evidence=ObligationEvidence(bound.bundle.bundle_id,query.query_id,query.scope,"H_delta","SATISFIED",frozenset({law_id}))
        dynamic_rule=CertifiedSupportRule(dynamic_evidence.support_refs,content_id(dynamic_evidence),self.adapter_id,adapter_hash,"DYNAMIC_CLOSURE_BINDING")
        base_rules=(claim_rule,law_rule,fact_rule,input_rule,dynamic_rule)
        try:
            active=SupportKernel().certified_closure(tuple(roots),base_rules,policy)
        except Exception as exc:
            return self._fail(bound,query,"INVALID",f"final composition trust closure failed: {exc}")
        output=QueryAssembler().assemble(bound.bundle.bundle_id,query.query_id,query.scope,"LAW",(fact,),active)
        exact_witness=ExactnessWitness(bound.bundle.bundle_id,query.query_id,query.scope,content_id(output),output.kind,frozenset({fact_id}))
        witness_rule=CertifiedSupportRule(exact_witness.support_refs,content_id(exact_witness),self.adapter_id,adapter_hash,"EXACTNESS_ASSEMBLY_BINDING")
        try:
            active=SupportKernel().certified_closure(tuple(roots),base_rules+(witness_rule,),policy)
        except Exception as exc:
            return self._fail(bound,query,"INVALID",f"composition exactness closure failed: {exc}")
        run=RunSpec(bound.bundle.bundle_id,query.query_id,query.scope,release_id,frozenset({"H_N"}))
        faces=FaceEvaluator().evaluate(run,FaceInputs(input_evidence,exact_witness,output,active,active,dynamic_evidence,None))
        report=ReportBuilder().build(run,output,faces,active,tuple())
        status="VALID" if output.kind=="EXACT_LAW" and report.status=="CURRENT" else "INVALID"
        return CoupledEvidenceResult(status,"exact local port laws composed through signed coupling" if status=="VALID" else "composed output failed",bound.bundle.bundle_id,query.query_id,(coupling.coupling_id,),tuple(local_rule_ids),law,output,faces,report,active,"ZERO","NONE")


def coupled_evidence_summary(result: CoupledEvidenceResult) -> Mapping[str,Any]:
    return {
        "status":result.status,
        "reason":result.reason,
        "bundle_id":result.bundle_id,
        "query_id":result.query_id,
        "coupling_ids":result.coupling_ids,
        "local_rule_ids":result.local_rule_ids,
        "composition_theorem_credit":result.composition_theorem_credit,
        "existence_credit":result.existence_credit,
        "law":canonical_data(result.law) if result.law else None,
        "output":canonical_data(result.output) if result.output else None,
        "faces":canonical_data(result.faces) if result.faces else None,
        "report":canonical_data(result.report) if result.report else None,
        "active_id":content_id(result.active),
    }

DEFECT_COUPLING_FIXTURE_ID = "linear-functional-signed-relation-v1"
DEFECT_COUPLING_FIXTURE_KIND = "LINEAR_FUNCTIONAL_SIGNED_RELATION"
DEFECT_COUPLING_FIXTURE_CONTENT_ID = "3d34d11f39c0eaa035993e30a4fe75420d39613d04dfbdabeea65c2ed4b85e53"


@dataclass(frozen=True)
class CoupledDefectEvidenceResult:
    status: str
    reason: str
    bundle_id: str
    query_id: str
    coupling_ids: Tuple[str, ...]
    local_rule_ids: Tuple[Tuple[str, str], ...]
    law: CoupledDefectBalanceLaw | None
    output: OutputArtifact | None
    faces: FaceVector | None
    report: CanonicalReport | None
    residuals: Tuple[object, ...]
    active: frozenset[str]
    composition_theorem_credit: str = "ZERO"
    existence_credit: str = "NONE"


class CoupledDefectCompositionChecker:
    checker_id = "coupled-defect-composition-checker"
    version = "0.1.0"

    def check_structure(self, bound: BoundPDEBundle, query: BundleLawQuerySpec,
                        local_results: Mapping[str, AutoEvidenceResult], claim: CouplingProjectionClaim,
                        active: frozenset[str]):
        if not bound.validation.valid or len(bound.bundle.couplings)!=1:
            return CheckResult.INVALID, None
        coupling=bound.bundle.couplings[0]
        if coupling.kind!="SIGNED_BALANCE" or not isinstance(coupling.equals,CouplingDefectSpec):
            return CheckResult.INVALID, None
        rhs=coupling.equals
        if query.bundle_id!=bound.bundle.bundle_id or query.kind!="LAW" or query.observable_primitive!="SUM_LOCAL_MEAN" or query.reader_kind!="CONSTANT_TEST" or query.reader_id!="one":
            return CheckResult.INVALID, None
        expected_defect=f"<{rhs.defect_id},trace(1)>"
        if claim.claim_id not in active or not claim.exact or claim.projected_object!=expected_defect:
            return CheckResult.INVALID, None
        if claim.claim_id != coupling_projection_claim_semantic_id(claim.bundle_id,claim.coupling_id,claim.query_id,claim.scope,claim.projected_port_terms,claim.projected_object,claim.exact):
            return CheckResult.INVALID, None
        if (claim.bundle_id,claim.coupling_id,claim.query_id,claim.scope)!=(bound.bundle.bundle_id,coupling.coupling_id,query.query_id,query.scope):
            return CheckResult.INVALID, None
        by_name={m.profile.name:m for m in bound.bound_models}
        if set(local_results)!=set(by_name) or {r.model_ref for r in coupling.terms}!=set(by_name):
            return CheckResult.INVALID, None
        claim_rows={(mid,port):(sgn,obj) for mid,port,sgn,obj in claim.projected_port_terms}
        if len(claim_rows)!=len(claim.projected_port_terms):
            return CheckResult.INVALID, None
        local_derivatives=[]; retained=[]; law_ids=[]; multiplier=None
        for cref in coupling.terms:
            bm=by_name.get(cref.model_ref); result=local_results.get(cref.model_ref)
            if bm is None or result is None or result.status!="VALID" or result.law is None or result.output is None or result.report is None:
                return CheckResult.INVALID, None
            if result.rule_id!="heat-mean-open-port-constant-test-v1" or result.output.kind!="EXACT_LAW" or result.report.status!="CURRENT":
                return CheckResult.INVALID, None
            law=result.law
            if law.model_id!=bm.model_id or law.scope!=query.scope or law.defect_terms:
                return CheckResult.INVALID, None
            law_id=content_id({"type":"VerifiedBalanceLaw","law":law})
            if law_id not in result.active: return CheckResult.INVALID, None
            law_ids.append(law_id)
            ports={p.port_id:p for p in bm.profile.ports}; port=ports.get(cref.port_ref)
            if port is None or port.field!=query.field or port.orientation!="OUTWARD" or port.realization_kind!="WEAK_CONORMAL" or port.semantic_space!=rhs.semantic_space:
                return CheckResult.INVALID, None
            ir_ports=[t for ir in bm.ir_balances for t in ir.terms if t.role=="PORT" and t.semantic_ref==cref.port_ref]
            if len(ir_ports)!=1: return CheckResult.INVALID, None
            expected_obj=f"<{cref.port_ref},trace(1)>"
            hits=[(sgn,obj) for sgn,obj in law.retained_terms if obj==expected_obj]
            if len(hits)!=1 or hits[0][0]!=ir_ports[0].sign: return CheckResult.INVALID, None
            local_sign=hits[0][0]
            if claim_rows.get((bm.model_id,cref.port_ref))!=(cref.sign,expected_obj): return CheckResult.INVALID, None
            ratio=local_sign*cref.sign
            if multiplier is None: multiplier=ratio
            elif ratio!=multiplier: return CheckResult.INVALID, None
            local_derivatives.append((bm.model_id,law.derivative_object))
            skipped=False
            for sgn,obj in law.retained_terms:
                if not skipped and (sgn,obj)==(local_sign,expected_obj): skipped=True; continue
                retained.append((bm.model_id,sgn,obj))
        expected_projected=tuple((by_name[r.model_ref].model_id,r.port_ref,r.sign,f"<{r.port_ref},trace(1)>") for r in coupling.terms)
        if claim.projected_port_terms!=expected_projected or multiplier not in (-1,1):
            return CheckResult.INVALID, None
        return CheckResult.VALID,(tuple(local_derivatives),tuple(retained),multiplier,expected_defect,frozenset(law_ids+[claim.claim_id]))


class CoupledDefectPortBalanceEvidenceAdapter:
    """Compose local exact port laws through q-coupling = declared defect, then propagate its bound."""
    adapter_id="coupled-defect-port-balance-evidence-adapter"
    version="0.1.0"

    def _fail(self,bound,query,status,reason):
        return CoupledDefectEvidenceResult(status,reason,bound.bundle.bundle_id,query.query_id,tuple(),tuple(),None,None,None,None,tuple(),frozenset())

    def adapt(self,bound: BoundPDEBundle,query: BundleLawQuerySpec,registry: TheoremFixtureRegistry,*,release_id: str="coupled-defect-auto-evidence") -> CoupledDefectEvidenceResult:
        if not bound.validation.valid or len(bound.bundle.couplings)!=1:
            return self._fail(bound,query,"INVALID","bundle binding invalid or unsupported coupling arity")
        try:
            if PDEBundleBinder().bind(bound.bundle)!=bound:
                return self._fail(bound,query,"INVALID","BoundPDEBundle is not reproducible binder output")
        except Exception as exc:
            return self._fail(bound,query,"INVALID",f"bundle rebind failed: {exc}")
        coupling=bound.bundle.couplings[0]
        if not isinstance(coupling.equals,CouplingDefectSpec):
            return self._fail(bound,query,"UNSUPPORTED","defect composer requires typed defect coupling RHS")
        rhs=coupling.equals
        try:
            row=registry.row(DEFECT_COUPLING_FIXTURE_ID)
            if row.get("role")!="trusted_theorem_fixture" or row.get("theorem_kind")!=DEFECT_COUPLING_FIXTURE_KIND or registry.content_id_for(DEFECT_COUPLING_FIXTURE_ID)!=DEFECT_COUPLING_FIXTURE_CONTENT_ID:
                return self._fail(bound,query,"UNSUPPORTED","defect coupling theorem fixture mismatch")
        except Exception as exc:
            return self._fail(bound,query,"UNSUPPORTED",f"defect coupling theorem fixture unavailable: {exc}")
        router=DeclarativeAutoEvidenceRouter(); local_results={}; local_rule_ids=[]
        for bm in bound.bound_models:
            lq=UserQuerySpec(f"{query.name}:{bm.profile.name}",bm.profile.name,bm.model_id,"LAW",f"mean({query.field})","CONSTANT_TEST","one",query.scope)
            lr=router.adapt(bm,lq,registry,release_id=f"{release_id}:{bm.profile.name}")
            if lr.status!="VALID": return self._fail(bound,query,lr.status,f"local law failed for {bm.profile.name}: {lr.reason}")
            local_results[bm.profile.name]=lr; local_rule_ids.append((bm.profile.name,lr.rule_id or ""))
        by_name={m.profile.name:m for m in bound.bound_models}
        projected=tuple((by_name[r.model_ref].model_id,r.port_ref,r.sign,f"<{r.port_ref},trace(1)>") for r in coupling.terms)
        defect_obj=f"<{rhs.defect_id},trace(1)>"
        claim=CouplingProjectionClaim(coupling_projection_claim_semantic_id(bound.bundle.bundle_id,coupling.coupling_id,query.query_id,query.scope,projected,defect_obj,True),bound.bundle.bundle_id,coupling.coupling_id,query.query_id,query.scope,projected,defect_obj,True)
        bound_claim=DefectBoundClaim(defect_bound_claim_semantic_id(bound.bundle.bundle_id,rhs.defect_id,query.scope,defect_obj,rhs.projected_abs_bound),bound.bundle.bundle_id,rhs.defect_id,query.scope,defect_obj,rhs.projected_abs_bound)
        adapter_hash=file_sha256(Path(__file__)); checker_hash=adapter_hash; binder_hash=file_sha256(Path(__file__).with_name("pde.py")); prop_hash=file_sha256(Path(__file__).with_name("checkers.py"))
        bundle_root=content_id({"type":"VerifiedBoundPDEBundleRoot","bundle":bound.bundle,"bound_models":bound.bound_models})
        fixture_root=registry.root_id_for(DEFECT_COUPLING_FIXTURE_ID)
        roots=[CertifiedRoot(bundle_root,"pde-bundle-binder",binder_hash,"BUNDLE_RELATION_BINDING"),CertifiedRoot(query.query_id,self.adapter_id,adapter_hash,"BUNDLE_QUERY_BINDING"),CertifiedRoot(fixture_root,"theorem-fixture:"+DEFECT_COUPLING_FIXTURE_ID,DEFECT_COUPLING_FIXTURE_CONTENT_ID,"THEOREM_FIXTURE_ROOT"),CertifiedRoot(bound_claim.claim_id,"pde-bundle-binder",binder_hash,"COUPLING_DEFECT_BOUND_ROOT")]
        for _,lr in sorted(local_results.items()): roots.append(CertifiedRoot(content_id({"type":"VerifiedBalanceLaw","law":lr.law}),self.adapter_id,adapter_hash,"VERIFIED_LOCAL_LAW_IMPORT"))
        allowed={("pde-bundle-binder",binder_hash,"BUNDLE_RELATION_BINDING"),("pde-bundle-binder",binder_hash,"COUPLING_DEFECT_BOUND_ROOT"),(self.adapter_id,adapter_hash,"BUNDLE_QUERY_BINDING"),(self.adapter_id,adapter_hash,"VERIFIED_LOCAL_LAW_IMPORT"),(self.adapter_id,adapter_hash,"COMPOSED_QUERY_BINDING"),(self.adapter_id,adapter_hash,"INPUT_CLOSURE_BINDING"),(self.adapter_id,adapter_hash,"DYNAMIC_CLOSURE_BINDING"),(self.adapter_id,adapter_hash,"EXACTNESS_ASSEMBLY_BINDING"),("theorem-fixture:"+DEFECT_COUPLING_FIXTURE_ID,DEFECT_COUPLING_FIXTURE_CONTENT_ID,"THEOREM_FIXTURE_ROOT"),(CoupledDefectCompositionChecker.checker_id,checker_hash,"COUPLING_DEFECT_PROJECTION_DERIVATION"),(CoupledDefectCompositionChecker.checker_id,checker_hash,"RELATIONAL_DEFECT_COMPOSITION_DERIVATION"),(DefectPropagationChecker.checker_id,prop_hash,"DEFECT_PROPAGATION_DERIVATION")}
        claim_rule=CertifiedSupportRule(frozenset({bundle_root,query.query_id,fixture_root}),claim.claim_id,CoupledDefectCompositionChecker.checker_id,checker_hash,"COUPLING_DEFECT_PROJECTION_DERIVATION")
        policy=RuntimeTrustPolicy(f"coupled-defect:{query.query_id}",frozenset(allowed))
        try: active=SupportKernel().certified_closure(tuple(roots),(claim_rule,),policy)
        except Exception as exc: return self._fail(bound,query,"INVALID",f"defect composition trust closure failed: {exc}")
        cr,parts=CoupledDefectCompositionChecker().check_structure(bound,query,local_results,claim,active)
        if cr!=CheckResult.VALID or parts is None: return self._fail(bound,query,cr.value,f"defect composition structure failed: {cr.value}")
        derivatives,retained,multiplier,defect_obj,supports=parts
        pe=DefectPropagationEvidence(query.query_id,query.scope,((multiplier,bound_claim),))
        pr,prop=DefectPropagationChecker().check(pe,active)
        if pr!=CheckResult.VALID or prop is None: return self._fail(bound,query,pr.value,f"defect propagation failed: {pr.value}")
        all_supports=frozenset(set(supports)|set(prop.support_refs))
        law=CoupledDefectBalanceLaw(bound.bundle.bundle_id,query.query_id,query.scope,derivatives,retained,((coupling.coupling_id,multiplier,defect_obj),),prop.interval,all_supports)
        law_id=content_id({"type":"VerifiedCoupledDefectBalanceLaw","law":law})
        law_rule=CertifiedSupportRule(all_supports,law_id,CoupledDefectCompositionChecker.checker_id,checker_hash,"RELATIONAL_DEFECT_COMPOSITION_DERIVATION")
        law_value={"type":"COUPLED_DEFECT_BALANCE_LAW","local_derivatives":tuple({"model_id":mid,"object":obj} for mid,obj in law.local_derivatives),"retained_terms":tuple({"model_id":mid,"sign":sgn,"object":obj} for mid,sgn,obj in law.retained_terms),"defect_terms":tuple({"coupling_id":cid,"sign":sgn,"object":obj} for cid,sgn,obj in law.defect_terms),"defect_interval":law.propagated_interval,"equation_form":"sum(local_derivatives) + signed retained terms + signed defect = 0"}
        fact=QueryFact(bound.bundle.bundle_id,query.query_id,query.scope,QueryFactType.DEFECT_LAW,law_value); fact_id=query_fact_id(fact)
        fact_rule=CertifiedSupportRule(frozenset({law_id}),fact_id,self.adapter_id,adapter_hash,"COMPOSED_QUERY_BINDING")
        input_evidence=ObligationEvidence(bound.bundle.bundle_id,query.query_id,query.scope,"H_I","SATISFIED",frozenset({bundle_root,query.query_id}))
        input_rule=CertifiedSupportRule(input_evidence.support_refs,content_id(input_evidence),self.adapter_id,adapter_hash,"INPUT_CLOSURE_BINDING")
        dynamic_evidence=ObligationEvidence(bound.bundle.bundle_id,query.query_id,query.scope,"H_delta","SATISFIED",frozenset({law_id}))
        dynamic_rule=CertifiedSupportRule(dynamic_evidence.support_refs,content_id(dynamic_evidence),self.adapter_id,adapter_hash,"DYNAMIC_CLOSURE_BINDING")
        base_rules=(claim_rule,law_rule,fact_rule,input_rule,dynamic_rule)
        try: active=SupportKernel().certified_closure(tuple(roots),base_rules,policy)
        except Exception as exc: return self._fail(bound,query,"INVALID",f"final defect trust closure failed: {exc}")
        output=QueryAssembler().assemble(bound.bundle.bundle_id,query.query_id,query.scope,"LAW",(fact,),active)
        exact_witness=ExactnessWitness(bound.bundle.bundle_id,query.query_id,query.scope,content_id(output),output.kind,frozenset({fact_id}))
        witness_rule=CertifiedSupportRule(exact_witness.support_refs,content_id(exact_witness),self.adapter_id,adapter_hash,"EXACTNESS_ASSEMBLY_BINDING")
        try: active=SupportKernel().certified_closure(tuple(roots),base_rules+(witness_rule,),policy)
        except Exception as exc: return self._fail(bound,query,"INVALID",f"defect exactness closure failed: {exc}")
        run=RunSpec(bound.bundle.bundle_id,query.query_id,query.scope,release_id,frozenset({"H_N"}))
        faces=FaceEvaluator().evaluate(run,FaceInputs(input_evidence,exact_witness,output,active,active,dynamic_evidence,None))
        residual=Residual(content_id({"type":"CouplingDefectResidual","bundle":bound.bundle.bundle_id,"coupling":coupling.coupling_id,"interval":prop.interval}),"BOUNDED",True)
        report=ReportBuilder().build(run,output,faces,active,(residual,))
        status="VALID" if output.kind=="CERTIFIED_DEFECT_LAW" and report.status=="CURRENT" and faces.H_E==FaceState.PASS else "INVALID"
        return CoupledDefectEvidenceResult(status,"exact defect-bearing coupling relation with certified propagated bound" if status=="VALID" else "defect output failed",bound.bundle.bundle_id,query.query_id,(coupling.coupling_id,),tuple(local_rule_ids),law,output,faces,report,(residual,),active,"ZERO","NONE")


def coupled_defect_evidence_summary(result: CoupledDefectEvidenceResult) -> Mapping[str,Any]:
    return {"status":result.status,"reason":result.reason,"bundle_id":result.bundle_id,"query_id":result.query_id,"coupling_ids":result.coupling_ids,"local_rule_ids":result.local_rule_ids,"composition_theorem_credit":result.composition_theorem_credit,"existence_credit":result.existence_credit,"law":canonical_data(result.law) if result.law else None,"output":canonical_data(result.output) if result.output else None,"faces":canonical_data(result.faces) if result.faces else None,"report":canonical_data(result.report) if result.report else None,"residuals":canonical_data(result.residuals),"active_id":content_id(result.active)}
