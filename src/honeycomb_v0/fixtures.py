from __future__ import annotations
from fractions import Fraction
from pathlib import Path
import json
from .types import *
from .checkers import *
from .kernel import *
from .assemblers import *
from .faces import *
from .conformance import ClosedLoopEvaluator, closed_loop_pass
from .report import *
from .release import OracleResult
from .canonical import content_id
from .dsl import DSLCompiler, DSLError
from .pde import PDEBinder, PDEBundleBinder
from .adapters import WeakConstantTestEvidenceAdapter, WeakConstantVectorInvariantAdapter, TheoremFixtureRegistry, DeclarativeAutoEvidenceRouter, DeclarativeBalanceEvidenceAdapter, official_adapter_rule_registry
from .rules import DeclarativeAdapterRuleRegistry
from .composition import CoupledPortBalanceEvidenceAdapter, CoupledDefectPortBalanceEvidenceAdapter, COUPLING_FIXTURE_ID, DEFECT_COUPLING_FIXTURE_ID
from .measure import MeasureValuedQueryPipeline
from .weak_evidence import (WeakLimitEvidenceAdapter, weak_evidence_source_content_id, weak_evidence_submission_semantic_id)

CONT = Scope(ScopeLevel.CONTINUUM, "weak")
DISC = Scope(ScopeLevel.DISCRETE, "semidiscrete")

DUAL_THEOREM_FIXTURES = frozenset({"nonclosed-range-guard-v1"})
WEAK_DEFECT_THEOREM_FIXTURES = frozenset({"weak-nonlinear-limit-guard-v1","weak-oscillation-young-measure-guard-v1","weak-concentration-measure-guard-v1","weak-linear-functional-continuity-v1"})
QUERY_TRANSPARENCY_THEOREM_FIXTURES = frozenset({"periodic-mean-divergence-defect-transparency-v1"})
WEAK_EVIDENCE_THEOREM_FIXTURES = frozenset({"explicit-oscillation-weak-young-v1","explicit-concentration-weak-young-concentration-v1"})
PDE_THEOREM_FIXTURES = frozenset({"weak-time-derivative-pairing-v1"})
REQUIRED_THEOREM_FIXTURES = DUAL_THEOREM_FIXTURES | WEAK_DEFECT_THEOREM_FIXTURES | QUERY_TRANSPARENCY_THEOREM_FIXTURES | WEAK_EVIDENCE_THEOREM_FIXTURES | PDE_THEOREM_FIXTURES

ORACLE_FAMILIES = {
    "r1.norm.complete": "R1",
    "r1.dsl.heat.bind": "R1",
    "r1.dsl.rd.bind": "R1",
    "r1.auto.heat.evidence": "R1",
    "r1.auto.rd.evidence": "R1",
    "r1.auto.heat.open-port.evidence": "R1",
    "r1.declarative.adapter.rules": "R1",
    "r2.fvm.incidence": "R2",
    "r2.dsl.interface.bind": "R2",
    "r2.auto.interface.composition": "R2",
    "r2.auto.interface.defect": "R2",
    "r3.behavioral.quotient": "R3",
    "r4.transition.congruence": "R4",
    "r5.branch.image": "R5",
    "r6.infinite.guard": "R6",
    "r6.infinite.dual": "R6",
    "r6.weak.defect": "R6",
    "r6.weak.evidence.ingress": "R6",
    "r6.measure.outer.query": "R6",
    "r6.measure.query.transparency": "R6",
    "r7.truth.output.scope": "R7",
    "r8.rollback.multisupport": "R8",
    "ga.identity.transport": "G_A",
    "gb.scope.firewall": "G_B",
    "gc.conflict.quarantine": "G_C",
    "gd.support.cycle": "G_D",
    "ge.numeric.semantic": "G_E",
    "gf.view.dynamic": "G_F",
    "gg.empty.vacuity": "G_G",
    "gg.he.closed.loop": "G_G",
}

def nonclosed_range_fixture_semantics_valid(registry: TheoremFixtureRegistry | None) -> bool:
    if registry is None:
        return True
    try:
        nr=registry.row("nonclosed-range-guard-v1"); ws=nr.get("witness_schema",{})
        return (nr.get("role")=="trusted_counterexample_fixture" and nr.get("theorem_kind")=="NONCLOSED_RANGE_GUARD" and
                ws.get("space")=="l2" and ws.get("operator")=="diag(1/n)" and ws.get("target")=="(1/n)" and
                ws.get("closure_membership") is True and ws.get("range_membership") is False)
    except Exception:
        return False


def weak_limit_fixture_semantics_valid(registry: TheoremFixtureRegistry | None) -> bool:
    if registry is None:
        return True
    try:
        osc=registry.row("weak-oscillation-young-measure-guard-v1")
        conc=registry.row("weak-concentration-measure-guard-v1")
        lin=registry.row("weak-linear-functional-continuity-v1")
        return (osc.get("role")=="trusted_counterexample_fixture" and osc.get("theorem_kind")=="WEAK_OSCILLATION_YOUNG_MEASURE_GUARD" and
                conc.get("role")=="trusted_counterexample_fixture" and conc.get("theorem_kind")=="WEAK_CONCENTRATION_MEASURE_GUARD" and
                lin.get("role")=="trusted_theorem_fixture" and lin.get("theorem_kind")=="WEAK_LINEAR_FUNCTIONAL_CONTINUITY")
    except Exception:
        return False




def weak_evidence_fixture_semantics_valid(registry: TheoremFixtureRegistry | None) -> bool:
    if registry is None:
        return True
    try:
        osc=registry.row("explicit-oscillation-weak-young-v1")
        conc=registry.row("explicit-concentration-weak-young-concentration-v1")
        os=osc.get("evidence_schema",{}); cs=conc.get("evidence_schema",{})
        return (osc.get("role")=="trusted_theorem_fixture" and osc.get("theorem_kind")=="EXPLICIT_SEQUENCE_EVIDENCE" and
                set(os.get("certified_kinds",[]))=={"WEAK_STATE","YOUNG_MEASURE"} and
                os.get("witness",{})=={
                    "ambient_space":"L2_PERIODIC_1D","sequence_family":"SIGN_SIN_NX","weak_limit":"0",
                    "young_measure":"HALF_DELTA_MINUS1_PLUS_HALF_DELTA_PLUS1"} and
                conc.get("role")=="trusted_theorem_fixture" and conc.get("theorem_kind")=="EXPLICIT_SEQUENCE_EVIDENCE" and
                set(cs.get("certified_kinds",[]))=={"WEAK_STATE","YOUNG_MEASURE","CONCENTRATION_MEASURE"} and
                cs.get("witness",{})=={
                    "ambient_space":"L2_0_1","concentration_measure":"SPATIAL_DELTA_0",
                    "sequence_family":"SQRT_N_INDICATOR_0_1_OVER_N","weak_limit":"0","young_measure":"VALUE_DELTA_0"})
    except Exception:
        return False


def _weak_submission(registry: TheoremFixtureRegistry, model: str, relation: str, seq: str, qid: str, kind: str, fixture_id: str, source_id: str) -> WeakLimitEvidenceSubmission:
    row=registry.row(fixture_id); witness=tuple(sorted(row["evidence_schema"]["witness"].items()))
    source_cid=weak_evidence_source_content_id(source_id,witness)
    fixture_cid=registry.content_id_for(fixture_id)
    sid=weak_evidence_submission_semantic_id(model,relation,seq,qid,CONT,kind,source_id,source_cid,fixture_id,fixture_cid,witness)
    return WeakLimitEvidenceSubmission(sid,model,relation,seq,qid,CONT,kind,source_id,source_cid,fixture_id,fixture_cid,witness)

def query_transparency_fixture_semantics_valid(registry: TheoremFixtureRegistry | None) -> bool:
    if registry is None:
        return True
    try:
        row=registry.row("periodic-mean-divergence-defect-transparency-v1"); ws=row.get("witness_schema",{})
        return (row.get("role")=="trusted_theorem_fixture" and row.get("theorem_kind")=="QUERY_DEFECT_TRANSPARENCY" and
                ws.get("geometry")=="PERIODIC" and ws.get("query")=="SPATIAL_MEAN" and ws.get("defect_form")=="DIVERGENCE" and
                ws.get("constant_test_annihilation") is True and ws.get("query_image_equality") is True and
                ws.get("formalization_status")=="trusted_theorem_fixture")
    except Exception:
        return False

def infinite_fixture_semantics_valid(registry: TheoremFixtureRegistry | None) -> bool:
    return nonclosed_range_fixture_semantics_valid(registry) and weak_limit_fixture_semantics_valid(registry) and query_transparency_fixture_semantics_valid(registry)

def scenario_oracles(theorem_fixture_ids: frozenset[str] = REQUIRED_THEOREM_FIXTURES, trust_policy_valid: bool = True, theorem_registry: TheoremFixtureRegistry | None = None):
    out=[]
    # R1: source-bound normalization. Omitting a real source term must fail.
    source = SourceBalanceSpec("heat","heat-source", (Term("diff0",1,"INTERNAL","diff"), Term("src0",-1,"SOURCE","src")))
    heat = BalanceRelationIR("heat","heat", CONT, "storage", (Term("diff",1,"INTERNAL","diff"), Term("src",-1,"SOURCE","src")))
    nm = NormalizationManifest("heat-source","heat",("diff0","src0"),(("diff0","diff",1),("src0","src",-1)))
    bad = NormalizationManifest("heat-source","heat",("diff0",),(("diff0","diff",1),))
    role_bad = BalanceRelationIR("heat","heat", CONT, "storage", (Term("diff",1,"INTERNAL","diff"), Term("src",-1,"INTERNAL","src")))
    expr_bad = BalanceRelationIR("heat","heat", CONT, "storage", (Term("diff",1,"INTERNAL","diff"), Term("src",-1,"SOURCE","other")))
    r1 = (NormalizationValidator().check(source,heat,nm)==CheckResult.VALID and
          NormalizationValidator().check(source,heat,bad)==CheckResult.INVALID and
          NormalizationValidator().check(source,role_bad,nm)==CheckResult.INVALID and
          NormalizationValidator().check(source,expr_bad,nm)==CheckResult.INVALID)
    out.append(OracleResult("r1.norm.complete","R1", r1))

    # R2: exact FVM shared-interface cancellation; ragged/float carriers are rejected.
    row=(Fraction(1),)*3
    B=((Fraction(-1),Fraction(0)),(Fraction(1),Fraction(-1)),(Fraction(0),Fraction(1)))
    la=ExactLinearAlgebraChecker()
    r2 = la.check_row_zero(row,B)==CheckResult.VALID and la.check_row_zero((1.0,1.0,1.0),B)==CheckResult.INVALID
    out.append(OracleResult("r2.fvm.incidence","R2", r2))

    # R3: finite behavioral quotient witness + explicit overcompression counterexample.
    contexts=(lambda x:x[0], lambda x:2*x[0])
    x=(1,9); xp=(1,7); y=(2,9)
    safe=all(c(x)==c(xp) for c in contexts)
    over_bad=any(c(x)!=c(y) for c in contexts)
    out.append(OracleResult("r3.behavioral.quotient","R3", safe and over_bad))

    # R4: transition state needs velocity.
    A=((1,1),(0,1))
    next1=A[0][0]*0+A[0][1]*1
    next2=A[0][0]*0+A[0][1]*2
    out.append(OracleResult("r4.transition.congruence","R4", next1!=next2))

    # R5: exact finite image requires complete witnesses; selector alone cannot claim exact image.
    q=QueryAssembler()
    f=(QueryFact("branch-model","branch",CONT,QueryFactType.MODEL_NONEMPTY),
       QueryFact("branch-model","branch",CONT,QueryFactType.OUTER_SET,frozenset({-2,2})),
       QueryFact("branch-model","branch",CONT,QueryFactType.MEMBER,-2),
       QueryFact("branch-model","branch",CONT,QueryFactType.MEMBER,2))
    fa=frozenset(query_fact_id(x) for x in f)
    o=q.assemble("branch-model","branch",CONT,"IMAGE",f,fa)
    sf=(QueryFact("branch-model","branch",CONT,QueryFactType.MODEL_NONEMPTY),
        QueryFact("branch-model","branch",CONT,QueryFactType.OUTER_SET,frozenset({-2,2})),
        QueryFact("branch-model","branch",CONT,QueryFactType.MEMBER,2))
    selector=q.assemble("branch-model","branch",CONT,"IMAGE",sf,frozenset(query_fact_id(x) for x in sf))
    out.append(OracleResult("r5.branch.image","R5", o.kind=="EXACT_FINITE_IMAGE" and selector.kind!="EXACT_FINITE_IMAGE"))

    # R6: executable infinite-dimensional firewalls. The theorem fixture file is still pinned,
    # but release credit now comes from typed checkers rather than string labels.
    dual_fixture_ok = DUAL_THEOREM_FIXTURES.issubset(theorem_fixture_ids) and nonclosed_range_fixture_semantics_valid(theorem_registry)
    weak_fixture_ok = WEAK_DEFECT_THEOREM_FIXTURES.issubset(theorem_fixture_ids) and weak_limit_fixture_semantics_valid(theorem_registry)
    transparency_fixture_ok = QUERY_TRANSPARENCY_THEOREM_FIXTURES.issubset(theorem_fixture_ids) and query_transparency_fixture_semantics_valid(theorem_registry)
    op="diag-1-over-n"; target="y-star"
    closure=InfiniteDualClaim(infinite_dual_claim_semantic_id(op,target,CONT,"ADJOINT_CLOSURE_MEMBERSHIP"),op,target,CONT,"ADJOINT_CLOSURE_MEMBERSHIP")
    closed=InfiniteDualClaim(infinite_dual_claim_semantic_id(op,target,CONT,"CLOSED_RANGE"),op,target,CONT,"CLOSED_RANGE")
    witness=InfiniteDualClaim(infinite_dual_claim_semantic_id(op,target,CONT,"ADJOINT_WITNESS","c-star"),op,target,CONT,"ADJOINT_WITNESS","c-star")
    dc=InfiniteDimensionalDualChecker()
    _,a0=dc.check((closure,),frozenset({closure.claim_id}))
    _,a1=dc.check((closure,closed),frozenset({closure.claim_id,closed.claim_id}))
    _,a2=dc.check((witness,),frozenset({witness.claim_id}))
    dual_ok=bool(a0 and a1 and a2 and a0.uniqueness_credit=="EXACT_UNIQUENESS" and a0.range_credit=="CLOSURE_ONLY" and a0.computational_credit=="NO_EXECUTABLE_DUAL_WITNESS" and a1.range_credit=="RANGE_EXISTENCE_NONCONSTRUCTIVE" and a1.computational_credit=="NO_EXECUTABLE_DUAL_WITNESS" and a2.computational_credit=="BOUNDED_DUAL_CERTIFICATE")
    model="mv-model"; rel="mv-r6"; seq="weak-seq"; qid="nonlinear-observable"
    weak=WeakLimitClaim(weak_limit_claim_semantic_id(model,rel,seq,qid,CONT,"WEAK_STATE"),model,rel,seq,qid,CONT,"WEAK_STATE")
    young=WeakLimitClaim(weak_limit_claim_semantic_id(model,rel,seq,qid,CONT,"YOUNG_MEASURE"),model,rel,seq,qid,CONT,"YOUNG_MEASURE")
    conc=WeakLimitClaim(weak_limit_claim_semantic_id(model,rel,seq,qid,CONT,"CONCENTRATION_MEASURE"),model,rel,seq,qid,CONT,"CONCENTRATION_MEASURE")
    invis=WeakLimitClaim(weak_limit_claim_semantic_id(model,rel,seq,qid,CONT,"DEFECT_ANNIHILATION"),model,rel,seq,qid,CONT,"DEFECT_ANNIHILATION")
    wc=WeakLimitDefectChecker()
    _,w0=wc.check("NONLINEAR_OSCILLATION",(weak,),frozenset({weak.claim_id}))
    _,w1=wc.check("NONLINEAR_OSCILLATION",(weak,young),frozenset({weak.claim_id,young.claim_id}))
    _,w2=wc.check("CONCENTRATION_SENSITIVE",(weak,young),frozenset({weak.claim_id,young.claim_id}))
    _,w3=wc.check("CONCENTRATION_SENSITIVE",(weak,young,conc),frozenset({weak.claim_id,young.claim_id,conc.claim_id}))
    _,w4=wc.check("CONCENTRATION_SENSITIVE",(weak,invis),frozenset({weak.claim_id,invis.claim_id}))
    weak_ok=bool(w0 and w1 and w2 and w3 and w4 and w0.status=="DEFECT_REQUIRED" and w1.status=="DEFECT_ACCOUNTED" and w2.status=="CONCENTRATION_DEFECT_REQUIRED" and w3.status=="DEFECT_ACCOUNTED" and w4.status=="QUERY_EXACT_DEFECT_INVISIBLE")
    # Aggregate guard is finalized after evidence-ingress/query oracles below.
    out.append(OracleResult("r6.infinite.dual","R6", dual_fixture_ok and dual_ok))
    out.append(OracleResult("r6.weak.defect","R6", weak_fixture_ok and weak_ok))

    # R6 evidence ingress + computation path: external evidence envelope -> verifier -> Ksafe -> outer relation -> QueryAssembler -> Report.
    def wclaim(model,relation_id,seq,qid,kind):
        return WeakLimitClaim(weak_limit_claim_semantic_id(model,relation_id,seq,qid,CONT,kind),model,relation_id,seq,qid,CONT,kind)
    pipe=MeasureValuedQueryPipeline(); ingress=WeakLimitEvidenceAdapter()
    evidence_fixture_ok=(theorem_registry is not None and WEAK_EVIDENCE_THEOREM_FIXTURES.issubset(theorem_fixture_ids) and weak_evidence_fixture_semantics_valid(theorem_registry))
    if evidence_fixture_ok:
        seqo="osc-seq"; qido="osc-square"; ofid="explicit-oscillation-weak-young-v1"
        osubs=tuple(_weak_submission(theorem_registry,"mv-model","mv-osc",seqo,qido,k,ofid,"external-proof:oscillation-v1") for k in ("WEAK_STATE","YOUNG_MEASURE"))
        oing=ingress.ingest(osubs,theorem_registry)
        oq=WeakQueryProfile("mv-model","mv-osc",qido,CONT,"NONLINEAR_OSCILLATION")
        orun=pipe.run(oing.relation,oq,oing.active,release_id="r6-mv") if oing.relation else None

        seqc="conc-seq"; qidc="energy"; cfid="explicit-concentration-weak-young-concentration-v1"
        csubs=tuple(_weak_submission(theorem_registry,"mv-model","mv-conc",seqc,qidc,k,cfid,"external-proof:concentration-v1") for k in ("WEAK_STATE","YOUNG_MEASURE","CONCENTRATION_MEASURE"))
        cing=ingress.ingest(csubs,theorem_registry)
        cing_missing=ingress.ingest(csubs[:2],theorem_registry)
        cq=WeakQueryProfile("mv-model","mv-conc",qidc,CONT,"CONCENTRATION_SENSITIVE")
        crun=pipe.run(cing.relation,cq,cing.active,release_id="r6-mv") if cing.relation else None
        crun_missing=pipe.run(cing_missing.relation,cq,cing_missing.active,release_id="r6-mv") if cing_missing.relation else None
        # Negative ingress firewall: content-correct but semantically forged witness, stale theorem fingerprint, and cross-model reuse must fail.
        base=osubs[0]
        forged_witness=tuple(sorted({**dict(base.witness),"weak_limit":"1"}.items()))
        forged_source=weak_evidence_source_content_id(base.source_id,forged_witness)
        forged_sid=weak_evidence_submission_semantic_id(base.model_id,base.relation_id,base.sequence_id,base.query_id,base.scope,base.kind,base.source_id,forged_source,base.theorem_fixture_id,base.theorem_fixture_content_id,forged_witness)
        forged=WeakLimitEvidenceSubmission(forged_sid,base.model_id,base.relation_id,base.sequence_id,base.query_id,base.scope,base.kind,base.source_id,forged_source,base.theorem_fixture_id,base.theorem_fixture_content_id,forged_witness)
        stale_sid=weak_evidence_submission_semantic_id(base.model_id,base.relation_id,base.sequence_id,base.query_id,base.scope,base.kind,base.source_id,base.source_content_id,base.theorem_fixture_id,"stale",base.witness)
        stale=WeakLimitEvidenceSubmission(stale_sid,base.model_id,base.relation_id,base.sequence_id,base.query_id,base.scope,base.kind,base.source_id,base.source_content_id,base.theorem_fixture_id,"stale",base.witness)
        forged_rejected=ingress.ingest((forged,),theorem_registry).status=="INVALID"
        stale_rejected=ingress.ingest((stale,),theorem_registry).status=="UNSUPPORTED"
        cross_rel=MeasureValuedOuterRelation("other-model","mv-osc",seqo,CONT,oing.claims,frozenset(c.claim_id for c in oing.claims)) if oing.claims else None
        cross_rejected=bool(cross_rel and MeasureValuedQueryChecker().check(cross_rel,WeakQueryProfile("other-model","mv-osc",qido,CONT,"NONLINEAR_OSCILLATION"),oing.active)[0]==CheckResult.INVALID)
        ingress_ok=bool(oing.status=="VALID" and cing.status=="VALID" and cing_missing.status=="VALID" and
                        oing.relation and cing.relation and cing_missing.relation and
                        all(c.claim_id in oing.active for c in oing.claims) and all(c.claim_id in cing.active for c in cing.claims) and
                        all(v.support_refs for v in oing.verifications+cing.verifications) and forged_rejected and stale_rejected and cross_rejected)
        outer_query_ok=bool(orun and crun and crun_missing and orun.output and orun.faces and orun.report and orun.output.kind=="CERTIFIED_OUTER_RELATION" and orun.faces.H_E==FaceState.OPEN and orun.report.status=="CURRENT" and orun.projection and orun.projection.visible_defects==("OSCILLATION",) and orun.projection.accounted_defects==("OSCILLATION",) and
                            crun_missing.output and crun_missing.output.kind=="OPEN" and crun_missing.projection and crun_missing.projection.missing_defects==("CONCENTRATION",) and any(r.effect=="BLOCKS_EXACT" for r in crun_missing.residuals) and
                            crun.output and crun.output.kind=="CERTIFIED_OUTER_RELATION" and crun.projection and crun.projection.accounted_defects==("CONCENTRATION","OSCILLATION"))
    else:
        ingress_ok=False; outer_query_ok=False
    out.append(OracleResult("r6.weak.evidence.ingress","R6", evidence_fixture_ok and ingress_ok))
    out.append(OracleResult("r6.measure.outer.query","R6", weak_fixture_ok and evidence_fixture_ok and ingress_ok and outer_query_ok))

    seqt="periodic-defect"; qidt="mean"; tw=wclaim("mv-model","mv-periodic",seqt,qidt,"WEAK_STATE"); ta=wclaim("mv-model","mv-periodic",seqt,qidt,"DEFECT_ANNIHILATION")
    trel=MeasureValuedOuterRelation("mv-model","mv-periodic",seqt,CONT,(tw,),frozenset({tw.claim_id}))
    tq=WeakQueryProfile("mv-model","mv-periodic",qidt,CONT,"CONCENTRATION_SENSITIVE")
    tfid="periodic-mean-divergence-defect-transparency-v1"
    tcid=(theorem_registry.content_id_for(tfid) if theorem_registry is not None else "fixture-content")
    tclaim=QueryTransparencyClaim(query_transparency_claim_semantic_id("mv-model","strong-periodic","mv-periodic",qidt,CONT,tfid,tcid),"mv-model","strong-periodic","mv-periodic",qidt,CONT,tfid,tcid)
    trun=pipe.run(trel,tq,frozenset({tw.claim_id,ta.claim_id,tclaim.claim_id}),release_id="r6-mv",defect_annihilation=ta,transparency=tclaim)
    transparency_ok=bool(trun.output and trun.exactness_witness and trun.faces and trun.report and trun.output.kind=="EXACT_RELATION" and trun.faces.H_E==FaceState.PASS and trun.report.status=="CURRENT" and trun.projection and not trun.projection.visible_defects and any(r.effect=="CERTIFIED_NONE" for r in trun.residuals))
    out.append(OracleResult("r6.measure.query.transparency","R6", weak_fixture_ok and transparency_fixture_ok and transparency_ok))
    out.append(OracleResult("r6.infinite.guard","R6", dual_fixture_ok and weak_fixture_ok and transparency_fixture_ok and evidence_fixture_ok and dual_ok and weak_ok and ingress_ok and outer_query_ok and transparency_ok))

    # R7: exactness can be certified while the displayed support is locally unverifiable and a representation bridge is violated.
    run=RunSpec("m","q",CONT,"rel",frozenset({"H_delta"}))
    output=OutputArtifact("m","q",CONT,"EXACT_VALUE",3,frozenset({"fact-root"}))
    input_ev=ObligationEvidence("m","q",CONT,"H_I","SATISFIED",frozenset({"input-root"}))
    num_ev=ObligationEvidence("m","q",CONT,"H_N","VIOLATED",frozenset({"num-root"}))
    witness=ExactnessWitness("m","q",CONT,content_id(output),output.kind,frozenset({"fact-root"}))
    active=frozenset({"input-root","num-root","fact-root",content_id(input_ev),content_id(num_ev),content_id(witness)})
    verified=frozenset({"input-root","num-root"})
    fv=FaceEvaluator().evaluate(run,FaceInputs(input_ev,witness,output,active,verified,None,num_ev))
    out.append(OracleResult("r7.truth.output.scope","R7", fv.H_E==FaceState.PASS and fv.H_O==FaceState.FAIL and fv.H_N==FaceState.FAIL and fv.H_R==FaceState.PASS))

    # R8: multi-support rollback.
    k=SupportKernel(); rules=[SupportRule(frozenset({"p1","p2"}),"Q"),SupportRule(frozenset({"p3"}),"Q")]
    a=k.closure({"p1","p2","p3"},rules); b=k.closure({"p2","p3"},rules); c=k.closure({"p2"},rules)
    out.append(OracleResult("r8.rollback.multisupport","R8", "Q" in a and "Q" in b and "Q" not in c))

    # GA: cross-model transport requires an active exact certificate.
    it=IdentityTransportChecker()
    tc=RelationTransportClaim(transport_claim_semantic_id("m1","m2",True),"m1","m2",True)
    cross=(QueryFact("m1","shared.q",CONT,QueryFactType.OUTER_SET,frozenset({1})),)
    cross_active=frozenset(query_fact_id(x) for x in cross)
    cross_out=QueryAssembler().assemble("m2","shared.q",CONT,"VALUE",cross,cross_active)
    ga = (it.check("m1","m2",None,frozenset())==CheckResult.INVALID and
          it.check("m1","m2",tc,frozenset({tc.claim_id}))==CheckResult.VALID and
          cross_out.kind=="INVALID_FACT_BINDING")
    out.append(OracleResult("ga.identity.transport","G_A",ga))

    # GB: discrete facts cannot be laundered into continuum output by choosing a continuum request scope.
    bf=(QueryFact("m","q",DISC,QueryFactType.MODEL_NONEMPTY),QueryFact("m","q",DISC,QueryFactType.OUTER_SET,frozenset({3})),QueryFact("m","q",DISC,QueryFactType.MEMBER,3))
    bad_scope=q.assemble("m","q",CONT,"VALUE",bf,frozenset(query_fact_id(x) for x in bf))
    out.append(OracleResult("gb.scope.firewall","G_B", bad_scope.kind=="INVALID_FACT_BINDING"))

    # GC: conflict quarantine is local and excludes conflict endpoints from roots/premises/conclusions.
    rules=[SupportRule(frozenset({"GOOD"}),"R"), SupportRule(frozenset({"P"}),"BAD")]
    safeK=SupportKernel().quarantine({"P","notP","GOOD"},rules,[("P","notP")])
    out.append(OracleResult("gc.conflict.quarantine","G_C", "P" not in safeK and "notP" not in safeK and "BAD" not in safeK and "R" in safeK))

    # GD: cycle no bootstrap and premise-free rule rejected.
    cyc=SupportKernel().closure(set(),[SupportRule(frozenset({"P"}),"Q"),SupportRule(frozenset({"Q"}),"P")])
    empty_rule_rejected=False
    try:
        SupportKernel().closure(set(),[SupportRule(frozenset(),"P")])
    except ValueError:
        empty_rule_rejected=True
    
    policy=RuntimeTrustPolicy("strict-test",frozenset({("good","cid-good","TEST_ROOT")}))
    trust_rejected=False
    class_rejected=False
    try:
        SupportKernel().certified_closure([CertifiedRoot("FORGED","bad","cid-bad","TEST_ROOT")],[],policy)
    except TrustViolation:
        trust_rejected=True
    try:
        SupportKernel().certified_closure([CertifiedRoot("ESCALATE","good","cid-good","MODEL_NONEMPTY")],[],policy)
    except TrustViolation:
        class_rejected=True
    out.append(OracleResult("gd.support.cycle","G_D", trust_policy_valid and not cyc and empty_rule_rejected and trust_rejected and class_rejected))

    # GE: exact rational and approximate float have distinct typed canonical identities.
    exact=ExactRational(Fraction(1,10)); approx=ApproxDisplay(0.1)
    out.append(OracleResult("ge.numeric.semantic","G_E", content_id(exact)!=content_id(approx)))

    # GF: static u-only view is insufficient for this transition.
    out.append(OracleResult("gf.view.dynamic","G_F", next1!=next2))

    # GG: empty vacuity and contradictory inner/outer facts cannot manufacture exact output.
    ef=(QueryFact("m","v",CONT,QueryFactType.MODEL_EMPTY),QueryFact("m","v",CONT,QueryFactType.OUTER_SET,frozenset({8})))
    empty=q.assemble("m","v",CONT,"VALUE",ef,frozenset(query_fact_id(x) for x in ef))
    cf=(QueryFact("m","v",CONT,QueryFactType.MODEL_NONEMPTY),QueryFact("m","v",CONT,QueryFactType.OUTER_SET,frozenset({8})),QueryFact("m","v",CONT,QueryFactType.MEMBER,9))
    contradiction=q.assemble("m","v",CONT,"VALUE",cf,frozenset(query_fact_id(x) for x in cf))
    out.append(OracleResult("gg.empty.vacuity","G_G", empty.kind=="NO_VALUE" and contradiction.kind=="CONFLICT_LEAK"))
    return tuple(out)

def pde_input_oracles(example_dir: str | Path):
    root=Path(example_dir)
    out=[]
    c=DSLCompiler()
    try:
        heat=c.compile_model(json.loads((root/"heat_neumann.model.json").read_text(encoding="utf-8")))
        hb=PDEBinder().bind(heat)
        hq=c.compile_query(json.loads((root/"heat_mean.query.json").read_text(encoding="utf-8")),heat)
        heat_ok=(hb.validation.valid and len(hb.ir_balances)==1 and
                 NormalizationValidator().check(hb.source_balances[0],hb.ir_balances[0],hb.normalization_manifests[0])==CheckResult.VALID and
                 hq.model_id==heat.model_id and hq.scope==hb.scope)
    except Exception:
        heat_ok=False
    out.append(OracleResult("r1.dsl.heat.bind","R1",heat_ok))

    try:
        rd=c.compile_model(json.loads((root/"reaction_diffusion.model.json").read_text(encoding="utf-8")))
        rb=PDEBinder().bind(rd)
        rd_data={d.name:d.value for d in rd.data}; S=rd_data["S"]; ell=rd_data["ell"]
        rq=c.compile_query(json.loads((root/"reaction_invariant.query.json").read_text(encoding="utf-8")),rd)
        rd_ok=(rb.validation.valid and len(rb.ir_balances)==1 and
               NormalizationValidator().check(rb.source_balances[0],rb.ir_balances[0],rb.normalization_manifests[0])==CheckResult.VALID and
               ExactLinearAlgebraChecker().check_row_zero(ell,S)==CheckResult.VALID and
               rq.model_id==rd.model_id)
    except Exception:
        rd_ok=False
    out.append(OracleResult("r1.dsl.rd.bind","R1",rd_ok))

    try:
        bundle=c.compile_bundle(json.loads((root/"two_cell_interface.bundle.json").read_text(encoding="utf-8")))
        bb=PDEBundleBinder().bind(bundle)
        interface_ok=(bb.validation.valid and len(bb.bound_models)==2 and bundle.couplings and
                      bundle.couplings[0].kind=="SIGNED_BALANCE" and bundle.couplings[0].equals==0 and
                      all(m.validation.valid and len(m.ir_balances)==1 and
                          NormalizationValidator().check(m.source_balances[0],m.ir_balances[0],m.normalization_manifests[0])==CheckResult.VALID
                          for m in bb.bound_models))
    except Exception:
        interface_ok=False
    out.append(OracleResult("r2.dsl.interface.bind","R2",interface_ok))
    return tuple(out)

def auto_evidence_oracles(example_dir: str | Path, theorem_path: str | Path):
    root=Path(example_dir)
    c=DSLCompiler()
    registry=TheoremFixtureRegistry.from_path(theorem_path)
    try:
        profile=c.compile_model(json.loads((root/"heat_neumann.model.json").read_text(encoding="utf-8")))
        bound=PDEBinder().bind(profile)
        query=c.compile_query(json.loads((root/"heat_mean.query.json").read_text(encoding="utf-8")),profile)
        result=WeakConstantTestEvidenceAdapter().adapt(bound,query,registry,release_id="release-auto-evidence-oracle")
        positive=(result.status=="VALID" and result.output is not None and result.output.kind=="EXACT_LAW" and
                  result.report is not None and result.report.status=="CURRENT" and result.adapter_theorem_credit=="ZERO" and
                  result.existence_credit=="NONE")

        raw=json.loads((root/"heat_neumann.model.json").read_text(encoding="utf-8"))
        raw["equations"][0]["terms"][0]["expr"]="kappa*int(u*phi)"
        mutated=c.compile_model(raw); mb=PDEBinder().bind(mutated)
        mq=c.compile_query(json.loads((root/"heat_mean.query.json").read_text(encoding="utf-8")),mutated)
        refused=WeakConstantTestEvidenceAdapter().adapt(mb,mq,registry).status=="UNSUPPORTED"

        reduced=TheoremFixtureRegistry(registry.fixture_set_id,registry.version,tuple(x for x in registry.fixtures if x.get("id")!="constant-gradient-zero-v1"))
        missing_fixture=WeakConstantTestEvidenceAdapter().adapt(bound,query,reduced).status=="UNSUPPORTED"
        ok=positive and refused and missing_fixture
    except Exception:
        ok=False

    try:
        rd=c.compile_model(json.loads((root/"reaction_diffusion.model.json").read_text(encoding="utf-8")))
        rb=PDEBinder().bind(rd)
        rq=c.compile_query(json.loads((root/"reaction_invariant.query.json").read_text(encoding="utf-8")),rd)
        rr=WeakConstantVectorInvariantAdapter().adapt(rb,rq,registry,release_id="release-auto-rd-oracle")
        rd_positive=(rr.status=="VALID" and rr.output is not None and rr.output.kind=="EXACT_LAW" and
                     rr.adapter_theorem_credit=="ZERO" and rr.existence_credit=="NONE")
        bad=json.loads((root/"reaction_diffusion.model.json").read_text(encoding="utf-8"))
        bad["data"]["ell"]["vector"]=[[1,1],[0,1]]
        bp=c.compile_model(bad); bb=PDEBinder().bind(bp); bq=c.compile_query(json.loads((root/"reaction_invariant.query.json").read_text(encoding="utf-8")),bp)
        rd_refused=WeakConstantVectorInvariantAdapter().adapt(bb,bq,registry).status=="UNSUPPORTED"
        rd_ok=rd_positive and rd_refused
    except Exception:
        rd_ok=False

    try:
        op=c.compile_model(json.loads((root/"heat_open_port.model.json").read_text(encoding="utf-8")))
        ob=PDEBinder().bind(op)
        oq=c.compile_query(json.loads((root/"heat_open_mean.query.json").read_text(encoding="utf-8")),op)
        vq=c.compile_query(json.loads((root/"heat_open_mean_value.query.json").read_text(encoding="utf-8")),op)
        router=DeclarativeAutoEvidenceRouter()
        orr=router.adapt(ob,oq,registry,release_id="release-auto-open-port-oracle")
        open_positive=(orr.status=="VALID" and orr.output is not None and orr.output.kind=="EXACT_LAW" and
                       orr.report is not None and orr.report.status=="CURRENT" and orr.law is not None and
                       orr.law.retained_terms==((-1,"<f,1>"),(-1,"<flux,trace(1)>")) and not orr.law.defect_terms and
                       orr.adapter_theorem_credit=="ZERO" and orr.existence_credit=="NONE")
        value_refused=router.adapt(ob,vq,registry).status=="UNSUPPORTED"
        value_out=QueryAssembler().assemble(op.model_id,vq.query_id,vq.scope,"VALUE",tuple(),orr.active)
        value_run=RunSpec(op.model_id,vq.query_id,vq.scope,"release-open-value",frozenset({"H_N"}))
        value_input=ObligationEvidence(op.model_id,vq.query_id,vq.scope,"H_I","SATISFIED",frozenset())
        value_active=frozenset(set(orr.active)|{content_id(value_input)})
        value_faces=FaceEvaluator().evaluate(value_run,FaceInputs(value_input,None,value_out,value_active,value_active,None,None))
        value_report=ReportBuilder().build(value_run,value_out,value_faces,value_active,(Residual("open-port-history-unresolved","BLOCKS_EXACT",True),))
        value_separation=(value_out.kind=="OPEN" and value_faces.H_E==FaceState.OPEN and value_faces.H_delta==FaceState.OPEN and value_report.status=="CURRENT")
        bad=json.loads((root/"heat_open_port.model.json").read_text(encoding="utf-8")); bad["ports"][0]["orientation"]="INWARD"
        bp=c.compile_model(bad); bb=PDEBinder().bind(bp); bq=c.compile_query(json.loads((root/"heat_open_mean.query.json").read_text(encoding="utf-8")),bp)
        orientation_refused=router.adapt(bb,bq,registry).status=="UNSUPPORTED"
        reduced=TheoremFixtureRegistry(registry.fixture_set_id,registry.version,tuple(x for x in registry.fixtures if x.get("id")!="constant-trace-one-v1"))
        trace_fixture_refused=router.adapt(ob,oq,reduced).status=="UNSUPPORTED"
        open_ok=open_positive and value_refused and value_separation and orientation_refused and trace_fixture_refused
    except Exception:
        open_ok=False

    try:
        bundle=c.compile_bundle(json.loads((root/"two_cell_interface.bundle.json").read_text(encoding="utf-8")))
        bbound=PDEBundleBinder().bind(bundle)
        bquery=c.compile_bundle_query(json.loads((root/"two_cell_global_mean.query.json").read_text(encoding="utf-8")),bundle)
        cres=CoupledPortBalanceEvidenceAdapter().adapt(bbound,bquery,registry,release_id="release-auto-interface-composition")
        composition_positive=(cres.status=="VALID" and cres.output is not None and cres.output.kind=="EXACT_LAW" and
                              cres.report is not None and cres.report.status=="CURRENT" and cres.law is not None and
                              cres.law.eliminated_couplings==("flux_glue",) and len(cres.law.local_derivatives)==2 and
                              all(obj=="<f,1>" and sign==-1 for _,sign,obj in cres.law.retained_terms) and
                              all("flux" not in obj for _,_,obj in cres.law.retained_terms) and
                              cres.composition_theorem_credit=="ZERO" and cres.existence_credit=="NONE")
        import copy
        sign_bad=json.loads((root/"two_cell_interface.bundle.json").read_text(encoding="utf-8"))
        sign_bad["couplings"][0]["terms"][1]["sign"]=-1
        sb=c.compile_bundle(sign_bad); sbb=PDEBundleBinder().bind(sb); sbq=c.compile_bundle_query(json.loads((root/"two_cell_global_mean.query.json").read_text(encoding="utf-8")),sb)
        coupling_sign_refused=CoupledPortBalanceEvidenceAdapter().adapt(sbb,sbq,registry).status!="VALID"
        local_bad=json.loads((root/"two_cell_interface.bundle.json").read_text(encoding="utf-8"))
        local_bad["models"][1]["equations"][0]["terms"][2]["sign"]=1
        lb=c.compile_bundle(local_bad); lbb=PDEBundleBinder().bind(lb); lbq=c.compile_bundle_query(json.loads((root/"two_cell_global_mean.query.json").read_text(encoding="utf-8")),lb)
        local_sign_refused=CoupledPortBalanceEvidenceAdapter().adapt(lbb,lbq,registry).status!="VALID"
        orient_bad=json.loads((root/"two_cell_interface.bundle.json").read_text(encoding="utf-8"))
        orient_bad["models"][1]["ports"][0]["orientation"]="INWARD"
        obundle=c.compile_bundle(orient_bad); obound=PDEBundleBinder().bind(obundle)
        orientation_refused=(not obound.validation.valid)
        theorem_rows=[]
        for row in registry.fixtures:
            rr=dict(row)
            if rr.get("id")==COUPLING_FIXTURE_ID: rr["claim"]="forged signed-balance theorem"
            theorem_rows.append(rr)
        forged_registry=TheoremFixtureRegistry(registry.fixture_set_id,registry.version,tuple(theorem_rows))
        theorem_refused=CoupledPortBalanceEvidenceAdapter().adapt(bbound,bquery,forged_registry).status=="UNSUPPORTED"
        composition_ok=composition_positive and coupling_sign_refused and local_sign_refused and orientation_refused and theorem_refused
    except Exception:
        composition_ok=False


    try:
        dbundle=c.compile_bundle(json.loads((root/"two_cell_interface_defect.bundle.json").read_text(encoding="utf-8")))
        dbound=PDEBundleBinder().bind(dbundle)
        dquery=c.compile_bundle_query(json.loads((root/"two_cell_defect_global_mean.query.json").read_text(encoding="utf-8")),dbundle)
        dres=CoupledDefectPortBalanceEvidenceAdapter().adapt(dbound,dquery,registry,release_id="release-auto-interface-defect")
        defect_positive=(dres.status=="VALID" and dres.output is not None and dres.output.kind=="CERTIFIED_DEFECT_LAW" and
                         dres.report is not None and dres.report.status=="CURRENT" and dres.law is not None and
                         dres.law.propagated_interval==(Fraction(-1,10),Fraction(1,10)) and len(dres.law.defect_terms)==1 and
                         dres.residuals and dres.residuals[0].effect=="BOUNDED" and dres.faces is not None and dres.faces.H_E==FaceState.PASS and
                         dres.composition_theorem_credit=="ZERO" and dres.existence_credit=="NONE")
        bad=json.loads((root/"two_cell_interface_defect.bundle.json").read_text(encoding="utf-8"))
        bad["couplings"][0]["equals"]["projected_abs_bound"]=[-1,10]
        bound_bad=False
        try:
            bbundle=c.compile_bundle(bad); bound_bad=not PDEBundleBinder().bind(bbundle).validation.valid
        except Exception:
            bound_bad=True
        sign_bad=json.loads((root/"two_cell_interface_defect.bundle.json").read_text(encoding="utf-8")); sign_bad["couplings"][0]["terms"][1]["sign"]=-1
        sb=c.compile_bundle(sign_bad); sbb=PDEBundleBinder().bind(sb); sbq=c.compile_bundle_query(json.loads((root/"two_cell_defect_global_mean.query.json").read_text(encoding="utf-8")),sb)
        sign_refused=CoupledDefectPortBalanceEvidenceAdapter().adapt(sbb,sbq,registry).status!="VALID"
        theorem_rows=[]
        for row in registry.fixtures:
            rr=dict(row)
            if rr.get("id")==DEFECT_COUPLING_FIXTURE_ID: rr["claim"]="forged defect-coupling theorem"
            theorem_rows.append(rr)
        forged=TheoremFixtureRegistry(registry.fixture_set_id,registry.version,tuple(theorem_rows))
        theorem_refused=CoupledDefectPortBalanceEvidenceAdapter().adapt(dbound,dquery,forged).status=="UNSUPPORTED"
        defect_composition_ok=defect_positive and bound_bad and sign_refused and theorem_refused
    except Exception:
        defect_composition_ok=False

    try:
        rules=official_adapter_rule_registry()
        expected_ids={"heat-mean-constant-test-v1","heat-mean-open-port-constant-test-v1","reaction-diffusion-constant-vector-invariant-v1"}
        basic=(set(r.rule_id for r in rules.rules)==expected_ids)
        hp=c.compile_model(json.loads((root/"heat_neumann.model.json").read_text(encoding="utf-8"))); hb=PDEBinder().bind(hp); hq=c.compile_query(json.loads((root/"heat_mean.query.json").read_text(encoding="utf-8")),hp)
        op=c.compile_model(json.loads((root/"heat_open_port.model.json").read_text(encoding="utf-8"))); ob=PDEBinder().bind(op); oq=c.compile_query(json.loads((root/"heat_open_mean.query.json").read_text(encoding="utf-8")),op)
        rp=c.compile_model(json.loads((root/"reaction_diffusion.model.json").read_text(encoding="utf-8"))); rb=PDEBinder().bind(rp); rq=c.compile_query(json.loads((root/"reaction_invariant.query.json").read_text(encoding="utf-8")),rp)
        router=DeclarativeAutoEvidenceRouter(rules)
        route_ok=(router.select_rule_id(hb,hq)=="heat-mean-constant-test-v1" and
                  router.select_rule_id(ob,oq)=="heat-mean-open-port-constant-test-v1" and
                  router.select_rule_id(rb,rq)=="reaction-diffusion-constant-vector-invariant-v1")
        official_heat_valid=DeclarativeBalanceEvidenceAdapter("heat-mean-constant-test-v1",rules).adapt(hb,hq,registry).status=="VALID"
        official_open_valid=DeclarativeBalanceEvidenceAdapter("heat-mean-open-port-constant-test-v1",rules).adapt(ob,oq,registry).status=="VALID"
        official_rd_valid=DeclarativeBalanceEvidenceAdapter("reaction-diffusion-constant-vector-invariant-v1",rules).adapt(rb,rq,registry).status=="VALID"
        import copy
        obj={"rule_set_id":rules.rule_set_id,"version":rules.version,"rules":[copy.deepcopy(r.raw) for r in rules.rules]}
        obj["rules"][0]["terms"][0]["primitive"]="ARBITRARY_PYTHON"
        unknown_rejected=False
        try: DeclarativeAdapterRuleRegistry.from_object(obj)
        except ValueError: unknown_rejected=True
        obj={"rule_set_id":rules.rule_set_id,"version":rules.version,"rules":[copy.deepcopy(r.raw) for r in rules.rules]}
        obj["rules"][0]["terms"][1]["action"]="ANNIHILATE"
        action_rejected=False
        try: DeclarativeAdapterRuleRegistry.from_object(obj)
        except ValueError: action_rejected=True
        obj={"rule_set_id":rules.rule_set_id,"version":rules.version,"rules":[copy.deepcopy(r.raw) for r in rules.rules]}
        obj["rules"][1]["terms"][2]["action"]="ANNIHILATE"
        port_action_rejected=False
        try: DeclarativeAdapterRuleRegistry.from_object(obj)
        except ValueError: port_action_rejected=True
        obj={"rule_set_id":rules.rule_set_id,"version":rules.version,"rules":[copy.deepcopy(r.raw) for r in rules.rules]}
        obj["rules"][0]["reader_admissibility_fixture"]=copy.deepcopy(obj["rules"][0]["time_pairing_fixture"])
        theorem_slot_rejected=False
        try: DeclarativeAdapterRuleRegistry.from_object(obj)
        except ValueError: theorem_slot_rejected=True
        obj={"rule_set_id":rules.rule_set_id,"version":rules.version,"rules":[copy.deepcopy(r.raw) for r in rules.rules]}
        obj["rules"][0]["derivative"]["template"]="d_dt(forged_target)"
        derivative_rejected=False
        try: DeclarativeAdapterRuleRegistry.from_object(obj)
        except ValueError: derivative_rejected=True
        obj={"rule_set_id":rules.rule_set_id,"version":rules.version,"rules":[copy.deepcopy(r.raw) for r in rules.rules]}
        obj["rules"][0]["terms"][0]["support"]["fixture"]["content_id"]="0"*64
        forged_rules=DeclarativeAdapterRuleRegistry.from_object(obj)
        forged_refused=DeclarativeBalanceEvidenceAdapter("heat-mean-constant-test-v1",forged_rules).adapt(hb,hq,registry).status=="UNSUPPORTED"
        obj={"rule_set_id":rules.rule_set_id,"version":rules.version,"rules":[copy.deepcopy(r.raw) for r in rules.rules]}
        obj["rules"][1]["terms"][2]["support"]["fixture"]["content_id"]="0"*64
        forged_port_rules=DeclarativeAdapterRuleRegistry.from_object(obj)
        forged_port_refused=DeclarativeBalanceEvidenceAdapter("heat-mean-open-port-constant-test-v1",forged_port_rules).adapt(ob,oq,registry).status=="UNSUPPORTED"
        rules_ok=(basic and route_ok and official_heat_valid and official_open_valid and official_rd_valid and unknown_rejected and action_rejected and
                  port_action_rejected and theorem_slot_rejected and derivative_rejected and forged_refused and forged_port_refused)
    except Exception:
        rules_ok=False
    return (
        OracleResult("r1.auto.heat.evidence","R1",ok),
        OracleResult("r1.auto.rd.evidence","R1",rd_ok),
        OracleResult("r1.auto.heat.open-port.evidence","R1",open_ok),
        OracleResult("r1.declarative.adapter.rules","R1",rules_ok),
        OracleResult("r2.auto.interface.composition","R2",composition_ok),
        OracleResult("r2.auto.interface.defect","R2",defect_composition_ok),
    )

def closed_loop_oracle() -> OracleResult:
    """Positive closed loop plus the three frozen adversarial firewalls."""
    issuer_id="closed-loop-fixture"; issuer_cid="closed-loop-fixture-cid"
    roots=tuple(CertifiedRoot(x,issuer_id,issuer_cid,"CLOSED_LOOP_ROOT") for x in ("model","query","feasible","law"))
    outer=QueryFact("cl-model","cl-query",CONT,QueryFactType.OUTER_SET,frozenset({Fraction(7)}))
    nonempty=QueryFact("cl-model","cl-query",CONT,QueryFactType.MODEL_NONEMPTY)
    member=QueryFact("cl-model","cl-query",CONT,QueryFactType.MEMBER,Fraction(7))
    outer_id=query_fact_id(outer); nonempty_id=query_fact_id(nonempty); member_id=query_fact_id(member)
    input_ev=ObligationEvidence("cl-model","cl-query",CONT,"H_I","SATISFIED",frozenset({"model","query"}))
    input_id=content_id(input_ev)
    base_rules=(
        CertifiedSupportRule(frozenset({"law"}),outer_id,issuer_id,issuer_cid,"CLOSED_LOOP_DERIVATION"),
        CertifiedSupportRule(frozenset({"feasible"}),nonempty_id,issuer_id,issuer_cid,"CLOSED_LOOP_DERIVATION"),
        CertifiedSupportRule(frozenset({"feasible",outer_id}),member_id,issuer_id,issuer_cid,"CLOSED_LOOP_DERIVATION"),
        CertifiedSupportRule(input_ev.support_refs,input_id,issuer_id,issuer_cid,"CLOSED_LOOP_DERIVATION"),
    )
    policy=RuntimeTrustPolicy("closed-loop-policy",frozenset({
        (issuer_id,issuer_cid,"CLOSED_LOOP_ROOT"),
        (issuer_id,issuer_cid,"CLOSED_LOOP_DERIVATION"),
    }))
    pre=SupportKernel().certified_closure(roots,base_rules,policy)
    output=QueryAssembler().assemble("cl-model","cl-query",CONT,"VALUE",(outer,nonempty,member),pre)
    witness=ExactnessWitness("cl-model","cl-query",CONT,content_id(output),output.kind,frozenset({outer_id,nonempty_id,member_id}))
    wrule=CertifiedSupportRule(witness.support_refs,content_id(witness),issuer_id,issuer_cid,"CLOSED_LOOP_DERIVATION")
    rules=base_rules+(wrule,)
    run=RunSpec("cl-model","cl-query",CONT,"reconstructed-closed-loop",frozenset({"H_delta","H_N"}))
    evaluator=ClosedLoopEvaluator()
    good=evaluator.run(run,roots=roots,rules=rules,policy=policy,conflicts=tuple(),output=output,input_evidence=input_ev,exactness_witness=witness)
    positive=closed_loop_pass(run,good)

    # Attack 1: an exact-looking output without an active exactness witness cannot make H_E pass.
    no_witness=evaluator.run(run,roots=roots,rules=base_rules,policy=policy,conflicts=tuple(),output=output,input_evidence=input_ev,exactness_witness=None)
    attack_truth_blocked=(no_witness.faces.H_E!=FaceState.PASS and not closed_loop_pass(run,no_witness))

    # Attack 2: illegal N/A on H_I is rejected by the frozen face firewall.
    bad_na=RunSpec("cl-model","cl-query",CONT,"reconstructed-closed-loop",frozenset({"H_I","H_delta","H_N"}))
    illegal=evaluator.run(bad_na,roots=roots,rules=rules,policy=policy,conflicts=tuple(),output=output,input_evidence=input_ev,exactness_witness=witness)
    attack_na_blocked=(illegal.faces.H_I==FaceState.FAIL and not closed_loop_pass(bad_na,illegal))

    # Attack 3: a CHECK-shaped label cannot bypass TrustGate; the untrusted root is rejected.
    fake_roots=roots+(CertifiedRoot("fake-check-root","fake-check","fake-cid","CLOSED_LOOP_ROOT"),)
    attack_check_blocked=False
    try:
        evaluator.run(run,roots=fake_roots,rules=rules,policy=policy,conflicts=tuple(),output=output,input_evidence=input_ev,exactness_witness=witness)
    except TrustViolation:
        attack_check_blocked=True
    return OracleResult("gg.he.closed.loop","G_G",positive and attack_truth_blocked and attack_na_blocked and attack_check_blocked)


def all_release_oracles(theorem_fixture_ids: frozenset[str] = REQUIRED_THEOREM_FIXTURES, trust_policy_valid: bool = True, example_dir: str | Path | None = None, theorem_path: str | Path | None = None):
    if example_dir is not None:
        example_dir=Path(example_dir)
        if theorem_path is None:
            theorem_path=example_dir.parent/"theorems"/"theorem_fixtures.json"
    registry=TheoremFixtureRegistry.from_path(theorem_path) if theorem_path is not None else None
    rows=list(scenario_oracles(theorem_fixture_ids,trust_policy_valid,registry))
    rows.append(closed_loop_oracle())
    if example_dir is not None:
        rows.extend(pde_input_oracles(example_dir))
        rows.extend(auto_evidence_oracles(example_dir,theorem_path))
    return tuple(rows)

def mandatory_capabilities(example_dir: str | Path | None = None, theorem_path: str | Path | None = None):
    caps=set()
    # Heat: actual normalization + reader verification path.
    source=SourceBalanceSpec("heat","heat-source",(Term("diff0",1,"INTERNAL","diff"),Term("src0",-1,"SOURCE","src")))
    ir=BalanceRelationIR("heat","heat",CONT,"storage",(Term("diff",1,"INTERNAL","diff"),Term("src",-1,"SOURCE","src")))
    nm=NormalizationManifest("heat-source","heat",("diff0","src0"),(("diff0","diff",1),("src0","src",-1)))
    pc0=ProjectionClaim(projection_claim_semantic_id("heat","one","diff","heat.mass",CONT,ZERO),"heat","one","diff","heat.mass",CONT,ZERO)
    pc1=ProjectionClaim(projection_claim_semantic_id("heat","one","src","heat.mass",CONT,"int_f"),"heat","one","src","heat.mass",CONT,"int_f")
    tl=TargetDerivativeLink(target_link_semantic_id("heat","one","storage","heat.mass",CONT,"dM"),"heat","one","storage","heat.mass",CONT,"dM")
    ev=BalanceReaderEvidence("heat","heat","heat.mass","one",CONT,frozenset({"one-admissible"}),tl.claim_id,(
        ProjectedTermEvidence("diff",Action.ANNIHILATE,ZERO,pc0.claim_id),
        ProjectedTermEvidence("src",Action.RETAIN,"int_f",pc1.claim_id)))
    heat_norm=NormalizationValidator().check(source,ir,nm)==CheckResult.VALID
    active=frozenset({"one-admissible",tl.claim_id,pc0.claim_id,pc1.claim_id})
    heat_read,_=BalanceReaderChecker().check(ir,ev,active,{pc0.claim_id:pc0,pc1.claim_id:pc1},{tl.claim_id:tl})
    if heat_norm and heat_read==CheckResult.VALID:
        caps.add("CONTINUUM_WEAK_PDE")

    la=ExactLinearAlgebraChecker()
    S=((Fraction(1),Fraction(-1)),(Fraction(2),Fraction(-2)))
    ell=(Fraction(2),Fraction(-1))
    if la.check_row_zero(ell,S)==CheckResult.VALID:
        caps.add("NONLINEAR_PDE_STRUCTURAL")
    B=((Fraction(-1),Fraction(0)),(Fraction(1),Fraction(-1)),(Fraction(0),Fraction(1)))
    if la.check_row_zero((Fraction(1),)*3,B)==CheckResult.VALID:
        caps.add("DISCRETE_NUMERICAL_BALANCE")
    if example_dir is not None:
        example_dir=Path(example_dir)
        if theorem_path is None:
            theorem_path=example_dir.parent/"theorems"/"theorem_fixtures.json"
        pde_rows=pde_input_oracles(example_dir)
        if pde_rows and all(r.passed for r in pde_rows):
            caps.add("PDE_INPUT_BINDING")
        auto_rows=auto_evidence_oracles(example_dir,theorem_path)
        amap={r.oracle_id:r.passed for r in auto_rows}
        if amap.get("r1.auto.heat.evidence"):
            caps.add("PDE_AUTO_EVIDENCE")
        if amap.get("r1.auto.rd.evidence"):
            caps.add("PDE_AUTO_NONLINEAR_EVIDENCE")
        if amap.get("r1.auto.heat.open-port.evidence"):
            caps.add("PDE_AUTO_RELATIONAL_PORT_EVIDENCE")
        if amap.get("r1.declarative.adapter.rules"):
            caps.add("DECLARATIVE_ADAPTER_RULES")
        if amap.get("r2.auto.interface.composition"):
            caps.add("PDE_AUTO_COUPLING_COMPOSITION")
        if amap.get("r2.auto.interface.defect"):
            caps.add("PDE_AUTO_COUPLING_DEFECT_PROPAGATION")
        treg=TheoremFixtureRegistry.from_path(theorem_path)
        smap={r.oracle_id:r.passed for r in scenario_oracles(treg.ids,True,treg)}
        if smap.get("r6.infinite.dual") and smap.get("r6.weak.defect"):
            caps.add("INFINITE_DIMENSIONAL_GUARDS")
        if smap.get("r6.weak.evidence.ingress"):
            caps.add("WEAK_LIMIT_EVIDENCE_INGRESS")
        if smap.get("r6.measure.outer.query") and smap.get("r6.measure.query.transparency"):
            caps.add("MEASURE_VALUED_QUERY_ASSEMBLY")
        if closed_loop_oracle().passed:
            caps.add("HE_CORE_CLOSED_LOOP")
    return frozenset(caps)

def deterministic_payload(release_id: str, trusted_issuer: tuple[str,str]):
    issuer_id, issuer_cid = trusted_issuer
    k=SupportKernel()
    outer=QueryFact("heat","heat.value",CONT,QueryFactType.OUTER_SET,frozenset({Fraction(3)}))
    nonempty=QueryFact("heat","heat.value",CONT,QueryFactType.MODEL_NONEMPTY)
    member=QueryFact("heat","heat.value",CONT,QueryFactType.MEMBER,Fraction(3))
    outer_id=query_fact_id(outer); nonempty_id=query_fact_id(nonempty); member_id=query_fact_id(member)
    input_ev=ObligationEvidence("heat","heat.value",CONT,"H_I","SATISFIED",frozenset({"feasible"}))
    input_id=content_id(input_ev)
    base_rules=(
        CertifiedSupportRule(frozenset({"law","initial","integral"}),outer_id,issuer_id,issuer_cid,"FIXTURE_DERIVATION"),
        CertifiedSupportRule(frozenset({"feasible"}),nonempty_id,issuer_id,issuer_cid,"FIXTURE_DERIVATION"),
        CertifiedSupportRule(frozenset({"feasible",outer_id}),member_id,issuer_id,issuer_cid,"FIXTURE_DERIVATION"),
        CertifiedSupportRule(frozenset({"feasible"}),input_id,issuer_id,issuer_cid,"FIXTURE_DERIVATION"),
    )
    roots=tuple(CertifiedRoot(x,issuer_id,issuer_cid,"FIXTURE_ROOT") for x in ("law","initial","integral","feasible"))
    policy=RuntimeTrustPolicy("release-runtime",frozenset({(issuer_id,issuer_cid,"FIXTURE_ROOT"),(issuer_id,issuer_cid,"FIXTURE_DERIVATION")}))
    K=k.certified_closure(roots,base_rules,policy)
    q=QueryAssembler()
    output=q.assemble("heat","heat.value",CONT,"VALUE",(outer,nonempty,member),K)
    witness=ExactnessWitness("heat","heat.value",CONT,content_id(output),output.kind,frozenset({outer_id,nonempty_id,member_id}))
    witness_rule=CertifiedSupportRule(witness.support_refs,content_id(witness),issuer_id,issuer_cid,"FIXTURE_DERIVATION")
    K=k.certified_closure(roots,base_rules+(witness_rule,),policy)
    run=RunSpec("heat","heat.value",CONT,release_id,frozenset({"H_delta","H_N"}))
    fv=FaceEvaluator().evaluate(run,FaceInputs(input_ev,witness,output,K,K,None,None))
    report=ReportBuilder().build(run,output,fv,K,tuple())
    return {"KsafeID":content_id(K),"OutputID":content_id(output),"FaceVector":fv,"ReportID":content_id(report)}
