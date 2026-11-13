from fractions import Fraction
from pathlib import Path
import math, sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from honeycomb_v0 import *
from honeycomb_v0.fixtures import scenario_oracles, all_release_oracles, mandatory_capabilities, ORACLE_FAMILIES


def test_all_release_families_pass():
    rows=all_release_oracles(example_dir=ROOT/'examples')
    fam={r.family for r in rows if r.passed}
    assert fam == REQUIRED_FAMILIES
    assert all(r.passed for r in rows)
    assert {r.oracle_id:r.family for r in rows} == ORACLE_FAMILIES

def test_mandatory_capabilities():
    assert mandatory_capabilities(ROOT/'examples')==REQUIRED_CAPABILITIES

def test_normalization_binds_real_source_and_rejects_hidden_omission():
    sc=Scope(ScopeLevel.CONTINUUM,'w')
    source=SourceBalanceSpec('m','src',(Term('a0',1,'I','a'),Term('b0',-1,'S','b')))
    ir=BalanceRelationIR('m','x',sc,'s',(Term('a',1,'I','a'),Term('b',-1,'S','b')))
    good=NormalizationManifest('src','x',('a0','b0'),(('a0','a',1),('b0','b',-1)))
    hidden=NormalizationManifest('src','x',('a0',),(('a0','a',1),))
    v=NormalizationValidator()
    assert v.check(source,ir,good)==CheckResult.VALID
    assert v.check(source,ir,hidden)==CheckResult.INVALID

def test_balance_reader_false_annihilation_rejected():
    sc=Scope(ScopeLevel.CONTINUUM,'w')
    ir=BalanceRelationIR('m','x',sc,'storage',(Term('src',-1,'SOURCE','f'),))
    pc=ProjectionClaim(projection_claim_semantic_id('m','r','src','q',sc,'NONZERO'),'m','r','src','q',sc,'NONZERO')
    tl=TargetDerivativeLink(target_link_semantic_id('m','r','storage','q',sc,'dT'),'m','r','storage','q',sc,'dT')
    ev=BalanceReaderEvidence('m','x','q','r',sc,frozenset({'adm'}),tl.claim_id,(ProjectedTermEvidence('src',Action.ANNIHILATE,'NONZERO',pc.claim_id),))
    res,_=BalanceReaderChecker().check(ir,ev,frozenset({'adm',tl.claim_id,pc.claim_id}),{pc.claim_id:pc},{tl.claim_id:tl})
    assert res==CheckResult.INVALID

def test_query_scope_laundering_rejected():
    cont=Scope(ScopeLevel.CONTINUUM,'w'); disc=Scope(ScopeLevel.DISCRETE,'h')
    facts=(QueryFact('m','q',disc,QueryFactType.MODEL_NONEMPTY),QueryFact('m','q',disc,QueryFactType.OUTER_SET,frozenset({3})),QueryFact('m','q',disc,QueryFactType.MEMBER,3)); out=QueryAssembler().assemble('m','q',cont,'VALUE',facts,frozenset(query_fact_id(f) for f in facts))
    assert out.kind=='INVALID_FACT_BINDING'

def test_query_empty_vacuity_and_inconsistent_bounds():
    sc=Scope(ScopeLevel.CONTINUUM,'w')
    q=QueryAssembler()
    facts=(QueryFact('m','q',sc,QueryFactType.MODEL_EMPTY),QueryFact('m','q',sc,QueryFactType.OUTER_SET,frozenset({8}))); out=q.assemble('m','q',sc,'VALUE',facts,frozenset(query_fact_id(f) for f in facts))
    assert out.kind=='NO_VALUE'
    df=(QueryFact('m','q',sc,QueryFactType.DEFECT_INTERVAL,(Fraction(0),Fraction(1))),QueryFact('m','q',sc,QueryFactType.DEFECT_INTERVAL,(Fraction(2),Fraction(3)))); bad=q.assemble('m','q',sc,'VALUE',df,frozenset(query_fact_id(f) for f in df))
    assert bad.kind=='CONFLICT_LEAK'

def test_multisupport_cycle_and_premise_free_rule():
    k=SupportKernel(); rules=[SupportRule(frozenset({'p1','p2'}),'Q'),SupportRule(frozenset({'p3'}),'Q')]
    assert 'Q' in k.closure({'p2','p3'},rules)
    assert 'Q' not in k.closure({'p2'},rules)
    assert not k.closure(set(),[SupportRule(frozenset({'P'}),'Q'),SupportRule(frozenset({'Q'}),'P')])
    try:
        k.closure(set(),[SupportRule(frozenset(),'P')])
    except ValueError:
        pass
    else:
        raise AssertionError('premise-free rule bootstrapped truth')

def test_conflict_quarantine_local_and_conclusion_blocked():
    k=SupportKernel(); safe=k.quarantine({'P','notP','GOOD'},[SupportRule(frozenset({'GOOD'}),'R'),SupportRule(frozenset({'P'}),'BAD')],[('P','notP')])
    assert safe==frozenset({'GOOD','R'})

def test_r7_face_independence_and_na_firewall():
    cont=Scope(ScopeLevel.CONTINUUM,'w')
    run=RunSpec('m','q',cont,'rel',frozenset({'H_delta'}))
    out=OutputArtifact('m','q',cont,'EXACT_VALUE',3,frozenset({'fact'}))
    ie=ObligationEvidence('m','q',cont,'H_I','SATISFIED',frozenset({'input'}))
    ne=ObligationEvidence('m','q',cont,'H_N','VIOLATED',frozenset({'num'}))
    ew=ExactnessWitness('m','q',cont,content_id(out),out.kind,frozenset({'fact'}))
    active=frozenset({'input','num','fact',content_id(ie),content_id(ne),content_id(ew)})
    fv=FaceEvaluator().evaluate(run,FaceInputs(ie,ew,out,active,frozenset({'input','num'}),None,ne))
    assert (fv.H_E,fv.H_O,fv.H_N,fv.H_R)==(FaceState.PASS,FaceState.FAIL,FaceState.FAIL,FaceState.PASS)
    badrun=RunSpec('m','q',cont,'rel',frozenset({'H_I'}))
    bad=FaceEvaluator().evaluate(badrun,FaceInputs(None,None,None,frozenset(),frozenset()))
    assert bad.H_I==FaceState.FAIL and bad.H_N==FaceState.FAIL and bad.H_R==FaceState.FAIL

def test_report_stale_residual_and_fabricated_exact_firewall():
    cont=Scope(ScopeLevel.CONTINUUM,'w'); run=RunSpec('m','q',cont,'rel',frozenset({'H_delta','H_N'}))
    out=OutputArtifact('m','q',cont,'EXACT_VALUE',3,frozenset({'s'}))
    fv=FaceVector(FaceState.PASS,FaceState.PASS,FaceState.NA,FaceState.NA,FaceState.PASS,FaceState.PASS)
    rb=ReportBuilder()
    assert rb.build(run,out,fv,frozenset(),tuple()).status=='STALE'
    res=(Residual('b','BLOCKS_EXACT',True),)
    assert rb.build(run,out,fv,frozenset({'s'}),res).status=='INVALID_AFFECTING_RESIDUAL'
    forged=OutputArtifact('m','q',cont,'EXACT_VALUE',3,frozenset())
    assert rb.build(run,forged,fv,frozenset(),tuple()).status=='INVALID_UNSUPPORTED_EXACT'
    wrong=OutputArtifact('m','other',cont,'EXACT_VALUE',3,frozenset({'s'}))
    assert rb.build(run,wrong,fv,frozenset({'s'}),tuple()).status=='INVALID_OUTPUT_BINDING'

def test_exact_linear_algebra_rejects_float_and_ragged():
    c=ExactLinearAlgebraChecker()
    assert c.check_row_zero((1.0,1.0),((1,-1),(-1,1)))==CheckResult.INVALID
    assert c.check_row_zero((1,1),((1,),(-1,2)))==CheckResult.INVALID

def test_canonical_rejects_key_collision_and_nonfinite_float():
    try:
        canonical_data({1:'a','1':'b'})
    except TypeError:
        pass
    else:
        raise AssertionError('non-string dict key accepted')
    for x in (math.nan, math.inf, -math.inf):
        try:
            canonical_data(x)
        except TypeError:
            pass
        else:
            raise AssertionError('nonfinite float accepted')

def test_release_runner_rejects_oracle_laundering():
    from honeycomb_v0.release import ExecutablePin,OraclePin,ReleaseSpec,ReleaseRunner
    pins=tuple(OraclePin(oid,fam,'1','x') for oid,fam in ORACLE_FAMILIES.items())
    spec=ReleaseSpec((ExecutablePin('f','1','x'),),pins,(ExecutablePin('c','1','x'),),(),ExecutablePin('t','1','x'),CANON_VERSION,HASH_SCHEME)
    fake=tuple(OracleResult(f'fake-{fam}',fam,True) for fam in sorted(REQUIRED_FAMILIES))
    rr=ReleaseRunner().run(spec,fake,REQUIRED_CAPABILITIES)
    assert not rr.passed
    assert rr.missing_oracles
    assert rr.unexpected_oracles

def test_release_id_content_sensitive_and_order_invariant():
    from honeycomb_v0.release import ExecutablePin,OraclePin,ReleaseSpec
    p1=ExecutablePin('a','1','x'); p2=ExecutablePin('b','1','y'); trust=ExecutablePin('t','1','z')
    oracles=tuple(OraclePin(oid,fam,'1','o') for oid,fam in ORACLE_FAMILIES.items())
    s1=ReleaseSpec((p1,p2),oracles,(p1,p2),(),trust,CANON_VERSION,HASH_SCHEME)
    s2=ReleaseSpec((p2,p1),tuple(reversed(oracles)),(p2,p1),(),trust,CANON_VERSION,HASH_SCHEME)
    assert s1.release_id==s2.release_id
    s3=ReleaseSpec((ExecutablePin('a','1','CHANGED'),p2),oracles,(p1,p2),(),trust,CANON_VERSION,HASH_SCHEME)
    assert s1.release_id!=s3.release_id

def test_unverified_content_addressed_query_fact_rejected():
    sc=Scope(ScopeLevel.CONTINUUM,'w')
    f=QueryFact('m','q',sc,QueryFactType.OUTER_SET,frozenset({3}))
    out=QueryAssembler().assemble('m','q',sc,'VALUE',(f,),frozenset())
    assert out.kind=='UNVERIFIED_FACT'

def test_projection_claim_content_tamper_rejected():
    sc=Scope(ScopeLevel.CONTINUUM,'w')
    ir=BalanceRelationIR('m','x',sc,'storage',(Term('src',-1,'SOURCE','f'),))
    # ID is the certified ZERO projection ID, but the object payload is tampered to NONZERO.
    forged_id=projection_claim_semantic_id('m','r','src','q',sc,ZERO)
    pc=ProjectionClaim(forged_id,'m','r','src','q',sc,'NONZERO')
    tlid=target_link_semantic_id('m','r','storage','q',sc,'dT')
    tl=TargetDerivativeLink(tlid,'m','r','storage','q',sc,'dT')
    ev=BalanceReaderEvidence('m','x','q','r',sc,frozenset({'adm'}),tlid,(ProjectedTermEvidence('src',Action.RETAIN,'NONZERO',forged_id),))
    res,_=BalanceReaderChecker().check(ir,ev,frozenset({'adm',forged_id,tlid}),{forged_id:pc},{tlid:tl})
    assert res==CheckResult.INVALID

def test_exactness_witness_must_itself_be_active():
    sc=Scope(ScopeLevel.CONTINUUM,'w')
    run=RunSpec('m','q',sc,'rel',frozenset({'H_delta','H_N'}))
    ie=ObligationEvidence('m','q',sc,'H_I','SATISFIED',frozenset({'premise'}))
    out=OutputArtifact('m','q',sc,'EXACT_VALUE',3,frozenset({'premise'}))
    ew=ExactnessWitness('m','q',sc,content_id(out),out.kind,frozenset({'premise'}))
    active=frozenset({'premise',content_id(ie)})
    fv=FaceEvaluator().evaluate(run,FaceInputs(ie,ew,out,active,active))
    assert fv.H_E==FaceState.OPEN

def test_theorem_and_trust_artifacts_affect_oracles():
    rows=scenario_oracles(frozenset(),False)
    failed={r.oracle_id for r in rows if not r.passed}
    assert 'r6.infinite.guard' in failed
    assert 'gd.support.cycle' in failed

def test_balance_reader_cross_model_reuse_rejected():
    sc=Scope(ScopeLevel.CONTINUUM,'w')
    balance=BalanceRelationIR('m2','rel',sc,'storage',(Term('src',-1,'SOURCE','f'),))
    pcid=projection_claim_semantic_id('m1','r','src','q',sc,'fproj')
    pc=ProjectionClaim(pcid,'m1','r','src','q',sc,'fproj')
    tlid=target_link_semantic_id('m1','r','storage','q',sc,'dT')
    tl=TargetDerivativeLink(tlid,'m1','r','storage','q',sc,'dT')
    ev=BalanceReaderEvidence('m1','rel','q','r',sc,frozenset({'adm'}),tlid,(ProjectedTermEvidence('src',Action.RETAIN,'fproj',pcid),))
    active=frozenset({'adm',pcid,tlid})
    result,_=BalanceReaderChecker().check(balance,ev,active,{pcid:pc},{tlid:tl})
    assert result==CheckResult.INVALID

def test_trust_gate_rejects_claim_class_escalation():
    policy=RuntimeTrustPolicy('p',frozenset({('checker','cid','ALGEBRA_IDENTITY')}))
    claim=CertifiedRoot('MODEL_NONEMPTY','checker','cid','MODEL_NONEMPTY')
    try:
        SupportKernel().certified_closure((claim,),(),policy)
    except TrustViolation:
        pass
    else:
        raise AssertionError('claim-class escalation accepted')

def _example_json(name):
    import json
    return json.loads((ROOT/'examples'/name).read_text(encoding='utf-8'))

def test_dsl_heat_bind_end_to_end_relation_path():
    c=DSLCompiler()
    profile=c.compile_model(_example_json('heat_neumann.model.json'))
    bound=PDEBinder().bind(profile)
    assert bound.validation.valid
    assert len(bound.source_balances)==len(bound.ir_balances)==len(bound.normalization_manifests)==1
    assert NormalizationValidator().check(bound.source_balances[0],bound.ir_balances[0],bound.normalization_manifests[0])==CheckResult.VALID
    query=c.compile_query(_example_json('heat_mean.query.json'),profile)
    ir=bound.ir_balances[0]
    pc0=ProjectionClaim(projection_claim_semantic_id(profile.model_id,'one','diffusion',query.query_id,query.scope,ZERO),profile.model_id,'one','diffusion',query.query_id,query.scope,ZERO)
    pc1=ProjectionClaim(projection_claim_semantic_id(profile.model_id,'one','source',query.query_id,query.scope,'int_f'),profile.model_id,'one','source',query.query_id,query.scope,'int_f')
    tl=TargetDerivativeLink(target_link_semantic_id(profile.model_id,'one','storage',query.query_id,query.scope,'dM'),profile.model_id,'one','storage',query.query_id,query.scope,'dM')
    ev=BalanceReaderEvidence(profile.model_id,ir.relation_id,query.query_id,'one',query.scope,frozenset({'one-admissible'}),tl.claim_id,(
        ProjectedTermEvidence('diffusion',Action.ANNIHILATE,ZERO,pc0.claim_id),
        ProjectedTermEvidence('source',Action.RETAIN,'int_f',pc1.claim_id)))
    active=frozenset({'one-admissible',tl.claim_id,pc0.claim_id,pc1.claim_id})
    result,law=BalanceReaderChecker().check(ir,ev,active,{pc0.claim_id:pc0,pc1.claim_id:pc1},{tl.claim_id:tl})
    assert result==CheckResult.VALID and law is not None
    assert law.model_id==profile.model_id and law.query_id==query.query_id

def test_dsl_reaction_diffusion_bind_and_exact_stoichiometry():
    c=DSLCompiler(); p=c.compile_model(_example_json('reaction_diffusion.model.json')); b=PDEBinder().bind(p)
    assert b.validation.valid
    assert NormalizationValidator().check(b.source_balances[0],b.ir_balances[0],b.normalization_manifests[0])==CheckResult.VALID
    S={d.name:d.value for d in p.data}['S']
    assert ExactLinearAlgebraChecker().check_row_zero((Fraction(2),Fraction(-1)),S)==CheckResult.VALID
    q=c.compile_query(_example_json('reaction_invariant.query.json'),p)
    assert q.model_id==p.model_id and q.scope==b.scope

def test_dsl_two_cell_interface_binding_and_glue_typing():
    c=DSLCompiler(); bundle=c.compile_bundle(_example_json('two_cell_interface.bundle.json')); bound=PDEBundleBinder().bind(bundle)
    assert bound.validation.valid
    assert len(bound.bound_models)==2
    for bm in bound.bound_models:
        assert bm.validation.valid
        assert NormalizationValidator().check(bm.source_balances[0],bm.ir_balances[0],bm.normalization_manifests[0])==CheckResult.VALID
        port_terms=[t for t in bm.ir_balances[0].terms if t.role=='PORT']
        assert len(port_terms)==1 and port_terms[0].term_id=='interface_flux'
    coupling=bundle.couplings[0]
    assert coupling.kind=='SIGNED_BALANCE' and coupling.equals==0
    assert {x.model_ref for x in coupling.terms}=={'cell_left','cell_right'}

def test_dsl_rejects_proof_fields_and_unknown_fields():
    c=DSLCompiler(); d=_example_json('heat_neumann.model.json')
    import copy
    x=copy.deepcopy(d); x['verified']=True
    try: c.compile_model(x)
    except DSLError as e: assert e.code=='ILLEGAL_PROOF_FIELD'
    else: raise AssertionError('proof field accepted')
    x=copy.deepcopy(d); x['geometry']['mystery']=1
    try: c.compile_model(x)
    except DSLError as e: assert e.code=='UNKNOWN_FIELD'
    else: raise AssertionError('unknown semantic field accepted')

def test_dsl_no_truth_bearing_time_default_and_initial_gap():
    c=DSLCompiler(); import copy
    d=_example_json('heat_neumann.model.json'); x=copy.deepcopy(d); del x['time']
    try: c.compile_model(x)
    except DSLError as e: assert e.code=='MISSING_FIELD'
    else: raise AssertionError('missing time defaulted silently')
    x=copy.deepcopy(d); x['initial']=[]
    p=c.compile_model(x); b=PDEBinder().bind(p)
    assert not b.validation.valid and 'INITIAL_DATA_GAP' in b.validation.error_codes and not b.ir_balances

def test_dsl_missing_boundary_is_typed_input_gap_but_declared_port_is_legal():
    c=DSLCompiler(); import copy
    d=_example_json('heat_neumann.model.json'); x=copy.deepcopy(d); x['boundary']=[]
    b=PDEBinder().bind(c.compile_model(x))
    assert not b.validation.valid and 'BOUNDARY_GAP' in b.validation.error_codes
    bundle=PDEBundleBinder().bind(c.compile_bundle(_example_json('two_cell_interface.bundle.json')))
    assert bundle.validation.valid

def test_dsl_symbol_closure_and_strong_form_refusal():
    c=DSLCompiler(); import copy
    d=_example_json('heat_neumann.model.json'); x=copy.deepcopy(d); x['equations'][0]['terms'][0]['symbols'].append('ghost')
    b=PDEBinder().bind(c.compile_model(x))
    assert 'UNDECLARED_SYMBOL' in b.validation.error_codes
    x=copy.deepcopy(d); x['equations'][0]['sense']='STRONG'; x['solution']['equation_sense']='STRONG'
    b=PDEBinder().bind(c.compile_model(x))
    assert 'UNSUPPORTED_SEMANTIC_CONSTRUCT' in b.validation.error_codes

def test_dsl_model_identity_is_content_sensitive_and_query_model_bound():
    c=DSLCompiler(); import copy
    d=_example_json('heat_neumann.model.json'); p1=c.compile_model(d); x=copy.deepcopy(d); x['data']['kappa']['rational']=[2,3]; p2=c.compile_model(x)
    assert p1.model_id!=p2.model_id
    q=_example_json('heat_mean.query.json'); q['model_ref']='other'
    try: c.compile_query(q,p1)
    except DSLError as e: assert e.code=='MODEL_REF_MISMATCH'
    else: raise AssertionError('cross-model query ref accepted')

def test_dsl_interface_space_or_orientation_mismatch_rejected():
    c=DSLCompiler(); import copy
    d=_example_json('two_cell_interface.bundle.json'); x=copy.deepcopy(d); x['models'][1]['ports'][0]['semantic_space']='L2(Sigma)'
    b=PDEBundleBinder().bind(c.compile_bundle(x)); assert 'COUPLING_PORT_SPACE_MISMATCH' in b.validation.error_codes
    x=copy.deepcopy(d); x['models'][1]['ports'][0]['orientation']='INWARD'
    b=PDEBundleBinder().bind(c.compile_bundle(x)); assert 'COUPLING_ORIENTATION_UNSAFE' in b.validation.error_codes

def test_binder_storage_normalization_tamper_rejected():
    c=DSLCompiler(); p=c.compile_model(_example_json('heat_neumann.model.json')); b=PDEBinder().bind(p)
    s,ir,m=b.source_balances[0],b.ir_balances[0],b.normalization_manifests[0]
    bad=NormalizationManifest(m.source_relation_id,m.ir_relation_id,m.source_term_ids,m.mappings,(s.storage_term_id,'other-storage'))
    assert NormalizationValidator().check(s,ir,bad)==CheckResult.INVALID

def test_normalization_rejects_role_expression_and_semantic_ref_rewrite():
    sc=Scope(ScopeLevel.CONTINUUM,'weak')
    source=SourceBalanceSpec('m','src',(Term('src:a',1,'SOURCE','f','port-x'),),'src:s','<ut,p>',sc)
    good_ir=BalanceRelationIR('m','ir',sc,'s',(Term('a',1,'SOURCE','f','port-x'),),'<ut,p>')
    man=NormalizationManifest('src','ir',('src:a',),(('src:a','a',1),),('src:s','s'))
    v=NormalizationValidator(); assert v.check(source,good_ir,man)==CheckResult.VALID
    assert v.check(source,BalanceRelationIR('m','ir',sc,'s',(Term('a',1,'INTERNAL','f','port-x'),),'<ut,p>'),man)==CheckResult.INVALID
    assert v.check(source,BalanceRelationIR('m','ir',sc,'s',(Term('a',1,'SOURCE','g','port-x'),),'<ut,p>'),man)==CheckResult.INVALID
    assert v.check(source,BalanceRelationIR('m','ir',sc,'s',(Term('a',1,'SOURCE','f','port-y'),),'<ut,p>'),man)==CheckResult.INVALID

def test_declared_open_port_cannot_disappear_from_balance():
    c=DSLCompiler(); import copy
    d=_example_json('two_cell_interface.bundle.json'); x=copy.deepcopy(d)
    x['models'][0]['equations'][0]['terms']=[t for t in x['models'][0]['equations'][0]['terms'] if t['role']!='PORT']
    bound=PDEBundleBinder().bind(c.compile_bundle(x))
    codes={i.code for i in bound.validation.issues}
    assert 'PORT_UNUSED_BY_BALANCE' in codes

def test_nonzero_neumann_must_have_explicit_boundary_term():
    c=DSLCompiler(); import copy
    d=_example_json('heat_neumann.model.json'); x=copy.deepcopy(d)
    x['boundary'][0]['value']={'semantic':'EXACT_RATIONAL','rational':[1,1]}
    b=PDEBinder().bind(c.compile_model(x))
    assert 'BOUNDARY_EFFECT_MISSING_FROM_BALANCE' in b.validation.error_codes
    x['equations'][0]['terms'].append({'id':'boundary_flux','sign':-1,'role':'BOUNDARY','expr':'<Gamma,phi>','symbols':['Gamma','phi'],'boundary_ref':'Gamma'})
    b2=PDEBinder().bind(c.compile_model(x))
    assert b2.validation.valid
    assert any(t.semantic_ref=='Gamma' and t.role=='BOUNDARY' for t in b2.ir_balances[0].terms)

def test_dsl_rejects_query_status_smuggling_and_numeric_coercion():
    c=DSLCompiler(); import copy
    p=c.compile_model(_example_json('heat_neumann.model.json'))
    q=_example_json('heat_mean.query.json'); q['query']['kind']='EXACT_VALUE'
    try: c.compile_query(q,p)
    except DSLError as e: assert e.code=='UNSUPPORTED_QUERY_KIND'
    else: raise AssertionError('exact status smuggled as query kind')
    d=_example_json('heat_neumann.model.json'); x=copy.deepcopy(d); x['geometry']['dimension']='2'
    try: c.compile_model(x)
    except DSLError as e: assert e.code=='TYPE_MISMATCH'
    else: raise AssertionError('dimension string silently coerced')
    x=copy.deepcopy(d); x['time']['interval']=[0.1,'T']
    try: c.compile_model(x)
    except DSLError as e: assert e.code=='NUMERIC_SEMANTIC_INVALID'
    else: raise AssertionError('float time endpoint silently accepted')

def test_defect_propagation_exact_triangle_bound():
    sc=Scope(ScopeLevel.CONTINUUM,'weak')
    c1=DefectBoundClaim(defect_bound_claim_semantic_id('owner','d1',sc,'p1',Fraction(1,10)),'owner','d1',sc,'p1',Fraction(1,10))
    c2=DefectBoundClaim(defect_bound_claim_semantic_id('owner','d2',sc,'p2',Fraction(1,5)),'owner','d2',sc,'p2',Fraction(1,5))
    ev=DefectPropagationEvidence('q',sc,((2,c1),(-1,c2)))
    r,out=DefectPropagationChecker().check(ev,frozenset({c1.claim_id,c2.claim_id}))
    assert r==CheckResult.VALID and out is not None and out.interval==(Fraction(-2,5),Fraction(2,5))


def test_infinite_dimensional_dual_separates_uniqueness_from_bounded_witness():
    sc=Scope(ScopeLevel.CONTINUUM,'weak')
    closure=InfiniteDualClaim(infinite_dual_claim_semantic_id('M','q',sc,'ADJOINT_CLOSURE_MEMBERSHIP'),'M','q',sc,'ADJOINT_CLOSURE_MEMBERSHIP')
    closed=InfiniteDualClaim(infinite_dual_claim_semantic_id('M','q',sc,'CLOSED_RANGE'),'M','q',sc,'CLOSED_RANGE')
    witness=InfiniteDualClaim(infinite_dual_claim_semantic_id('M','q',sc,'ADJOINT_WITNESS','c'),'M','q',sc,'ADJOINT_WITNESS','c')
    ck=InfiniteDimensionalDualChecker()
    _,a=ck.check((closure,),frozenset({closure.claim_id}))
    _,b=ck.check((closure,closed),frozenset({closure.claim_id,closed.claim_id}))
    _,c=ck.check((witness,),frozenset({witness.claim_id}))
    assert a and a.uniqueness_credit=='EXACT_UNIQUENESS' and a.range_credit=='CLOSURE_ONLY' and a.computational_credit=='NO_EXECUTABLE_DUAL_WITNESS'
    assert b and b.range_credit=='RANGE_EXISTENCE_NONCONSTRUCTIVE' and b.computational_credit=='NO_EXECUTABLE_DUAL_WITNESS'
    assert c and c.computational_credit=='BOUNDED_DUAL_CERTIFICATE'


def test_weak_limit_requires_young_and_concentration_defects():
    sc=Scope(ScopeLevel.CONTINUUM,'weak'); model='m'; rel='r'; seq='s'; q='q'
    def mk(kind): return WeakLimitClaim(weak_limit_claim_semantic_id(model,rel,seq,q,sc,kind),model,rel,seq,q,sc,kind)
    weak,young,conc,invis=[mk(k) for k in ('WEAK_STATE','YOUNG_MEASURE','CONCENTRATION_MEASURE','DEFECT_ANNIHILATION')]
    ck=WeakLimitDefectChecker()
    _,a=ck.check('NONLINEAR_OSCILLATION',(weak,),frozenset({weak.claim_id}))
    _,b=ck.check('NONLINEAR_OSCILLATION',(weak,young),frozenset({weak.claim_id,young.claim_id}))
    _,c=ck.check('CONCENTRATION_SENSITIVE',(weak,young),frozenset({weak.claim_id,young.claim_id}))
    _,d=ck.check('CONCENTRATION_SENSITIVE',(weak,young,conc),frozenset({weak.claim_id,young.claim_id,conc.claim_id}))
    _,e=ck.check('CONCENTRATION_SENSITIVE',(weak,invis),frozenset({weak.claim_id,invis.claim_id}))
    assert (a.status,b.status,c.status,d.status,e.status)==('DEFECT_REQUIRED','DEFECT_ACCOUNTED','CONCENTRATION_DEFECT_REQUIRED','DEFECT_ACCOUNTED','QUERY_EXACT_DEFECT_INVISIBLE')


def _mv_claim(model,rel,seq,q,sc,kind):
    return WeakLimitClaim(weak_limit_claim_semantic_id(model,rel,seq,q,sc,kind),model,rel,seq,q,sc,kind)


def test_measure_valued_young_measure_is_outer_not_strong_exact():
    sc=Scope(ScopeLevel.CONTINUUM,'weak'); seq='osc'; qid='square'
    weak=_mv_claim('m','mv',seq,qid,sc,'WEAK_STATE'); young=_mv_claim('m','mv',seq,qid,sc,'YOUNG_MEASURE')
    rel=MeasureValuedOuterRelation('m','mv',seq,sc,(weak,young),frozenset({weak.claim_id,young.claim_id}))
    q=WeakQueryProfile('m','mv',qid,sc,'NONLINEAR_OSCILLATION')
    r=MeasureValuedQueryPipeline().run(rel,q,frozenset({weak.claim_id,young.claim_id}))
    assert r.status=='VALID' and r.output.kind=='CERTIFIED_OUTER_RELATION'
    assert r.projection.visible_defects==('OSCILLATION',) and r.projection.accounted_defects==('OSCILLATION',)
    assert r.faces.H_E==FaceState.OPEN and any(x.effect=='BLOCKS_EXACT' for x in r.residuals)


def test_measure_valued_concentration_missing_stays_open():
    sc=Scope(ScopeLevel.CONTINUUM,'weak'); seq='conc'; qid='energy'
    weak=_mv_claim('m','mv',seq,qid,sc,'WEAK_STATE'); young=_mv_claim('m','mv',seq,qid,sc,'YOUNG_MEASURE')
    rel=MeasureValuedOuterRelation('m','mv',seq,sc,(weak,young),frozenset({weak.claim_id,young.claim_id}))
    q=WeakQueryProfile('m','mv',qid,sc,'CONCENTRATION_SENSITIVE')
    r=MeasureValuedQueryPipeline().run(rel,q,frozenset({weak.claim_id,young.claim_id}))
    assert r.status=='OPEN' and r.output.kind=='OPEN'
    assert r.projection.missing_defects==('CONCENTRATION',)
    assert r.report.status=='CURRENT' and r.faces.H_E==FaceState.OPEN


def test_measure_query_transparency_binding_cannot_cross_relation():
    sc=Scope(ScopeLevel.CONTINUUM,'weak'); seq='s'; qid='mean'
    weak=_mv_claim('m','mv',seq,qid,sc,'WEAK_STATE'); invis=_mv_claim('m','mv',seq,qid,sc,'DEFECT_ANNIHILATION')
    rel=MeasureValuedOuterRelation('m','mv',seq,sc,(weak,),frozenset({weak.claim_id}))
    q=WeakQueryProfile('m','mv',qid,sc,'CONCENTRATION_SENSITIVE')
    cid='fixture'; bad=QueryTransparencyClaim(query_transparency_claim_semantic_id('m','strong','other',qid,sc,'tf',cid),'m','strong','other',qid,sc,'tf',cid)
    cr,p=MeasureValuedQueryChecker().check(rel,q,frozenset({weak.claim_id,invis.claim_id,bad.claim_id}),invis,bad)
    assert cr==CheckResult.INVALID and p is None


def test_measure_exact_relation_report_stales_on_support_rollback():
    sc=Scope(ScopeLevel.CONTINUUM,'weak'); seq='s'; qid='mean'
    weak=_mv_claim('m','mv',seq,qid,sc,'WEAK_STATE'); invis=_mv_claim('m','mv',seq,qid,sc,'DEFECT_ANNIHILATION')
    rel=MeasureValuedOuterRelation('m','mv',seq,sc,(weak,),frozenset({weak.claim_id}))
    q=WeakQueryProfile('m','mv',qid,sc,'CONCENTRATION_SENSITIVE')
    cid='fixture'; tr=QueryTransparencyClaim(query_transparency_claim_semantic_id('m','strong','mv',qid,sc,'tf',cid),'m','strong','mv',qid,sc,'tf',cid)
    r=MeasureValuedQueryPipeline().run(rel,q,frozenset({weak.claim_id,invis.claim_id,tr.claim_id}),defect_annihilation=invis,transparency=tr)
    assert r.output.kind=='EXACT_RELATION' and r.report.status=='CURRENT'
    stale_active=frozenset(x for x in r.active if x not in r.output.support_refs)
    run=RunSpec('m',qid,sc,'x',frozenset({'H_delta','H_N'}))
    rep=ReportBuilder().build(run,r.output,r.faces,stale_active,r.residuals)
    assert rep.status=='STALE'


def test_measure_visibility_is_derived_from_observable_kind():
    sc=Scope(ScopeLevel.CONTINUUM,'weak'); seq='s'; qid='q'
    weak=_mv_claim('m','mv',seq,qid,sc,'WEAK_STATE'); young=_mv_claim('m','mv',seq,qid,sc,'YOUNG_MEASURE'); conc=_mv_claim('m','mv',seq,qid,sc,'CONCENTRATION_MEASURE')
    rel=MeasureValuedOuterRelation('m','mv',seq,sc,(weak,young,conc),frozenset({weak.claim_id,young.claim_id,conc.claim_id}))
    active=frozenset({weak.claim_id,young.claim_id,conc.claim_id})
    ck=MeasureValuedQueryChecker()
    _,lin=ck.check(rel,WeakQueryProfile('m','mv',qid,sc,'LINEAR'),active)
    _,osc=ck.check(rel,WeakQueryProfile('m','mv',qid,sc,'NONLINEAR_OSCILLATION'),active)
    _,energy=ck.check(rel,WeakQueryProfile('m','mv',qid,sc,'CONCENTRATION_SENSITIVE'),active)
    assert lin.visible_defects==tuple()
    assert osc.visible_defects==('OSCILLATION',)
    assert energy.visible_defects==('CONCENTRATION','OSCILLATION')


def test_measure_open_relation_report_stales_on_support_rollback():
    sc=Scope(ScopeLevel.CONTINUUM,'weak'); seq='conc-open'; qid='energy-open'
    weak=_mv_claim('m','mv-open',seq,qid,sc,'WEAK_STATE'); young=_mv_claim('m','mv-open',seq,qid,sc,'YOUNG_MEASURE')
    rel=MeasureValuedOuterRelation('m','mv-open',seq,sc,(weak,young),frozenset({weak.claim_id,young.claim_id}))
    q=WeakQueryProfile('m','mv-open',qid,sc,'CONCENTRATION_SENSITIVE')
    r=MeasureValuedQueryPipeline().run(rel,q,frozenset({weak.claim_id,young.claim_id}))
    assert r.output.kind=='OPEN' and r.output.support_refs
    stale_active=frozenset(x for x in r.active if x not in r.output.support_refs)
    run=RunSpec('m',qid,sc,'x',frozenset({'H_delta','H_N'}))
    rep=ReportBuilder().build(run,r.output,r.faces,stale_active,r.residuals)
    assert rep.status=='STALE'


def _closed_loop_test_fixture():
    issuer_id='test-closed-loop'; issuer_cid='test-closed-loop-cid'
    sc=Scope(ScopeLevel.CONTINUUM,'w')
    roots=tuple(CertifiedRoot(x,issuer_id,issuer_cid,'ROOT') for x in ('model','query','feasible','law'))
    outer=QueryFact('mcl','qcl',sc,QueryFactType.OUTER_SET,frozenset({5}))
    nonempty=QueryFact('mcl','qcl',sc,QueryFactType.MODEL_NONEMPTY)
    member=QueryFact('mcl','qcl',sc,QueryFactType.MEMBER,5)
    ids=[query_fact_id(x) for x in (outer,nonempty,member)]
    ie=ObligationEvidence('mcl','qcl',sc,'H_I','SATISFIED',frozenset({'model','query'}))
    rules=(
        CertifiedSupportRule(frozenset({'law'}),ids[0],issuer_id,issuer_cid,'DERIVE'),
        CertifiedSupportRule(frozenset({'feasible'}),ids[1],issuer_id,issuer_cid,'DERIVE'),
        CertifiedSupportRule(frozenset({'feasible',ids[0]}),ids[2],issuer_id,issuer_cid,'DERIVE'),
        CertifiedSupportRule(ie.support_refs,content_id(ie),issuer_id,issuer_cid,'DERIVE'),
    )
    policy=RuntimeTrustPolicy('pcl',frozenset({(issuer_id,issuer_cid,'ROOT'),(issuer_id,issuer_cid,'DERIVE')}))
    pre=SupportKernel().certified_closure(roots,rules,policy)
    out=QueryAssembler().assemble('mcl','qcl',sc,'VALUE',(outer,nonempty,member),pre)
    ew=ExactnessWitness('mcl','qcl',sc,content_id(out),out.kind,frozenset(ids))
    wr=CertifiedSupportRule(ew.support_refs,content_id(ew),issuer_id,issuer_cid,'DERIVE')
    run=RunSpec('mcl','qcl',sc,'reconstructed',frozenset({'H_delta','H_N'}))
    return run,roots,rules+(wr,),policy,out,ie,ew


def test_closed_loop_free_truth_boolean_route_cannot_pass_exactness():
    run,roots,rules,policy,out,ie,ew=_closed_loop_test_fixture()
    r=ClosedLoopEvaluator().run(run,roots=roots,rules=rules[:-1],policy=policy,conflicts=tuple(),output=out,input_evidence=ie,exactness_witness=None)
    assert r.faces.H_E==FaceState.OPEN
    assert not closed_loop_pass(run,r)
    assert 'truth_state' not in FaceInputs.__dataclass_fields__


def test_closed_loop_illegal_na_is_rejected():
    run,roots,rules,policy,out,ie,ew=_closed_loop_test_fixture()
    bad=RunSpec(run.model_id,run.query_id,run.scope,run.release_id,frozenset({'H_I','H_delta','H_N'}))
    r=ClosedLoopEvaluator().run(bad,roots=roots,rules=rules,policy=policy,conflicts=tuple(),output=out,input_evidence=ie,exactness_witness=ew)
    assert r.faces.H_I==FaceState.FAIL
    assert not closed_loop_pass(bad,r)


def test_closed_loop_requires_real_trustgate_not_check_label():
    run,roots,rules,policy,out,ie,ew=_closed_loop_test_fixture()
    forged=roots+(CertifiedRoot('fake','CHECK','fake-cid','ROOT'),)
    try:
        ClosedLoopEvaluator().run(run,roots=forged,rules=rules,policy=policy,conflicts=tuple(),output=out,input_evidence=ie,exactness_witness=ew)
    except TrustViolation:
        pass
    else:
        raise AssertionError('fake CHECK label bypassed TrustGate')
