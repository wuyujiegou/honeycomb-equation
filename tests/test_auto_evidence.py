from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))

from honeycomb_v0 import (  # noqa: E402
    DSLCompiler,
    PDEBinder,
    TheoremFixtureRegistry,
    WeakConstantTestEvidenceAdapter,
    WeakConstantVectorInvariantAdapter,
    FaceState,
    PDEBundleBinder,
    CoupledPortBalanceEvidenceAdapter,
    CoupledDefectPortBalanceEvidenceAdapter,
    COUPLING_FIXTURE_ID,
    DEFECT_COUPLING_FIXTURE_ID,
)


def _j(name):
    return json.loads((ROOT/'examples'/name).read_text(encoding='utf-8'))


def _build(model=None, query=None, registry=None):
    c=DSLCompiler()
    p=c.compile_model(model or _j('heat_neumann.model.json'))
    b=PDEBinder().bind(p)
    q=c.compile_query(query or _j('heat_mean.query.json'),p)
    reg=registry or TheoremFixtureRegistry.from_path(ROOT/'theorems'/'theorem_fixtures.json')
    return WeakConstantTestEvidenceAdapter().adapt(b,q,reg,release_id='test-release')


def test_heat_auto_evidence_end_to_end_current_exact_law():
    r=_build()
    assert r.status=='VALID'
    assert r.output is not None and r.output.kind=='EXACT_LAW'
    assert r.report is not None and r.report.status=='CURRENT'
    assert r.faces is not None
    assert (r.faces.H_I,r.faces.H_O,r.faces.H_delta,r.faces.H_N,r.faces.H_E,r.faces.H_R)==(
        FaceState.PASS,FaceState.PASS,FaceState.PASS,FaceState.NA,FaceState.PASS,FaceState.PASS)
    assert r.adapter_theorem_credit=='ZERO'
    assert r.existence_credit=='NONE'
    assert r.law is not None and r.law.derivative_object=='measure(Omega)*d_dt(mean(u))'
    assert r.law.retained_terms==((-1,'<f,1>'),)
    assert not r.law.defect_terms


def test_heat_auto_evidence_refuses_unrecognized_internal_pattern():
    m=_j('heat_neumann.model.json')
    m['equations'][0]['terms'][0]['expr']='kappa*int(u*phi)'
    r=_build(model=m)
    assert r.status=='UNSUPPORTED'


def test_heat_auto_evidence_refuses_missing_required_fixture():
    reg=TheoremFixtureRegistry.from_path(ROOT/'theorems'/'theorem_fixtures.json')
    reg=TheoremFixtureRegistry(reg.fixture_set_id,reg.version,tuple(x for x in reg.fixtures if x.get('id')!='constant-gradient-zero-v1'))
    r=_build(registry=reg)
    assert r.status=='UNSUPPORTED'


def test_heat_auto_evidence_refuses_temporal_regularity_drift():
    m=_j('heat_neumann.model.json')
    m['solution']['regularity']['u']='L2(H1)'
    r=_build(model=m)
    assert r.status=='UNSUPPORTED'


def test_heat_auto_evidence_refuses_nonzero_neumann_without_adapter_extension():
    m=_j('heat_neumann.model.json')
    m['boundary'][0]['value']['rational']=[1,1]
    # Keep the PDE structurally valid by adding the required boundary term; the automatic adapter still refuses it.
    m['equations'][0]['terms'].append({
        'id':'boundary_flux','sign':-1,'role':'BOUNDARY','expr':'<Gamma,phi>',
        'symbols':['Gamma','phi'],'boundary_ref':'Gamma'
    })
    r=_build(model=m)
    assert r.status=='UNSUPPORTED'


def test_run_pde_auto_evidence_cli():
    cmd=[sys.executable,str(ROOT/'run_pde.py'),str(ROOT/'examples'/'heat_neumann.model.json'),
         '--query',str(ROOT/'examples'/'heat_mean.query.json'),'--auto-evidence']
    cp=subprocess.run(cmd,capture_output=True,text=True,check=False)
    assert cp.returncode==0, cp.stderr
    obj=json.loads(cp.stdout)
    ae=obj['auto_evidence']
    assert ae['status']=='VALID'
    assert ae['adapter_theorem_credit']=='ZERO'
    assert ae['existence_credit']=='NONE'
    assert ae['output']['kind']=='EXACT_LAW'
    assert ae['report']['status']=='CURRENT'


def test_heat_auto_evidence_refuses_forged_fixture_same_id():
    reg=TheoremFixtureRegistry.from_path(ROOT/'theorems'/'theorem_fixtures.json')
    rows=[]
    for x in reg.fixtures:
        y=dict(x)
        if y.get('id')=='constant-gradient-zero-v1':
            y['claim']='forged weaker or unrelated statement'
        rows.append(y)
    forged=TheoremFixtureRegistry(reg.fixture_set_id,reg.version,tuple(rows))
    r=_build(registry=forged)
    assert r.status=='UNSUPPORTED'
    assert 'fingerprint mismatch' in r.reason


def test_heat_auto_evidence_refuses_hand_forged_bound_object():
    from dataclasses import replace
    from honeycomb_v0 import DSLCompiler, PDEBinder
    c=DSLCompiler(); p=c.compile_model(_j('heat_neumann.model.json')); b=PDEBinder().bind(p)
    ir=replace(b.ir_balances[0],relation_id='forged-relation')
    manifest=replace(b.normalization_manifests[0],ir_relation_id='forged-relation')
    forged=replace(b,ir_balances=(ir,),normalization_manifests=(manifest,))
    q=c.compile_query(_j('heat_mean.query.json'),p)
    reg=TheoremFixtureRegistry.from_path(ROOT/'theorems'/'theorem_fixtures.json')
    r=WeakConstantTestEvidenceAdapter().adapt(forged,q,reg)
    assert r.status=='INVALID'
    assert 'provenance mismatch' in r.reason


def _build_rd(model=None, query=None, registry=None):
    from honeycomb_v0 import WeakConstantVectorInvariantAdapter
    c=DSLCompiler()
    p=c.compile_model(model or _j('reaction_diffusion.model.json'))
    b=PDEBinder().bind(p)
    q=c.compile_query(query or _j('reaction_invariant.query.json'),p)
    reg=registry or TheoremFixtureRegistry.from_path(ROOT/'theorems'/'theorem_fixtures.json')
    return WeakConstantVectorInvariantAdapter().adapt(b,q,reg,release_id='test-release')


def test_rd_auto_evidence_end_to_end_current_exact_law():
    r=_build_rd()
    assert r.status=='VALID'
    assert r.output is not None and r.output.kind=='EXACT_LAW'
    assert r.report is not None and r.report.status=='CURRENT'
    assert r.adapter_theorem_credit=='ZERO' and r.existence_credit=='NONE'
    assert r.law is not None
    assert r.law.derivative_object=='d_dt(int(ell^T u))'
    assert r.law.retained_terms==((-1,'int(ell^T f)'),)
    assert r.law.defect_terms==()


def test_rd_auto_evidence_refuses_reader_not_in_left_nullspace():
    m=_j('reaction_diffusion.model.json')
    m['data']['ell']['vector']=[[1,1],[0,1]]
    r=_build_rd(model=m)
    assert r.status=='UNSUPPORTED'
    assert 'left nullspace' in r.reason


def test_rd_auto_evidence_refuses_hidden_reader_vector():
    m=_j('reaction_diffusion.model.json')
    del m['data']['ell']
    r=_build_rd(model=m)
    assert r.status=='INVALID'


def test_rd_auto_evidence_refuses_reaction_expression_drift():
    m=_j('reaction_diffusion.model.json')
    m['equations'][0]['terms'][1]['expr']='int(phi^T reaction(u))'
    r=_build_rd(model=m)
    assert r.status=='UNSUPPORTED'


def test_rd_auto_evidence_refuses_forged_vector_fixture_same_id():
    reg=TheoremFixtureRegistry.from_path(ROOT/'theorems'/'theorem_fixtures.json')
    rows=[]
    for x in reg.fixtures:
        y=dict(x)
        if y.get('id')=='constant-vector-gradient-zero-v1':
            y['claim']='forged statement'
        rows.append(y)
    forged=TheoremFixtureRegistry(reg.fixture_set_id,reg.version,tuple(rows))
    r=_build_rd(registry=forged)
    assert r.status=='UNSUPPORTED'


def test_run_pde_auto_evidence_rd_cli():
    cmd=[sys.executable,str(ROOT/'run_pde.py'),str(ROOT/'examples'/'reaction_diffusion.model.json'),
         '--query',str(ROOT/'examples'/'reaction_invariant.query.json'),'--auto-evidence']
    cp=subprocess.run(cmd,capture_output=True,text=True,check=False)
    assert cp.returncode==0, cp.stderr
    obj=json.loads(cp.stdout); ae=obj['auto_evidence']
    assert ae['status']=='VALID'
    assert ae['adapter_id']=='declarative-balance-evidence-engine'
    assert ae['rule_id']=='reaction-diffusion-constant-vector-invariant-v1'
    assert ae['output']['kind']=='EXACT_LAW'
    assert ae['adapter_theorem_credit']=='ZERO'



def test_declarative_rule_router_selects_both_frozen_rules():
    from honeycomb_v0 import DeclarativeAutoEvidenceRouter, official_adapter_rule_registry
    router=DeclarativeAutoEvidenceRouter(official_adapter_rule_registry())
    c=DSLCompiler()
    hp=c.compile_model(_j('heat_neumann.model.json')); hb=PDEBinder().bind(hp); hq=c.compile_query(_j('heat_mean.query.json'),hp)
    op=c.compile_model(_j('heat_open_port.model.json')); ob=PDEBinder().bind(op); oq=c.compile_query(_j('heat_open_mean.query.json'),op)
    rp=c.compile_model(_j('reaction_diffusion.model.json')); rb=PDEBinder().bind(rp); rq=c.compile_query(_j('reaction_invariant.query.json'),rp)
    assert router.select_rule_id(hb,hq)=='heat-mean-constant-test-v1'
    assert router.select_rule_id(ob,oq)=='heat-mean-open-port-constant-test-v1'
    assert router.select_rule_id(rb,rq)=='reaction-diffusion-constant-vector-invariant-v1'


def test_declarative_rule_registry_rejects_unknown_primitive_and_action_laundering():
    from honeycomb_v0 import DeclarativeAdapterRuleRegistry, official_adapter_rule_registry
    reg=official_adapter_rule_registry()
    obj={'rule_set_id':reg.rule_set_id,'version':reg.version,'rules':[copy.deepcopy(r.raw) for r in reg.rules]}
    obj['rules'][0]['terms'][0]['primitive']='ARBITRARY_PYTHON'
    try:
        DeclarativeAdapterRuleRegistry.from_object(obj)
    except ValueError:
        pass
    else:
        raise AssertionError('unknown primitive accepted')
    obj={'rule_set_id':reg.rule_set_id,'version':reg.version,'rules':[copy.deepcopy(r.raw) for r in reg.rules]}
    obj['rules'][0]['terms'][1]['action']='ANNIHILATE'
    try:
        DeclarativeAdapterRuleRegistry.from_object(obj)
    except ValueError:
        pass
    else:
        raise AssertionError('primitive/action laundering accepted')


def test_compatibility_wrappers_are_semantically_identical_to_direct_rule_engine():
    from honeycomb_v0 import DeclarativeBalanceEvidenceAdapter, official_adapter_rule_registry
    c=DSLCompiler(); reg=TheoremFixtureRegistry.from_path(ROOT/'theorems'/'theorem_fixtures.json'); rules=official_adapter_rule_registry()
    hp=c.compile_model(_j('heat_neumann.model.json')); hb=PDEBinder().bind(hp); hq=c.compile_query(_j('heat_mean.query.json'),hp)
    wrapped=WeakConstantTestEvidenceAdapter().adapt(hb,hq,reg); direct=DeclarativeBalanceEvidenceAdapter('heat-mean-constant-test-v1',rules).adapt(hb,hq,reg)
    assert wrapped.status==direct.status=='VALID'
    assert wrapped.law==direct.law and wrapped.output.value==direct.output.value and wrapped.faces==direct.faces
    rp=c.compile_model(_j('reaction_diffusion.model.json')); rb=PDEBinder().bind(rp); rq=c.compile_query(_j('reaction_invariant.query.json'),rp)
    wrapped=WeakConstantVectorInvariantAdapter().adapt(rb,rq,reg); direct=DeclarativeBalanceEvidenceAdapter('reaction-diffusion-constant-vector-invariant-v1',rules).adapt(rb,rq,reg)
    assert wrapped.status==direct.status=='VALID'
    assert wrapped.law==direct.law and wrapped.output.value==direct.output.value and wrapped.faces==direct.faces

def test_declarative_rule_registry_rejects_theorem_slot_swap_and_derivative_laundering():
    from honeycomb_v0 import DeclarativeAdapterRuleRegistry, official_adapter_rule_registry
    reg=official_adapter_rule_registry()
    obj={'rule_set_id':reg.rule_set_id,'version':reg.version,'rules':[copy.deepcopy(r.raw) for r in reg.rules]}
    # Use a real theorem reference from another semantic slot; the kind binding must reject it.
    obj['rules'][0]['reader_admissibility_fixture']=copy.deepcopy(obj['rules'][0]['time_pairing_fixture'])
    try:
        DeclarativeAdapterRuleRegistry.from_object(obj)
    except ValueError:
        pass
    else:
        raise AssertionError('theorem slot swap accepted')
    obj={'rule_set_id':reg.rule_set_id,'version':reg.version,'rules':[copy.deepcopy(r.raw) for r in reg.rules]}
    obj['rules'][0]['derivative']['template']='d_dt(forged_target)'
    try:
        DeclarativeAdapterRuleRegistry.from_object(obj)
    except ValueError:
        pass
    else:
        raise AssertionError('derivative template laundering accepted')



def _build_open(model=None, query=None, registry=None):
    c=DSLCompiler()
    p=c.compile_model(model or _j('heat_open_port.model.json'))
    b=PDEBinder().bind(p)
    q=c.compile_query(query or _j('heat_open_mean.query.json'),p)
    reg=registry or TheoremFixtureRegistry.from_path(ROOT/'theorems'/'theorem_fixtures.json')
    from honeycomb_v0 import DeclarativeAutoEvidenceRouter
    return DeclarativeAutoEvidenceRouter().adapt(b,q,reg,release_id='test-open-release')


def test_open_port_heat_auto_evidence_retains_boundary_channel_exactly():
    r=_build_open()
    assert r.status=='VALID'
    assert r.rule_id=='heat-mean-open-port-constant-test-v1'
    assert r.output is not None and r.output.kind=='EXACT_LAW'
    assert r.report is not None and r.report.status=='CURRENT'
    assert r.law is not None
    assert r.law.derivative_object=='measure(Omega)*d_dt(mean(u))'
    assert r.law.retained_terms==((-1,'<f,1>'),(-1,'<flux,trace(1)>'))
    assert r.law.defect_terms==()
    assert r.adapter_theorem_credit=='ZERO' and r.existence_credit=='NONE'


def test_open_port_heat_exact_law_does_not_upgrade_to_exact_value():
    from honeycomb_v0 import QueryAssembler, RunSpec, FaceEvaluator, FaceInputs, ReportBuilder, Residual, ObligationEvidence, content_id
    c=DSLCompiler(); p=c.compile_model(_j('heat_open_port.model.json')); b=PDEBinder().bind(p)
    lawq=c.compile_query(_j('heat_open_mean.query.json'),p)
    valueq=c.compile_query(_j('heat_open_mean_value.query.json'),p)
    reg=TheoremFixtureRegistry.from_path(ROOT/'theorems'/'theorem_fixtures.json')
    from honeycomb_v0 import DeclarativeAutoEvidenceRouter
    law=DeclarativeAutoEvidenceRouter().adapt(b,lawq,reg,release_id='test-open-law')
    assert law.status=='VALID' and law.output.kind=='EXACT_LAW'
    refused=DeclarativeAutoEvidenceRouter().adapt(b,valueq,reg,release_id='test-open-value')
    assert refused.status=='UNSUPPORTED'
    value_out=QueryAssembler().assemble(p.model_id,valueq.query_id,valueq.scope,'VALUE',tuple(),law.active)
    assert value_out.kind=='OPEN'
    run=RunSpec(p.model_id,valueq.query_id,valueq.scope,'test-open-value',frozenset({'H_N'}))
    input_ev=ObligationEvidence(p.model_id,valueq.query_id,valueq.scope,'H_I','SATISFIED',frozenset())
    active=frozenset(set(law.active)|{content_id(input_ev)})
    faces=FaceEvaluator().evaluate(run,FaceInputs(input_ev,None,value_out,active,active,None,None))
    assert faces.H_I==FaceState.PASS and faces.H_O==FaceState.PASS
    assert faces.H_E==FaceState.OPEN and faces.H_delta==FaceState.OPEN
    residual=Residual('open-port-history-unresolved','BLOCKS_EXACT',True)
    report=ReportBuilder().build(run,value_out,faces,law.active,(residual,))
    assert report.status=='CURRENT'


def test_open_port_heat_refuses_wrong_port_orientation_or_realization():
    m=_j('heat_open_port.model.json'); m['ports'][0]['orientation']='INWARD'
    assert _build_open(model=m).status=='UNSUPPORTED'
    m=_j('heat_open_port.model.json'); m['ports'][0]['realization']='TRACE'
    assert _build_open(model=m).status=='UNSUPPORTED'
    m=_j('heat_open_port.model.json'); m['ports'][0]['semantic_space']='L2(Gamma)'
    assert _build_open(model=m).status=='UNSUPPORTED'


def test_open_port_heat_refuses_port_projection_expression_drift():
    m=_j('heat_open_port.model.json')
    m['equations'][0]['terms'][2]['expr']='<flux,phi>'
    r=_build_open(model=m)
    assert r.status=='UNSUPPORTED'
    assert 'port' in r.reason.lower()


def test_open_port_heat_refuses_forged_trace_fixture_same_id():
    reg=TheoremFixtureRegistry.from_path(ROOT/'theorems'/'theorem_fixtures.json')
    rows=[]
    for x in reg.fixtures:
        y=dict(x)
        if y.get('id')=='constant-trace-one-v1': y['claim']='forged trace claim'
        rows.append(y)
    forged=TheoremFixtureRegistry(reg.fixture_set_id,reg.version,tuple(rows))
    r=_build_open(registry=forged)
    assert r.status=='UNSUPPORTED' and 'fingerprint mismatch' in r.reason


def test_run_pde_auto_evidence_open_port_cli():
    cmd=[sys.executable,str(ROOT/'run_pde.py'),str(ROOT/'examples'/'heat_open_port.model.json'),
         '--query',str(ROOT/'examples'/'heat_open_mean.query.json'),'--auto-evidence']
    cp=subprocess.run(cmd,capture_output=True,text=True,check=False)
    assert cp.returncode==0,cp.stderr
    obj=json.loads(cp.stdout); ae=obj['auto_evidence']
    assert ae['status']=='VALID'
    assert ae['rule_id']=='heat-mean-open-port-constant-test-v1'
    assert ae['output']['kind']=='EXACT_LAW'
    assert ae['law']['retained_terms']==[
        [-1,'<f,1>'],[-1,'<flux,trace(1)>']
    ] or ae['law']['retained_terms']==(
        (-1,'<f,1>'),(-1,'<flux,trace(1)>')
    )


def _bundle_compose(root=ROOT):
    c=DSLCompiler()
    bundle=c.compile_bundle(_j('two_cell_interface.bundle.json'))
    bound=PDEBundleBinder().bind(bundle)
    query=c.compile_bundle_query(_j('two_cell_global_mean.query.json'),bundle)
    registry=TheoremFixtureRegistry.from_path(root/'theorems'/'theorem_fixtures.json')
    return c,bundle,bound,query,registry,CoupledPortBalanceEvidenceAdapter().adapt(bound,query,registry)


def test_coupled_open_port_laws_cancel_internal_interface_exactly():
    c,bundle,bound,query,registry,r=_bundle_compose()
    assert r.status=='VALID'
    assert r.output is not None and r.output.kind=='EXACT_LAW'
    assert r.report is not None and r.report.status=='CURRENT'
    assert r.law is not None and r.law.eliminated_couplings==('flux_glue',)
    assert len(r.law.local_derivatives)==2
    assert len(r.law.retained_terms)==2
    assert all(sign==-1 and obj=='<f,1>' for _,sign,obj in r.law.retained_terms)
    assert all('flux' not in obj for _,_,obj in r.law.retained_terms)
    assert r.composition_theorem_credit=='ZERO' and r.existence_credit=='NONE'


def test_coupled_composition_rejects_coupling_sign_not_proportional_to_local_laws():
    import copy
    raw=_j('two_cell_interface.bundle.json')
    raw=copy.deepcopy(raw); raw['couplings'][0]['terms'][1]['sign']=-1
    c=DSLCompiler(); bundle=c.compile_bundle(raw); bound=PDEBundleBinder().bind(bundle)
    assert bound.validation.valid
    q=c.compile_bundle_query(_j('two_cell_global_mean.query.json'),bundle)
    reg=TheoremFixtureRegistry.from_path(ROOT/'theorems'/'theorem_fixtures.json')
    assert CoupledPortBalanceEvidenceAdapter().adapt(bound,q,reg).status!='VALID'


def test_coupled_composition_rejects_one_local_port_sign_drift():
    import copy
    raw=copy.deepcopy(_j('two_cell_interface.bundle.json'))
    raw['models'][1]['equations'][0]['terms'][2]['sign']=1
    c=DSLCompiler(); bundle=c.compile_bundle(raw); bound=PDEBundleBinder().bind(bundle)
    assert bound.validation.valid
    q=c.compile_bundle_query(_j('two_cell_global_mean.query.json'),bundle)
    reg=TheoremFixtureRegistry.from_path(ROOT/'theorems'/'theorem_fixtures.json')
    assert CoupledPortBalanceEvidenceAdapter().adapt(bound,q,reg).status!='VALID'


def test_coupled_composition_rejects_forged_coupling_theorem_same_id():
    c,bundle,bound,query,registry,_=_bundle_compose()
    rows=[]
    for row in registry.fixtures:
        x=dict(row)
        if x.get('id')==COUPLING_FIXTURE_ID:
            x['claim']='forged theorem content'
        rows.append(x)
    forged=TheoremFixtureRegistry(registry.fixture_set_id,registry.version,tuple(rows))
    assert CoupledPortBalanceEvidenceAdapter().adapt(bound,query,forged).status=='UNSUPPORTED'


def test_coupling_validator_requires_weak_conormal_realization():
    import copy
    raw=copy.deepcopy(_j('two_cell_interface.bundle.json'))
    raw['models'][1]['ports'][0]['realization']='TRACE'
    c=DSLCompiler(); bundle=c.compile_bundle(raw); bound=PDEBundleBinder().bind(bundle)
    assert 'COUPLING_REALIZATION_UNSUPPORTED' in bound.validation.error_codes

def test_coupled_defect_composition_propagates_bound_and_keeps_relational_exactness():
    c=DSLCompiler(); reg=TheoremFixtureRegistry.from_path(ROOT/'theorems'/'theorem_fixtures.json')
    bundle=c.compile_bundle(_j('two_cell_interface_defect.bundle.json')); bound=PDEBundleBinder().bind(bundle)
    q=c.compile_bundle_query(_j('two_cell_defect_global_mean.query.json'),bundle)
    r=CoupledDefectPortBalanceEvidenceAdapter().adapt(bound,q,reg,release_id='defect-test')
    assert r.status=='VALID'
    assert r.output is not None and r.output.kind=='CERTIFIED_DEFECT_LAW'
    assert r.report is not None and r.report.status=='CURRENT'
    assert r.faces is not None and r.faces.H_E==FaceState.PASS
    assert r.law is not None and r.law.propagated_interval==(-__import__('fractions').Fraction(1,10),__import__('fractions').Fraction(1,10))
    assert len(r.law.defect_terms)==1 and r.residuals[0].effect=='BOUNDED'


def test_coupled_defect_composition_rejects_bad_sign_and_forged_theorem():
    c=DSLCompiler(); reg=TheoremFixtureRegistry.from_path(ROOT/'theorems'/'theorem_fixtures.json')
    bad=_j('two_cell_interface_defect.bundle.json'); bad['couplings'][0]['terms'][1]['sign']=-1
    bundle=c.compile_bundle(bad); bound=PDEBundleBinder().bind(bundle); q=c.compile_bundle_query(_j('two_cell_defect_global_mean.query.json'),bundle)
    assert CoupledDefectPortBalanceEvidenceAdapter().adapt(bound,q,reg).status!='VALID'
    good=c.compile_bundle(_j('two_cell_interface_defect.bundle.json')); gbound=PDEBundleBinder().bind(good); gq=c.compile_bundle_query(_j('two_cell_defect_global_mean.query.json'),good)
    rows=[]
    for row in reg.fixtures:
        rr=dict(row)
        if rr.get('id')==DEFECT_COUPLING_FIXTURE_ID: rr['claim']='forged'
        rows.append(rr)
    forged=TheoremFixtureRegistry(reg.fixture_set_id,reg.version,tuple(rows))
    assert CoupledDefectPortBalanceEvidenceAdapter().adapt(gbound,gq,forged).status=='UNSUPPORTED'

def test_run_pde_coupled_defect_cli():
    cmd=[sys.executable,str(ROOT/'run_pde.py'),str(ROOT/'examples'/'two_cell_interface_defect.bundle.json'),
         '--query',str(ROOT/'examples'/'two_cell_defect_global_mean.query.json'),'--auto-evidence']
    cp=subprocess.run(cmd,capture_output=True,text=True,check=False)
    assert cp.returncode==0, cp.stderr
    obj=json.loads(cp.stdout); ae=obj['auto_evidence']
    assert ae['status']=='VALID' and ae['output']['kind']=='CERTIFIED_DEFECT_LAW'
    assert ae['report']['status']=='CURRENT' and ae['residuals'][0]['effect']=='BOUNDED'
