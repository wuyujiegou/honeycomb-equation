from pathlib import Path

from honeycomb_v0 import (
    CheckResult, MeasureValuedQueryPipeline, Scope, ScopeLevel, WeakLimitDefectChecker,
    WeakLimitEvidenceAdapter, WeakLimitEvidenceSubmission, WeakLimitEvidenceVerifier,
    WeakQueryProfile, TheoremFixtureRegistry, weak_evidence_source_content_id,
    weak_evidence_submission_semantic_id,
)

ROOT=Path(__file__).resolve().parents[1]
CONT=Scope(ScopeLevel.CONTINUUM,"weak")


def registry():
    return TheoremFixtureRegistry.from_path(ROOT/'theorems'/'theorem_fixtures.json')


def submission(model,relation,seq,qid,kind,fixture_id,source_id='external-proof:v1'):
    reg=registry(); row=reg.row(fixture_id)
    witness=tuple(sorted(row['evidence_schema']['witness'].items()))
    scid=weak_evidence_source_content_id(source_id,witness)
    fcid=reg.content_id_for(fixture_id)
    sid=weak_evidence_submission_semantic_id(model,relation,seq,qid,CONT,kind,source_id,scid,fixture_id,fcid,witness)
    return WeakLimitEvidenceSubmission(sid,model,relation,seq,qid,CONT,kind,source_id,scid,fixture_id,fcid,witness)


def test_explicit_oscillation_evidence_enters_ksafe_then_outer_query():
    reg=registry(); fid='explicit-oscillation-weak-young-v1'
    subs=tuple(submission('m','mv','s','square',k,fid) for k in ('WEAK_STATE','YOUNG_MEASURE'))
    ing=WeakLimitEvidenceAdapter().ingest(subs,reg)
    assert ing.status=='VALID' and ing.relation is not None
    assert all(c.claim_id in ing.active for c in ing.claims)
    assert all(len(v.support_refs)==2 for v in ing.verifications)
    out=MeasureValuedQueryPipeline().run(ing.relation,WeakQueryProfile('m','mv','square',CONT,'NONLINEAR_OSCILLATION'),ing.active)
    assert out.status=='VALID' and out.output.kind=='CERTIFIED_OUTER_RELATION'


def test_external_receipt_hash_mismatch_is_invalid():
    reg=registry(); s=submission('m','mv','s','q','WEAK_STATE','explicit-oscillation-weak-young-v1')
    bad=WeakLimitEvidenceSubmission(s.submission_id,s.model_id,s.relation_id,s.sequence_id,s.query_id,s.scope,s.kind,s.source_id,'0'*64,s.theorem_fixture_id,s.theorem_fixture_content_id,s.witness)
    cr,vr,claim=WeakLimitEvidenceVerifier().verify(bad,reg)
    assert cr==CheckResult.INVALID and vr is None and claim is None


def test_same_fixture_id_with_wrong_witness_is_rejected():
    reg=registry(); s=submission('m','mv','s','q','WEAK_STATE','explicit-oscillation-weak-young-v1')
    witness=tuple(sorted(dict(s.witness,weak_limit='1').items()))
    scid=weak_evidence_source_content_id(s.source_id,witness)
    sid=weak_evidence_submission_semantic_id(s.model_id,s.relation_id,s.sequence_id,s.query_id,s.scope,s.kind,s.source_id,scid,s.theorem_fixture_id,s.theorem_fixture_content_id,witness)
    bad=WeakLimitEvidenceSubmission(sid,s.model_id,s.relation_id,s.sequence_id,s.query_id,s.scope,s.kind,s.source_id,scid,s.theorem_fixture_id,s.theorem_fixture_content_id,witness)
    assert WeakLimitEvidenceVerifier().verify(bad,reg)[0]==CheckResult.INVALID


def test_stale_theorem_content_id_is_unsupported():
    reg=registry(); s=submission('m','mv','s','q','WEAK_STATE','explicit-oscillation-weak-young-v1')
    sid=weak_evidence_submission_semantic_id(s.model_id,s.relation_id,s.sequence_id,s.query_id,s.scope,s.kind,s.source_id,s.source_content_id,s.theorem_fixture_id,'stale',s.witness)
    bad=WeakLimitEvidenceSubmission(sid,s.model_id,s.relation_id,s.sequence_id,s.query_id,s.scope,s.kind,s.source_id,s.source_content_id,s.theorem_fixture_id,'stale',s.witness)
    assert WeakLimitEvidenceVerifier().verify(bad,reg)[0]==CheckResult.UNSUPPORTED


def test_cross_model_weak_claim_reuse_is_rejected():
    reg=registry(); fid='explicit-oscillation-weak-young-v1'
    ing=WeakLimitEvidenceAdapter().ingest(tuple(submission('m1','mv','s','q',k,fid) for k in ('WEAK_STATE','YOUNG_MEASURE')),reg)
    assert ing.status=='VALID'
    claims=ing.claims
    # Claims are active, but their semantic IDs bind model/relation and cannot be relabeled into m2.
    from honeycomb_v0 import MeasureValuedOuterRelation
    forged=MeasureValuedOuterRelation('m2','mv','s',CONT,claims,frozenset(c.claim_id for c in claims))
    cr,_=__import__('honeycomb_v0',fromlist=['MeasureValuedQueryChecker']).MeasureValuedQueryChecker().check(forged,WeakQueryProfile('m2','mv','q',CONT,'NONLINEAR_OSCILLATION'),ing.active)
    assert cr==CheckResult.INVALID


def test_concentration_evidence_omission_remains_open_not_invalid():
    reg=registry(); fid='explicit-concentration-weak-young-concentration-v1'
    subs=tuple(submission('m','mv-conc','s','energy',k,fid) for k in ('WEAK_STATE','YOUNG_MEASURE'))
    ing=WeakLimitEvidenceAdapter().ingest(subs,reg)
    assert ing.status=='VALID'
    out=MeasureValuedQueryPipeline().run(ing.relation,WeakQueryProfile('m','mv-conc','energy',CONT,'CONCENTRATION_SENSITIVE'),ing.active)
    assert out.status=='OPEN' and out.output.kind=='OPEN'
    assert out.projection.missing_defects==('CONCENTRATION',)


def test_duplicate_evidence_kind_is_invalid():
    reg=registry(); s=submission('m','mv','s','q','WEAK_STATE','explicit-oscillation-weak-young-v1')
    ing=WeakLimitEvidenceAdapter().ingest((s,s),reg)
    assert ing.status=='INVALID'


def test_evidence_envelope_compiler_rejects_unknown_truth_field():
    reg=registry(); row=reg.row('explicit-oscillation-weak-young-v1')
    obj={
      'model_id':'m','relation_id':'mv','sequence_id':'s','query_id':'q',
      'scope':{'level':'CONTINUUM','solution_class':'weak'},
      'observable_kind':'NONLINEAR_OSCILLATION','source_id':'external-proof:v1',
      'theorem_fixture_id':'explicit-oscillation-weak-young-v1','kinds':['WEAK_STATE','YOUNG_MEASURE'],
      'witness':row['evidence_schema']['witness'],'verified':True,
    }
    from honeycomb_v0 import WeakLimitEvidenceEnvelopeCompiler
    import pytest
    with pytest.raises(ValueError): WeakLimitEvidenceEnvelopeCompiler().compile(obj,reg)


def test_weak_evidence_cli_is_deterministic_and_uses_verified_ingress():
    import subprocess,sys,json,os
    cmd=[sys.executable,str(ROOT/'run_weak_evidence.py'),str(ROOT/'examples'/'weak_oscillation.evidence.json')]
    env=dict(os.environ); env['PYTHONPATH']=str(ROOT/'src'); env['PYTHONHASHSEED']='1'
    a=subprocess.check_output(cmd,env=env,text=True)
    env['PYTHONHASHSEED']='987654'
    b=subprocess.check_output(cmd,env=env,text=True)
    assert a==b
    obj=json.loads(a)
    assert obj['IngressStatus']=='VALID' and obj['OutputKind']=='CERTIFIED_OUTER_RELATION' and obj['ReportStatus']=='CURRENT'
