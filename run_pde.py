from __future__ import annotations
from pathlib import Path
import argparse, json, sys

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'src'))
from honeycomb_v0 import (
    DSLCompiler, PDEBinder, PDEBundleBinder, NormalizationValidator, canonical_data,
    TheoremFixtureRegistry, DeclarativeAutoEvidenceRouter, auto_evidence_summary,
    CoupledPortBalanceEvidenceAdapter, coupled_evidence_summary,
    CoupledDefectPortBalanceEvidenceAdapter, coupled_defect_evidence_summary, CouplingDefectSpec,
)


def _load(path: Path):
    return json.loads(path.read_text(encoding='utf-8'))


def main(argv=None):
    ap=argparse.ArgumentParser(description='Honeycomb v0 typed PDE binding entry point')
    ap.add_argument('input', type=Path, help='model or bundle JSON')
    ap.add_argument('--query', type=Path, default=None, help='optional query JSON for a model or bundle')
    ap.add_argument('--auto-evidence', action='store_true', help='run strict automatic evidence for a model or coupled bundle')
    ap.add_argument('--theorem-fixtures', type=Path, default=ROOT/'theorems'/'theorem_fixtures.json', help='theorem fixture registry')
    ns=ap.parse_args(argv)
    compiler=DSLCompiler(); doc=_load(ns.input)
    auto_ok=True
    if 'model' in doc:
        profile=compiler.compile_model(doc); bound=PDEBinder().bind(profile)
        norms=[NormalizationValidator().check(s,ir,m).value for s,ir,m in zip(bound.source_balances,bound.ir_balances,bound.normalization_manifests)]
        result={
            'kind':'MODEL_BINDING','name':profile.name,'model_id':profile.model_id,'binding_valid':bound.validation.valid,
            'issues':[canonical_data(x) for x in bound.validation.issues],
            'relation_ids':[x.relation_id for x in bound.ir_balances],
            'normalization_results':norms,
        }
        query=None
        if ns.query is not None:
            query=compiler.compile_query(_load(ns.query),profile)
            result['query']={'name':query.name,'query_id':query.query_id,'kind':query.kind,'scope':canonical_data(query.scope),'reader_id':query.reader_id}
        if ns.auto_evidence:
            if query is None:
                raise SystemExit('--auto-evidence requires --query')
            registry=TheoremFixtureRegistry.from_path(ns.theorem_fixtures)
            router=DeclarativeAutoEvidenceRouter()
            auto=router.adapt(bound,query,registry,release_id='pde-cli-auto-evidence')
            result['auto_evidence']=canonical_data(auto_evidence_summary(auto))
            result['auto_evidence']['adapter_id']='declarative-balance-evidence-engine'
            result['auto_evidence']['adapter_version']=router.version
            auto_ok=(auto.status=='VALID')
    elif 'bundle' in doc:
        bundle=compiler.compile_bundle(doc); bound=PDEBundleBinder().bind(bundle)
        result={
            'kind':'BUNDLE_BINDING','name':bundle.name,'bundle_id':bundle.bundle_id,'binding_valid':bound.validation.valid,
            'issues':[canonical_data(x) for x in bound.validation.issues],
            'models':[{'name':m.profile.name,'model_id':m.model_id,'relation_ids':[x.relation_id for x in m.ir_balances]} for m in bound.bound_models],
            'couplings':[canonical_data(x) for x in bundle.couplings],
        }
        query=None
        if ns.query is not None:
            query=compiler.compile_bundle_query(_load(ns.query),bundle)
            result['query']={'name':query.name,'query_id':query.query_id,'kind':query.kind,'scope':canonical_data(query.scope),'observable_primitive':query.observable_primitive,'field':query.field,'reader_id':query.reader_id}
        if ns.auto_evidence:
            if query is None:
                raise SystemExit('--auto-evidence requires --query')
            registry=TheoremFixtureRegistry.from_path(ns.theorem_fixtures)
            has_defect=any(isinstance(c.equals,CouplingDefectSpec) for c in bundle.couplings)
            if has_defect:
                auto=CoupledDefectPortBalanceEvidenceAdapter().adapt(bound,query,registry,release_id='pde-cli-coupled-defect-auto-evidence')
                result['auto_evidence']=canonical_data(coupled_defect_evidence_summary(auto))
                result['auto_evidence']['adapter_id']=CoupledDefectPortBalanceEvidenceAdapter.adapter_id
                result['auto_evidence']['adapter_version']=CoupledDefectPortBalanceEvidenceAdapter.version
            else:
                auto=CoupledPortBalanceEvidenceAdapter().adapt(bound,query,registry,release_id='pde-cli-coupled-auto-evidence')
                result['auto_evidence']=canonical_data(coupled_evidence_summary(auto))
                result['auto_evidence']['adapter_id']=CoupledPortBalanceEvidenceAdapter.adapter_id
                result['auto_evidence']['adapter_version']=CoupledPortBalanceEvidenceAdapter.version
            auto_ok=(auto.status=='VALID')
    else:
        raise SystemExit('input must contain model or bundle')
    print(json.dumps(canonical_data(result),sort_keys=True,separators=(',',':'),ensure_ascii=False))
    if not result['binding_valid']:
        return 2
    return 0 if auto_ok else 3

if __name__=='__main__':
    raise SystemExit(main())
