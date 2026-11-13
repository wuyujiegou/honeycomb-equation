from pathlib import Path
import json, sys
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'src'))
from honeycomb_v0 import canonical_data
from honeycomb_v0.release import ExecutablePin, OraclePin, ReleaseSpec, ReleaseRunner, source_pins
from honeycomb_v0.canonical import CANON_VERSION, HASH_SCHEME, file_sha256
from honeycomb_v0.fixtures import all_release_oracles, mandatory_capabilities, deterministic_payload, ORACLE_FAMILIES

manifest=json.loads((ROOT/'manifests'/'release_manifest.json').read_text(encoding='utf-8'))
pkg=ROOT/'src'/'honeycomb_v0'
components=source_pins(pkg) + (
    ExecutablePin('driver:run_release.py','0.9.0',file_sha256(ROOT/'run_release.py')),
    ExecutablePin('driver:build_release_manifest.py','0.9.0',file_sha256(ROOT/'build_release_manifest.py')),
    ExecutablePin('driver:run_pde.py','0.5.0',file_sha256(ROOT/'run_pde.py')),
    ExecutablePin('driver:run_weak_evidence.py','0.1.0',file_sha256(ROOT/'run_weak_evidence.py')),
    ExecutablePin('rules:adapter_rules.json','0.3.0',file_sha256(ROOT/'rules'/'adapter_rules.json')),
)
fixture_hash=file_sha256(pkg/'fixtures.py')
example_root=ROOT/'examples'
example_pins=tuple(ExecutablePin(f'example:{p.name}','0.1.0',file_sha256(p)) for p in sorted(example_root.glob('*.json')))
fixtures=(ExecutablePin('fixture-suite','0.8.0',fixture_hash),)+example_pins
oracles=tuple(OraclePin(oid,fam,'0.8.0',fixture_hash) for oid,fam in ORACLE_FAMILIES.items())
theorems=(ExecutablePin('theorem-fixtures','0.8.0',file_sha256(ROOT/'theorems'/'theorem_fixtures.json')),)
trust=ExecutablePin('trust-policy','0.2.0',file_sha256(ROOT/'policy'/'trust_policy.json'))
spec=ReleaseSpec(fixtures,oracles,components,theorems,trust,CANON_VERSION,HASH_SCHEME).normalized()
if spec.release_id != manifest.get('release_id'):
    raise SystemExit('release manifest identity mismatch')
if canonical_data(spec) != manifest.get('release_spec'):
    raise SystemExit('release manifest content mismatch')
theorem_doc=json.loads((ROOT/'theorems'/'theorem_fixtures.json').read_text(encoding='utf-8'))
theorem_ids=frozenset(x.get('id') for x in theorem_doc.get('fixtures',[]) if isinstance(x,dict) and x.get('id'))
trust_doc=json.loads((ROOT/'policy'/'trust_policy.json').read_text(encoding='utf-8'))
principles=trust_doc.get('principles',{})
required_policy_keys={
 'premise_free_rules_forbidden',
 'unverified_evidence_cannot_enter_certified_support',
 'scope_expansion_requires_explicit_transport_certificate',
 'conflicting_propositions_are_quarantined_as_roots_premises_and_conclusions',
 'claim_class_restriction_required',
}
trust_policy_valid=(trust_doc.get('policy_id')=='strict-v2' and all(principles.get(k) is True for k in required_policy_keys))
results=all_release_oracles(theorem_ids,trust_policy_valid,ROOT/'examples',ROOT/'theorems'/'theorem_fixtures.json'); caps=mandatory_capabilities(ROOT/'examples',ROOT/'theorems'/'theorem_fixtures.json'); rr=ReleaseRunner().run(spec,results,caps)
payload=deterministic_payload(spec.release_id,(fixtures[0].object_id,fixtures[0].content_id))
out={
 'ReleaseID':spec.release_id,
 'ReleasePASS':rr.passed,
 'MissingFamilies':sorted(rr.missing_families),
 'MissingOracles':sorted(rr.missing_oracles),
 'UnexpectedOracles':sorted(rr.unexpected_oracles),
 'FailedOracles':sorted(rr.failed_oracles),
 'MissingCapabilities':sorted(rr.missing_capabilities),
 'SpecErrors':sorted(rr.spec_errors),
 'OracleResults':[{"id":r.oracle_id,"family":r.family,"pass":r.passed} for r in sorted(results,key=lambda r:(r.family,r.oracle_id))],
 'Capabilities':sorted(caps),
 **canonical_data(payload)
}
print(json.dumps(out,sort_keys=True,separators=(',',':'),ensure_ascii=False))
raise SystemExit(0 if rr.passed else 2)
