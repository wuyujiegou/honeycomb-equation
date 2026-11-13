from pathlib import Path
import json, sys
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'src'))
from honeycomb_v0.canonical import CANON_VERSION, HASH_SCHEME, file_sha256, canonical_data
from honeycomb_v0.release import ExecutablePin, OraclePin, ReleaseSpec, source_pins
from honeycomb_v0.fixtures import ORACLE_FAMILIES

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
theorem_path=ROOT/'theorems'/'theorem_fixtures.json'
trust_path=ROOT/'policy'/'trust_policy.json'
theorems=(ExecutablePin('theorem-fixtures','0.8.0',file_sha256(theorem_path)),)
trust=ExecutablePin('trust-policy','0.2.0',file_sha256(trust_path))
spec=ReleaseSpec(fixtures,oracles,components,theorems,trust,CANON_VERSION,HASH_SCHEME).normalized()
obj={'release_spec':canonical_data(spec),'release_id':spec.release_id}
(ROOT/'manifests'/'release_manifest.json').write_text(json.dumps(obj,sort_keys=True,indent=2),encoding='utf-8')
print(spec.release_id)
