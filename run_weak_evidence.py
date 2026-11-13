from pathlib import Path
import argparse, json, sys
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'src'))
from honeycomb_v0 import (
    TheoremFixtureRegistry, WeakLimitEvidenceEnvelopeCompiler, WeakLimitEvidenceAdapter,
    MeasureValuedQueryPipeline, canonical_data, content_id,
)

ap=argparse.ArgumentParser(description='Verify weak-limit evidence and assemble a measure-valued query result.')
ap.add_argument('evidence_json')
ap.add_argument('--theorem-fixtures',default=str(ROOT/'theorems'/'theorem_fixtures.json'))
args=ap.parse_args()
obj=json.loads(Path(args.evidence_json).read_text(encoding='utf-8'))
reg=TheoremFixtureRegistry.from_path(args.theorem_fixtures)
subs,query=WeakLimitEvidenceEnvelopeCompiler().compile(obj,reg)
ing=WeakLimitEvidenceAdapter().ingest(subs,reg)
if ing.status!='VALID' or ing.relation is None:
    out={'IngressStatus':ing.status,'Reason':ing.reason}
    print(json.dumps(out,sort_keys=True,separators=(',',':'),ensure_ascii=False)); raise SystemExit(2)
run=MeasureValuedQueryPipeline().run(ing.relation,query,ing.active,release_id='weak-evidence-cli')
out={
  'IngressStatus':ing.status,
  'RelationID':ing.relation.relation_id,
  'ClaimIDs':sorted(c.claim_id for c in ing.claims),
  'IngressKsafeID':content_id(ing.active),
  'QueryStatus':run.status,
  'OutputKind':run.output.kind if run.output else None,
  'OutputID':content_id(run.output) if run.output else None,
  'Projection':canonical_data(run.projection) if run.projection else None,
  'ReportID':content_id(run.report) if run.report else None,
  'ReportStatus':run.report.status if run.report else None,
}
print(json.dumps(out,sort_keys=True,separators=(',',':'),ensure_ascii=False))
raise SystemExit(0 if run.status in {'VALID','OPEN'} else 2)
