from __future__ import annotations
import json
from importlib.resources import files
from pathlib import Path
from .canonical import canonical_data, file_sha256
from .fixtures import all_release_oracles, mandatory_capabilities
from .release import REQUIRED_CAPABILITIES, REQUIRED_FAMILIES
from .adapters import TheoremFixtureRegistry


def _resource_path(*parts: str) -> Path:
    obj = files("honeycomb_v0").joinpath("data", *parts)
    return Path(str(obj))


def _trust_policy_valid(path: Path) -> bool:
    obj=json.loads(path.read_text(encoding="utf-8"))
    principles=obj.get("principles",{})
    required={
        "premise_free_rules_forbidden",
        "unverified_evidence_cannot_enter_certified_support",
        "scope_expansion_requires_explicit_transport_certificate",
        "conflicting_propositions_are_quarantined_as_roots_premises_and_conclusions",
        "claim_class_restriction_required",
    }
    return obj.get("policy_id")=="strict-v2" and all(principles.get(k) is True for k in required)


def selfcheck_payload() -> dict:
    example_dir=_resource_path("examples")
    theorem_path=_resource_path("theorems","theorem_fixtures.json")
    trust_path=_resource_path("policy","trust_policy.json")
    rules_path=_resource_path("rules","adapter_rules.json")
    registry=TheoremFixtureRegistry.from_path(theorem_path)
    trust_ok=_trust_policy_valid(trust_path)
    rows=all_release_oracles(registry.ids,trust_ok,example_dir,theorem_path)
    caps=mandatory_capabilities(example_dir,theorem_path)
    passed_oracles=tuple(r for r in rows if r.passed)
    passed_families=frozenset(r.family for r in passed_oracles)
    result=(len(rows)==30 and len(passed_oracles)==30 and
            passed_families==REQUIRED_FAMILIES and caps==REQUIRED_CAPABILITIES)
    return {
        "ConformancePASS": result,
        "SemanticBaseline": "HE_CORE_CLOSED_LOOP",
        "OracleCount": len(rows),
        "OraclePassCount": len(passed_oracles),
        "CapabilityCount": len(caps),
        "MissingFamilies": sorted(REQUIRED_FAMILIES-passed_families),
        "FailedOracles": sorted(r.oracle_id for r in rows if not r.passed),
        "MissingCapabilities": sorted(REQUIRED_CAPABILITIES-caps),
        "ClosedLoopOracle": next((r.passed for r in rows if r.oracle_id=="gg.he.closed.loop"),False),
        "ResourceHashes": {
            "theorem_fixtures": file_sha256(theorem_path),
            "trust_policy": file_sha256(trust_path),
            "adapter_rules": file_sha256(rules_path),
        },
    }


def selfcheck_main() -> int:
    payload=selfcheck_payload()
    print(json.dumps(canonical_data(payload),sort_keys=True,separators=(",",":"),ensure_ascii=False))
    return 0 if payload["ConformancePASS"] else 2


if __name__ == "__main__":
    raise SystemExit(selfcheck_main())
