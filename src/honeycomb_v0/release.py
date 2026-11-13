from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import FrozenSet, Iterable, Tuple
from .canonical import content_id, file_sha256, CANON_VERSION, HASH_SCHEME

REQUIRED_FAMILIES = frozenset({f"R{i}" for i in range(1,9)} | {f"G_{c}" for c in "ABCDEFG"})
REQUIRED_CAPABILITIES = frozenset({"CONTINUUM_WEAK_PDE", "NONLINEAR_PDE_STRUCTURAL", "DISCRETE_NUMERICAL_BALANCE", "PDE_INPUT_BINDING", "PDE_AUTO_EVIDENCE", "PDE_AUTO_NONLINEAR_EVIDENCE", "PDE_AUTO_RELATIONAL_PORT_EVIDENCE", "DECLARATIVE_ADAPTER_RULES", "PDE_AUTO_COUPLING_COMPOSITION", "PDE_AUTO_COUPLING_DEFECT_PROPAGATION", "INFINITE_DIMENSIONAL_GUARDS", "MEASURE_VALUED_QUERY_ASSEMBLY", "WEAK_LIMIT_EVIDENCE_INGRESS", "HE_CORE_CLOSED_LOOP"})

@dataclass(frozen=True)
class ExecutablePin:
    object_id: str
    version: str
    content_id: str

@dataclass(frozen=True)
class OraclePin:
    object_id: str
    family: str
    version: str
    content_id: str

@dataclass(frozen=True)
class ReleaseSpec:
    fixtures: Tuple[ExecutablePin, ...]
    oracles: Tuple[OraclePin, ...]
    components: Tuple[ExecutablePin, ...]
    theorem_fixtures: Tuple[ExecutablePin, ...]
    trust_policy: ExecutablePin
    canonicalization: str
    hash_scheme: str

    def normalized(self):
        pkey = lambda p: (p.object_id, p.version, p.content_id)
        okey = lambda p: (p.family, p.object_id, p.version, p.content_id)
        return ReleaseSpec(tuple(sorted(self.fixtures, key=pkey)), tuple(sorted(self.oracles, key=okey)),
                           tuple(sorted(self.components, key=pkey)), tuple(sorted(self.theorem_fixtures, key=pkey)),
                           self.trust_policy, self.canonicalization, self.hash_scheme)
    @property
    def release_id(self):
        return content_id(self.normalized())

@dataclass(frozen=True)
class OracleResult:
    oracle_id: str
    family: str
    passed: bool

@dataclass(frozen=True)
class ReleaseResult:
    release_id: str
    passed: bool
    missing_families: FrozenSet[str]
    missing_oracles: FrozenSet[str]
    unexpected_oracles: FrozenSet[str]
    failed_oracles: FrozenSet[str]
    missing_capabilities: FrozenSet[str]
    spec_errors: FrozenSet[str]

class ReleaseRunner:
    version = "0.4.0"
    def run(self, spec: ReleaseSpec, oracle_results: Iterable[OracleResult], capabilities: FrozenSet[str]) -> ReleaseResult:
        rows = tuple(oracle_results)
        expected = {p.object_id: p.family for p in spec.oracles}
        spec_errors = set()
        if len(expected) != len(spec.oracles):
            spec_errors.add("DUPLICATE_ORACLE_PIN")
        if set(expected.values()) != REQUIRED_FAMILIES:
            spec_errors.add("REQUIRED_FAMILY_PIN_MISMATCH")
        if spec.canonicalization != CANON_VERSION:
            spec_errors.add("CANONICALIZATION_MISMATCH")
        if spec.hash_scheme != HASH_SCHEME:
            spec_errors.add("HASH_SCHEME_MISMATCH")
        seen = {}
        duplicate_rows = set()
        for r in rows:
            if r.oracle_id in seen:
                duplicate_rows.add(r.oracle_id)
            seen[r.oracle_id] = r
        if duplicate_rows:
            spec_errors.add("DUPLICATE_ORACLE_RESULT")
        expected_ids = set(expected)
        actual_ids = set(seen)
        missing_oracles = expected_ids - actual_ids
        unexpected_oracles = actual_ids - expected_ids
        failed = set()
        passed_families = set()
        for oid in expected_ids & actual_ids:
            r = seen[oid]
            if r.family != expected[oid]:
                failed.add(oid)
                continue
            if r.passed:
                passed_families.add(r.family)
            else:
                failed.add(oid)
        missing_families = REQUIRED_FAMILIES - passed_families
        missing_caps = REQUIRED_CAPABILITIES - capabilities
        passed = not (spec_errors or missing_oracles or unexpected_oracles or failed or missing_families or missing_caps)
        return ReleaseResult(spec.release_id, passed, frozenset(missing_families), frozenset(missing_oracles),
                             frozenset(unexpected_oracles), frozenset(failed), frozenset(missing_caps), frozenset(spec_errors))

def source_pins(package_dir: Path) -> Tuple[ExecutablePin, ...]:
    pins=[]
    for p in sorted(package_dir.glob("*.py")):
        pins.append(ExecutablePin(f"src:{p.name}", "0.3.0", file_sha256(p)))
    return tuple(pins)
