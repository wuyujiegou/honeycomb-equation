from __future__ import annotations
from dataclasses import dataclass
from typing import FrozenSet, Iterable, Tuple
from .canonical import content_id

@dataclass(frozen=True)
class SupportRule:
    premises: FrozenSet[str]
    conclusion: str

@dataclass(frozen=True)
class CertifiedRoot:
    proposition_id: str
    issuer_id: str
    issuer_content_id: str
    claim_class: str
    verified: bool = True

@dataclass(frozen=True)
class CertifiedSupportRule:
    premises: FrozenSet[str]
    conclusion: str
    issuer_id: str
    issuer_content_id: str
    claim_class: str
    verified: bool = True

@dataclass(frozen=True)
class RuntimeTrustPolicy:
    policy_id: str
    allowed_claims: FrozenSet[Tuple[str, str, str]]

class TrustViolation(ValueError):
    pass

class TrustGate:
    def roots(self, claims: Iterable[CertifiedRoot], policy: RuntimeTrustPolicy) -> FrozenSet[str]:
        out=set()
        for c in claims:
            if not c.verified or (c.issuer_id,c.issuer_content_id,c.claim_class) not in policy.allowed_claims:
                raise TrustViolation(f"untrusted root: {c.proposition_id}")
            out.add(c.proposition_id)
        return frozenset(out)
    def rules(self, claims: Iterable[CertifiedSupportRule], policy: RuntimeTrustPolicy) -> Tuple[SupportRule, ...]:
        out=[]
        for c in claims:
            if not c.verified or (c.issuer_id,c.issuer_content_id,c.claim_class) not in policy.allowed_claims:
                raise TrustViolation(f"untrusted rule conclusion: {c.conclusion}")
            if not c.premises:
                raise TrustViolation("premise-free certified rule forbidden")
            out.append(SupportRule(c.premises,c.conclusion))
        return tuple(out)

class SupportKernel:
    @staticmethod
    def _validate_rules(rules: Iterable[SupportRule]) -> tuple[SupportRule, ...]:
        rows = tuple(rules)
        if any(not r.premises for r in rows):
            raise ValueError("Premise-free support rules are forbidden; use explicit trusted roots")
        return rows

    def closure(self, roots: Iterable[str], rules: Iterable[SupportRule], excluded: FrozenSet[str] = frozenset()) -> FrozenSet[str]:
        """Pure mathematical least-fixed-point closure. Does not assign certification credit."""
        rows = self._validate_rules(rules)
        K = set(roots) - set(excluded)
        ordered = sorted(rows, key=content_id)
        changed = True
        while changed:
            changed = False
            for r in ordered:
                if r.conclusion in excluded or r.premises & excluded:
                    continue
                if r.premises.issubset(K) and r.conclusion not in K:
                    K.add(r.conclusion)
                    changed = True
        return frozenset(K)

    def certified_closure(self, roots: Iterable[CertifiedRoot], rules: Iterable[CertifiedSupportRule],
                          policy: RuntimeTrustPolicy, excluded: FrozenSet[str] = frozenset()) -> FrozenSet[str]:
        gate=TrustGate()
        trusted_roots=gate.roots(roots,policy)
        trusted_rules=gate.rules(rules,policy)
        return self.closure(trusted_roots,trusted_rules,excluded)

    def quarantine(self, roots: Iterable[str], rules: Iterable[SupportRule], conflicts: Iterable[Tuple[str, str]]) -> FrozenSet[str]:
        rows = self._validate_rules(rules)
        candidate = self.closure(roots, rows)
        excluded = set()
        for a, b in conflicts:
            if a in candidate and b in candidate:
                excluded.update((a, b))
        return self.closure(roots, rows, frozenset(excluded))

    def certified_quarantine(self, roots: Iterable[CertifiedRoot], rules: Iterable[CertifiedSupportRule],
                             conflicts: Iterable[Tuple[str,str]], policy: RuntimeTrustPolicy) -> FrozenSet[str]:
        gate=TrustGate()
        trusted_roots=gate.roots(roots,policy)
        trusted_rules=gate.rules(rules,policy)
        return self.quarantine(trusted_roots,trusted_rules,conflicts)
