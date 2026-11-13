from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import sys
from typing import FrozenSet, Mapping, Tuple

from .adapters import TheoremFixtureRegistry
from .canonical import content_id, file_sha256
from .kernel import CertifiedRoot, CertifiedSupportRule, RuntimeTrustPolicy, SupportKernel
from .types import (
    CheckResult, MeasureValuedOuterRelation, WeakLimitClaim,
    WeakLimitEvidenceSubmission, WeakLimitEvidenceVerification,
)


def _module_hash(obj: object) -> str:
    mod=sys.modules[obj.__module__]
    path=getattr(mod,"__file__",None)
    if not path:
        raise RuntimeError(f"module file unavailable: {obj.__module__}")
    return file_sha256(Path(path))


def weak_limit_claim_semantic_id(model_id: str, relation_id: str, sequence_id: str, query_id: str, scope, kind: str) -> str:
    return content_id({
        "type":"WeakLimitClaim","model_id":model_id,"relation_id":relation_id,
        "sequence_id":sequence_id,"query_id":query_id,"scope":scope,"kind":kind,
    })


def weak_evidence_source_content_id(source_id: str, witness: Tuple[Tuple[str, object], ...]) -> str:
    return content_id({"type":"WeakEvidenceSource","source_id":source_id,"witness":witness})


def weak_evidence_submission_semantic_id(model_id: str, relation_id: str, sequence_id: str, query_id: str, scope, kind: str,
                                         source_id: str, source_content_id: str, theorem_fixture_id: str,
                                         theorem_fixture_content_id: str, witness: Tuple[Tuple[str, object], ...]) -> str:
    return content_id({
        "type":"WeakLimitEvidenceSubmission","model_id":model_id,"relation_id":relation_id,
        "sequence_id":sequence_id,"query_id":query_id,"scope":scope,"kind":kind,
        "source_id":source_id,"source_content_id":source_content_id,
        "theorem_fixture_id":theorem_fixture_id,"theorem_fixture_content_id":theorem_fixture_content_id,
        "witness":witness,
    })


class WeakLimitEvidenceVerifier:
    """Verify explicit weak-limit evidence envelopes against pinned machine-readable theorem witnesses.

    v0 intentionally supports only EXPLICIT_SEQUENCE_EVIDENCE theorem fixtures. A producer receipt
    is content integrity, not mathematical truth. Mathematical credit is issued only after this
    verifier matches the submission to the pinned theorem fixture's evidence_schema.
    """
    verifier_id="weak-limit-evidence-verifier"
    version="0.1.0"
    _KINDS=frozenset({"WEAK_STATE","YOUNG_MEASURE","CONCENTRATION_MEASURE"})

    def verify(self, submission: WeakLimitEvidenceSubmission, registry: TheoremFixtureRegistry) -> tuple[CheckResult, WeakLimitEvidenceVerification | None, WeakLimitClaim | None]:
        if submission.kind not in self._KINDS:
            return CheckResult.UNSUPPORTED, None, None
        if not submission.model_id or not submission.relation_id or not submission.sequence_id or not submission.query_id:
            return CheckResult.INVALID, None, None
        if len({k for k,_ in submission.witness}) != len(submission.witness):
            return CheckResult.INVALID, None, None
        if tuple(sorted(submission.witness,key=lambda x:x[0])) != submission.witness:
            return CheckResult.INVALID, None, None
        expected_source=weak_evidence_source_content_id(submission.source_id,submission.witness)
        if submission.source_content_id != expected_source:
            return CheckResult.INVALID, None, None
        expected_submission=weak_evidence_submission_semantic_id(
            submission.model_id,submission.relation_id,submission.sequence_id,submission.query_id,submission.scope,submission.kind,
            submission.source_id,submission.source_content_id,submission.theorem_fixture_id,submission.theorem_fixture_content_id,submission.witness)
        if submission.submission_id != expected_submission:
            return CheckResult.INVALID, None, None
        try:
            row=registry.row(submission.theorem_fixture_id)
        except Exception:
            return CheckResult.UNSUPPORTED, None, None
        if submission.theorem_fixture_content_id != registry.content_id_for(submission.theorem_fixture_id):
            return CheckResult.UNSUPPORTED, None, None
        if row.get("role") != "trusted_theorem_fixture" or row.get("theorem_kind") != "EXPLICIT_SEQUENCE_EVIDENCE":
            return CheckResult.UNSUPPORTED, None, None
        schema=row.get("evidence_schema")
        if not isinstance(schema,dict):
            return CheckResult.UNSUPPORTED, None, None
        certified=schema.get("certified_kinds")
        witness_schema=schema.get("witness")
        if not isinstance(certified,list) or submission.kind not in certified or not isinstance(witness_schema,dict):
            return CheckResult.UNSUPPORTED, None, None
        if dict(submission.witness) != witness_schema:
            return CheckResult.INVALID, None, None
        claim_id=weak_limit_claim_semantic_id(submission.model_id,submission.relation_id,submission.sequence_id,submission.query_id,submission.scope,submission.kind)
        claim=WeakLimitClaim(claim_id,submission.model_id,submission.relation_id,submission.sequence_id,submission.query_id,submission.scope,submission.kind)
        fixture_root=registry.root_id_for(submission.theorem_fixture_id)
        vh=_module_hash(WeakLimitEvidenceVerifier)
        verification=WeakLimitEvidenceVerification(submission.submission_id,claim_id,submission.theorem_fixture_id,submission.theorem_fixture_content_id,self.verifier_id,vh,frozenset({submission.submission_id,fixture_root}))
        return CheckResult.VALID, verification, claim


@dataclass(frozen=True)
class WeakLimitEvidenceIngressResult:
    status: str
    reason: str
    relation: MeasureValuedOuterRelation | None
    claims: Tuple[WeakLimitClaim, ...]
    verifications: Tuple[WeakLimitEvidenceVerification, ...]
    active: FrozenSet[str]


class WeakLimitEvidenceAdapter:
    adapter_id="weak-limit-evidence-adapter"
    version="0.1.0"

    def ingest(self, submissions: Tuple[WeakLimitEvidenceSubmission, ...], registry: TheoremFixtureRegistry) -> WeakLimitEvidenceIngressResult:
        if not submissions:
            return WeakLimitEvidenceIngressResult("INVALID","no weak-limit evidence submissions",None,tuple(),tuple(),frozenset())
        base=(submissions[0].model_id,submissions[0].relation_id,submissions[0].sequence_id,submissions[0].query_id,submissions[0].scope)
        if any((s.model_id,s.relation_id,s.sequence_id,s.query_id,s.scope)!=base for s in submissions):
            return WeakLimitEvidenceIngressResult("INVALID","evidence submissions do not share one model/relation/sequence/query/scope",None,tuple(),tuple(),frozenset())
        if len({s.kind for s in submissions}) != len(submissions):
            return WeakLimitEvidenceIngressResult("INVALID","duplicate weak-limit evidence kind",None,tuple(),tuple(),frozenset())

        verifier=WeakLimitEvidenceVerifier(); vh=_module_hash(WeakLimitEvidenceVerifier)
        claims=[]; verifications=[]; roots=[]; rules=[]; allowed=set()
        for s in sorted(submissions,key=lambda x:x.kind):
            cr,vr,claim=verifier.verify(s,registry)
            if cr!=CheckResult.VALID or vr is None or claim is None:
                return WeakLimitEvidenceIngressResult(cr.value,f"weak-limit evidence verification failed for {s.kind}: {cr.value}",None,tuple(),tuple(),frozenset())
            # Content receipt is trusted only as a byte/field receipt, never as a mathematical claim.
            roots.append(CertifiedRoot(s.submission_id,"weak-evidence-receipt",vh,"EVIDENCE_RECEIPT"))
            roots.append(CertifiedRoot(registry.root_id_for(s.theorem_fixture_id),"weak-evidence-theorem-registry",s.theorem_fixture_content_id,"THEOREM_FIXTURE_ROOT"))
            rules.append(CertifiedSupportRule(vr.support_refs,claim.claim_id,verifier.verifier_id,vh,"WEAK_LIMIT_EVIDENCE_DERIVATION"))
            allowed.update({
                ("weak-evidence-receipt",vh,"EVIDENCE_RECEIPT"),
                ("weak-evidence-theorem-registry",s.theorem_fixture_content_id,"THEOREM_FIXTURE_ROOT"),
                (verifier.verifier_id,vh,"WEAK_LIMIT_EVIDENCE_DERIVATION"),
            })
            claims.append(claim); verifications.append(vr)
        policy=RuntimeTrustPolicy("weak-evidence-ingress",frozenset(allowed))
        active=SupportKernel().certified_closure(tuple(roots),tuple(rules),policy)
        if not all(c.claim_id in active for c in claims):
            return WeakLimitEvidenceIngressResult("INVALID","verified claims failed support closure",None,tuple(claims),tuple(verifications),active)
        model,relation_id,seq,qid,scope=base
        relation=MeasureValuedOuterRelation(model,relation_id,seq,scope,tuple(sorted(claims,key=lambda c:c.kind)),frozenset(c.claim_id for c in claims))
        return WeakLimitEvidenceIngressResult("VALID","weak-limit evidence verified and admitted to Ksafe",relation,tuple(sorted(claims,key=lambda c:c.kind)),tuple(verifications),active)


class WeakLimitEvidenceEnvelopeCompiler:
    """Compile a strict external JSON-like evidence envelope into immutable submissions + query profile."""
    compiler_id="weak-limit-evidence-envelope-compiler"
    version="0.1.0"
    _KEYS=frozenset({"model_id","relation_id","sequence_id","query_id","scope","observable_kind","source_id","theorem_fixture_id","kinds","witness"})

    def compile(self, obj: Mapping[str, object], registry: TheoremFixtureRegistry):
        from .types import Scope, ScopeLevel, WeakQueryProfile
        if not isinstance(obj,Mapping) or set(obj)!=self._KEYS:
            raise ValueError("weak evidence envelope fields mismatch")
        for k in ("model_id","relation_id","sequence_id","query_id","observable_kind","source_id","theorem_fixture_id"):
            if not isinstance(obj[k],str) or not obj[k]:
                raise ValueError(f"invalid {k}")
        scope_obj=obj["scope"]
        if not isinstance(scope_obj,Mapping) or set(scope_obj)!={"level","solution_class"}:
            raise ValueError("invalid scope")
        if scope_obj["level"]!="CONTINUUM" or not isinstance(scope_obj["solution_class"],str) or not scope_obj["solution_class"]:
            raise ValueError("weak evidence v0 requires explicit continuum scope")
        scope=Scope(ScopeLevel.CONTINUUM,scope_obj["solution_class"])
        if obj["observable_kind"] not in {"LINEAR","NONLINEAR_OSCILLATION","CONCENTRATION_SENSITIVE"}:
            raise ValueError("invalid observable_kind")
        kinds=obj["kinds"]
        if not isinstance(kinds,list) or not kinds or len(set(kinds))!=len(kinds) or not all(isinstance(k,str) for k in kinds):
            raise ValueError("invalid evidence kinds")
        witness_obj=obj["witness"]
        if not isinstance(witness_obj,Mapping) or not witness_obj or not all(isinstance(k,str) and k for k in witness_obj):
            raise ValueError("invalid witness")
        witness=tuple(sorted(witness_obj.items()))
        source_id=obj["source_id"]; source_cid=weak_evidence_source_content_id(source_id,witness)
        fid=obj["theorem_fixture_id"]; fcid=registry.content_id_for(fid)
        submissions=[]
        for kind in sorted(kinds):
            sid=weak_evidence_submission_semantic_id(obj["model_id"],obj["relation_id"],obj["sequence_id"],obj["query_id"],scope,kind,source_id,source_cid,fid,fcid,witness)
            submissions.append(WeakLimitEvidenceSubmission(sid,obj["model_id"],obj["relation_id"],obj["sequence_id"],obj["query_id"],scope,kind,source_id,source_cid,fid,fcid,witness))
        query=WeakQueryProfile(obj["model_id"],obj["relation_id"],obj["query_id"],scope,obj["observable_kind"])
        return tuple(submissions),query
