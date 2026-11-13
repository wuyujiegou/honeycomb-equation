from __future__ import annotations
from fractions import Fraction
from typing import FrozenSet, Iterable
from .canonical import content_id
from .types import *


def query_fact_id(f: QueryFact) -> str:
    return content_id(f)

class QueryAssembler:
    assembler_id = "query-assembler"
    version = "0.6.0"
    def assemble(self, model_id: str, query_id: str, scope: Scope, kind: str,
                 facts: Iterable[QueryFact], active: FrozenSet[str]) -> OutputArtifact:
        rows=tuple(facts)
        supports=frozenset(query_fact_id(f) for f in rows)
        if any(f.model_id != model_id or f.query_id != query_id or f.scope != scope for f in rows):
            return OutputArtifact(model_id, query_id, scope, "INVALID_FACT_BINDING", None, supports)
        if any(query_fact_id(f) not in active for f in rows):
            return OutputArtifact(model_id, query_id, scope, "UNVERIFIED_FACT", None, supports)
        model_empty=any(f.fact_type==QueryFactType.MODEL_EMPTY for f in rows)
        model_nonempty=any(f.fact_type==QueryFactType.MODEL_NONEMPTY for f in rows)
        outers=tuple(f.value for f in rows if f.fact_type==QueryFactType.OUTER_SET)
        members={f.value for f in rows if f.fact_type==QueryFactType.MEMBER}
        laws=tuple(f.value for f in rows if f.fact_type==QueryFactType.EXACT_LAW)
        defect_laws=tuple(f.value for f in rows if f.fact_type==QueryFactType.DEFECT_LAW)
        outer_relations=tuple(f.value for f in rows if f.fact_type==QueryFactType.OUTER_RELATION)
        exact_relations=tuple(f.value for f in rows if f.fact_type==QueryFactType.EXACT_RELATION)
        open_relations=tuple(f.value for f in rows if f.fact_type==QueryFactType.OPEN_RELATION)
        defects=tuple(f.value for f in rows if f.fact_type==QueryFactType.DEFECT_INTERVAL)
        if model_empty and (model_nonempty or members or laws or defect_laws):
            return OutputArtifact(model_id, query_id, scope, "CONFLICT_LEAK", None, supports)
        if model_empty:
            empty_kind = {"VALUE": "NO_VALUE", "IMAGE": "EXACT_EMPTY_IMAGE", "LAW": "NO_LAW"}.get(kind, "EMPTY_RELATION")
            value = frozenset() if kind == "IMAGE" else None
            return OutputArtifact(model_id, query_id, scope, empty_kind, value, supports)
        if kind == "LAW":
            if laws and defect_laws:
                return OutputArtifact(model_id, query_id, scope, "CONFLICT_LEAK", None, supports)
            if laws:
                unique = {content_id(v): v for v in laws}
                if len(unique) != 1:
                    return OutputArtifact(model_id, query_id, scope, "CONFLICT_LEAK", None, supports)
                return OutputArtifact(model_id, query_id, scope, "EXACT_LAW", next(iter(unique.values())), supports)
            if defect_laws:
                unique = {content_id(v): v for v in defect_laws}
                if len(unique) != 1:
                    return OutputArtifact(model_id, query_id, scope, "CONFLICT_LEAK", None, supports)
                return OutputArtifact(model_id, query_id, scope, "CERTIFIED_DEFECT_LAW", next(iter(unique.values())), supports)
        if kind == "RELATION":
            populated=sum(bool(x) for x in (exact_relations,outer_relations,open_relations))
            if populated > 1:
                return OutputArtifact(model_id, query_id, scope, "CONFLICT_LEAK", None, supports)
            if exact_relations:
                unique={content_id(v):v for v in exact_relations}
                if len(unique)!=1:
                    return OutputArtifact(model_id, query_id, scope, "CONFLICT_LEAK", None, supports)
                return OutputArtifact(model_id, query_id, scope, "EXACT_RELATION", next(iter(unique.values())), supports)
            if outer_relations:
                unique={content_id(v):v for v in outer_relations}
                if len(unique)!=1:
                    return OutputArtifact(model_id, query_id, scope, "CONFLICT_LEAK", None, supports)
                return OutputArtifact(model_id, query_id, scope, "CERTIFIED_OUTER_RELATION", next(iter(unique.values())), supports)
            if open_relations:
                unique={content_id(v):v for v in open_relations}
                if len(unique)!=1:
                    return OutputArtifact(model_id, query_id, scope, "CONFLICT_LEAK", None, supports)
                return OutputArtifact(model_id, query_id, scope, "OPEN", next(iter(unique.values())), supports)
        outer = None
        for s in outers:
            if not isinstance(s,(set,frozenset)):
                return OutputArtifact(model_id, query_id, scope, "INVALID_FACT_TYPE", None, supports)
            outer = set(s) if outer is None else outer.intersection(s)
        if outer is not None:
            if members - outer:
                return OutputArtifact(model_id, query_id, scope, "CONFLICT_LEAK", None, supports)
            if model_nonempty and not outer:
                return OutputArtifact(model_id, query_id, scope, "CONFLICT_LEAK", None, supports)
        if kind == "VALUE":
            if outer is not None and len(outer) == 1 and model_nonempty and members == outer:
                return OutputArtifact(model_id, query_id, scope, "EXACT_VALUE", next(iter(outer)), supports)
            if outer is not None:
                return OutputArtifact(model_id, query_id, scope, "CERTIFIED_OUTER", frozenset(outer), supports)
        if kind == "IMAGE":
            if outer is not None and model_nonempty and members == outer:
                return OutputArtifact(model_id, query_id, scope, "EXACT_FINITE_IMAGE", frozenset(outer), supports)
            if outer is not None:
                return OutputArtifact(model_id, query_id, scope, "CERTIFIED_OUTER", frozenset(outer), supports)
        if defects:
            try:
                lo = max(a for a, _ in defects)
                hi = min(b for _, b in defects)
            except Exception:
                return OutputArtifact(model_id, query_id, scope, "INVALID_FACT_TYPE", None, supports)
            if lo > hi:
                return OutputArtifact(model_id, query_id, scope, "CONFLICT_LEAK", None, supports)
            return OutputArtifact(model_id, query_id, scope, "CERTIFIED_APPROXIMATION", (lo, hi), supports)
        return OutputArtifact(model_id, query_id, scope, "OPEN", None, supports)

class EvolutionAssembler:
    assembler_id = "evolution-assembler"
    version = "0.1.0"
    def singleton_outer(self, initial: Fraction, exact_integral: Fraction) -> FrozenSet[Fraction]:
        return frozenset({initial + exact_integral})


def measure_projection_fact(projection: MeasureValuedQueryProjection) -> QueryFact | None:
    if projection.status == "EXACT_QUERY_RELATION":
        ft=QueryFactType.EXACT_RELATION
    elif projection.status == "CERTIFIED_OUTER_QUERY_RELATION":
        ft=QueryFactType.OUTER_RELATION
    elif projection.status == "OPEN_DEFECT":
        ft=QueryFactType.OPEN_RELATION
    else:
        return None
    return QueryFact(projection.model_id,projection.query_id,projection.scope,ft,projection)
