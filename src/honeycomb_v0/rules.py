from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Mapping, Tuple

from .canonical import content_id


ALLOWED_OBSERVABLE_PRIMITIVES = frozenset({"MEAN_STATE", "VECTOR_INTEGRAL"})
ALLOWED_STATE_VALUE_PRIMITIVES = frozenset({"SCALAR", "FINITE_VECTOR"})
ALLOWED_BOUNDARY_PRIMITIVES = frozenset({"EXACT_ZERO_NEUMANN", "SINGLE_WEAK_CONORMAL_PORT"})
ALLOWED_DERIVATIVE_PRIMITIVES = frozenset({"SCALAR_MEAN_DERIVATIVE", "VECTOR_INTEGRAL_DERIVATIVE"})
ALLOWED_TERM_PRIMITIVES = frozenset({"SCALAR_DIFFUSION", "SCALAR_SOURCE", "SCALAR_WEAK_PORT", "VECTOR_DIFFUSION", "VECTOR_REACTION", "VECTOR_SOURCE"})
ALLOWED_SUPPORT_KINDS = frozenset({"THEOREM", "STRUCTURAL", "LEFT_NULLSPACE"})
ALLOWED_ACTIONS = frozenset({"ANNIHILATE", "RETAIN", "DEFECT"})
ALLOWED_READER_ID_MODES = frozenset({"LITERAL", "DATA_REF"})


@dataclass(frozen=True)
class DeclarativeAdapterRule:
    rule_id: str
    version: str
    raw: Mapping[str, Any]

    @property
    def content_id(self) -> str:
        return content_id({"type": "DeclarativeAdapterRule", "rule": self.raw})


@dataclass(frozen=True)
class DeclarativeAdapterRuleRegistry:
    rule_set_id: str
    version: str
    rules: Tuple[DeclarativeAdapterRule, ...]

    @classmethod
    def from_path(cls, path: str | Path) -> "DeclarativeAdapterRuleRegistry":
        obj = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(obj, dict):
            raise ValueError("adapter rule registry must be an object")
        allowed_top = {"rule_set_id", "version", "rules"}
        if set(obj) != allowed_top:
            raise ValueError("adapter rule registry fields are not canonical")
        rows = obj.get("rules")
        if not isinstance(rows, list) or not rows:
            raise ValueError("adapter rule registry requires nonempty rules")
        out=[]
        ids=set()
        for row in rows:
            cls._validate_rule(row)
            rid=row["id"]
            if rid in ids:
                raise ValueError(f"duplicate adapter rule id: {rid}")
            ids.add(rid)
            out.append(DeclarativeAdapterRule(str(rid), str(row["version"]), row))
        return cls(str(obj["rule_set_id"]), str(obj["version"]), tuple(out))

    @classmethod
    def from_object(cls, obj: Mapping[str, Any]) -> "DeclarativeAdapterRuleRegistry":
        # Round-trip through canonical JSON-like validation without accepting executable objects.
        tmp = json.loads(json.dumps(obj))
        rows=tmp.get("rules") if isinstance(tmp,dict) else None
        if not isinstance(tmp,dict) or set(tmp)!={"rule_set_id","version","rules"} or not isinstance(rows,list) or not rows:
            raise ValueError("invalid adapter rule registry object")
        out=[]; ids=set()
        for row in rows:
            cls._validate_rule(row)
            if row["id"] in ids: raise ValueError("duplicate adapter rule id")
            ids.add(row["id"]); out.append(DeclarativeAdapterRule(str(row["id"]),str(row["version"]),row))
        return cls(str(tmp["rule_set_id"]),str(tmp["version"]),tuple(out))

    @staticmethod
    def _validate_fixture_ref(v: Any) -> None:
        if not isinstance(v, dict) or set(v)!={"id","content_id","theorem_kind"}:
            raise ValueError("fixture reference must contain id/content_id/theorem_kind only")
        if not all(isinstance(v[k],str) and v[k] for k in ("id","content_id","theorem_kind")):
            raise ValueError("fixture reference fields must be nonempty strings")

    @classmethod
    def _validate_rule(cls, row: Any) -> None:
        if not isinstance(row, dict): raise ValueError("adapter rule must be object")
        req={"id","version","query","profile","storage","reader_admissibility_fixture","time_pairing_fixture","derivative","terms"}
        if set(row)!=req: raise ValueError(f"adapter rule fields mismatch: {sorted(set(row)^req)}")
        if not isinstance(row["id"],str) or not row["id"] or not isinstance(row["version"],str) or not row["version"]:
            raise ValueError("adapter rule id/version invalid")
        q=row["query"]
        if not isinstance(q,dict): raise ValueError("query rule invalid")
        base_q={"kind","reader_kind","reader_id_mode","observable_primitive"}
        if not base_q.issubset(q): raise ValueError("query rule missing fields")
        if q["reader_id_mode"] not in ALLOWED_READER_ID_MODES: raise ValueError("unknown reader id mode")
        if q["observable_primitive"] not in ALLOWED_OBSERVABLE_PRIMITIVES: raise ValueError("unknown observable primitive")
        if q["reader_id_mode"]=="LITERAL":
            if set(q)!=base_q|{"reader_id"}: raise ValueError("literal reader query fields invalid")
        else:
            if set(q)!=base_q|{"reader_data_role"}: raise ValueError("data-ref reader query fields invalid")
        # v0 declarative semantics are finite primitives, not free-form templates.
        if q["kind"]!="LAW": raise ValueError("v0 declarative rules only certify LAW queries")
        observable_bundle={
            "MEAN_STATE": {"reader_kind":"CONSTANT_TEST","reader_id_mode":"LITERAL","reader_id":"one"},
            "VECTOR_INTEGRAL": {"reader_kind":"CONSTANT_VECTOR_TEST","reader_id_mode":"DATA_REF","reader_data_role":"READER"},
        }[q["observable_primitive"]]
        for k,v in observable_bundle.items():
            if q.get(k)!=v: raise ValueError("observable/reader primitive bundle mismatch")
        p=row["profile"]
        pkeys={"domain_class","solution_sense","state_value_primitive","test_space_template","field_spatial_space_template","field_time_space","field_derivative_space","regularity","time_derivative_order","boundary_primitive"}
        if not isinstance(p,dict) or set(p)!=pkeys: raise ValueError("profile rule fields invalid")
        if p["state_value_primitive"] not in ALLOWED_STATE_VALUE_PRIMITIVES: raise ValueError("unknown state value primitive")
        if p["boundary_primitive"] not in ALLOWED_BOUNDARY_PRIMITIVES: raise ValueError("unknown boundary primitive")
        if not isinstance(p["time_derivative_order"],int) or isinstance(p["time_derivative_order"],bool): raise ValueError("invalid time derivative order")
        frozen_profiles={
            "MEAN_STATE": {
                "domain_class":"bounded_lipschitz","solution_sense":"WEAK","state_value_primitive":"SCALAR",
                "test_space_template":"H1({domain})","field_spatial_space_template":"H1({domain})",
                "field_time_space":"L2(0,T;H1)","field_derivative_space":"L2(0,T;H1*)",
                "regularity":"L2(H1) & H1(H1*)","time_derivative_order":1},
            "VECTOR_INTEGRAL": {
                "domain_class":"bounded_lipschitz","solution_sense":"WEAK","state_value_primitive":"FINITE_VECTOR",
                "test_space_template":"H1({domain};{value_type})","field_spatial_space_template":"H1({domain};{value_type})",
                "field_time_space":"L2(0,T;H1)","field_derivative_space":"L2(0,T;H1*)",
                "regularity":"L2(H1) & H1(H1*)","time_derivative_order":1},
        }
        base_profile={k:v for k,v in p.items() if k!="boundary_primitive"}
        if base_profile!=frozen_profiles[q["observable_primitive"]]: raise ValueError("profile primitive bundle mismatch")
        allowed_boundary={
            "MEAN_STATE": {"EXACT_ZERO_NEUMANN","SINGLE_WEAK_CONORMAL_PORT"},
            "VECTOR_INTEGRAL": {"EXACT_ZERO_NEUMANN"},
        }[q["observable_primitive"]]
        if p["boundary_primitive"] not in allowed_boundary: raise ValueError("boundary primitive is not allowed for observable")
        s=row["storage"]
        if not isinstance(s,dict) or set(s)!={"template"} or s["template"]!="<{state}_t,{test}>": raise ValueError("storage template is not a frozen primitive")
        cls._validate_fixture_ref(row["reader_admissibility_fixture"])
        cls._validate_fixture_ref(row["time_pairing_fixture"])
        d=row["derivative"]
        if not isinstance(d,dict) or set(d)!={"primitive","template"}: raise ValueError("derivative rule invalid")
        if d["primitive"] not in ALLOWED_DERIVATIVE_PRIMITIVES: raise ValueError("unknown derivative primitive")
        derivative_bundle={
            "MEAN_STATE": ("SCALAR_MEAN_DERIVATIVE","measure({domain})*d_dt(mean({state}))"),
            "VECTOR_INTEGRAL": ("VECTOR_INTEGRAL_DERIVATIVE","d_dt(int({reader}^T {state}))"),
        }[q["observable_primitive"]]
        if (d["primitive"],d["template"])!=derivative_bundle: raise ValueError("derivative primitive/template mismatch")
        expected_reader_kind={"MEAN_STATE":"CONSTANT_SCALAR_H1_ADMISSIBILITY","VECTOR_INTEGRAL":"CONSTANT_VECTOR_H1_ADMISSIBILITY"}[q["observable_primitive"]]
        if row["reader_admissibility_fixture"]["theorem_kind"]!=expected_reader_kind: raise ValueError("reader theorem-kind mismatch")
        if row["time_pairing_fixture"]["theorem_kind"]!="WEAK_TIME_DERIVATIVE_PAIRING": raise ValueError("time-pairing theorem-kind mismatch")
        terms=row["terms"]
        if not isinstance(terms,list) or not terms: raise ValueError("terms rule invalid")
        roles=[]
        primitive_action={
            "SCALAR_DIFFUSION":"ANNIHILATE",
            "SCALAR_SOURCE":"RETAIN",
            "SCALAR_WEAK_PORT":"RETAIN",
            "VECTOR_DIFFUSION":"ANNIHILATE",
            "VECTOR_REACTION":"ANNIHILATE",
            "VECTOR_SOURCE":"RETAIN",
        }
        primitive_support={
            "SCALAR_DIFFUSION":"THEOREM",
            "SCALAR_SOURCE":"STRUCTURAL",
            "SCALAR_WEAK_PORT":"THEOREM",
            "VECTOR_DIFFUSION":"THEOREM",
            "VECTOR_REACTION":"LEFT_NULLSPACE",
            "VECTOR_SOURCE":"STRUCTURAL",
        }
        primitive_role={
            "SCALAR_DIFFUSION":"INTERNAL",
            "SCALAR_SOURCE":"SOURCE",
            "SCALAR_WEAK_PORT":"PORT",
            "VECTOR_DIFFUSION":"INTERNAL",
            "VECTOR_REACTION":"REACTION",
            "VECTOR_SOURCE":"SOURCE",
        }
        for t in terms:
            if not isinstance(t,dict) or set(t)!={"role","primitive","action","count","support"}: raise ValueError("term rule fields invalid")
            if t["primitive"] not in ALLOWED_TERM_PRIMITIVES: raise ValueError("unknown term primitive")
            if t["role"]!=primitive_role[t["primitive"]]: raise ValueError("primitive/role mismatch")
            if t["action"] not in ALLOWED_ACTIONS or t["action"]!=primitive_action[t["primitive"]]: raise ValueError("primitive/action mismatch")
            if not isinstance(t["count"],int) or isinstance(t["count"],bool) or t["count"]!=1: raise ValueError("v0 term count must be exactly one")
            sup=t["support"]
            if not isinstance(sup,dict) or sup.get("kind") not in ALLOWED_SUPPORT_KINDS: raise ValueError("term support invalid")
            if sup["kind"]!=primitive_support[t["primitive"]]: raise ValueError("primitive/support mismatch")
            if sup["kind"]=="THEOREM":
                if set(sup)!={"kind","fixture"}: raise ValueError("theorem support fields invalid")
                cls._validate_fixture_ref(sup["fixture"])
                expected_tk={
                    "SCALAR_DIFFUSION":"CONSTANT_SCALAR_GRADIENT_ZERO",
                    "SCALAR_WEAK_PORT":"CONSTANT_SCALAR_TRACE_ONE",
                    "VECTOR_DIFFUSION":"CONSTANT_VECTOR_GRADIENT_ZERO",
                }.get(t["primitive"])
                if sup["fixture"]["theorem_kind"]!=expected_tk: raise ValueError("term theorem-kind mismatch")
            elif sup["kind"]=="LEFT_NULLSPACE":
                if set(sup)!={"kind","matrix_data_role"} or sup["matrix_data_role"]!="STOICHIOMETRY": raise ValueError("left-nullspace support fields invalid")
            else:
                if set(sup)!={"kind"}: raise ValueError("structural support fields invalid")
            roles.append(t["role"])
        if len(set(roles))!=len(roles): raise ValueError("v0 declarative rules require unique term roles")
        primitive_set={t["primitive"] for t in terms}
        expected_terms={
            ("MEAN_STATE","EXACT_ZERO_NEUMANN"): {"SCALAR_DIFFUSION","SCALAR_SOURCE"},
            ("MEAN_STATE","SINGLE_WEAK_CONORMAL_PORT"): {"SCALAR_DIFFUSION","SCALAR_SOURCE","SCALAR_WEAK_PORT"},
            ("VECTOR_INTEGRAL","EXACT_ZERO_NEUMANN"): {"VECTOR_DIFFUSION","VECTOR_REACTION","VECTOR_SOURCE"},
        }.get((q["observable_primitive"],p["boundary_primitive"]))
        if primitive_set!=expected_terms: raise ValueError("term primitive bundle mismatch")

    def rule(self, rule_id: str) -> DeclarativeAdapterRule:
        hits=[r for r in self.rules if r.rule_id==rule_id]
        if len(hits)!=1: raise KeyError(rule_id)
        return hits[0]

    @property
    def content_id(self) -> str:
        return content_id({"type":"DeclarativeAdapterRuleRegistry","rule_set_id":self.rule_set_id,"version":self.version,"rules":tuple(r.raw for r in self.rules)})
