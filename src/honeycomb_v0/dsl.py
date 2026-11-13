from __future__ import annotations
from dataclasses import dataclass
from fractions import Fraction
import json
from typing import Any, Mapping, Tuple

from .canonical import content_id
from .types import Scope, ScopeLevel
from .pde import *


FORBIDDEN_PROOF_KEYS = frozenset({
    "exact", "proved", "verified", "unique", "continuumCertified",
    "pass", "proofStatus", "truth", "certified", "proof_credit"
})


class DSLError(ValueError):
    def __init__(self, code: str, path: str, message: str):
        super().__init__(f"{code} at {path}: {message}")
        self.code = code
        self.path = path
        self.message = message


@dataclass(frozen=True)
class BundleLawQuerySpec:
    name: str
    bundle_name: str
    bundle_id: str
    kind: str
    observable_primitive: str
    field: str
    reader_kind: str
    reader_id: str
    scope: Scope

    @property
    def query_id(self) -> str:
        return content_id({"type": "BundleLawQuerySpec", "query": self})


@dataclass(frozen=True)
class UserQuerySpec:
    name: str
    model_name: str
    model_id: str
    kind: str
    observable: str
    reader_kind: str
    reader_id: str
    scope: Scope

    @property
    def query_id(self) -> str:
        return content_id({"type": "UserQuerySpec", "query": self})


def _load(obj: str | Mapping[str, Any]) -> Mapping[str, Any]:
    if isinstance(obj, str):
        try:
            value = json.loads(obj)
        except Exception as e:
            raise DSLError("SYNTAX_ERROR", "$", str(e)) from e
    elif isinstance(obj, Mapping):
        value = obj
    else:
        raise DSLError("TYPE_MISMATCH", "$", "DSL root must be a JSON object or JSON string")
    if not isinstance(value, Mapping):
        raise DSLError("TYPE_MISMATCH", "$", "DSL root must be an object")
    return value


def _scan_forbidden(value: Any, path: str = "$", *, forbidden=FORBIDDEN_PROOF_KEYS):
    if isinstance(value, Mapping):
        for k, v in value.items():
            if k in forbidden:
                raise DSLError("ILLEGAL_PROOF_FIELD", f"{path}.{k}", "proof/truth credit cannot be declared in user DSL")
            _scan_forbidden(v, f"{path}.{k}", forbidden=forbidden)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            _scan_forbidden(v, f"{path}[{i}]", forbidden=forbidden)


def _keys(d: Mapping[str, Any], allowed: set[str], required: set[str], path: str):
    unknown = set(d) - allowed
    missing = required - set(d)
    if unknown:
        raise DSLError("UNKNOWN_FIELD", path, f"unknown fields: {sorted(unknown)}")
    if missing:
        raise DSLError("MISSING_FIELD", path, f"missing fields: {sorted(missing)}")


def _text(v: Any, path: str) -> str:
    if not isinstance(v, str) or not v:
        raise DSLError("TYPE_MISMATCH", path, "expected nonempty string")
    return v

def _int_strict(v: Any, path: str) -> int:
    if not isinstance(v, int) or isinstance(v, bool):
        raise DSLError("TYPE_MISMATCH", path, "expected integer")
    return v

def _time_endpoint(v: Any, path: str):
    if isinstance(v, int) and not isinstance(v, bool):
        return v
    if isinstance(v, str) and v:
        return v
    raise DSLError("NUMERIC_SEMANTIC_INVALID", path, "time endpoint must be exact integer or symbolic string in v0")

def _as_tuple_str(v: Any, path: str) -> Tuple[str, ...]:
    if not isinstance(v, list) or any(not isinstance(x, str) or not x for x in v):
        raise DSLError("TYPE_MISMATCH", path, "expected list of nonempty strings")
    return tuple(v)


def _fraction(v: Any, path: str) -> Fraction:
    if isinstance(v, int) and not isinstance(v, bool):
        return Fraction(v)
    if isinstance(v, list) and len(v) == 2 and all(isinstance(x, int) and not isinstance(x, bool) for x in v):
        if v[1] == 0:
            raise DSLError("NUMERIC_SEMANTIC_INVALID", path, "rational denominator cannot be zero")
        return Fraction(v[0], v[1])
    raise DSLError("NUMERIC_SEMANTIC_INVALID", path, "exact rational must be integer or [numerator, denominator]")


def _data_value(spec: Mapping[str, Any], path: str):
    semantic = spec["semantic"].upper()
    if semantic == "EXACT_RATIONAL":
        if "rational" not in spec:
            raise DSLError("MISSING_FIELD", path, "EXACT_RATIONAL requires rational")
        return _fraction(spec["rational"], path + ".rational")
    if semantic == "EXACT_VECTOR":
        raw = spec.get("vector")
        if not isinstance(raw, list) or not raw:
            raise DSLError("NUMERIC_SEMANTIC_INVALID", path + ".vector", "EXACT_VECTOR requires a nonempty exact rational list")
        return tuple(_fraction(x, f"{path}.vector[{i}]") for i, x in enumerate(raw))
    if semantic == "EXACT_MATRIX":
        raw = spec.get("matrix")
        if not isinstance(raw, list) or not raw or any(not isinstance(r, list) for r in raw):
            raise DSLError("NUMERIC_SEMANTIC_INVALID", path + ".matrix", "EXACT_MATRIX requires nonempty row lists")
        widths = {len(r) for r in raw}
        if len(widths) != 1:
            raise DSLError("NUMERIC_SEMANTIC_INVALID", path + ".matrix", "matrix must not be ragged")
        return tuple(tuple(_fraction(x, f"{path}.matrix[{i}][{j}]") for j, x in enumerate(r)) for i, r in enumerate(raw))
    if semantic == "UNCERTAIN_INTERVAL":
        raw = spec.get("interval")
        if not isinstance(raw, list) or len(raw) != 2:
            raise DSLError("NUMERIC_SEMANTIC_INVALID", path + ".interval", "interval must have two exact rational endpoints")
        lo, hi = _fraction(raw[0], path + ".interval[0]"), _fraction(raw[1], path + ".interval[1]")
        if lo > hi:
            raise DSLError("NUMERIC_SEMANTIC_INVALID", path + ".interval", "interval lower endpoint exceeds upper")
        return (lo, hi)
    if semantic == "SYMBOLIC":
        val = spec.get("value")
        if not isinstance(val, str) or not val:
            raise DSLError("NUMERIC_SEMANTIC_INVALID", path + ".value", "SYMBOLIC requires a nonempty string value")
        return val
    raise DSLError("UNSUPPORTED_SEMANTIC_CONSTRUCT", path + ".semantic", f"unsupported data semantic {semantic}")


class DSLCompiler:
    version = "0.3.0"

    def compile_model(self, obj: str | Mapping[str, Any]) -> PDEProfile:
        d = _load(obj); _scan_forbidden(d)
        _keys(d, {"model","geometry","time","fields","data","operators","equations","initial","boundary","solution","ports"},
              {"model","geometry","time","fields","equations","boundary","solution"}, "$")
        if not isinstance(d["model"], str) or not d["model"]:
            raise DSLError("TYPE_MISMATCH", "$.model", "model must be a nonempty string")

        g=d["geometry"]; _keys(g,{"domain","dimension","class"},{"domain","dimension","class"},"$.geometry")
        geom=GeometrySpec(_text(g["domain"],"$.geometry.domain"), _int_strict(g["dimension"],"$.geometry.dimension"), _text(g["class"],"$.geometry.class"))

        t=d["time"]; _keys(t,{"interval","direction"},{"interval"},"$.time")
        interval=t["interval"]
        if not isinstance(interval,list) or len(interval)!=2:
            raise DSLError("TYPE_MISMATCH","$.time.interval","interval must have two endpoints")
        time=TimeSpec(_time_endpoint(interval[0],"$.time.interval[0]"),_time_endpoint(interval[1],"$.time.interval[1]"),_text(t.get("direction","FORWARD"),"$.time.direction").upper())

        fields=[]
        if not isinstance(d["fields"], Mapping): raise DSLError("TYPE_MISMATCH","$.fields","fields must be object")
        for name,s in d["fields"].items():
            path=f"$.fields.{name}"; _keys(s,{"role","value","spatial_space","time_space","time_derivative"},{"role","value","spatial_space","time_space","time_derivative"},path)
            td=s["time_derivative"]; _keys(td,{"order","space"},{"order","space"},path+".time_derivative")
            fields.append(FieldSpec(name,str(s["role"]).upper(),str(s["value"]),str(s["spatial_space"]),str(s["time_space"]),_int_strict(td["order"],path+".time_derivative.order"),str(td["space"])))

        data=[]
        raw_data=d.get("data",{})
        if not isinstance(raw_data,Mapping): raise DSLError("TYPE_MISMATCH","$.data","data must be object")
        for name,s in raw_data.items():
            path=f"$.data.{name}"; _keys(s,{"role","semantic","rational","vector","matrix","interval","value"},{"role","semantic"},path)
            data.append(DataSpec(name,str(s["role"]).upper(),str(s["semantic"]).upper(),_data_value(s,path)))

        operators=[]
        raw_ops=d.get("operators",{})
        if not isinstance(raw_ops,Mapping): raise DSLError("TYPE_MISMATCH","$.operators","operators must be object")
        for name,s in raw_ops.items():
            path=f"$.operators.{name}"; _keys(s,{"domain","codomain","kind"},{"domain","codomain","kind"},path)
            operators.append(OperatorSpec(name,str(s["domain"]),str(s["codomain"]),str(s["kind"])))

        ports=[]
        raw_ports=d.get("ports",[])
        if not isinstance(raw_ports,list): raise DSLError("TYPE_MISMATCH","$.ports","ports must be list")
        for i,s in enumerate(raw_ports):
            path=f"$.ports[{i}]"; _keys(s,{"id","semantic_space","orientation","realization","field","boundary"},{"id","semantic_space","orientation","realization","field","boundary"},path)
            ports.append(PortSpec(str(s["id"]),str(s["semantic_space"]),str(s["orientation"]).upper(),str(s["realization"]),str(s["field"]),str(s["boundary"])))

        equations=[]
        if not isinstance(d["equations"],list): raise DSLError("TYPE_MISMATCH","$.equations","equations must be list")
        for i,e in enumerate(d["equations"]):
            path=f"$.equations[{i}]"; _keys(e,{"id","sense","test","storage","terms"},{"id","sense","test","storage","terms"},path)
            test=e["test"]; _keys(test,{"symbol","space"},{"symbol","space"},path+".test")
            st=e["storage"]; _keys(st,{"id","expr","symbols"},{"id","expr","symbols"},path+".storage")
            terms=[]
            if not isinstance(e["terms"],list): raise DSLError("TYPE_MISMATCH",path+".terms","terms must be list")
            for j,x in enumerate(e["terms"]):
                xp=f"{path}.terms[{j}]"; _keys(x,{"id","sign","role","expr","symbols","port_ref","boundary_ref"},{"id","sign","role","expr","symbols"},xp)
                terms.append(WeakTermSpec(_text(x["id"],xp+".id"),_int_strict(x["sign"],xp+".sign"),_text(x["role"],xp+".role").upper(),_text(x["expr"],xp+".expr"),_as_tuple_str(x["symbols"],xp+".symbols"),x.get("port_ref"),x.get("boundary_ref")))
            try: sense=PDESense(str(e["sense"]).upper())
            except Exception as ex: raise DSLError("UNSUPPORTED_SEMANTIC_CONSTRUCT",path+".sense",str(e["sense"])) from ex
            equations.append(EquationSpec(str(e["id"]),sense,str(test["symbol"]),str(test["space"]),str(st["id"]),str(st["expr"]),_as_tuple_str(st["symbols"],path+".storage.symbols"),tuple(terms)))

        initial=[]
        raw_initial=d.get("initial",[])
        if not isinstance(raw_initial,list): raise DSLError("TYPE_MISMATCH","$.initial","initial must be list")
        for i,x in enumerate(raw_initial):
            path=f"$.initial[{i}]"; _keys(x,{"field","data_ref","derivative_slot"},{"field","data_ref"},path)
            initial.append(InitialSpec(str(x["field"]),str(x["data_ref"]),_int_strict(x.get("derivative_slot",0),path+".derivative_slot")))

        boundary=[]
        if not isinstance(d["boundary"],list): raise DSLError("TYPE_MISMATCH","$.boundary","boundary must be list")
        for i,x in enumerate(d["boundary"]):
            path=f"$.boundary[{i}]"; _keys(x,{"id","field","kind","semantic","value","admissible_set","port_ref"},{"id","field","kind","semantic"},path)
            try: kind=BoundaryKind(str(x["kind"]).upper())
            except Exception as ex: raise DSLError("UNSUPPORTED_SEMANTIC_CONSTRUCT",path+".kind",str(x["kind"])) from ex
            value=x.get("value")
            if isinstance(value,Mapping) and "semantic" in value:
                # Boundary data uses the same numeric semantic parser without a role field.
                tmp={"role":"BOUNDARY",**value}
                value=_data_value(tmp,path+".value")
            boundary.append(BoundarySpec(str(x["id"]),str(x["field"]),kind,str(x["semantic"]).upper(),value,x.get("admissible_set"),x.get("port_ref")))

        sol=d["solution"]; _keys(sol,{"equation_sense","regularity","admissibility"},{"equation_sense","regularity"},"$.solution")
        try: ssense=PDESense(str(sol["equation_sense"]).upper())
        except Exception as ex: raise DSLError("UNSUPPORTED_SEMANTIC_CONSTRUCT","$.solution.equation_sense",str(sol["equation_sense"])) from ex
        if not isinstance(sol["regularity"],Mapping): raise DSLError("TYPE_MISMATCH","$.solution.regularity","regularity must be object")
        reg=tuple(sorted((str(k),str(v)) for k,v in sol["regularity"].items()))
        adm=tuple(str(x) for x in sol.get("admissibility",[]))

        return PDEProfile(str(d["model"]),geom,time,tuple(fields),tuple(data),tuple(operators),tuple(equations),tuple(initial),tuple(boundary),SolutionClassSpec(ssense,reg,adm),tuple(ports))

    def compile_query(self, obj: str | Mapping[str, Any], profile: PDEProfile) -> UserQuerySpec:
        d=_load(obj); _scan_forbidden(d)
        _keys(d,{"run","model_ref","query","scope"},{"run","model_ref","query","scope"},"$")
        if d["model_ref"] != profile.name:
            raise DSLError("MODEL_REF_MISMATCH","$.model_ref","query model_ref does not match compiled model")
        q=d["query"]; _keys(q,{"kind","observable","reader"},{"kind","observable","reader"},"$.query")
        r=q["reader"]; _keys(r,{"kind","id"},{"kind","id"},"$.query.reader")
        sc=d["scope"]; _keys(sc,{"level","tag"},{"level"},"$.scope")
        try: level=ScopeLevel(_text(sc["level"],"$.scope.level").upper())
        except Exception as ex: raise DSLError("SCOPE_INVALID","$.scope.level",str(sc["level"])) from ex
        kind=_text(q["kind"],"$.query.kind").upper()
        if kind not in {"LAW","VALUE","IMAGE","FEASIBILITY"}:
            raise DSLError("UNSUPPORTED_QUERY_KIND","$.query.kind",kind)
        reader_kind=_text(r["kind"],"$.query.reader.kind").upper()
        if reader_kind not in {"CONSTANT_TEST","CONSTANT_VECTOR_TEST","LEFT_COVECTOR"}:
            raise DSLError("UNSUPPORTED_READER_KIND","$.query.reader.kind",reader_kind)
        tag=_text(sc.get("tag","weak"),"$.scope.tag")
        if level != ScopeLevel.CONTINUUM or tag != "weak":
            raise DSLError("SCOPE_INVALID","$.scope","direct PDEProfile query must use CONTINUUM/weak in v0")
        return UserQuerySpec(_text(d["run"],"$.run"),profile.name,profile.model_id,kind,_text(q["observable"],"$.query.observable"),reader_kind,_text(r["id"],"$.query.reader.id"),Scope(level,tag))

    def compile_bundle(self, obj: str | Mapping[str, Any]) -> PDEBundle:
        d=_load(obj); _scan_forbidden(d)
        _keys(d,{"bundle","models","couplings"},{"bundle","models","couplings"},"$")
        if not isinstance(d["models"],list): raise DSLError("TYPE_MISMATCH","$.models","models must be list")
        models=tuple(self.compile_model(x) for x in d["models"])
        couplings=[]
        if not isinstance(d["couplings"],list): raise DSLError("TYPE_MISMATCH","$.couplings","couplings must be list")
        for i,c in enumerate(d["couplings"]):
            path=f"$.couplings[{i}]"; _keys(c,{"id","kind","terms","equals"},{"id","kind","terms","equals"},path)
            refs=[]
            if not isinstance(c["terms"],list): raise DSLError("TYPE_MISMATCH",path+".terms","terms must be list")
            for j,r in enumerate(c["terms"]):
                rp=f"{path}.terms[{j}]"; _keys(r,{"model_ref","port_ref","sign"},{"model_ref","port_ref","sign"},rp)
                refs.append(CouplingPortRef(str(r["model_ref"]),str(r["port_ref"]),_int_strict(r["sign"],rp+".sign")))
            eq=c["equals"]
            if isinstance(eq,Mapping):
                semantic=str(eq.get("semantic","")).upper()
                if semantic=="DEFECT_CHANNEL":
                    _keys(eq,{"semantic","id","semantic_space","projection_reader","projected_abs_bound"},{"semantic","id","semantic_space","projection_reader","projected_abs_bound"},path+".equals")
                    eq=CouplingDefectSpec(
                        _text(eq["id"],path+".equals.id"),
                        _text(eq["semantic_space"],path+".equals.semantic_space"),
                        _text(eq["projection_reader"],path+".equals.projection_reader"),
                        _fraction(eq["projected_abs_bound"],path+".equals.projected_abs_bound"),
                    )
                else:
                    tmp={"role":"COUPLING",**eq}; eq=_data_value(tmp,path+".equals")
            couplings.append(CouplingSpec(str(c["id"]),str(c["kind"]).upper(),tuple(refs),eq))
        return PDEBundle(str(d["bundle"]),models,tuple(couplings))
    def compile_bundle_query(self, obj: str | Mapping[str, Any], bundle: PDEBundle) -> BundleLawQuerySpec:
        d=_load(obj); _scan_forbidden(d)
        _keys(d,{"run","bundle_ref","query","scope"},{"run","bundle_ref","query","scope"},"$")
        if d["bundle_ref"] != bundle.name:
            raise DSLError("BUNDLE_REF_MISMATCH","$.bundle_ref","query bundle_ref does not match compiled bundle")
        q=d["query"]; _keys(q,{"kind","observable","reader"},{"kind","observable","reader"},"$.query")
        obs=q["observable"]
        if not isinstance(obs,Mapping):
            raise DSLError("TYPE_MISMATCH","$.query.observable","bundle observable must be an object")
        _keys(obs,{"primitive","field"},{"primitive","field"},"$.query.observable")
        primitive=_text(obs["primitive"],"$.query.observable.primitive").upper()
        if primitive!="SUM_LOCAL_MEAN":
            raise DSLError("UNSUPPORTED_SEMANTIC_CONSTRUCT","$.query.observable.primitive",primitive)
        field=_text(obs["field"],"$.query.observable.field")
        if any(field not in {f.name for f in m.fields} for m in bundle.models):
            raise DSLError("UNDECLARED_SYMBOL","$.query.observable.field","field is not declared in every bundle model")
        r=q["reader"]; _keys(r,{"kind","id"},{"kind","id"},"$.query.reader")
        kind=_text(q["kind"],"$.query.kind").upper()
        if kind!="LAW":
            raise DSLError("UNSUPPORTED_QUERY_KIND","$.query.kind","bundle composition v0 certifies LAW queries only")
        reader_kind=_text(r["kind"],"$.query.reader.kind").upper()
        reader_id=_text(r["id"],"$.query.reader.id")
        if (reader_kind,reader_id)!=("CONSTANT_TEST","one"):
            raise DSLError("UNSUPPORTED_READER_KIND","$.query.reader","bundle composition v0 requires CONSTANT_TEST/one")
        sc=d["scope"]; _keys(sc,{"level","tag"},{"level"},"$.scope")
        try: level=ScopeLevel(_text(sc["level"],"$.scope.level").upper())
        except Exception as ex: raise DSLError("SCOPE_INVALID","$.scope.level",str(sc["level"])) from ex
        tag=_text(sc.get("tag","weak"),"$.scope.tag")
        if level!=ScopeLevel.CONTINUUM or tag!="weak":
            raise DSLError("SCOPE_INVALID","$.scope","bundle composition v0 requires CONTINUUM/weak")
        return BundleLawQuerySpec(_text(d["run"],"$.run"),bundle.name,bundle.bundle_id,kind,primitive,field,reader_kind,reader_id,Scope(level,tag))

