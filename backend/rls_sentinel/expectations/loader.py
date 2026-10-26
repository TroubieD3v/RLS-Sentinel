"""Safe loading and validation of expectation specs (YAML or JSON)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from ..errors import SpecError
from ..identifiers import parse_qualified
from .models import Spec

MAX_BYTES = 256 * 1024
MAX_DEPTH = 16
MAX_NODES = 20_000


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate keys."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[Any] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=True)
            if key in seen:
                raise yaml.constructor.ConstructorError(
                    None, None, f"duplicate key {key!r}", key_node.start_mark)
            seen.add(key)
        return super().construct_mapping(node, deep)


def _check_structure(obj: Any) -> None:
    nodes = 0
    stack: list[tuple[Any, int]] = [(obj, 0)]
    while stack:
        cur, depth = stack.pop()
        nodes += 1
        if depth > MAX_DEPTH:
            raise SpecError(f"Spec nesting is deeper than {MAX_DEPTH} levels.")
        if nodes > MAX_NODES:
            raise SpecError(f"Spec has more than {MAX_NODES} nodes.")
        if isinstance(cur, dict):
            stack.extend((v, depth + 1) for v in cur.values())
        elif isinstance(cur, list):
            stack.extend((v, depth + 1) for v in cur)


def parse_document(text: str | bytes, *, filename: str = "") -> Any:
    raw = text.encode() if isinstance(text, str) else text
    if len(raw) > MAX_BYTES:
        raise SpecError(f"Spec is larger than {MAX_BYTES // 1024} KiB.")
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SpecError("Spec must be UTF-8 encoded.") from exc
    is_json = filename.lower().endswith(".json") or decoded.lstrip().startswith("{")
    try:
        if is_json:
            data = json.loads(decoded)
        else:
            # Aliases/anchors are rejected outright (expansion bombs; shared mutable structure).
            for ev in yaml.parse(decoded, Loader=_UniqueKeySafeLoader):
                if isinstance(ev, yaml.AliasEvent):
                    raise SpecError("YAML aliases are not allowed in specs.")
            data = yaml.load(decoded, Loader=_UniqueKeySafeLoader)  # noqa: S506 - SafeLoader subclass
    except SpecError:
        raise
    except (yaml.YAMLError, json.JSONDecodeError) as exc:
        raise SpecError(f"Could not parse spec: {str(exc).splitlines()[0][:200]}") from exc
    if not isinstance(data, dict):
        raise SpecError("Spec must be a mapping at the top level.")
    _check_structure(data)
    return data


def _issues_from_validation(exc: ValidationError) -> list[dict]:
    out = []
    for e in exc.errors():
        loc = ".".join(str(p) for p in e["loc"])
        out.append({"path": loc, "message": e["msg"].removeprefix("Value error, "), "type": e["type"], "level": "error"})
    return out


def load_spec_text(text: str | bytes, *, filename: str = "") -> Spec:
    data = parse_document(text, filename=filename)
    try:
        spec = Spec.model_validate(data)
    except ValidationError as exc:
        issues = _issues_from_validation(exc)
        raise SpecError(f"Spec is invalid ({len(issues)} issue(s)).", issues=issues) from exc
    issues = [i for i in check_internal_references(spec) if i["level"] == "error"]
    if issues:
        raise SpecError(f"Spec has {len(issues)} reference error(s).", issues=issues)
    return spec


def load_spec(path: str | Path) -> Spec:
    p = Path(path)
    return load_spec_text(p.read_bytes(), filename=p.name)


def spec_checksum(spec: Spec) -> str:
    blob = json.dumps(spec.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def check_internal_references(spec: Spec) -> list[dict]:
    """Validate referential integrity inside the spec (no database needed)."""
    issues: list[dict] = []

    def err(path: str, msg: str, level: str = "error") -> None:
        issues.append({"path": path, "message": msg, "level": level})

    def dup(items: list[str], what: str, root: str) -> None:
        seen: set[str] = set()
        for i, v in enumerate(items):
            if v in seen:
                err(f"{root}.{i}", f"Duplicate {what} id '{v}'.")
            seen.add(v)

    dup([a.id for a in spec.actors], "actor", "actors")
    dup([r.id for r in spec.resources], "resource", "resources")
    dup([e.id for e in spec.expectations], "expectation", "expectations")
    dup([t.id for t in spec.tenants], "tenant", "tenants")

    tenant_ids = {t.id for t in spec.tenants}
    declared_tenants = bool(tenant_ids)
    actors = {a.id: a for a in spec.actors}
    resources = {r.id: r for r in spec.resources}

    def check_tenant(path: str, tid: str | None) -> None:
        if tid and declared_tenants and tid not in tenant_ids:
            err(path, f"Unknown tenant '{tid}'. Declared tenants: {sorted(tenant_ids)}.")

    for i, a in enumerate(spec.actors):
        check_tenant(f"actors.{i}.tenant", a.tenant)
        if spec.identity_mode == "postgres_roles" and a.claims:
            err(f"actors.{i}.claims", "Claims are only valid with identity_mode: supabase_synthetic.")
    for i, r in enumerate(spec.resources):
        check_tenant(f"resources.{i}.tenant", r.tenant)
        try:
            parse_qualified(r.table)
        except Exception as exc:
            err(f"resources.{i}.table", str(exc))
    table_cfg = {t.table for t in spec.tables}
    for i, t in enumerate(spec.tables):
        try:
            parse_qualified(t.table)
        except Exception as exc:
            err(f"tables.{i}.table", str(exc))
    for i, e in enumerate(spec.expectations):
        base = f"expectations.{i}"
        if e.actor not in actors:
            err(f"{base}.actor", f"Unknown actor '{e.actor}'.")
        res = resources.get(e.resource) if e.resource else None
        if e.resource and res is None:
            err(f"{base}.resource", f"Unknown resource '{e.resource}'.")
        check_tenant(f"{base}.as_tenant", e.as_tenant)
        check_tenant(f"{base}.set_tenant", e.set_tenant)
        table = e.table or (res.table if res else None)
        if e.table and res and e.table != res.table:
            err(f"{base}.table", f"'table' ({e.table}) conflicts with resource table ({res.table}).")
        if table:
            tcfg = spec.table_config(table)
            if (e.as_tenant or e.set_tenant) and not (tcfg and tcfg.tenant_column):
                err(f"{base}", f"as_tenant/set_tenant need tables[].tenant_column configured for {table}.")
            if e.operation in ("UPDATE", "UPSERT") and not (e.set or e.set_tenant or (tcfg and tcfg.touch_column)):
                err(f"{base}", f"{e.operation} needs 'set', 'set_tenant' or tables[].touch_column for {table}.")
        if e.claims_override is not None and spec.identity_mode != "supabase_synthetic":
            err(f"{base}.claims_override", "claims_override requires identity_mode: supabase_synthetic.")
        if e.operation == "INSERT":
            for k, v in e.row.items():
                _check_token(v, spec, f"{base}.row.{k}", err)
        for j, v in enumerate(e.args):
            _check_token(v, spec, f"{base}.args.{j}", err)
    for i, p in enumerate(spec.privileges):
        try:
            parse_qualified(p.table)
        except Exception as exc:
            err(f"privileges.{i}.table", str(exc))
        both = set(p.allow) & set(p.deny)
        if both:
            err(f"privileges.{i}", f"Privilege(s) {sorted(both)} are both allowed and denied.")
    if table_cfg and len(table_cfg) != len(spec.tables):
        err("tables", "Duplicate table configuration entries.")
    if not spec.expectations and not spec.privileges:
        err("expectations", "No expectations declared; static analysis will run but nothing is verified.", "warning")
    return issues


def _check_token(v: Any, spec: Spec, path: str, err) -> None:
    if not isinstance(v, str) or not v.startswith("$"):
        return
    if v == "$uuid" or v == "$actor_tenant":
        return
    if v.startswith("$tenant:"):
        tid = v.split(":", 1)[1]
        if spec.tenants and tid not in {t.id for t in spec.tenants}:
            err(path, f"Unknown tenant in token '{v}'.")
        return
    if v.startswith("$pk:"):
        ref = v.split(":", 1)[1]
        rid, _, c = ref.partition(".")
        r = spec.resource(rid)
        if r is None or c not in r.pk:
            err(path, f"Token '{v}' does not reference a declared resource primary-key column.")
        return
    err(path, f"Unknown value token '{v}'. Supported: $uuid, $actor_tenant, $tenant:<id>, $pk:<resource>.<col>.")
