"""AST-based analysis of policy / view expressions.

Input is the *deparsed* expression text produced by PostgreSQL itself (``pg_get_expr``), which is
parsed with the real PostgreSQL parser (libpg_query via pglast). No regular expressions are used to
decide semantics. Unparseable input yields ``parse_error`` and unknown (``None``) judgements, never
a guess.
"""

from __future__ import annotations

from typing import Any

from pglast import ast, parse_sql
from pglast.enums import A_Expr_Kind, BoolExprType, NullTestType, SQLValueFunctionOp
from pglast.visitors import Visitor
from pydantic import BaseModel, Field

IDENTITY_FUNCS = {"current_setting", "auth.uid", "auth.jwt", "auth.role", "auth.email", "current_user", "session_user", "current_role", "user"}


class ExprInfo(BaseModel):
    parse_error: str | None = None
    const_value: bool | None = None  # True / False when the whole expression folds to a boolean constant
    columns: list[str] = Field(default_factory=list)
    qualified_columns: list[str] = Field(default_factory=list)
    functions: list[str] = Field(default_factory=list)
    guc_keys: list[str] = Field(default_factory=list)
    identity_sources: list[str] = Field(default_factory=list)
    has_sublink: bool = False
    sublink_tables: list[str] = Field(default_factory=list)
    null_identity_test: bool = False  # expression contains "<identity function> IS NULL" (missing identity may open access)
    negative_filter: bool = False  # top-level NOT / <> predicate(s) only: typically a restriction, not a grant

    @property
    def is_const_true(self) -> bool:
        return self.const_value is True

    @property
    def is_const_false(self) -> bool:
        return self.const_value is False


def _const(node: Any) -> Any:
    """Constant-fold a tiny subset of expressions. Returns a python value or the sentinel _UNKNOWN."""
    if isinstance(node, ast.A_Const):
        if node.isnull:
            return None
        v = node.val
        if isinstance(v, ast.Boolean):
            return v.boolval
        if isinstance(v, ast.Integer):
            return v.ival
        if isinstance(v, ast.String):
            return v.sval
        if isinstance(v, ast.Float):
            return float(v.fval)
        return _UNKNOWN
    if isinstance(node, ast.TypeCast):
        return _const(node.arg)
    if isinstance(node, ast.BoolExpr):
        vals = [_const(a) for a in node.args]
        if node.boolop == BoolExprType.AND_EXPR:
            if any(v is False for v in vals):
                return False
            if all(v is True for v in vals):
                return True
            return _UNKNOWN
        if node.boolop == BoolExprType.OR_EXPR:
            if any(v is True for v in vals):
                return True
            if all(v is False for v in vals):
                return False
            return _UNKNOWN
        if node.boolop == BoolExprType.NOT_EXPR:
            v = vals[0]
            return (not v) if isinstance(v, bool) else _UNKNOWN
    if isinstance(node, ast.A_Expr) and node.kind == A_Expr_Kind.AEXPR_OP and len(node.name) == 1:
        op = node.name[0].sval
        left, right = _const(node.lexpr), _const(node.rexpr)
        if left is _UNKNOWN or right is _UNKNOWN or left is None or right is None:
            return _UNKNOWN
        try:
            return {"=": left == right, "<>": left != right, "!=": left != right,
                    "<": left < right, ">": left > right, "<=": left <= right, ">=": left >= right}.get(op, _UNKNOWN)
        except TypeError:
            return _UNKNOWN
    return _UNKNOWN


class _Unknown:
    def __repr__(self) -> str:
        return "<unknown>"


_UNKNOWN = _Unknown()


class _Collector(Visitor):
    def __init__(self) -> None:
        super().__init__()
        self.columns: set[str] = set()
        self.qualified: set[str] = set()
        self.functions: set[str] = set()
        self.gucs: set[str] = set()
        self.identity: set[str] = set()
        self.sublink = False
        self.sub_tables: set[str] = set()
        self.null_identity = False

    def visit_ColumnRef(self, ancestors: Any, node: Any) -> None:
        names = [getattr(f, "sval", None) for f in node.fields]
        names = [n for n in names if n]
        if names:
            self.columns.add(names[-1])
            if len(names) >= 2:
                self.qualified.add(".".join(names))

    def visit_FuncCall(self, ancestors: Any, node: Any) -> None:
        name = ".".join(s.sval for s in node.funcname)
        self.functions.add(name)
        if name in IDENTITY_FUNCS or name.endswith(".current_setting"):
            self.identity.add(name)
        if name.split(".")[-1] == "current_setting" and node.args:
            first = node.args[0]
            if isinstance(first, ast.TypeCast):
                first = first.arg
            v = _const(first)
            if isinstance(v, str):
                self.gucs.add(v)

    def visit_SQLValueFunction(self, ancestors: Any, node: Any) -> None:
        try:
            name = SQLValueFunctionOp(node.op).name.replace("SVFOP_", "").lower()
        except ValueError:
            name = str(node.op)
        self.identity.add(name)

    def visit_SubLink(self, ancestors: Any, node: Any) -> None:
        self.sublink = True

    def visit_NullTest(self, ancestors: Any, node: Any) -> None:
        arg = node.arg
        if isinstance(arg, ast.TypeCast):
            arg = arg.arg
        if (isinstance(arg, ast.FuncCall) and node.nulltesttype == NullTestType.IS_NULL
                and ".".join(s.sval for s in arg.funcname) in IDENTITY_FUNCS):
            self.null_identity = True

    def visit_RangeVar(self, ancestors: Any, node: Any) -> None:
        self.sub_tables.add(f"{node.schemaname}.{node.relname}" if node.schemaname else node.relname)


def analyze_expression(expr: str | None) -> ExprInfo:
    if expr is None or not expr.strip():
        return ExprInfo()
    try:
        tree = parse_sql("SELECT " + expr)
    except Exception as exc:  # pglast.Error
        return ExprInfo(parse_error=str(exc)[:200])
    stmt = tree[0].stmt
    target = stmt.targetList[0].val
    c = _Collector()
    c(tree)
    folded = _const(target)
    const_value = folded if isinstance(folded, bool) else None

    def _negative(n: Any) -> bool:
        if isinstance(n, ast.BoolExpr):
            if n.boolop == BoolExprType.NOT_EXPR:
                return True
            if n.boolop == BoolExprType.AND_EXPR:
                return all(_negative(a) for a in n.args)
            return False
        if isinstance(n, ast.A_Expr) and n.kind == A_Expr_Kind.AEXPR_OP and len(n.name) == 1:
            return n.name[0].sval in ("<>", "!=")
        return False

    return ExprInfo(
        negative_filter=_negative(target),
        null_identity_test=c.null_identity,
        const_value=const_value,
        columns=sorted(c.columns),
        qualified_columns=sorted(c.qualified),
        functions=sorted(c.functions),
        guc_keys=sorted(c.gucs),
        identity_sources=sorted(c.identity),
        has_sublink=c.sublink,
        sublink_tables=sorted(c.sub_tables),
    )
