"""Safe handling of schema-qualified identifiers.

User-provided names are parsed into parts and always composed through ``psycopg.sql.Identifier``;
they are never concatenated into SQL text.
"""

from __future__ import annotations

from psycopg import sql

from .errors import SpecError


def parse_qualified(name: str, *, default_schema: str = "public") -> tuple[str, str]:
    """Parse ``schema.table`` / ``"Sch"."Tbl"`` / ``table`` into (schema, table)."""
    parts: list[str] = []
    buf: list[str] = []
    i, n = 0, len(name)
    in_q = False
    while i < n:
        ch = name[i]
        if in_q:
            if ch == '"':
                if i + 1 < n and name[i + 1] == '"':
                    buf.append('"')
                    i += 1
                else:
                    in_q = False
            else:
                buf.append(ch)
        elif ch == '"':
            in_q = True
        elif ch == ".":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    if in_q:
        raise SpecError(f"Unterminated quoted identifier in '{name}'.")
    parts.append("".join(buf))
    if any(not p for p in parts) or len(parts) > 2:
        raise SpecError(f"Invalid relation name '{name}'. Use 'schema.table'.")
    if len(parts) == 1:
        return default_schema, parts[0]
    return parts[0], parts[1]


def qualify(schema: str, name: str) -> str:
    return f"{schema}.{name}"


def ident(qualified: str) -> sql.Identifier:
    schema, name = parse_qualified(qualified)
    return sql.Identifier(schema, name)


def col(name: str) -> sql.Identifier:
    return sql.Identifier(name)
