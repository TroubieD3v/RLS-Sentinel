"""Role membership semantics (PostgreSQL 15-18) and an independent effective-privilege calculator.

The calculator is deliberately separate from the database's own ``has_table_privilege`` results stored in the
snapshot: tests cross-check the two, which exposes modelling bugs in either side.
"""

from __future__ import annotations

from collections import defaultdict, deque

from ..catalog.models import Snapshot

ALL_TABLE_PRIVS = ["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"]


class RoleGraph:
    def __init__(self, snap: Snapshot):
        self.snap = snap
        self.roles = {r.name: r for r in snap.roles}
        # member -> list[(granted_role, inherit, set_option)]
        self.up: dict[str, list[tuple[str, bool, bool]]] = defaultdict(list)
        self.down: dict[str, list[tuple[str, bool, bool]]] = defaultdict(list)
        for m in snap.memberships:
            member = self.roles.get(m.member)
            inherit = m.inherit_option if m.inherit_option is not None else bool(member.inherit if member else True)
            set_opt = m.set_option if m.set_option is not None else True
            self.up[m.member].append((m.role, inherit, set_opt))
            self.down[m.role].append((m.member, inherit, set_opt))
        self.cycles: list[list[str]] = self._find_cycles()

    # -------------------------------------------------------------- closures
    def _closure(self, start: str, kind: str) -> set[str]:
        seen = {start}
        q: deque[str] = deque([start])
        while q:
            cur = q.popleft()
            for granted, inherit, set_opt in self.up.get(cur, []):
                ok = inherit if kind == "inherit" else set_opt
                if ok and granted not in seen:
                    seen.add(granted)
                    q.append(granted)
        return seen

    def inherit_closure(self, role: str) -> set[str]:
        """Roles whose privileges ``role`` automatically uses (including itself)."""
        return self._closure(role, "inherit")

    def set_closure(self, role: str) -> set[str]:
        """Roles ``role`` may SET ROLE to (including itself)."""
        return self._closure(role, "set")

    def inheritors(self, group: str) -> set[str]:
        """All roles that automatically use ``group``'s privileges (including the group itself)."""
        seen = {group}
        q: deque[str] = deque([group])
        while q:
            cur = q.popleft()
            for member, inherit, _ in self.down.get(cur, []):
                if inherit and member not in seen:
                    seen.add(member)
                    q.append(member)
        return seen

    def _find_cycles(self) -> list[list[str]]:
        cycles: list[list[str]] = []
        state: dict[str, int] = {}

        def dfs(n: str, path: list[str]) -> None:
            state[n] = 1
            for g, _, _ in self.up.get(n, []):
                if state.get(g) == 1:
                    cycles.append([*path, n, g])
                elif state.get(g) is None:
                    dfs(g, [*path, n])
            state[n] = 2

        for r in list(self.up):
            if state.get(r) is None:
                dfs(r, [])
        return cycles

    # --------------------------------------------------------------- classification
    def is_system(self, role: str) -> bool:
        r = self.roles.get(role)
        return bool(r and r.system)

    def applicable_roles(self, policy_roles: list[str]) -> set[str]:
        """Concrete (non-system, non-superuser) roles a policy applies to, resolving PUBLIC and inheritance."""
        out: set[str] = set()
        if "PUBLIC" in policy_roles:
            out |= {n for n, r in self.roles.items() if not r.system}
        else:
            for pr in policy_roles:
                if pr in self.roles:
                    out |= self.inheritors(pr)
        return {r for r in out if r in self.roles and not self.roles[r].system}

    # ----------------------------------------------------------- privileges
    def effective_table_privileges(self, role: str, table: str) -> set[str]:
        r = self.roles.get(role)
        t = self.snap.table(table)
        if r is None or t is None:
            return set()
        if r.superuser:
            return set(ALL_TABLE_PRIVS)
        closure = self.inherit_closure(role)
        if t.owner in closure:
            return set(ALL_TABLE_PRIVS)
        privs: set[str] = set()
        for g in self.snap.grants:
            if g.object_type == "table" and g.object == table and (g.grantee == "PUBLIC" or g.grantee in closure):
                privs.add(g.privilege)
        return privs

    def owner_effective(self, role: str, table: str) -> bool:
        t = self.snap.table(table)
        return bool(t and t.owner in self.inherit_closure(role))

    def bypasses_rls(self, role: str, table: str) -> str | None:
        """Why ``role`` ignores RLS on ``table`` (SUPERUSER | BYPASSRLS | TABLE_OWNER) or None."""
        r = self.roles.get(role)
        t = self.snap.table(table)
        if r is None or t is None:
            return None
        if r.superuser:
            return "SUPERUSER"
        if r.bypassrls:
            return "BYPASSRLS"
        if t.rls_enabled and not t.rls_forced and self.owner_effective(role, table):
            return "TABLE_OWNER"
        return None
