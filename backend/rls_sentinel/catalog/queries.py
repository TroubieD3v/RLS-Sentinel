"""The complete, closed set of SQL statements the catalog inspector may execute.

Every statement is a read-only ``SELECT`` over ``pg_catalog`` (plus built-in privilege-check
functions such as ``has_table_privilege``). Identifiers are never interpolated: schema scoping is
done with bound array parameters. A unit test parses every statement with the PostgreSQL parser
and asserts that each one is a single ``SelectStmt``.
"""

from __future__ import annotations

SCHEMA_FILTER = "n.nspname = ANY(%(schemas)s::text[])"
REL_KINDS = "('r','p','v','m','f')"

Q: dict[str, str] = {}

Q["server"] = """
SELECT current_setting('server_version')              AS version,
       current_setting('server_version_num')::int     AS version_num,
       current_database()                             AS database,
       current_user                                   AS current_user,
       session_user                                   AS session_user,
       r.rolsuper                                     AS is_superuser,
       r.rolbypassrls                                 AS bypass_rls,
       r.rolcreaterole OR r.rolcreatedb               AS can_create
FROM pg_roles r WHERE r.rolname = current_user
"""

Q["databases"] = """
SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate ORDER BY datname LIMIT 200
"""

Q["schemas"] = """
SELECT n.oid::bigint AS oid, n.nspname AS name, pg_get_userbyid(n.nspowner) AS owner,
       n.nspacl IS NULL AS acl_default
FROM pg_namespace n
WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
ORDER BY n.nspname
"""

Q["relations"] = f"""
SELECT c.oid::bigint AS oid, n.nspname AS schema, c.relname AS name, c.relkind::text AS relkind,
       pg_get_userbyid(c.relowner) AS owner,
       c.relrowsecurity AS rls_enabled, c.relforcerowsecurity AS rls_forced,
       c.reltuples::bigint AS row_estimate, c.relispartition AS is_partition,
       c.relacl IS NULL AS acl_default, c.reloptions AS reloptions,
       (SELECT pn.nspname || '.' || pc.relname
          FROM pg_inherits i
          JOIN pg_class pc ON pc.oid = i.inhparent
          JOIN pg_namespace pn ON pn.oid = pc.relnamespace
         WHERE i.inhrelid = c.oid LIMIT 1) AS parent,
       EXISTS (SELECT 1 FROM pg_depend d
                WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e') AS extension_owned,
       CASE WHEN c.relkind IN ('v','m') THEN pg_get_viewdef(c.oid, true) END AS view_definition
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN {REL_KINDS} AND {SCHEMA_FILTER}
ORDER BY n.nspname, c.relname
LIMIT %(limit)s
"""

Q["columns"] = f"""
SELECT n.nspname AS schema, c.relname AS rel, a.attnum AS position, a.attname AS name,
       format_type(a.atttypid, a.atttypmod) AS type, a.attnotnull AS not_null,
       a.atthasdef AS has_default, a.attgenerated <> '' AS generated, a.attidentity <> '' AS identity
FROM pg_attribute a
JOIN pg_class c ON c.oid = a.attrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE a.attnum > 0 AND NOT a.attisdropped AND c.relkind IN {REL_KINDS} AND {SCHEMA_FILTER}
ORDER BY n.nspname, c.relname, a.attnum
LIMIT %(limit)s
"""

Q["constraints"] = f"""
SELECT n.nspname AS schema, c.relname AS rel, k.conname AS name, k.contype::text AS type,
       ARRAY(SELECT a.attname FROM unnest(k.conkey) WITH ORDINALITY u(attnum, ord)
              JOIN pg_attribute a ON a.attrelid = k.conrelid AND a.attnum = u.attnum ORDER BY u.ord) AS columns,
       fn.nspname || '.' || fc.relname AS ref_table,
       ARRAY(SELECT a.attname FROM unnest(k.confkey) WITH ORDINALITY u(attnum, ord)
              JOIN pg_attribute a ON a.attrelid = k.confrelid AND a.attnum = u.attnum ORDER BY u.ord) AS ref_columns
FROM pg_constraint k
JOIN pg_class c ON c.oid = k.conrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_class fc ON fc.oid = k.confrelid
LEFT JOIN pg_namespace fn ON fn.oid = fc.relnamespace
WHERE k.contype IN ('p','u','f') AND {SCHEMA_FILTER}
ORDER BY n.nspname, c.relname, k.conname
LIMIT %(limit)s
"""

Q["triggers"] = f"""
SELECT n.nspname AS schema, c.relname AS rel, t.tgname AS name, t.tgenabled::text AS enabled,
       fn.nspname || '.' || p.proname AS function, pg_get_triggerdef(t.oid) AS definition
FROM pg_trigger t
JOIN pg_class c ON c.oid = t.tgrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_proc p ON p.oid = t.tgfoid
JOIN pg_namespace fn ON fn.oid = p.pronamespace
WHERE NOT t.tgisinternal AND {SCHEMA_FILTER}
ORDER BY n.nspname, c.relname, t.tgname
LIMIT %(limit)s
"""

Q["view_deps"] = f"""
SELECT DISTINCT vn.nspname AS view_schema, v.relname AS view_name,
       rn.nspname AS ref_schema, rc.relname AS ref_name
FROM pg_rewrite rw
JOIN pg_class v ON v.oid = rw.ev_class
JOIN pg_namespace vn ON vn.oid = v.relnamespace
JOIN pg_depend d ON d.classid = 'pg_rewrite'::regclass AND d.objid = rw.oid AND d.refclassid = 'pg_class'::regclass
JOIN pg_class rc ON rc.oid = d.refobjid AND rc.oid <> v.oid
JOIN pg_namespace rn ON rn.oid = rc.relnamespace
WHERE v.relkind IN ('v','m') AND rc.relkind IN {REL_KINDS} AND vn.nspname = ANY(%(schemas)s::text[])
ORDER BY 1, 2, 3, 4
LIMIT %(limit)s
"""

Q["policies"] = f"""
SELECT p.oid::bigint AS oid, n.nspname AS schema, c.relname AS rel, p.polname AS name,
       p.polcmd::text AS cmd, p.polpermissive AS permissive,
       ARRAY(SELECT CASE WHEN r = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(r) END
               FROM unnest(p.polroles) AS r) AS roles,
       pg_get_expr(p.polqual, p.polrelid)      AS using_expr,
       pg_get_expr(p.polwithcheck, p.polrelid) AS check_expr
FROM pg_policy p
JOIN pg_class c ON c.oid = p.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE {SCHEMA_FILTER}
ORDER BY n.nspname, c.relname, p.polname
LIMIT %(limit)s
"""

# Cross-check count against the pg_policies view (reported in coverage notes).
Q["policies_view_count"] = """
SELECT count(*)::int AS n FROM pg_policies WHERE schemaname = ANY(%(schemas)s::text[])
"""

Q["policy_deps"] = """
SELECT p.oid::bigint AS policy_oid, 'column' AS kind, n.nspname AS schema, c.relname AS name, a.attname AS detail
FROM pg_policy p
JOIN pg_depend d ON d.classid = 'pg_policy'::regclass AND d.objid = p.oid
JOIN pg_class c ON c.oid = d.refobjid AND d.refclassid = 'pg_class'::regclass AND d.refobjsubid > 0
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = d.refobjsubid
WHERE n.nspname = ANY(%(schemas)s::text[])
UNION ALL
SELECT p.oid::bigint, 'relation', n.nspname, c.relname, NULL
FROM pg_policy p
JOIN pg_depend d ON d.classid = 'pg_policy'::regclass AND d.objid = p.oid
JOIN pg_class c ON c.oid = d.refobjid AND d.refclassid = 'pg_class'::regclass AND d.refobjsubid = 0
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = ANY(%(schemas)s::text[]) AND c.oid <> p.polrelid
UNION ALL
SELECT p.oid::bigint, 'function', fn.nspname, f.proname, pg_get_function_identity_arguments(f.oid)
FROM pg_policy p
JOIN pg_depend d ON d.classid = 'pg_policy'::regclass AND d.objid = p.oid
JOIN pg_proc f ON f.oid = d.refobjid AND d.refclassid = 'pg_proc'::regclass
JOIN pg_namespace fn ON fn.oid = f.pronamespace
ORDER BY 1, 2, 3, 4
LIMIT %(limit)s
"""

Q["roles"] = """
SELECT r.oid::bigint AS oid, r.rolname AS name, r.rolsuper AS superuser, r.rolinherit AS inherit,
       r.rolcreaterole AS createrole, r.rolcreatedb AS createdb, r.rolcanlogin AS login,
       r.rolreplication AS replication, r.rolbypassrls AS bypassrls, r.rolconnlimit AS connlimit
FROM pg_roles r ORDER BY r.rolname LIMIT %(limit)s
"""

Q["memberships_pg16"] = """
SELECT pg_get_userbyid(m.roleid) AS role, pg_get_userbyid(m.member) AS member,
       pg_get_userbyid(m.grantor) AS grantor, m.admin_option AS admin_option,
       m.inherit_option AS inherit_option, m.set_option AS set_option
FROM pg_auth_members m ORDER BY 1, 2, 3 LIMIT %(limit)s
"""

Q["memberships_pg15"] = """
SELECT pg_get_userbyid(m.roleid) AS role, pg_get_userbyid(m.member) AS member,
       pg_get_userbyid(m.grantor) AS grantor, m.admin_option AS admin_option,
       NULL::boolean AS inherit_option, NULL::boolean AS set_option
FROM pg_auth_members m ORDER BY 1, 2, 3 LIMIT %(limit)s
"""

Q["relation_grants"] = f"""
SELECT c.oid::bigint AS oid, n.nspname AS schema, c.relname AS name,
       CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END AS grantee,
       a.privilege_type AS privilege, a.is_grantable AS grantable, pg_get_userbyid(a.grantor) AS grantor
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN LATERAL aclexplode(c.relacl) a
WHERE c.relkind IN {REL_KINDS} AND {SCHEMA_FILTER}
ORDER BY 2, 3, 4, 5
LIMIT %(limit)s
"""

Q["column_grants"] = f"""
SELECT c.oid::bigint AS oid, n.nspname AS schema, c.relname AS name, at.attname AS column,
       CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END AS grantee,
       a.privilege_type AS privilege, a.is_grantable AS grantable, pg_get_userbyid(a.grantor) AS grantor
FROM pg_attribute at
JOIN pg_class c ON c.oid = at.attrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN LATERAL aclexplode(at.attacl) a
WHERE at.attacl IS NOT NULL AND NOT at.attisdropped AND at.attnum > 0 AND {SCHEMA_FILTER}
ORDER BY 2, 3, 4, 5, 6
LIMIT %(limit)s
"""

Q["schema_grants"] = """
SELECT n.oid::bigint AS oid, n.nspname AS name,
       CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END AS grantee,
       a.privilege_type AS privilege, a.is_grantable AS grantable, pg_get_userbyid(a.grantor) AS grantor
FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) a
WHERE n.nspname = ANY(%(schemas)s::text[])
ORDER BY 2, 3, 4
LIMIT %(limit)s
"""

Q["functions"] = """
SELECT p.oid::bigint AS oid, n.nspname AS schema, p.proname AS name,
       pg_get_function_identity_arguments(p.oid) AS identity_args,
       pg_get_userbyid(p.proowner) AS owner, p.prosecdef AS security_definer, p.proconfig AS config,
       l.lanname AS language, p.prokind::text AS kind, p.proleakproof AS leakproof,
       p.provolatile::text AS volatility, pg_get_function_result(p.oid) AS returns,
       p.proacl IS NULL AS acl_default,
       EXISTS (SELECT 1 FROM pg_depend d
                WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e') AS extension_owned,
       encode(sha256(convert_to(p.prosrc, 'UTF8')), 'hex') AS src_sha256,
       (p.proacl IS NULL OR EXISTS (SELECT 1 FROM aclexplode(p.proacl) a
                                     WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE')) AS public_execute
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
JOIN pg_language l ON l.oid = p.prolang
WHERE n.nspname = ANY(%(schemas)s::text[])
ORDER BY n.nspname, p.proname, 4
LIMIT %(limit)s
"""

Q["function_grants"] = """
SELECT p.oid::bigint AS oid, n.nspname AS schema, p.proname AS name,
       pg_get_function_identity_arguments(p.oid) AS identity_args,
       CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END AS grantee,
       a.privilege_type AS privilege, a.is_grantable AS grantable, pg_get_userbyid(a.grantor) AS grantor
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
CROSS JOIN LATERAL aclexplode(p.proacl) a
WHERE n.nspname = ANY(%(schemas)s::text[])
ORDER BY 2, 3, 4, 5
LIMIT %(limit)s
"""

Q["default_acls"] = """
SELECT pg_get_userbyid(d.defaclrole) AS for_role,
       COALESCE((SELECT nspname FROM pg_namespace WHERE oid = d.defaclnamespace), '*') AS schema,
       d.defaclobjtype::text AS objtype,
       CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END AS grantee,
       a.privilege_type AS privilege, a.is_grantable AS grantable
FROM pg_default_acl d CROSS JOIN LATERAL aclexplode(d.defaclacl) a
ORDER BY 1, 2, 3, 4, 5
LIMIT %(limit)s
"""

Q["extensions"] = "SELECT extname AS name, extversion AS version FROM pg_extension ORDER BY extname"

Q["effective_table_privileges"] = f"""
SELECT role, rel, privs FROM (
  SELECT r.rolname AS role, n.nspname || '.' || c.relname AS rel,
         array_remove(ARRAY[
           CASE WHEN has_table_privilege(r.oid, c.oid, 'SELECT')     THEN 'SELECT' END,
           CASE WHEN has_table_privilege(r.oid, c.oid, 'INSERT')     THEN 'INSERT' END,
           CASE WHEN has_table_privilege(r.oid, c.oid, 'UPDATE')     THEN 'UPDATE' END,
           CASE WHEN has_table_privilege(r.oid, c.oid, 'DELETE')     THEN 'DELETE' END,
           CASE WHEN has_table_privilege(r.oid, c.oid, 'TRUNCATE')   THEN 'TRUNCATE' END,
           CASE WHEN has_table_privilege(r.oid, c.oid, 'REFERENCES') THEN 'REFERENCES' END,
           CASE WHEN has_table_privilege(r.oid, c.oid, 'TRIGGER')    THEN 'TRIGGER' END
         ], NULL) AS privs
  FROM (SELECT oid, rolname FROM pg_roles WHERE rolname !~ '^pg_' ORDER BY rolname LIMIT %(role_limit)s) r
  CROSS JOIN pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE c.relkind IN {REL_KINDS} AND {SCHEMA_FILTER}
) x WHERE cardinality(privs) > 0
ORDER BY 1, 2
LIMIT %(limit)s
"""

Q["effective_function_execute"] = """
SELECT r.rolname AS role, n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')' AS fn
FROM (SELECT oid, rolname FROM pg_roles WHERE rolname !~ '^pg_' ORDER BY rolname LIMIT %(role_limit)s) r
CROSS JOIN pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = ANY(%(schemas)s::text[]) AND has_function_privilege(r.oid, p.oid, 'EXECUTE')
ORDER BY 1, 2
LIMIT %(limit)s
"""

Q["effective_schema_usage"] = """
SELECT r.rolname AS role, n.nspname AS schema
FROM (SELECT oid, rolname FROM pg_roles WHERE rolname !~ '^pg_' ORDER BY rolname LIMIT %(role_limit)s) r
CROSS JOIN pg_namespace n
WHERE n.nspname = ANY(%(schemas)s::text[]) AND has_schema_privilege(r.oid, n.oid, 'USAGE')
ORDER BY 1, 2
LIMIT %(limit)s
"""

Q["effective_column_select"] = """
SELECT r.rolname AS role, n.nspname || '.' || c.relname AS rel, a.attname AS column
FROM (SELECT oid, rolname FROM pg_roles WHERE rolname !~ '^pg_' ORDER BY rolname LIMIT %(role_limit)s) r
CROSS JOIN pg_attribute a
JOIN pg_class c ON c.oid = a.attrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE a.attacl IS NOT NULL AND NOT a.attisdropped AND a.attnum > 0
  AND n.nspname = ANY(%(schemas)s::text[]) AND has_column_privilege(r.oid, a.attrelid, a.attnum, 'SELECT')
ORDER BY 1, 2, 3
LIMIT %(limit)s
"""
