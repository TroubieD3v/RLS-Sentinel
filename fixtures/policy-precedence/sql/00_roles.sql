-- Fixture B: policy-precedence  -- SYNTHETIC DATA ONLY
CREATE ROLE pp_owner     NOLOGIN;                         -- owns every table (plain owner, not BYPASSRLS)
CREATE ROLE pp_staff     NOLOGIN;                         -- group: any staff member
CREATE ROLE pp_editors   NOLOGIN;                         -- group: may write articles of their org
CREATE ROLE pp_reader    NOLOGIN IN ROLE pp_staff;        -- acme reader
CREATE ROLE pp_editor    NOLOGIN IN ROLE pp_staff, pp_editors;  -- acme editor
CREATE ROLE pp_globex    NOLOGIN IN ROLE pp_staff;        -- globex staff (read-only)
CREATE ROLE pp_gx_editor NOLOGIN IN ROLE pp_staff, pp_editors;  -- globex editor
CREATE ROLE pp_outsider  NOLOGIN;                         -- no memberships: only PUBLIC applies
CREATE ROLE pp_bypass    NOLOGIN BYPASSRLS;               -- BYPASSRLS auditor (the attribute is NOT inherited)
