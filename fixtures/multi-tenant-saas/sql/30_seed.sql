-- Deterministic SYNTHETIC seed data (no real people, companies or credentials).
INSERT INTO organizations (id, slug, name) VALUES
    ('11111111-1111-1111-1111-111111111111', 'alpha', 'Alpha Synthetic Co'),
    ('22222222-2222-2222-2222-222222222222', 'beta',  'Beta Synthetic Co');

INSERT INTO memberships (id, org_id, user_name, role) VALUES
    ('0a000000-0000-0000-0000-000000000001', '11111111-1111-1111-1111-111111111111', 'app_alice',   'admin'),
    ('0a000000-0000-0000-0000-000000000002', '11111111-1111-1111-1111-111111111111', 'app_charlie', 'member'),
    ('0b000000-0000-0000-0000-000000000001', '22222222-2222-2222-2222-222222222222', 'app_bob',     'admin');

INSERT INTO projects (id, org_id, name, is_public) VALUES
    ('a0000000-0000-0000-0000-0000000000a1', '11111111-1111-1111-1111-111111111111', 'Alpha private roadmap', false),
    ('b0000000-0000-0000-0000-0000000000b1', '22222222-2222-2222-2222-222222222222', 'Beta public showcase',  true);

INSERT INTO invoices (id, org_id, number, amount_cents, status, internal_note) VALUES
    ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', '11111111-1111-1111-1111-111111111111', 'A-0001', 120000, 'open', 'synthetic: fraud review pending'),
    ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaab', '11111111-1111-1111-1111-111111111111', 'A-0002',  45000, 'paid', NULL),
    ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', '22222222-2222-2222-2222-222222222222', 'B-0001',  98000, 'open', 'synthetic: vip customer');

INSERT INTO comments (id, org_id, project_id, author, body) VALUES
    ('ca000000-0000-0000-0000-000000000001', '11111111-1111-1111-1111-111111111111', 'a0000000-0000-0000-0000-0000000000a1', 'app_alice', 'synthetic alpha comment'),
    ('cb000000-0000-0000-0000-000000000001', '22222222-2222-2222-2222-222222222222', 'b0000000-0000-0000-0000-0000000000b1', 'app_bob',   'synthetic beta comment');

INSERT INTO documents (id, org_id, title, classification, body) VALUES
    ('da000000-0000-0000-0000-000000000001', '11111111-1111-1111-1111-111111111111', 'Alpha contract', 'confidential', 'synthetic body alpha'),
    ('db000000-0000-0000-0000-000000000001', '22222222-2222-2222-2222-222222222222', 'Beta contract',  'confidential', 'synthetic body beta');
