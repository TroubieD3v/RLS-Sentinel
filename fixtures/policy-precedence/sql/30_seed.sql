INSERT INTO staff (role_name, org) VALUES ('pp_reader', 'acme'), ('pp_editor', 'acme'), ('pp_globex', 'globex'), ('pp_gx_editor', 'globex');

INSERT INTO articles (id, org, title, visibility, archived, legal_hold, body) VALUES
    ('a1000000-0000-0000-0000-000000000001', 'acme',   'Acme public post',      'public',   false, false, 'synthetic'),
    ('a1000000-0000-0000-0000-000000000002', 'acme',   'Acme internal memo',    'internal', false, false, 'synthetic'),
    ('a1000000-0000-0000-0000-000000000003', 'globex', 'Globex internal memo',  'internal', false, false, 'synthetic'),
    ('a1000000-0000-0000-0000-000000000004', 'acme',   'Acme archived memo',    'internal', true,  false, 'synthetic'),
    ('a1000000-0000-0000-0000-000000000005', 'acme',   'Acme legal-hold memo',  'internal', false, true,  'synthetic');

INSERT INTO ledger (id, org, amount) VALUES
    ('1e000000-0000-0000-0000-000000000001', 'acme',   1000),
    ('1e000000-0000-0000-0000-000000000002', 'globex', 2000);

INSERT INTO locked (id, note) VALUES ('10000000-0000-0000-0000-000000000001', 'synthetic locked row');
