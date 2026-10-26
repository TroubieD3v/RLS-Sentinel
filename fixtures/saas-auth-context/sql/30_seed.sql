INSERT INTO profiles (id, display_name, email) VALUES
    ('aaaa1111-0000-0000-0000-000000000001', 'Alice Synthetic', 'alice@example.invalid'),
    ('bbbb2222-0000-0000-0000-000000000002', 'Bob Synthetic',   'bob@example.invalid');

INSERT INTO todos (id, owner_id, title, done) VALUES
    ('70d00000-0000-0000-0000-00000000a001', 'aaaa1111-0000-0000-0000-000000000001', 'alice todo', false),
    ('70d00000-0000-0000-0000-00000000b001', 'bbbb2222-0000-0000-0000-000000000002', 'bob todo',   false);

INSERT INTO team_notes (id, org_id, author, body) VALUES
    ('7e000000-0000-0000-0000-00000000a001', '11111111-1111-1111-1111-111111111111', 'aaaa1111-0000-0000-0000-000000000001', 'alpha note'),
    ('7e000000-0000-0000-0000-00000000b001', '22222222-2222-2222-2222-222222222222', 'bbbb2222-0000-0000-0000-000000000002', 'beta note');

INSERT INTO legacy_notes (id, org_id, body) VALUES
    ('1e900000-0000-0000-0000-00000000a001', '11111111-1111-1111-1111-111111111111', 'alpha legacy'),
    ('1e900000-0000-0000-0000-00000000b001', '22222222-2222-2222-2222-222222222222', 'beta legacy');
