INSERT INTO passwd (user_name, pwhash, uid, gid, real_name, home_phone, extra_info, home_dir, shell) VALUES
    ('bench_admin', 'xxx', 0, 0, 'Admin', '111-222-3333', NULL, '/root',        '/bin/dash'),
    ('bench_bob',   'xxx', 1, 1, 'Bob',   '123-456-7890', NULL, '/home/bob',    '/bin/zsh'),
    ('bench_alice', 'xxx', 2, 1, 'Alice', '098-765-4321', NULL, '/home/alice',  '/bin/zsh');
