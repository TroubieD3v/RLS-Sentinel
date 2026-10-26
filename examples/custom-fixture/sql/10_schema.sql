SET ROLE ex_owner;
CREATE TABLE notes (
    id    int PRIMARY KEY,
    owner text NOT NULL,
    body  text NOT NULL
);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON notes TO ex_alice, ex_bob;
RESET ROLE;
