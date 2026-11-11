-- Fixture data for the Node + Postgres practice target. The secret row is reachable only by
-- subverting the WHERE clause (e.g. tag=' OR '1'='1), which is what a confirmed SQLi proves.
CREATE TABLE IF NOT EXISTS notes (
    id   SERIAL PRIMARY KEY,
    tag  TEXT NOT NULL,
    body TEXT NOT NULL
);

INSERT INTO notes (tag, body) VALUES
    ('public', 'Welcome to the notes service.'),
    ('public', 'Second public note.'),
    ('todo',   'Buy milk.'),
    ('secret', 'FLAG{nodepg-practice-sqli-confirmed}');
