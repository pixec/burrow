# Migrations

The store's schema, as numbered migrations applied in order and recorded in
`_sqlx_migrations`. They are embedded into the binaries at build time.

- One directory per backend. `sqlite/` serves nodes and single-process
  orchestrators; `postgres/` serves orchestrators with `--database-url`.
- A schema change is one new file in each directory, with the same number and
  name, e.g. `0002_add_usage_intervals.sql`. A test fails if the two disagree.
- Never edit a migration that has shipped. The migrator checksums applied
  files and refuses to start on a changed one; write a new migration instead.
- No `IF NOT EXISTS`. A migration states what it changes and fails loudly if
  the database is not what it expects.
- Integers are `INTEGER` in SQLite and `BIGINT` in Postgres; blobs are `BLOB`
  and `BYTEA`. Every query in `src/lib.rs` is written once for both, so a
  column's meaning must match across the two.
