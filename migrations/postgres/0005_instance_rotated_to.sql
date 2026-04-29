-- Twin of migrations/sqlite/0008_instance_rotated_to.sql; see that
-- file for the design rationale.  Kept in lockstep so the postgres
-- backend (gated behind the `postgres` cargo feature) sees the same
-- schema.
ALTER TABLE instances ADD COLUMN rotated_to TEXT;
