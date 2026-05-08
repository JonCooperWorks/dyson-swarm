-- Remove file-backed skill marketplace sources without reading host paths.
-- SQLite cannot alter CHECK constraints in place, so rebuild the table while
-- quarantining any legacy file rows.

CREATE TABLE IF NOT EXISTS skill_marketplace_sources_new (
  id                   TEXT    PRIMARY KEY,
  source_type          TEXT    NOT NULL CHECK (source_type IN ('inline', 'http', 'inline_quarantined')),
  location             TEXT    NOT NULL,
  enabled              INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  created_at           INTEGER NOT NULL,
  updated_at           INTEGER NOT NULL,
  deleted_at           INTEGER,
  last_fetch_at        INTEGER,
  last_success_at      INTEGER,
  last_error           TEXT
);

INSERT INTO skill_marketplace_sources_new
  (id, source_type, location, enabled, created_at, updated_at, deleted_at, last_fetch_at, last_success_at, last_error)
SELECT id,
       CASE source_type WHEN 'file' THEN 'inline_quarantined' ELSE source_type END,
       location,
       CASE source_type WHEN 'file' THEN 0 ELSE enabled END,
       created_at,
       updated_at,
       deleted_at,
       last_fetch_at,
       last_success_at,
       CASE source_type
         WHEN 'file' THEN 'file source removed; re-add as inline JSON'
         ELSE last_error
       END
  FROM skill_marketplace_sources;

DROP TABLE skill_marketplace_sources;
ALTER TABLE skill_marketplace_sources_new RENAME TO skill_marketplace_sources;

CREATE INDEX IF NOT EXISTS idx_skill_marketplace_sources_visible
  ON skill_marketplace_sources(deleted_at, enabled, id);
