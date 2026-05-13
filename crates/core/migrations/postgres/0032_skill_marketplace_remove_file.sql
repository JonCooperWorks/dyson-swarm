ALTER TABLE skill_marketplace_sources
  DROP CONSTRAINT IF EXISTS chk_skill_marketplace_source_type;

UPDATE skill_marketplace_sources
   SET source_type = 'inline_quarantined',
       enabled = 0,
       last_error = 'file source removed; re-add as inline JSON'
 WHERE source_type = 'file';

ALTER TABLE skill_marketplace_sources
  ADD CONSTRAINT chk_skill_marketplace_source_type
  CHECK (source_type IN ('inline', 'http', 'inline_quarantined'));
