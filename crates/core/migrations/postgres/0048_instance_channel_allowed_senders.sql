ALTER TABLE instance_channels
  ADD COLUMN allowed_senders TEXT NOT NULL DEFAULT '[]';
