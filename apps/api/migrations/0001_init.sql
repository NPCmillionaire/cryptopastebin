-- CryptoPaste schema.
--
-- Note what is absent: no author column, no IP address, no user agent, no
-- title, no language, no content type. The server keeps only what it needs to
-- serve a blob and expire it on time. Everything descriptive lives inside the
-- ciphertext, where the operator cannot read it.

CREATE TABLE IF NOT EXISTS pastes (
  id           TEXT    PRIMARY KEY,
  -- Ciphertext, stored inline when small. Exactly one of blob / r2_key is set.
  blob         BLOB,
  r2_key       TEXT,
  size         INTEGER NOT NULL,
  -- 1 = destroy on first successful read.
  burn         INTEGER NOT NULL DEFAULT 0,
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  CHECK (burn IN (0, 1)),
  CHECK ((blob IS NULL) != (r2_key IS NULL))
);

-- Drives the scheduled purge.
CREATE INDEX IF NOT EXISTS idx_pastes_expires_at ON pastes (expires_at);

-- Request counters keyed by a truncated HMAC of the client address, never the
-- address itself. Rows are short-lived and removed by the same scheduled job.
CREATE TABLE IF NOT EXISTS rate_buckets (
  bucket_key   TEXT    PRIMARY KEY,
  count        INTEGER NOT NULL,
  window_start INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rate_buckets_window ON rate_buckets (window_start);
