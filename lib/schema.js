const MIGRATION_SQL = `
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS schema_migrations (version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL DEFAULT '', email text UNIQUE NOT NULL,
  password_hash text NOT NULL, role text NOT NULL DEFAULT 'user', approved boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login timestamptz;
ALTER TABLE users ADD COLUMN IF NOT EXISTS department text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS justification text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS approved boolean NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS name text NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_demo boolean NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS demo_key text;
CREATE UNIQUE INDEX IF NOT EXISTS users_demo_key_uq ON users (demo_key) WHERE demo_key IS NOT NULL;
CREATE TABLE IF NOT EXISTS soc_records (
  id text PRIMARY KEY, kind text NOT NULL, payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  owner_user_id uuid REFERENCES users(id) ON DELETE SET NULL, created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(), is_demo boolean NOT NULL DEFAULT false, demo_key text
);
CREATE UNIQUE INDEX IF NOT EXISTS soc_records_demo_key_uq ON soc_records (kind, demo_key) WHERE demo_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS soc_records_kind_created_idx ON soc_records (kind, created_at DESC);
CREATE TABLE IF NOT EXISTS sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  refresh_token_hash text, status text NOT NULL DEFAULT 'active', started_at timestamptz NOT NULL DEFAULT now(),
  last_activity timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL, revoked_at timestamptz,
  ip text NOT NULL DEFAULT '', user_agent text NOT NULL DEFAULT '', device text NOT NULL DEFAULT '',
  location text NOT NULL DEFAULT '', current boolean NOT NULL DEFAULT false, is_demo boolean NOT NULL DEFAULT false, demo_key text
);
CREATE UNIQUE INDEX IF NOT EXISTS sessions_demo_key_uq ON sessions (demo_key) WHERE demo_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS sessions_user_status_idx ON sessions (user_id, status);
CREATE TABLE IF NOT EXISTS notifications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title text NOT NULL, body text NOT NULL, severity text NOT NULL DEFAULT 'info', category text NOT NULL DEFAULT 'system',
  read boolean NOT NULL DEFAULT false, link text, event_key text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  is_demo boolean NOT NULL DEFAULT false, demo_key text, UNIQUE (user_id, event_key)
);
CREATE UNIQUE INDEX IF NOT EXISTS notifications_demo_key_uq ON notifications (demo_key) WHERE demo_key IS NOT NULL;
CREATE TABLE IF NOT EXISTS audit_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  actor_email text NOT NULL DEFAULT '', action text NOT NULL, resource text NOT NULL DEFAULT '', ip text NOT NULL DEFAULT '',
  previous_value jsonb, new_value jsonb, result text NOT NULL DEFAULT 'success', created_at timestamptz NOT NULL DEFAULT now(),
  is_demo boolean NOT NULL DEFAULT false, demo_key text
);
CREATE UNIQUE INDEX IF NOT EXISTS audit_logs_demo_key_uq ON audit_logs (demo_key) WHERE demo_key IS NOT NULL;
CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE, expires_at timestamptz NOT NULL, used_at timestamptz, created_at timestamptz NOT NULL DEFAULT now()
);
`;

async function applyMigrations(pool) {
  const current = await pool.query("SELECT version FROM schema_migrations WHERE version = 1").catch(() => ({ rowCount: 0 }));
  if (current.rowCount) return;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(MIGRATION_SQL);
    await client.query("INSERT INTO schema_migrations(version) VALUES (1) ON CONFLICT DO NOTHING");
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

module.exports = { applyMigrations, MIGRATION_SQL };
