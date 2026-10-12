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

const SENSOR_MIGRATION_SQL = `
CREATE TABLE IF NOT EXISTS sensors (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name text NOT NULL,
  secret_hash text NOT NULL,
  hostname text NOT NULL DEFAULT '',
  platform text NOT NULL DEFAULT 'windows',
  sensor_version text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now(),
  last_heartbeat_at timestamptz,
  last_observation_at timestamptz,
  last_error_at timestamptz,
  last_error text,
  last_ip text NOT NULL DEFAULT '',
  heartbeat_interval_seconds integer NOT NULL DEFAULT 60,
  revoked_at timestamptz,
  is_demo boolean NOT NULL DEFAULT false,
  demo_key text,
  CONSTRAINT sensors_status_check CHECK (status IN ('active', 'revoked'))
);
CREATE UNIQUE INDEX IF NOT EXISTS sensors_demo_key_uq ON sensors (demo_key) WHERE demo_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS sensors_owner_idx ON sensors (owner_user_id, created_at DESC);
CREATE TABLE IF NOT EXISTS network_snapshots (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  sensor_id uuid NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
  client_observation_id text NOT NULL,
  observed_at timestamptz NOT NULL,
  connection_state text NOT NULL DEFAULT 'unknown',
  ssid text,
  bssid text,
  local_ip text,
  subnet text,
  gateway text,
  dns jsonb NOT NULL DEFAULT '[]'::jsonb,
  signal jsonb NOT NULL DEFAULT '{}'::jsonb,
  collection_methods jsonb NOT NULL DEFAULT '[]'::jsonb,
  collection_errors jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (sensor_id, client_observation_id)
);
CREATE INDEX IF NOT EXISTS network_snapshots_sensor_time_idx ON network_snapshots (sensor_id, observed_at DESC);
CREATE TABLE IF NOT EXISTS network_interfaces (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  sensor_id uuid NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
  snapshot_id uuid NOT NULL REFERENCES network_snapshots(id) ON DELETE CASCADE,
  name text NOT NULL,
  alias text NOT NULL DEFAULT '',
  state text NOT NULL DEFAULT 'unknown',
  connection_type text NOT NULL DEFAULT 'unknown',
  mac text NOT NULL DEFAULT '',
  local_ips jsonb NOT NULL DEFAULT '[]'::jsonb,
  collection_method text NOT NULL DEFAULT '',
  observed_at timestamptz NOT NULL,
  UNIQUE (snapshot_id, name)
);
CREATE INDEX IF NOT EXISTS network_interfaces_sensor_idx ON network_interfaces (sensor_id, observed_at DESC);
CREATE TABLE IF NOT EXISTS device_observations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  sensor_id uuid NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
  snapshot_id uuid NOT NULL REFERENCES network_snapshots(id) ON DELETE CASCADE,
  observation_key text NOT NULL,
  ip text NOT NULL DEFAULT '',
  mac text NOT NULL DEFAULT '',
  hostname text,
  vendor text,
  device_state text NOT NULL DEFAULT 'observed',
  services jsonb NOT NULL DEFAULT '[]'::jsonb,
  collection_methods jsonb NOT NULL DEFAULT '[]'::jsonb,
  observed_at timestamptz NOT NULL,
  UNIQUE (sensor_id, snapshot_id, observation_key)
);
CREATE INDEX IF NOT EXISTS device_observations_sensor_time_idx ON device_observations (sensor_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS device_observations_identity_idx ON device_observations (sensor_id, ip, mac, observed_at DESC);
`;

async function applyMigrations(pool) {
  const apply = async (version, sql) => {
    const current = await pool.query("SELECT version FROM schema_migrations WHERE version = $1", [version]).catch(() => ({ rowCount: 0 }));
    if (current.rowCount) return;
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(sql);
      await client.query("INSERT INTO schema_migrations(version) VALUES($1) ON CONFLICT DO NOTHING", [version]);
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  };
  await apply(1, MIGRATION_SQL);
  await apply(2, SENSOR_MIGRATION_SQL);
}

module.exports = { applyMigrations, MIGRATION_SQL, SENSOR_MIGRATION_SQL };
