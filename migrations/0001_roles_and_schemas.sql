-- 0001 — roles and schemas
--
-- Lane D owns this file. See CLOUD_V1.md §6.1 and agents/D-worker-auth.md.
--
-- These are the SAME migrations that run against Pigsty. There is no second
-- schema for local development (CLOUD_V1.md §4, M1). In Pigsty the roles are
-- normally created by the cluster provisioner; creating them here idempotently
-- means one file works on a bare cluster and on a provisioned one.
--
-- Role separation is load-bearing, not hygiene:
--   * the API role must NOT own the tables, because a table owner bypasses RLS
--     unless FORCE ROW LEVEL SECURITY is also set. We set FORCE as well — belt
--     and braces — but the ownership split is the primary defence.
--   * the API role must NOT have BYPASSRLS. 0006 asserts this and the battery
--     re-checks it, because it is the single attribute that silently voids
--     every policy in this schema.

BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'computedriven_migrations') THEN
    CREATE ROLE computedriven_migrations NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'computedriven_api') THEN
    CREATE ROLE computedriven_api NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'computedriven_jobs') THEN
    CREATE ROLE computedriven_jobs NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'computedriven_readonly') THEN
    CREATE ROLE computedriven_readonly NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
  -- Owns the three resolvers in 0005 and nothing else. See the note below.
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'computedriven_bootstrap') THEN
    CREATE ROLE computedriven_bootstrap NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END
$$;

-- Lets the migration runner hand ownership of the resolvers to the bootstrap
-- role in 0005 without needing superuser.
GRANT computedriven_bootstrap TO computedriven_migrations;

-- WHY A FOURTH ROLE EXISTS
--
-- Found by the battery, not by design: with FORCE ROW LEVEL SECURITY on, the
-- table OWNER is policed too -- and the SECURITY DEFINER resolvers in 0005 must
-- read cd.organizations BEFORE any tenant context exists, because deriving that
-- context is precisely their job. Running them as the owner made every login
-- path raise CD-TENANT-MISSING.
--
-- The fix is not to drop FORCE. It is to give the bootstrap path its own role
-- with its own NAMED, NARROW policies (0007). The rule that falls out is worth
-- stating on its own:
--
--     FORCE RLS stays on everywhere, and every exemption is a named policy.
--
-- Nothing bypasses invisibly. `SELECT * FROM pg_policies` is the complete list
-- of who can see across a tenant boundary, and it is short.

-- Defence in depth: even if a future migration forgets, these are never valid.
ALTER ROLE computedriven_api      NOSUPERUSER NOBYPASSRLS;
ALTER ROLE computedriven_jobs     NOSUPERUSER NOBYPASSRLS;
ALTER ROLE computedriven_readonly NOSUPERUSER NOBYPASSRLS;

-- app: the tenant-context contract and the three resolvers that are allowed to
--      run WITHOUT tenant context (see 0002).
-- cd:  ComputeDriven product truth. Every table here is either tenant-scoped
--      under RLS or unreachable by the API role.
CREATE SCHEMA IF NOT EXISTS app AUTHORIZATION computedriven_migrations;
CREATE SCHEMA IF NOT EXISTS cd  AUTHORIZATION computedriven_migrations;

COMMENT ON SCHEMA app IS
  'Tenant-context contract. app.current_organization_id() raises rather than '
  'returning NULL — see CLOUD_V1.md 6.1.';
COMMENT ON SCHEMA cd IS
  'ComputeDriven product truth (R7). Pigsty owns this; studbook holds none of it (R15).';

GRANT USAGE ON SCHEMA app, cd TO computedriven_api, computedriven_jobs, computedriven_readonly;

COMMIT;
