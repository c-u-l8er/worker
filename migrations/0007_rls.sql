-- 0007 — row-level security, and the privilege split it rests on
--
-- Layering, per CLOUD_V1.md. RLS is the LAST line, never the only one:
--
--     1. verified OIDC identity
--     2. verified organization membership     app.authorize_membership()
--     3. application authorization            the Worker
--     4. resource ownership / grant
--     5. RLS                                  <- this file, defence in depth
--
-- Two things here are easy to get wrong and both are fatal in the quiet way:
--
--   FORCE ROW LEVEL SECURITY -- without it, the TABLE OWNER bypasses every
--   policy below. ENABLE alone is not enough. The battery asserts FORCE is on
--   for every tenant table, because "we enabled RLS" is exactly the sentence
--   people say right before a cross-tenant read.
--
--   NOBYPASSRLS on the API role -- the single role attribute that silently
--   voids this entire file. Asserted at the bottom, and re-checked by the
--   battery from a different angle.

BEGIN;

SET LOCAL ROLE computedriven_migrations;

-- ---------------------------------------------------------------------------
-- Tenant tables: RLS on, FORCEd, one policy each.
-- ---------------------------------------------------------------------------

ALTER TABLE cd.organizations           ENABLE ROW LEVEL SECURITY;
ALTER TABLE cd.organizations           FORCE  ROW LEVEL SECURITY;
ALTER TABLE cd.organization_principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE cd.organization_principals FORCE  ROW LEVEL SECURITY;
ALTER TABLE cd.worlds                  ENABLE ROW LEVEL SECURITY;
ALTER TABLE cd.worlds                  FORCE  ROW LEVEL SECURITY;
ALTER TABLE cd.world_versions          ENABLE ROW LEVEL SECURITY;
ALTER TABLE cd.world_versions          FORCE  ROW LEVEL SECURITY;
ALTER TABLE cd.wrl_heads               ENABLE ROW LEVEL SECURITY;
ALTER TABLE cd.wrl_heads               FORCE  ROW LEVEL SECURITY;
ALTER TABLE cd.audit_events            ENABLE ROW LEVEL SECURITY;
ALTER TABLE cd.audit_events            FORCE  ROW LEVEL SECURITY;

-- Policies are scoped TO explicit roles rather than left at PUBLIC. A role with
-- no policy on a FORCEd table gets nothing, so the default for anything added
-- later is deny -- which is the direction a mistake should fail in.
--
-- Two policies per tenant table, generated in a loop so "every table has exactly
-- these" is structurally true rather than a copy-paste hope:
--
--   <t>_tenant  the request path. api/jobs/readonly, filtered by context.
--   <t>_owner   the migration runner. Named and visible, precisely because
--               FORCE RLS would otherwise make schema-time data work impossible.
--
-- On cd.organizations the comparison column is `id`, not `organization_id`.
DO $$
DECLARE
  t text; col text;
  tables text[][] := ARRAY[
    ['organizations',           'id'],
    ['organization_principals', 'organization_id'],
    ['worlds',                  'organization_id'],
    ['world_versions',          'organization_id'],
    ['wrl_heads',               'organization_id'],
    ['audit_events',            'organization_id']
  ];
  i int;
BEGIN
  FOR i IN 1 .. array_length(tables, 1) LOOP
    t   := tables[i][1];
    col := tables[i][2];

    EXECUTE format(
      'CREATE POLICY %I ON cd.%I FOR ALL '
      'TO computedriven_api, computedriven_jobs, computedriven_readonly '
      'USING (%I = app.current_organization_id()) '
      'WITH CHECK (%I = app.current_organization_id())',
      t || '_tenant', t, col, col);

    EXECUTE format(
      'CREATE POLICY %I ON cd.%I FOR ALL TO computedriven_migrations '
      'USING (true) WITH CHECK (true)',
      t || '_owner', t);
  END LOOP;
END
$$;

-- The bootstrap exemptions. These are the ONLY cross-tenant reads in the schema,
-- and they exist because the code that DERIVES tenant context cannot require it:
--
--     verified token -> principal -> organization -> context -> queries
--                       ^^^^^^^^^^^^^^^^^^^^^^^^^ no context yet
--
-- Both are SELECT-only, and the role that holds them owns nothing else and can
-- log in nowhere. It cannot write a single row anywhere in cd.
CREATE POLICY organizations_bootstrap ON cd.organizations
  FOR SELECT TO computedriven_bootstrap
  USING (status = 'active');

CREATE POLICY organization_principals_bootstrap ON cd.organization_principals
  FOR SELECT TO computedriven_bootstrap
  USING (true);

-- ---------------------------------------------------------------------------
-- Privilege split.
--
-- cd.principals, cd.principal_identities and cd.organization_identities get NO
-- grant to the API role at all. They are reachable only through the SECURITY
-- DEFINER resolvers in 0005. This is stronger than a policy: there is no
-- statement the API role can write that touches them directly.
--
-- It is also why they carry no RLS -- a principal is not tenant-owned. One human
-- can belong to several organizations, so "which organization does this row
-- belong to" has no answer for cd.principals, and inventing one would be worse
-- than the privilege split.
-- ---------------------------------------------------------------------------

GRANT SELECT, INSERT, UPDATE, DELETE ON
  cd.organizations,
  cd.organization_principals,
  cd.worlds,
  cd.world_versions,
  cd.wrl_heads,
  cd.audit_events
TO computedriven_api;

GRANT SELECT ON
  cd.organizations,
  cd.organization_principals,
  cd.worlds,
  cd.world_versions,
  cd.wrl_heads,
  cd.audit_events
TO computedriven_readonly;

GRANT SELECT, INSERT, UPDATE ON
  cd.organizations,
  cd.organization_principals,
  cd.worlds,
  cd.world_versions,
  cd.wrl_heads,
  cd.audit_events
TO computedriven_jobs;

GRANT EXECUTE ON FUNCTION
  app.current_organization_id(),
  app.set_organization_context(uuid),
  app.resolve_principal(text, text, text),
  app.resolve_organization(text, text, text),
  app.authorize_membership(uuid, uuid)
TO computedriven_api;

GRANT EXECUTE ON FUNCTION
  app.current_organization_id(),
  app.set_organization_context(uuid)
TO computedriven_jobs, computedriven_readonly;

-- ---------------------------------------------------------------------------
-- Assertions. A migration that can check its own premise should.
-- ---------------------------------------------------------------------------

DO $$
DECLARE
  bad text;
BEGIN
  SELECT string_agg(rolname, ', ') INTO bad
  FROM pg_roles
  WHERE rolname IN ('computedriven_api', 'computedriven_jobs',
                    'computedriven_readonly', 'computedriven_bootstrap')
    AND (rolbypassrls OR rolsuper);
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'CD-RLS-VOID: role(s) % hold BYPASSRLS or SUPERUSER', bad;
  END IF;
END
$$;

DO $$
DECLARE
  bad text;
BEGIN
  SELECT string_agg(c.relname, ', ') INTO bad
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'cd'
    AND c.relkind = 'r'
    AND c.relname IN ('organizations', 'organization_principals', 'worlds',
                      'world_versions', 'wrl_heads', 'audit_events')
    AND NOT (c.relrowsecurity AND c.relforcerowsecurity);
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'CD-RLS-WEAK: table(s) % lack ENABLE+FORCE row level security', bad;
  END IF;
END
$$;

COMMIT;
