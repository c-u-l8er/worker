-- 0009 — take EXECUTE away from PUBLIC. Runs LAST, on purpose.
--
-- BUG, found by outside review 2026-08-21 and reproduced before fixing. This is
-- the most serious defect the first pass shipped.
--
-- PostgreSQL grants EXECUTE on a newly created function to PUBLIC by default.
-- 0007 wrote an explicit grant matrix and never revoked the implicit one, so the
-- matrix documented an intent the database was not enforcing. Measured:
--
--     all 5 app.* functions            PUBLIC CAN EXECUTE
--     computedriven_readonly           successfully called resolve_principal()
--                                      and CREATED A PRINCIPAL
--
-- A read-only role performing an INSERT. The resolvers are SECURITY DEFINER, so
-- they run as computedriven_bootstrap regardless of who calls them -- which is
-- exactly why the caller list has to be closed rather than open. SECURITY
-- DEFINER plus default PUBLIC EXECUTE is the documented footgun, and we stepped
-- on it.
--
-- The battery missed it because groups D and F asserted TABLE privileges and
-- never once asked who could execute a FUNCTION. New checks in D12-D17 close
-- that, and they fail against the pre-0009 schema.
--
-- Ordering note: this file is last so it locks down whatever the earlier files
-- created or replaced. CREATE OR REPLACE preserves an existing ACL, so a future
-- migration that replaces a function keeps these grants -- but a future
-- migration that creates a NEW one is covered by the DEFAULT PRIVILEGES below
-- rather than by anyone remembering.
--
-- >>> RETRACTED 2026-08-22 (round 7). THE SENTENCE ABOVE IS FALSE, and it was
-- >>> false the day it was written. Measured on PostgreSQL 18.4:
-- >>>
-- >>>     ALTER DEFAULT PRIVILEGES FOR ROLE r IN SCHEMA app
-- >>>       REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
-- >>>     SELECT count(*) FROM pg_default_acl;   ->  0
-- >>>     ...then CREATE FUNCTION as r           ->  PUBLIC CAN EXECUTE IT
-- >>>
-- >>> No rule is stored, so nothing later is covered. The REVOKE-from-PUBLIC form
-- >>> has nothing to remove: PUBLIC's EXECUTE comes from the built-in default,
-- >>> represented by a NULL ACL rather than by an entry. The GRANT form DOES
-- >>> store a row, which is why the mechanism looks like it works.
-- >>>
-- >>> What actually held the line for two rounds was every later migration
-- >>> remembering to REVOKE explicitly -- 0010, 0011, 0014 and 0017 did; 0016
-- >>> did not, and battery check D12 caught it.
-- >>>
-- >>> 0018 installs the real net: a ddl_command_end event trigger, per database
-- >>> rather than per role, PROVEN by a canary in the same file. The statements
-- >>> below are left in place because they are harmless and because deleting
-- >>> them would erase the evidence of what was believed.
-- >>>
-- >>> This is the round-5 law from a new direction: every earlier instance was
-- >>> prose describing a restriction THE CODE did not implement. This one is
-- >>> prose describing a restriction THE DATABASE does not implement, which
-- >>> reading could not have revealed. Only running it does.

BEGIN;

SET LOCAL ROLE computedriven_migrations;

-- 1. Close the door on everything that exists.
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA app FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA cd  FROM PUBLIC;

-- 2. Close it on everything created later by either owning role.
ALTER DEFAULT PRIVILEGES FOR ROLE computedriven_migrations IN SCHEMA app
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE computedriven_migrations IN SCHEMA cd
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE computedriven_bootstrap IN SCHEMA app
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- 3. Re-open it to exactly the intended callers, and no one else.
--
--    role       context fns   resolvers
--    api            yes          yes      the request path needs both
--    jobs           yes          NO       background work is already tenanted
--    readonly       yes          NO       it must not be able to create anything
--    bootstrap       -            -       it OWNS them; ownership is not a grant
GRANT EXECUTE ON FUNCTION
  app.current_organization_id(),
  app.set_organization_context(uuid)
TO computedriven_api, computedriven_jobs, computedriven_readonly;

GRANT EXECUTE ON FUNCTION
  app.resolve_principal(text, text, text),
  app.resolve_organization(text, text, text),
  app.authorize_membership(uuid, uuid)
TO computedriven_api;

-- 4. Assert it, so a later migration that reopens PUBLIC fails here rather than
--    in production.
DO $$
DECLARE
  leaked text;
BEGIN
  SELECT string_agg(n.nspname || '.' || p.proname, ', ') INTO leaked
  FROM pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname IN ('app', 'cd')
    AND has_function_privilege('public', p.oid, 'EXECUTE');
  IF leaked IS NOT NULL THEN
    RAISE EXCEPTION 'CD-ACL-PUBLIC: PUBLIC still holds EXECUTE on %', leaked;
  END IF;
END
$$;

DO $$
DECLARE
  bad text;
BEGIN
  -- A role that can neither log in nor bypass RLS is still a role that must not
  -- be able to mint principals.
  SELECT string_agg(r.rolname, ', ') INTO bad
  FROM pg_roles r, pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'app'
    AND p.proname IN ('resolve_principal', 'resolve_organization', 'authorize_membership')
    AND r.rolname IN ('computedriven_jobs', 'computedriven_readonly')
    AND has_function_privilege(r.rolname, p.oid, 'EXECUTE');
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'CD-ACL-WIDE: role(s) % can execute a resolver', bad;
  END IF;
END
$$;

COMMIT;
