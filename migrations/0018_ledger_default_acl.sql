-- 0018 — the PUBLIC EXECUTE safety net that 0009 described and did not have
--
-- ===========================================================================
-- CORRECTED BY 0020, 2026-08-22. READ THIS BEFORE THE REST OF THIS FILE.
--
-- The leak below is real and the measurement below is real. The EXPLANATION is
-- wrong, and it is wrong in the way this project keeps warning about: one
-- measurement generalized into a rule.
--
-- This file says the REVOKE-from-PUBLIC form of ALTER DEFAULT PRIVILEGES
-- "specifically does not do what 0009 assumed". It does. What breaks it is the
-- `IN SCHEMA` clause, which both 0009 and the experiment below happened to use.
-- Per-schema default privileges can ADD to the built-in defaults; they cannot
-- SUBTRACT the built-in global PUBLIC EXECUTE grant, because that grant is a
-- NULL ACL and there is no stored per-schema entry for a REVOKE to remove.
--
--   ALTER DEFAULT PRIVILEGES FOR ROLE r IN SCHEMA s REVOKE ...   0 rows, no effect
--   ALTER DEFAULT PRIVILEGES FOR ROLE r            REVOKE ...   1 row, {r=X/r}, works
--
-- Measured identically on 17.10 and 18.4. 0020 installs the global form, keeps
-- the event trigger below -- per-role rules do NOT cover a role created later,
-- and that is measured too -- and fixes a genuine bug in the trigger: it watches
-- CREATE PROCEDURE and issues REVOKE ... ON FUNCTION, which is a syntax error
-- against a procedure.
--
-- The retraction is left in place rather than rewritten, because "0009 was
-- carried by every later migration remembering to REVOKE" is still true and is
-- still the reason D12 exists.
-- ===========================================================================
--
-- Started as "0014 added a third function-owning role and default privileges are
-- per role". That was true, and it was not the bug. Measuring it found a larger
-- one underneath.
--
-- ---------------------------------------------------------------------------
-- WHAT 0009 CLAIMS
--
--     "a future migration that creates a NEW one is covered by the DEFAULT
--      PRIVILEGES below rather than by anyone remembering."
--
-- ---------------------------------------------------------------------------
-- WHAT IS ACTUALLY TRUE, measured on a throwaway PostgreSQL 18.4 cluster
--
--     CREATE ROLE r1;  CREATE SCHEMA app AUTHORIZATION r1;
--     ALTER DEFAULT PRIVILEGES FOR ROLE r1 IN SCHEMA app
--       REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
--
--     SELECT count(*) FROM pg_default_acl;          ->  0
--
--     SET ROLE r1; CREATE FUNCTION app.f1() ...;
--     has_function_privilege('public','app.f1()','EXECUTE')  ->  TRUE
--     pg_proc.proacl for f1                                  ->  NULL
--
-- No rule is stored and no future function is protected. The same test with the
-- GRANT form DOES store a row (`cdtest=X/r1`), so the mechanism works and the
-- REVOKE-from-PUBLIC form specifically does not do what 0009 assumed: PUBLIC's
-- EXECUTE comes from the built-in default, represented by a NULL ACL, and there
-- is no stored entry for a REVOKE to remove.
--
-- So the sentence has been reassuring for two rounds while the thing it describes
-- was carried entirely by every later migration remembering to REVOKE explicitly.
-- 0010, 0011, 0014 and 0017 remembered. 0016 did not, and D12 caught it -- which
-- is how this was found at all.
--
--     THE SAFETY NET WAS A COMMENT. THE EXPLICIT REVOKES WERE THE MECHANISM.
--
-- This is the round-5 law arriving from a new direction. Every previous instance
-- was prose describing a restriction the code did not implement. This one is
-- prose describing a restriction the DATABASE does not implement, which is worse,
-- because reading the migration carefully would not have revealed it. Only
-- running it does.
--
-- ---------------------------------------------------------------------------
-- THE FIX: AN EVENT TRIGGER, WHICH IS A MECHANISM
--
-- Revoking on everything that exists is a one-time act and it is not a net. The
-- net is a ddl_command_end trigger that revokes PUBLIC EXECUTE from every
-- function created in app or cd, whoever creates it and whenever. It is
-- per-database rather than per-role, so a fourth owning role is covered on the
-- day it appears -- which is exactly what 0009 promised and could not deliver.
--
-- And the trigger is PROVEN at the bottom of this file rather than assumed: a
-- canary function is created, checked, and dropped. A safety net installed and
-- not exercised is how this file's subject matter came to exist.

BEGIN;

-- Superuser scope: event triggers require it, and this file is the only place in
-- the schema that needs it. Recorded here so an operator applying migrations
-- knows why the migration runner cannot be a plain owner role.
CREATE OR REPLACE FUNCTION app.revoke_public_execute()
RETURNS event_trigger
LANGUAGE plpgsql
AS $$
DECLARE
  obj record;
BEGIN
  FOR obj IN
    SELECT * FROM pg_event_trigger_ddl_commands()
     WHERE command_tag IN ('CREATE FUNCTION', 'CREATE PROCEDURE')
  LOOP
    IF obj.schema_name IN ('app', 'cd') THEN
      -- format(%s) on object_identity: it is already a fully qualified, quoted
      -- identity string from the catalogue, so re-quoting it would produce a
      -- name that does not exist.
      EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', obj.object_identity);
    END IF;
  END LOOP;
END;
$$;

COMMENT ON FUNCTION app.revoke_public_execute() IS
  'The PUBLIC-EXECUTE net 0009 described. ALTER DEFAULT PRIVILEGES ... REVOKE '
  'EXECUTE ON FUNCTIONS FROM PUBLIC stores no rule and protects nothing '
  '(measured, PG 18.4); this trigger does, per database rather than per role.';

-- Revoked as the OWNER, which here is the superuser applying migrations. The
-- trigger function is created before the trigger exists, so it is the one
-- function in the schema the net cannot catch -- and computedriven_migrations
-- cannot revoke on it, because it does not own it. The first draft of this file
-- tried and got "no privileges could be revoked", then failed its own leak
-- assertion on the function that installs the leak assertion.
REVOKE EXECUTE ON FUNCTION app.revoke_public_execute() FROM PUBLIC;

DROP EVENT TRIGGER IF EXISTS cd_revoke_public_execute;
CREATE EVENT TRIGGER cd_revoke_public_execute
  ON ddl_command_end
  WHEN TAG IN ('CREATE FUNCTION', 'CREATE PROCEDURE')
  EXECUTE FUNCTION app.revoke_public_execute();

-- Everything that already exists, including the one 0016 leaked.
--
-- Run as the SUPERUSER, not as computedriven_migrations. 0009 did this under the
-- migration role and it worked only because that role was a member of every
-- owner at the time. It is not a member of the superuser that owns the trigger
-- function above, and `REVOKE ... ON ALL FUNCTIONS` on a function you do not own
-- is `permission denied` once that function has an explicit ACL -- a silent
-- WARNING before, a hard error after. Doing it as the superuser is both simpler
-- and strictly more complete.
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA app FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA cd  FROM PUBLIC;

SET LOCAL ROLE computedriven_migrations;

-- The re-grants the blanket revoke took back. Listed rather than looped, because
-- "which role may call which function" is the matrix this schema is built around
-- and a loop would hide it.
GRANT EXECUTE ON FUNCTION
  app.current_organization_id(),
  app.set_organization_context(uuid),
  app.resolve_principal(text, text, text),
  app.resolve_organization(text, text, text),
  app.authorize_membership(uuid, uuid),
  app.membership_role(uuid, uuid),
  app.reserve_storage(uuid, uuid, bigint, text, interval),
  app.finalize_storage(uuid, bigint),
  app.abort_storage(uuid),
  app.offer_upload(uuid, text, bigint, text, interval),
  app.storage_divergence(uuid)
TO computedriven_api;

GRANT EXECUTE ON FUNCTION
  app.current_organization_id(),
  app.set_organization_context(uuid)
TO computedriven_jobs, computedriven_readonly;

GRANT EXECUTE ON FUNCTION
  app.expire_storage_reservations(uuid),
  app.storage_divergence(uuid),
  app.observe_storage_object(text, text, text, bigint, text, timestamptz)
TO computedriven_jobs;

-- The ledger's own functions call these; without the grant the first membership
-- check inside reserve_storage() fails.
GRANT EXECUTE ON FUNCTION
  app.current_organization_id(),
  app.authorize_membership(uuid, uuid),
  app.membership_role(uuid, uuid),
  app.max_reservation_ttl(),
  app.parse_object_key(text),
  app.assert_reservation_matches(uuid, uuid, uuid, bigint, uuid, uuid, bigint),
  app.expire_storage_reservations(uuid)
TO computedriven_ledger;

RESET ROLE;

-- ---------------------------------------------------------------------------
-- Prove the net, do not describe it.
-- ---------------------------------------------------------------------------
DO $$
DECLARE leaked text;
BEGIN
  SELECT string_agg(n.nspname || '.' || p.proname, ', ') INTO leaked
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname IN ('app', 'cd')
    AND has_function_privilege('public', p.oid, 'EXECUTE');
  IF leaked IS NOT NULL THEN
    RAISE EXCEPTION 'CD-ACL-PUBLIC: PUBLIC still holds EXECUTE on %', leaked;
  END IF;
END
$$;

DO $$
BEGIN
  -- The canary. Created by the MIGRATION role, which is the role 0009's
  -- default-privilege rule was supposed to cover and did not.
  SET LOCAL ROLE computedriven_migrations;
  EXECUTE 'CREATE FUNCTION app.acl_canary() RETURNS int LANGUAGE sql AS ''SELECT 1''';
  RESET ROLE;

  IF has_function_privilege('public', 'app.acl_canary()', 'EXECUTE') THEN
    RAISE EXCEPTION
      'CD-ACL-NET-DEAD: a newly created function is PUBLIC-executable; the event '
      'trigger is not doing what this migration claims';
  END IF;

  EXECUTE 'DROP FUNCTION app.acl_canary()';
END
$$;

COMMIT;
