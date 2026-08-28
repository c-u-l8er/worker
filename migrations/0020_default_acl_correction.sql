-- 0020 — 0018 found a real leak and blamed the wrong clause
--
-- ---------------------------------------------------------------------------
-- WHAT 0018 SAYS
--
--     "ALTER DEFAULT PRIVILEGES ... REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC
--      stores zero rows and protects nothing ... the REVOKE-from-PUBLIC form
--      specifically does not do what 0009 assumed"
--
-- That generalizes one measurement into a rule about PostgreSQL, and the rule is
-- false. The form 0009 and 0018 both tested was SCHEMA-SCOPED. The scoping is the
-- defect, not the REVOKE.
--
-- Per-schema default privileges can ADD to the built-in defaults. They cannot
-- SUBTRACT the built-in global PUBLIC EXECUTE grant, because that grant is
-- represented by a NULL ACL and there is no stored per-schema entry for a REVOKE
-- to remove. Drop `IN SCHEMA` and there is: the rule is stored against the role
-- globally and it applies.
--
-- ---------------------------------------------------------------------------
-- MEASURED, both PostgreSQL 18.4 and 17.10, throwaway clusters, identical results
--
--   A  ALTER DEFAULT PRIVILEGES FOR ROLE r IN SCHEMA s
--        REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
--      pg_default_acl rows                          0
--      has_function_privilege('public', new_fn)     TRUE      <- 0018's finding
--      pg_proc.proacl                               NULL
--
--   B  ALTER DEFAULT PRIVILEGES FOR ROLE r
--        REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;      -- no IN SCHEMA
--      pg_default_acl rows                          1
--      defaclacl                                    {r=X/r}
--      has_function_privilege('public', new_fn)     FALSE     <- it works
--      pg_proc.proacl                               {r=X/r}
--
--   C  ON ROUTINES covers FUNCTION and PROCEDURE alike; so, in fact, does
--      ON FUNCTIONS -- both land on defaclobjtype 'f'. ROUTINES is used below
--      because it is the name that says what it does.
--   D  The global rule reaches a schema it never named (created later).
--   E  It applies to SECURITY DEFINER functions and survives CREATE OR REPLACE.
--   H  A NON-SUPERUSER may install it FOR any role it is a member of.
--      computedriven_migrations is a member of _bootstrap and _ledger (0001,
--      0014), so it can install all three.
--   I  For a role it is NOT a member of: "permission denied to change default
--      privileges". The mechanism is scoped to what the migration role may
--      already impersonate, which is the right amount of authority.
--
-- ---------------------------------------------------------------------------
-- SO WHY IS THE EVENT TRIGGER STILL BELOW?
--
-- Because the two mechanisms do not cover the same set, and the difference was
-- measured rather than reasoned about:
--
--   J  owner_b has a global rule, owner_new does not, both create a function in
--      the same schema.
--        has_function_privilege('public', app.f_b)     FALSE
--        has_function_privilege('public', app.f_new)   TRUE
--
-- DEFAULT PRIVILEGES ARE PER ROLE. THE EVENT TRIGGER IS PER DATABASE. A fourth
-- routine-owning role appearing in migration 0031 is covered by the trigger on
-- the day it appears and is NOT covered by any rule written today. That is
-- exactly the promise 0009 made, 0018 kept, and dropping the trigger would give
-- back.
--
-- And a canary that creates its canary AS THE MIGRATION ROLE cannot see the
-- difference -- which is why D18 passed and would have kept passing.
--
--     THE REVIEW WAS RIGHT ABOUT THE DIAGNOSIS AND THE FIX IS NOT A SWAP.
--
-- What this file does instead:
--
--   1. Installs the global default-privilege rules that 0009 believed it had.
--      They are the cheap, un-privileged, per-role floor.
--   2. KEEPS the event trigger as the per-database net, and narrows the honest
--      claim about it: it is the only mechanism that covers a role nobody has
--      created yet.
--   3. Fixes a real defect in the trigger that the review spotted: it watched
--      CREATE PROCEDURE and then issued REVOKE ... ON FUNCTION for it.
--   4. Adds the gate that makes the per-role floor a MECHANISM rather than a
--      habit: if any role owns a routine in app or cd and has no default-privilege
--      rule, the migration FAILS. A leak becomes a failed migration instead of a
--      silent grant.
--
-- The superuser requirement stays, and it is now a stated cost of item 2 rather
-- than an accident of item 1.

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. The per-role floor. What 0009 meant.
--
-- Written FOR ROLE explicitly rather than relying on the current user, because
-- "whichever role happens to be running this migration" is not a specification.
-- ---------------------------------------------------------------------------
SET LOCAL ROLE computedriven_migrations;

ALTER DEFAULT PRIVILEGES FOR ROLE computedriven_migrations
  REVOKE EXECUTE ON ROUTINES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE computedriven_bootstrap
  REVOKE EXECUTE ON ROUTINES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE computedriven_ledger
  REVOKE EXECUTE ON ROUTINES FROM PUBLIC;

RESET ROLE;

-- ---------------------------------------------------------------------------
-- 3. The trigger, corrected.
--
-- pg_event_trigger_ddl_commands() reports CREATE PROCEDURE with command_tag
-- 'CREATE PROCEDURE', and 0018 then executed
--
--     REVOKE EXECUTE ON FUNCTION <identity> FROM PUBLIC
--
-- for it. PostgreSQL distinguishes FUNCTION, PROCEDURE and ROUTINE in REVOKE, so
-- that is a syntax error against a procedure -- inside a ddl_command_end trigger,
-- which means CREATE PROCEDURE would have FAILED rather than leaked. Fail-closed,
-- and still wrong. ON ROUTINE accepts both.
--
-- There are no procedures in this schema today, which is the only reason nothing
-- has hit it. "Nothing has exercised it" is the same standing this file's
-- subject matter had two rounds ago.
-- ---------------------------------------------------------------------------
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
      -- ON ROUTINE, not ON FUNCTION: one spelling that accepts both object
      -- kinds. format(%s) on object_identity because it is already a fully
      -- qualified, quoted identity string from the catalogue.
      EXECUTE format('REVOKE EXECUTE ON ROUTINE %s FROM PUBLIC', obj.object_identity);
    END IF;
  END LOOP;
END;
$$;

COMMENT ON FUNCTION app.revoke_public_execute() IS
  'The per-DATABASE half of the PUBLIC-EXECUTE net. The per-ROLE half is '
  'ALTER DEFAULT PRIVILEGES (0020); this trigger is what covers a routine-owning '
  'role that does not exist yet. Handles procedures via ON ROUTINE.';

REVOKE EXECUTE ON FUNCTION app.revoke_public_execute() FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- 4. THE GATE. Without this, item 1 is a habit; with it, it is a mechanism.
--
-- Two clauses, because the first draft had one and it was wrong on its first
-- run in a way worth recording.
--
-- It demanded a global rule for EVERY role owning a routine in app or cd, and
-- immediately failed with
--
--     CD-ACL-NODEFAULT: cdtest owns routines in app/cd
--
-- cdtest is the SUPERUSER APPLYING THE MIGRATIONS. It owns exactly one routine:
-- app.revoke_public_execute(), which 0018 must create as the superuser because
-- the event trigger cannot exist before its own function does. So there has been
-- a fourth routine-owning role in this schema the whole time, and the gate found
-- it in the first minute -- but demanding a per-role rule for it is wrong twice
-- over: that role's NAME is a deployment detail, and it is already covered by
-- the per-database trigger like every other creator.
--
--     A GATE THAT FAILS ON A CASE ALREADY COVERED IS NOT STRICTER. IT IS WRONG.
--
-- What is actually being defended is one property:
--
--     EVERY ROUTINE-OWNING ROLE IS COVERED BY AT LEAST ONE MECHANISM,
--     AND THE THREE APPLICATION ROLES ARE COVERED BY THE ONE THAT SURVIVES
--     A DATABASE WHERE WE ARE NOT SUPERUSER.
--
-- That second half is not hypothetical. The trigger needs superuser; plenty of
-- managed PostgreSQL will not give it. On such a provider 0018 cannot apply at
-- all and the per-role floor is the ONLY mechanism -- which is the real reason
-- the review's correction matters, quite apart from who was right about
-- ALTER DEFAULT PRIVILEGES.
--
-- defaclnamespace = 0 is the global scope. A per-SCHEMA row would satisfy a
-- naive EXISTS and protect nothing, which is precisely the confusion this file
-- exists to correct, so both clauses insist on the global one.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  missing   text;
  uncovered text;
  has_net   boolean;
BEGIN
  -- 4a. The three application roles, unconditionally. These are named in this
  -- file, so forgetting one is a fact about this file and not about a provider.
  SELECT string_agg(r, ', ') INTO missing
  FROM unnest(ARRAY['computedriven_migrations',
                    'computedriven_bootstrap',
                    'computedriven_ledger']) AS r
  WHERE NOT EXISTS (
    SELECT 1 FROM pg_default_acl d JOIN pg_roles ro ON ro.oid = d.defaclrole
     WHERE ro.rolname = r AND d.defaclnamespace = 0 AND d.defaclobjtype = 'f');
  IF missing IS NOT NULL THEN
    RAISE EXCEPTION
      'CD-ACL-NODEFAULT: % has no GLOBAL default-privilege rule. Add  ALTER '
      'DEFAULT PRIVILEGES FOR ROLE <role> REVOKE EXECUTE ON ROUTINES FROM '
      'PUBLIC;  -- WITHOUT IN SCHEMA. The schema-scoped form stores no row and '
      'protects nothing, which is the mistake 0009 made and 0018 mis-diagnosed', missing;
  END IF;

  -- 4b. Anyone else who owns a routine here -- the migration superuser today,
  -- an owning role a future migration invents tomorrow -- must be covered by
  -- the per-database net instead. If that net is ever removed, this stops being
  -- satisfiable and the migration says so rather than leaking.
  SELECT EXISTS (SELECT 1 FROM pg_event_trigger WHERE evtname = 'cd_revoke_public_execute'
                   AND evtenabled <> 'D') INTO has_net;

  SELECT string_agg(DISTINCT ro.rolname, ', ') INTO uncovered
  FROM pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace
  JOIN pg_roles ro    ON ro.oid = p.proowner
  WHERE n.nspname IN ('app', 'cd')
    AND NOT EXISTS (
      SELECT 1 FROM pg_default_acl d
       WHERE d.defaclrole = p.proowner AND d.defaclnamespace = 0 AND d.defaclobjtype = 'f');

  IF uncovered IS NOT NULL AND NOT has_net THEN
    RAISE EXCEPTION
      'CD-ACL-UNCOVERED: % owns routines in app/cd, has no global default-privilege '
      'rule, and the cd_revoke_public_execute event trigger is absent or disabled. '
      'Nothing would stop the next function that role creates from being '
      'PUBLIC-executable', uncovered;
  END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- The standing assertion from 0018: nothing in app or cd is PUBLIC-executable.
-- Kept because the two mechanisms above are means and this is the end.
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

-- ---------------------------------------------------------------------------
-- TWO CANARIES, because one was not enough to tell the mechanisms apart.
--
-- 0018 created its canary as computedriven_migrations only. That role now has a
-- default-privilege rule, so the canary would pass with the trigger DROPPED and
-- prove nothing about it. The second canary is created by a role invented here
-- and given no rule -- the "fourth role" case -- so it can only be protected by
-- the trigger. If someone deletes the trigger, this fails.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  SET LOCAL ROLE computedriven_migrations;
  EXECUTE 'CREATE FUNCTION app.acl_canary() RETURNS int LANGUAGE sql AS ''SELECT 1''';
  RESET ROLE;
  IF has_function_privilege('public', 'app.acl_canary()', 'EXECUTE') THEN
    RAISE EXCEPTION
      'CD-ACL-NET-DEAD: a function created by the migration role is PUBLIC-executable';
  END IF;
  EXECUTE 'DROP FUNCTION app.acl_canary()';
END
$$;

DO $$
BEGIN
  -- A role with NO default-privilege rule, which is what a role added by a
  -- future migration looks like on the day it is added.
  CREATE ROLE cd_acl_canary_role NOLOGIN NOSUPERUSER;
  -- USAGE as well as CREATE, and the reason is a property of the trigger worth
  -- knowing: app.revoke_public_execute() is NOT security definer, so it runs as
  -- whoever ran the CREATE FUNCTION. That role has to be able to NAME its own
  -- new function in a REVOKE, which needs USAGE on the schema. Without it the
  -- trigger raises "permission denied for schema app" and the CREATE FUNCTION
  -- fails -- fail-closed, but it fails the CREATE rather than the leak.
  GRANT CREATE, USAGE ON SCHEMA app TO cd_acl_canary_role;
  SET LOCAL ROLE cd_acl_canary_role;
  EXECUTE 'CREATE FUNCTION app.acl_canary_norule() RETURNS int LANGUAGE sql AS ''SELECT 1''';
  RESET ROLE;

  IF has_function_privilege('public', 'app.acl_canary_norule()', 'EXECUTE') THEN
    RAISE EXCEPTION
      'CD-ACL-NET-DEAD: a function created by a role with no default-privilege '
      'rule is PUBLIC-executable. The per-database event trigger is the only '
      'thing that covers this case and it is not working';
  END IF;

  EXECUTE 'DROP FUNCTION app.acl_canary_norule()';
  REVOKE CREATE, USAGE ON SCHEMA app FROM cd_acl_canary_role;
  DROP ROLE cd_acl_canary_role;
END
$$;

COMMIT;
