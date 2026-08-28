-- 0002 — the tenant-context contract
--
-- R14: RLS fails closed by RAISING. A missing tenant context is an error, never
-- an empty result set.
--
-- WHY THIS FILE EXISTS AT ALL
--
-- PostgreSQL's current_setting(name, true) returns NULL when the setting is
-- absent, and an RLS USING clause that evaluates to NULL merely *hides the row*.
-- So the naive policy
--
--     USING (organization_id = current_setting('app.organization_id', true)::uuid)
--
-- turns "the server forgot to establish tenant context" into "this organization
-- has no worlds". That is a silent wrong answer in the direction that looks
-- normal, and no happy-path test will ever catch it.
--
-- Every policy in 0006 therefore goes through app.current_organization_id(),
-- whose contract is:
--
--     valid setting      ->  uuid
--     setting missing    ->  RAISE
--     setting malformed  ->  RAISE

BEGIN;

SET LOCAL ROLE computedriven_migrations;

CREATE OR REPLACE FUNCTION app.current_organization_id()
RETURNS uuid
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
  raw text;
  val uuid;
BEGIN
  raw := current_setting('app.organization_id', true);

  IF raw IS NULL OR btrim(raw) = '' THEN
    RAISE EXCEPTION
      USING ERRCODE = '42501',
            MESSAGE = 'CD-TENANT-MISSING: app.organization_id is not set for this transaction',
            HINT    = 'Call app.set_organization_context(<uuid>) inside the transaction, '
                      'with a SERVER-DERIVED organization id. Never one the client sent.';
  END IF;

  BEGIN
    val := raw::uuid;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION
      USING ERRCODE = '42501',
            MESSAGE = format('CD-TENANT-MALFORMED: app.organization_id is not a uuid (%L)', raw);
  END;

  RETURN val;
END;
$$;

COMMENT ON FUNCTION app.current_organization_id() IS
  'Returns the transaction-local tenant context, or RAISES. Never returns NULL. R14.';

-- Establishing context. is_local = true makes it transaction-scoped, which is
-- the correct primitive under a transaction pooler: Hyperdrive (and PgBouncer in
-- transaction mode) hand the connection back at COMMIT and reset transaction
-- state. A plain SET would survive into whichever request got the connection
-- next -- that is the leak this shape avoids, and the battery proves it rather
-- than assuming it.
--
-- The uuid parameter type is deliberate: a malformed id fails at bind time, on
-- the server, before it can reach a policy.
CREATE OR REPLACE FUNCTION app.set_organization_context(p_organization_id uuid)
RETURNS void
LANGUAGE plpgsql
VOLATILE
AS $$
BEGIN
  IF p_organization_id IS NULL THEN
    RAISE EXCEPTION
      USING ERRCODE = '42501',
            MESSAGE = 'CD-TENANT-NULL: refusing to establish a NULL tenant context';
  END IF;
  PERFORM set_config('app.organization_id', p_organization_id::text, true);
END;
$$;

COMMENT ON FUNCTION app.set_organization_context(uuid) IS
  'Transaction-local tenant context. The argument MUST be server-derived.';

COMMIT;
