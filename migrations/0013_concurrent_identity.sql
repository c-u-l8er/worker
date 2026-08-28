-- 0013 — make resolve_principal idempotent under CONCURRENCY, not just in a row
--
-- BUG, found by outside review 2026-08-22 and reproduced before fixing. It has
-- survived five rounds because the check that was supposed to catch it could
-- not, by construction.
--
-- F1 in the battery asserts
--
--     resolve_principal(x) = resolve_principal(x)
--
-- which is two calls, one session, one after the other. That is a real property
-- and it is not the property a login endpoint needs. Two tabs, two devices, or
-- one client retrying a timed-out request produce a state no sequential test can
-- construct: the first call has not committed when the second one starts.
--
-- Measured on a throwaway cluster, hand-stepped so it is an interleaving rather
-- than a race the test hoped to hit:
--
--     S1  BEGIN; resolve_principal('sub')     inserts, does NOT commit
--     S2  BEGIN; resolve_principal('sub')     SELECT sees nothing (uncommitted)
--     S2                                      inserts its own principal
--     S2                                      INSERT identity BLOCKS on the index
--     S1  COMMIT
--     S2  ERROR: duplicate key value violates
--                "principal_identities_active_uq"
--
-- and unstructured, 4 simultaneous first logins per subject: 6 of 12 rounds
-- diverged. So the honest statement of the old behaviour is
--
--     same external identity + two simultaneous first requests
--         != reliably the same successful result
--
-- One of them 500s. It is not a corruption bug -- the unique partial index did
-- its job and the loser's subtransaction rolls back its orphan principal -- but
-- "your first login sometimes fails" is not a thing to discover from Keycloak.
--
--     SERIAL CORRECTNESS IS NOT CONCURRENT CORRECTNESS.
--
-- THE FIX. An xact-scoped advisory lock keyed on the identity triple, taken
-- BEFORE the lookup. The second session then blocks before it can conclude the
-- identity is absent, and when it wakes its next statement takes a fresh
-- snapshot that includes the winner's committed row.
--
-- Why an advisory lock and not ON CONFLICT: there are two inserts into two
-- tables and the second one is the one that conflicts, so the principal row is
-- already spent by the time a conflict clause could fire. Locking the identity
-- before deciding is the smaller thing to reason about.
--
-- Two properties of the key worth stating, because both look like problems and
-- neither is:
--
--   * hashtext() can collide. A collision makes two unrelated first logins
--     serialize on one lock. That is a few microseconds of contention and never
--     a wrong answer -- the lock is a serialization device, not the correctness
--     mechanism. The unique partial index is still the correctness mechanism.
--   * the lock is transaction-scoped, so it is released by COMMIT or ROLLBACK
--     including a crash. Nothing has to remember to unlock.
--
-- The EXCEPTION block is a backstop, not the fix. Under READ COMMITTED -- what
-- Hyperdrive's transaction pooling gives us -- the lock closes the window and
-- the handler never fires. Under REPEATABLE READ the re-SELECT runs against the
-- transaction's original snapshot and still cannot see the winner, so the
-- handler refuses by name instead of returning a duplicate. A refusal the
-- Worker can retry beats a duplicate-key stack trace.

BEGIN;

SET LOCAL ROLE computedriven_migrations;

-- Same borrow-and-return dance as 0005 and 0008: CREATE OR REPLACE requires
-- ownership, and these belong to the bootstrap role.
GRANT CREATE ON SCHEMA app TO computedriven_bootstrap;
SET LOCAL ROLE computedriven_bootstrap;

CREATE OR REPLACE FUNCTION app.resolve_principal(
  p_provider text,
  p_issuer   text,
  p_subject  text
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cd, pg_temp
AS $$
DECLARE
  found  uuid;
  st     text;
  fresh  uuid;
BEGIN
  IF p_provider IS NULL OR p_issuer IS NULL OR p_subject IS NULL
     OR btrim(p_provider) = '' OR btrim(p_issuer) = '' OR btrim(p_subject) = '' THEN
    RAISE EXCEPTION
      USING ERRCODE = '22023',
            MESSAGE = 'CD-IDENTITY-INCOMPLETE: provider, issuer and subject are all required';
  END IF;

  -- Serialize concurrent FIRST logins for this one identity, and nothing else.
  -- The namespace half keeps this out of the way of any other advisory-lock user
  -- in the cluster; the record separator keeps ('a','bc') from hashing the same
  -- as ('ab','c').
  PERFORM pg_advisory_xact_lock(
            hashtext('app.resolve_principal'),
            hashtext(p_provider || E'\x1f' || p_issuer || E'\x1f' || p_subject));

  SELECT pi.principal_id, p.status
    INTO found, st
  FROM cd.principal_identities pi
  JOIN cd.principals p ON p.id = pi.principal_id
  WHERE pi.provider = p_provider
    AND pi.issuer   = p_issuer
    AND pi.subject  = p_subject
    AND pi.status   = 'active';

  IF found IS NOT NULL THEN
    IF st <> 'active' THEN
      -- A live IdP binding onto a principal that is not active. The binding is
      -- fine; the principal is not. Refuse by name.
      RAISE EXCEPTION
        USING ERRCODE = '42501',
              MESSAGE = format('CD-PRINCIPAL-%s: principal %s is %s, not active',
                               upper(st), found, st);
    END IF;
    RETURN found;                       -- idempotent: same subject, same principal
  END IF;

  INSERT INTO cd.principals DEFAULT VALUES RETURNING id INTO fresh;

  INSERT INTO cd.principal_identities (principal_id, provider, issuer, subject)
  VALUES (fresh, p_provider, p_issuer, p_subject);

  RETURN fresh;

EXCEPTION
  WHEN unique_violation THEN
    -- Unreachable under READ COMMITTED with the lock held. Reached only if a
    -- caller raised the isolation level, where the re-read is bound to the
    -- original snapshot and genuinely cannot see the winner.
    --
    -- The subtransaction this handler opens has already rolled back the
    -- principal row inserted above, so no orphan survives -- which the battery
    -- checks rather than assumes.
    SELECT pi.principal_id INTO found
    FROM cd.principal_identities pi
    WHERE pi.provider = p_provider
      AND pi.issuer   = p_issuer
      AND pi.subject  = p_subject
      AND pi.status   = 'active';
    IF found IS NOT NULL THEN
      RETURN found;
    END IF;
    RAISE EXCEPTION
      USING ERRCODE = '40001',
            MESSAGE = 'CD-IDENTITY-CONCURRENT: another transaction bound this identity; retry';
END;
$$;

COMMENT ON FUNCTION app.resolve_principal(text, text, text) IS
  'Idempotently maps an external OIDC identity to a ComputeDriven principal, '
  'CONCURRENTLY as well as sequentially (0013). The IdP subject is a BINDING, '
  'not the identity (R10).';

RESET ROLE;
SET LOCAL ROLE computedriven_migrations;
REVOKE CREATE ON SCHEMA app FROM computedriven_bootstrap;

COMMIT;
