-- 0015 — R30 AMENDED: concurrent idempotence WITHOUT advisory locks
--
-- BLOCKER, found by outside review 2026-08-22 and verified first-party against
-- Cloudflare's documentation before changing anything.
--
-- 0013 closed the concurrent-first-login race with
--
--     PERFORM pg_advisory_xact_lock(...)
--
-- which is correct PostgreSQL, is proven by the concurrency battery, and CANNOT
-- REACH PRODUCTION. Cloudflare's Hyperdrive compatibility page lists, verbatim:
--
--     "Advisory locks, LISTEN and NOTIFY, PREPARE and DEALLOCATE, any
--      modification to per-session state not explicitly documented as supported
--      elsewhere."
--
--     https://developers.cloudflare.com/hyperdrive/reference/supported-databases-and-features/
--
-- R7 puts every control-plane query through Hyperdrive. So the fix that made the
-- battery green was a fix the production transport refuses, and the battery could
-- not see that because it talks to PostgreSQL directly over TCP.
--
--     A LOCAL BATTERY PROVES THE DATABASE'S BEHAVIOUR, NOT THE TRANSPORT'S.
--
-- This is a new category of blind spot for this tree, and a more interesting one
-- than the previous rounds' -- every earlier finding was something the battery
-- COULD have tested and did not. This one it structurally cannot: there is no
-- Hyperdrive to test against, and there will not be until an account exists.
-- Battery group L is the substitute: it asks the DATABASE which functions the API
-- role may execute and reads their bodies, so a future migration reintroducing an
-- advisory lock on the request path fails a check rather than a deployment.
--
-- ---------------------------------------------------------------------------
-- WHAT R30 SHOULD HAVE SAID
--
-- R30 ruled concurrent idempotence and then named a mechanism. The ruling stands;
-- the mechanism is superseded:
--
--     RULED      resolve_principal() is idempotent under CONCURRENCY, not merely
--                in sequence.
--     SUPERSEDED the advisory lock. The serialization primitive is the unique
--                partial index that was already there.
--
-- ON CONFLICT is ordinary SQL with defined Read Committed behaviour: when the
-- conflicting row exists but is UNCOMMITTED, the inserting statement WAITS for
-- the other transaction, then does nothing if it committed and proceeds if it
-- rolled back. That is precisely the serialization the advisory lock was buying,
-- performed by the index that has to be consulted anyway.
--
-- ---------------------------------------------------------------------------
-- WHY A LOOP, AND WHY IT IS BOUNDED
--
--     read  ->  if bound, done
--     write ->  candidate principal, then the binding
--     lost? ->  the subtransaction rolls the candidate back; read again
--
-- One retry would be enough for the ordinary race. The loop exists for the
-- unordinary one: the winner may UNBIND the identity between our conflict and our
-- re-read (0003 allows it, F4 exercises it), and then the re-read finds nothing
-- and we must be allowed to try again. It is bounded at three because an
-- unbounded retry against a pathological caller is a busy loop holding a
-- connection, and a refusal the Worker can retry is better than one that never
-- returns.
--
-- ---------------------------------------------------------------------------
-- WHY THE INDEX RAISES INSTEAD OF `ON CONFLICT DO NOTHING`, WHICH IS WHAT THE
-- REVIEW SUGGESTED
--
-- Both use the unique partial index as the serialization primitive, which is the
-- part that matters and the part the ruling is about. Both WAIT the same way:
-- under Read Committed an INSERT that conflicts with an UNCOMMITTED row blocks
-- until that transaction ends, either way. They differ only in what happens to
-- the candidate principal already inserted above.
--
-- ON CONFLICT DO NOTHING raises nothing, so nothing rolls back, and the loser
-- must DELETE its own orphan -- which was written, and failed:
--
--     ERROR: permission denied for table principals
--     CONTEXT: SQL statement "DELETE FROM cd.principals WHERE id = fresh"
--
-- because computedriven_bootstrap holds SELECT and INSERT on cd.principals and
-- nothing else (0005). Making that version work means granting the bootstrap role
-- DELETE on the principal table -- widening the narrowest role in the schema, so
-- that a rare losing path can clean up after itself.
--
-- Letting the index RAISE costs nothing and cleans up for free: a plpgsql
-- EXCEPTION block is a subtransaction, so the candidate principal is rolled back
-- by the database rather than by remembered code. Fewer privileges and less to
-- forget, for the same concurrency behaviour.
--
--     THE CHEAPEST CLEANUP IS THE ONE THE DATABASE ALREADY DOES.
--
-- N5 checks the orphan count regardless, because "the subtransaction handles it"
-- is a claim and claims in this tree get measured.

BEGIN;

SET LOCAL ROLE computedriven_migrations;

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
  found   uuid;
  st      text;
  fresh   uuid;
  bound   uuid;
  attempt int := 0;
BEGIN
  IF p_provider IS NULL OR p_issuer IS NULL OR p_subject IS NULL
     OR btrim(p_provider) = '' OR btrim(p_issuer) = '' OR btrim(p_subject) = '' THEN
    RAISE EXCEPTION
      USING ERRCODE = '22023',
            MESSAGE = 'CD-IDENTITY-INCOMPLETE: provider, issuer and subject are all required';
  END IF;

  WHILE attempt < 3 LOOP
    attempt := attempt + 1;

    -- Each iteration is a new statement, so under READ COMMITTED it takes a
    -- fresh snapshot and can see a winner that committed while we were blocked.
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
      RETURN found;                     -- idempotent: same subject, same principal
    END IF;

    -- One subtransaction around BOTH inserts. principal_identities_active_uq --
    -- the partial unique index -- is the serialization primitive: this INSERT
    -- blocks on a conflicting-but-uncommitted row and raises once that
    -- transaction commits. Catching the raise costs one subtransaction on the
    -- losing path and rolls the candidate principal back with it.
    BEGIN
      INSERT INTO cd.principals DEFAULT VALUES RETURNING id INTO fresh;

      INSERT INTO cd.principal_identities (principal_id, provider, issuer, subject)
      VALUES (fresh, p_provider, p_issuer, p_subject)
      RETURNING principal_id INTO bound;

      RETURN bound;                     -- we won the race
    EXCEPTION
      WHEN unique_violation THEN
        -- Someone else bound this identity while we were inserting. The
        -- candidate principal above is already rolled back. Loop and re-read;
        -- the next statement takes a fresh snapshot and will see the winner.
        fresh := NULL;
        bound := NULL;
    END;
  END LOOP;

  -- Three attempts and the identity was neither bound nor bindable. Something is
  -- churning it. A named, retryable refusal beats a duplicate-key stack trace.
  RAISE EXCEPTION
    USING ERRCODE = '40001',
          MESSAGE = 'CD-IDENTITY-CONCURRENT: this identity is being rebound concurrently; retry';
END;
$$;

COMMENT ON FUNCTION app.resolve_principal(text, text, text) IS
  'Idempotently maps an external OIDC identity to a ComputeDriven principal, '
  'CONCURRENTLY as well as sequentially. Serialized by the unique partial index '
  'via ON CONFLICT, NOT by an advisory lock -- Hyperdrive does not support those '
  '(R30, amended 0015). The IdP subject is a BINDING, not the identity (R10).';

RESET ROLE;
SET LOCAL ROLE computedriven_migrations;
REVOKE CREATE ON SCHEMA app FROM computedriven_bootstrap;

COMMIT;
