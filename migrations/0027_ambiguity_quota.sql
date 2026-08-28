-- 0027 — the other half of the quota equation
--
-- Finding 86 from outside review 2026-08-23, the round immediately after 0026
-- introduced the defect. Reproduced against 0026 before this file was written.
--
-- ===========================================================================
-- 86. R75 MOVED ONE SIDE OF THE LEDGER AND LEFT THE OTHER JOINING ON A COLUMN
--     R75 HAD JUST TAUGHT TO BE NULL.
--
-- 0026 was right that `current_observation_id` should go NULL on an ambiguous
-- tip: *which* observation is current is exactly the open question. It changed
-- `storage_divergence_for()` to stop joining through that column, and said so.
-- It did not change `app.storage_outstanding()`, which joins through it too:
--
--     reservation -> intent -> observation -> storage_objects.current_observation_id
--
-- So the same bytes became visible to one side of the quota and invisible to
-- the other. MEASURED against 0026, one 20-byte reservation on one key whose
-- two observations tie:
--
--     object   size=20  etag=(unknown)  current_obs=NULL  ambiguous=true
--     ledger   committed=40  outstanding=20  used=60
--
-- against a correct 40 / 0 / 40. The observer charged the occupancy and the
-- reservation kept its entire hold, so a provider-observed byte was counted
-- once as occupancy and once as not-yet-accounted-for.
--
-- It is SAFE -- it over-counts, so nothing oversubscribes -- and it is still
-- wrong, and the direction of the error is the least useful kind: a tenant who
-- hits an ambiguity is charged twice for it until reconciliation, for an
-- ambiguity that is our problem and not theirs.
--
--     R78 -- TWO QUERIES THAT PARTITION ONE QUANTITY MUST DERIVE IT FROM THE
--     SAME RELATION. `committed + outstanding` is a partition of the tenant's
--     quota position; the two halves were reading two different definitions of
--     "which object does this reservation account for".
--
-- The fix is 0026's own, applied to the query it missed: attribute by KEY --
-- reservation -> intent -> observation -> (bucket, object_key) -> the
-- set-derived projection. `upload_intents.object_key` is UNIQUE
-- (`upload_intents_key_uq`, 0017), so one key belongs to at most one intent and
-- therefore at most one reservation; the key-based join cannot count an object
-- against two reservations.
--
-- WHY THE BATTERY DID NOT CATCH IT, which is the more useful half. O23b is
-- named "the ledger charges the same either way" and it queried
--
--     SELECT sum(size_bytes) FROM cd.storage_objects WHERE object_key IN (...)
--
-- -- the committed PROJECTION, not the ledger. It proved the thing its own name
-- did not claim, and the quantity admission actually reads was never asserted
-- by any check in group O. O23b now calls `app.storage_ledger_for()`, and O29
-- asserts the partition directly.
--
--     A CHECK NAMED AFTER A QUANTITY MUST QUERY THAT QUANTITY. Round 2 learned
--     that a gate with nothing to check passes; this is the same law one layer
--     up -- a gate checking the wrong thing passes too, and its name is what
--     stops anyone re-reading it.

BEGIN;

SET LOCAL ROLE computedriven_migrations;

DROP FUNCTION app.storage_ledger();
DROP FUNCTION app.storage_ledger_for(uuid);
DROP FUNCTION app.storage_outstanding(uuid);

-- 0026 revoked this at its own end, deliberately. The ledger role holds CREATE
-- on `app` only for the span of a migration that defines its own functions.
GRANT CREATE ON SCHEMA app TO computedriven_ledger;
SET LOCAL ROLE computedriven_ledger;

CREATE FUNCTION app.storage_outstanding(p_organization_id uuid)
RETURNS bigint
LANGUAGE sql
SECURITY DEFINER
SET search_path = cd, pg_temp
STABLE
AS $$
  SELECT coalesce(sum(GREATEST(r.bytes - coalesce(o.observed, 0), 0)), 0)::bigint
    FROM cd.storage_reservations r
    LEFT JOIN LATERAL (
      SELECT sum(so.size_bytes) AS observed
        FROM (SELECT DISTINCT ob.bucket, ob.object_key
                FROM cd.upload_intents i
                JOIN cd.storage_observations ob ON ob.intent_id = i.id
               WHERE i.reservation_id = r.id) keys
        JOIN cd.storage_objects so
          ON so.bucket = keys.bucket AND so.object_key = keys.object_key
    ) o ON true
   WHERE r.organization_id = p_organization_id
     AND r.state <> 'settled';
$$;

COMMENT ON FUNCTION app.storage_outstanding(uuid) IS
  'Bytes authorized and not yet accounted for by a provider observation. '
  'DERIVED, never stored: a reservation fully observed contributes zero without '
  'anything having released it, and one that expired unobserved keeps holding '
  'because our clock passing is not evidence the bytes did not land (R69). '
  'Attributes BY KEY, exactly as app.storage_divergence_for() does -- the '
  'previous version joined through storage_objects.current_observation_id, '
  'which R75 sets to NULL on an ambiguous tip, so an ambiguous object was '
  'charged as occupancy AND still held its whole reservation (R78, finding 86). '
  'Ranges over reservations, which are few and short-lived -- occupancy ranges '
  'over objects and therefore stays an incremented column.';

CREATE FUNCTION app.storage_ledger_for(p_organization_id uuid)
RETURNS TABLE (committed_bytes bigint, outstanding_bytes bigint, used_bytes bigint)
LANGUAGE sql
SECURITY DEFINER
SET search_path = cd, pg_temp
STABLE
AS $$
  SELECT c.committed, o.outstanding, c.committed + o.outstanding
    FROM (SELECT coalesce((SELECT u.committed_bytes FROM cd.storage_usage u
                            WHERE u.organization_id = p_organization_id), 0) AS committed) c,
         (SELECT app.storage_outstanding(p_organization_id) AS outstanding) o;
$$;

COMMENT ON FUNCTION app.storage_ledger_for(uuid) IS
  'The whole quota position: provider-observed occupancy + outstanding '
  'authority. CROSS-TENANT and jobs-only for the reason in 0024 finding 72; '
  'the request form is app.storage_ledger(), which takes no argument. The two '
  'halves must derive from the SAME relation or the partition stops being one '
  '(R78, finding 86).';

CREATE FUNCTION app.storage_ledger()
RETURNS TABLE (committed_bytes bigint, outstanding_bytes bigint, used_bytes bigint)
LANGUAGE sql
SECURITY DEFINER
SET search_path = cd, pg_temp
STABLE
AS $$ SELECT * FROM app.storage_ledger_for(app.current_organization_id()); $$;

COMMENT ON FUNCTION app.storage_ledger() IS
  'This tenant''s quota position. NO ORGANIZATION ARGUMENT: the tenant comes '
  'from transaction context, which raises when absent, so reading another '
  'tenant is unspeakable rather than merely forbidden (0024, finding 72).';

RESET ROLE;
SET LOCAL ROLE computedriven_migrations;
REVOKE CREATE ON SCHEMA app FROM computedriven_ledger;

-- DROP + CREATE DISCARDS THE ACL (0026's lesson, second application). These
-- three carried grants from 0023 and 0024 and would otherwise come back
-- unreachable -- and `reserve_storage()` calls storage_outstanding(), so the
-- failure would surface as admission breaking, four files away from here.
REVOKE EXECUTE ON FUNCTION
  app.storage_outstanding(uuid), app.storage_ledger_for(uuid), app.storage_ledger()
FROM PUBLIC;

GRANT EXECUTE ON FUNCTION app.storage_outstanding(uuid) TO computedriven_jobs;
GRANT EXECUTE ON FUNCTION app.storage_ledger_for(uuid)  TO computedriven_jobs;
GRANT EXECUTE ON FUNCTION app.storage_ledger()          TO computedriven_api, computedriven_readonly;

DO $$
BEGIN
  IF NOT has_function_privilege('computedriven_api', 'app.storage_ledger()', 'EXECUTE') THEN
    RAISE EXCEPTION 'CD-LEDGER-UNREACHABLE: the request role cannot read its own quota position';
  END IF;
  IF has_function_privilege('computedriven_api', 'app.storage_ledger_for(uuid)', 'EXECUTE')
     OR has_function_privilege('computedriven_readonly', 'app.storage_ledger_for(uuid)', 'EXECUTE') THEN
    RAISE EXCEPTION 'CD-XTENANT-DEFINER: a request role can name a tenant through storage_ledger_for';
  END IF;
END
$$;

-- R78 as a gate. `current_observation_id` is a fact about WHICH observation is
-- current, and R75 made it legitimately NULL; any query that uses it to decide
-- WHETHER a reservation accounts for an object is asking the wrong question and
-- will silently omit exactly the ambiguous rows. Two functions did; both were
-- fixed a round apart, which is the argument for the gate rather than a third
-- careful reading.
DO $$
DECLARE offenders text;
BEGIN
  SELECT string_agg(p.proname, ', ' ORDER BY p.proname) INTO offenders
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'app'
     AND p.prosrc ~ 'current_observation_id[[:space:]]*='
     AND p.proname <> 'observe_storage_object';
  IF offenders IS NOT NULL THEN
    RAISE EXCEPTION 'CD-AMBIGUITY-BLIND: % joins on current_observation_id, which R75 sets NULL '
                    'on an ambiguous tip; attribute by (bucket, object_key) instead (R78)', offenders;
  END IF;
END
$$;

COMMIT;
