-- 0025 — observation coherence: a replay must return the recorded decision,
--        and the two clocks must come from ONE event
--
-- Findings 78, 79 and 80 from outside review 2026-08-23. All reproduced against
-- 0024 before this file was written.
--
-- ===========================================================================
-- 79. A DUPLICATE DELIVERY RECOMPUTED ITS ANSWER FROM TODAY'S WORLD.
--
-- observe_storage_object() derives `v_intent` from CURRENT state, then inserts.
-- When the insert conflicts -- this delivery is already recorded -- the
-- duplicate branch returned that freshly-computed `v_intent`, and the
-- `attributed` flag derived from it, rather than what the stored row says.
--
--     T1  the provider writes; no intent exists
--     T2  the notification arrives    ->  observation stored with intent_id NULL
--     T3  an intent for that key appears
--     T4  the SAME queue message is redelivered
--         ->  the insert conflicts
--         ->  v_intent is recomputed against T3's world
--         ->  the caller is told  attributed = true
--
-- MEASURED against 0024:
--
--     duplicate=true  RETURNED attributed=true  RETURNED intent=34b58d07-...
--     PERSISTED intent_id IS NULL = true
--
-- The database was right the whole time. The function told its caller the
-- opposite, and reconcile.mjs uses that bit as an operational signal -- so the
-- provenance log and the consumer's telemetry disagree about the same event.
--
--     R73 -- A REPLAY RETURNS THE RECORDED DECISION. IT DOES NOT RE-DECIDE
--     USING TODAY'S WORLD.
--
-- This is R54 pointed at the RETURN VALUE instead of at the row: 0022 stopped a
-- late writer from overwriting provider truth, and the read path was still
-- willing to narrate it differently. Fifth time a version of this distinction
-- has had to be drawn, and the first time on an answer rather than a record.
--
-- The sibling defect is in the same branch. The fallback unique index is
-- `(bucket, object_key, etag, event_time)` and the duplicate LOOKUP omitted
-- event_time, so two genuine writes of identical bytes at different moments
-- were indistinguishable to the reader that had just been told they differ.
-- MEASURED: redelivering the older of two fallback observations returned the
-- NEWER row's id. A lookup must use the whole key its uniqueness is built on.
--
-- ---------------------------------------------------------------------------
-- 78. THE BACKFILL PAIRED TWO CLOCKS FROM TWO DIFFERENT EVENTS.
--
-- 0024 split provider_event_at (R2's) from provider_observed_at (ours),
-- correctly, and its BACKFILL then chose the provider time with
--
--     ORDER BY intent_id, event_time ASC
--
-- while provider_observed_at had been written when the FIRST NOTIFICATION WE
-- CONSUMED reached the observer. Queues does not guarantee order, so those are
-- different questions. MEASURED, delivering B (later event) before A (earlier):
--
--     0024's backfill picks        etag A, event_time 12:15:33
--     the first CONSUMED row is    etag B, event_time 12:16:33
--
-- The runtime path was already right -- it writes both timestamps from the same
-- arguments in one statement -- so this only ever affected rows migrated by
-- 0024. It is still worth fixing rather than noting, because the reason it was
-- possible is structural: the intent stores two timestamps whose COMMON
-- PROVENANCE is implicit, and nothing in the schema says they came from one
-- observation.
--
--     R74 -- IF TWO COLUMNS DESCRIBE ONE EVENT, THE SCHEMA SHOULD NAME THE
--     EVENT. `observing_observation_id` is the fact; the timestamps are its
--     projection, written together and never separately.
--
-- Same shape as R71 (independent facts get independent columns) read from the
-- other end: DEPENDENT facts get a shared referent.
--
-- ---------------------------------------------------------------------------
-- 80. THERE WERE TWO O0c's AND THEY DISAGREED.
--
-- The battery's asks for any ledger-owned SECURITY DEFINER storage function
-- taking a uuid and reachable by computedriven_api OR computedriven_readonly.
-- 0024's apply-time copy -- which the bundle called "the same assertion" --
-- checked only computedriven_api and EXEMPTED every name ending `_for`.
--
-- Those are precisely the cross-tenant doors the round exists to keep shut. A
-- later `GRANT EXECUTE ON app.storage_ledger_for(uuid) TO computedriven_api`
-- would have applied cleanly.
--
--     A SUFFIX THAT MARKS A FUNCTION AS DANGEROUS IS NOT A REASON FOR THE GATE
--     TO SKIP IT. IT IS THE REASON TO CHECK IT.
--
-- The exemption existed because the predicate was written to describe the
-- fixed state rather than the rule: `_for` functions are dangerous AND
-- jobs-only, and the gate encoded the second clause as if it were the first.
-- One predicate now, shared verbatim, and it is the battery's.

BEGIN;

SET LOCAL ROLE computedriven_migrations;

-- ---------------------------------------------------------------------------
-- 78. The event the two timestamps came from.
-- ---------------------------------------------------------------------------
ALTER TABLE cd.upload_intents
  ADD COLUMN observing_observation_id uuid REFERENCES cd.storage_observations(id) ON DELETE RESTRICT;

COMMENT ON COLUMN cd.upload_intents.observing_observation_id IS
  'The provider event that told us this intent landed. provider_event_at and '
  'provider_observed_at are its two clocks and are written WITH it, never '
  'separately -- 0024 backfilled them from two different observations because '
  'nothing in the schema said they shared a referent (R74, finding 78).';

-- Re-backfill all three together from the FIRST CONSUMED observation, which is
-- the one that actually set provider_observed_at. `observed_at ASC`, not
-- `event_time ASC`: the question is "which notification did we act on", and
-- those coincide only when delivery order matches provider order, which Queues
-- does not promise.
WITH first_consumed AS (
  SELECT DISTINCT ON (intent_id) intent_id, id, event_time, observed_at
    FROM cd.storage_observations
   WHERE intent_id IS NOT NULL
   ORDER BY intent_id, observed_at ASC, event_time ASC
)
UPDATE cd.upload_intents i
   SET observing_observation_id = f.id,
       provider_event_at        = f.event_time
  FROM first_consumed f
 WHERE f.intent_id = i.id AND i.provider_observed_at IS NOT NULL;

-- An intent that claims a provider observation must name it. Stated as a
-- constraint because the whole finding was that two columns agreed to describe
-- one event and nothing checked they did.
ALTER TABLE cd.upload_intents
  ADD CONSTRAINT upload_intents_observed_together_ck
  CHECK ((provider_observed_at IS NULL) = (provider_event_at IS NULL)
     AND (provider_observed_at IS NULL) = (observing_observation_id IS NULL));

CREATE OR REPLACE FUNCTION app.upload_intent_observed_is_final() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.provider_observed_at IS NOT NULL
     AND NEW.provider_observed_at IS DISTINCT FROM OLD.provider_observed_at THEN
    RAISE EXCEPTION USING ERRCODE = '55000',
      MESSAGE = format('CD-INTENT-OBSERVED-FINAL: intent %s was observed at %s; '
                       'provider truth is monotonic (R54)', OLD.id, OLD.provider_observed_at);
  END IF;
  IF OLD.provider_event_at IS NOT NULL
     AND NEW.provider_event_at IS DISTINCT FROM OLD.provider_event_at THEN
    RAISE EXCEPTION USING ERRCODE = '55000',
      MESSAGE = format('CD-INTENT-EVENTAT-FINAL: intent %s carries provider event time %s; '
                       'the provider''s clock is not ours to revise (R54)',
                       OLD.id, OLD.provider_event_at);
  END IF;
  IF OLD.observing_observation_id IS NOT NULL
     AND NEW.observing_observation_id IS DISTINCT FROM OLD.observing_observation_id THEN
    RAISE EXCEPTION USING ERRCODE = '55000',
      MESSAGE = format('CD-INTENT-OBSERVER-FINAL: intent %s was settled by observation %s; '
                       'which event told us is not revisable either (R74)',
                       OLD.id, OLD.observing_observation_id);
  END IF;
  RETURN NEW;
END;
$$;

GRANT CREATE ON SCHEMA app TO computedriven_ledger;
SET LOCAL ROLE computedriven_ledger;

-- ---------------------------------------------------------------------------
-- 79. The observer, with a duplicate branch that READS instead of re-deciding.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.observe_storage_object(
  p_bucket     text,
  p_object_key text,
  p_etag       text,
  p_size_bytes bigint,
  p_action     text,
  p_event_time timestamptz,
  p_message_id text DEFAULT NULL
)
RETURNS app.observation_result
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cd, pg_temp
AS $$
DECLARE
  k        record;
  v_intent uuid;
  i        cd.upload_intents;
  v_id     uuid;
  prior    record;
  v_prior  bigint;
  v_after  bigint;
  v_delta  bigint;
  out_row  app.observation_result;
BEGIN
  IF p_bucket IS NULL OR btrim(p_bucket) = '' OR p_etag IS NULL OR btrim(p_etag) = '' THEN
    RAISE EXCEPTION USING ERRCODE = '22023',
      MESSAGE = 'CD-OBSERVE-SHAPE: bucket and etag are required';
  END IF;
  IF p_size_bytes IS NULL OR p_size_bytes < 0 THEN
    RAISE EXCEPTION USING ERRCODE = '22023',
      MESSAGE = 'CD-OBSERVE-SIZE: size must be zero or more';
  END IF;
  IF p_action NOT IN ('PutObject', 'CopyObject', 'CompleteMultipartUpload') THEN
    RAISE EXCEPTION USING ERRCODE = '22023',
      MESSAGE = format('CD-OBSERVE-ACTION: %L is not an object-create action', p_action);
  END IF;
  IF p_event_time IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = '22023',
      MESSAGE = 'CD-OBSERVE-TIME: an event time is required';
  END IF;

  SELECT * INTO k FROM app.parse_object_key(p_object_key);
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '22023',
      MESSAGE = format('CD-OBSERVE-KEY: %L is not a key this control plane minted', p_object_key);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM cd.organizations o WHERE o.id = k.organization_id) THEN
    RAISE EXCEPTION USING ERRCODE = '22023',
      MESSAGE = 'CD-OBSERVE-ORG: the key names an organization that does not exist';
  END IF;

  -- THE REPLAY CHECK COMES FIRST (R73). Before 0025 this ran after v_intent had
  -- been computed against today's world, and the duplicate branch then reported
  -- that value instead of the stored one -- so a redelivery of an unattributed
  -- write could be announced as attributed once an intent for the key existed.
  --
  -- The lookup uses the WHOLE key its uniqueness is built on. The fallback index
  -- is (bucket, object_key, etag, event_time); omitting event_time returned the
  -- wrong row for a redelivery of the older of two identical-body writes.
  SELECT o.id, o.intent_id, o.size_bytes INTO prior
    FROM cd.storage_observations o
   WHERE (p_message_id IS NOT NULL AND o.message_id = p_message_id)
      OR (p_message_id IS NULL AND o.message_id IS NULL
          AND o.bucket = p_bucket AND o.object_key = p_object_key
          AND o.etag = p_etag AND o.event_time = p_event_time)
   LIMIT 1;
  IF FOUND THEN
    -- Every field from the RECORDED row. Nothing here consults current state.
    out_row := (prior.id, prior.intent_id, prior.size_bytes, true, prior.intent_id IS NOT NULL);
    RETURN out_row;
  END IF;

  -- THE CAUSAL TEST (R72). An event the provider says happened before the
  -- intent existed cannot have been caused by it.
  SELECT id INTO v_intent FROM cd.upload_intents
   WHERE object_key = p_object_key
     AND created_at - app.provider_clock_skew_allowance() <= p_event_time;
  IF v_intent IS NOT NULL THEN
    i := app.lock_intent(v_intent);
  END IF;

  INSERT INTO cd.storage_observations
    (organization_id, world_id, intent_id, bucket, object_key, etag, size_bytes,
     action, event_time, message_id)
  VALUES (k.organization_id, k.world_id, v_intent, p_bucket, p_object_key, p_etag,
          p_size_bytes, p_action, p_event_time, p_message_id)
  ON CONFLICT DO NOTHING
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN
    -- A concurrent observer inserted the same delivery between the read above
    -- and this insert. Same rule: read the row that won, do not re-decide.
    SELECT o.id, o.intent_id, o.size_bytes INTO prior
      FROM cd.storage_observations o
     WHERE (p_message_id IS NOT NULL AND o.message_id = p_message_id)
        OR (p_message_id IS NULL AND o.message_id IS NULL
            AND o.bucket = p_bucket AND o.object_key = p_object_key
            AND o.etag = p_etag AND o.event_time = p_event_time)
     LIMIT 1;
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE = '40001',
        MESSAGE = 'CD-OBSERVE-CONCURRENT: the competing observation vanished; retry';
    END IF;
    out_row := (prior.id, prior.intent_id, prior.size_bytes, true, prior.intent_id IS NOT NULL);
    RETURN out_row;
  END IF;

  INSERT INTO cd.storage_objects
    (bucket, object_key, organization_id, world_id, etag, size_bytes,
     first_event_at, last_event_at, current_observation_id)
  VALUES (p_bucket, p_object_key, k.organization_id, k.world_id, p_etag, p_size_bytes,
          p_event_time, p_event_time, v_id)
  ON CONFLICT (bucket, object_key) DO NOTHING
  RETURNING size_bytes INTO v_after;

  IF v_after IS NOT NULL THEN
    v_delta := v_after;
  ELSE
    SELECT size_bytes INTO v_prior FROM cd.storage_objects
     WHERE bucket = p_bucket AND object_key = p_object_key
     FOR UPDATE;

    UPDATE cd.storage_objects so SET
      etag = CASE WHEN p_event_time >= so.last_event_at THEN p_etag ELSE so.etag END,
      size_bytes = CASE WHEN p_event_time >= so.last_event_at
                        THEN p_size_bytes ELSE so.size_bytes END,
      current_observation_id = CASE WHEN p_event_time >= so.last_event_at
                        THEN v_id ELSE so.current_observation_id END,
      first_event_at = LEAST   (so.first_event_at, p_event_time),
      last_event_at  = GREATEST(so.last_event_at,  p_event_time),
      event_count    = so.event_count + 1,
      overwrite_count = (SELECT greatest(count(DISTINCT o.etag) - 1, 0)
                           FROM cd.storage_observations o
                          WHERE o.bucket = p_bucket AND o.object_key = p_object_key),
      updated_at = now()
     WHERE so.bucket = p_bucket AND so.object_key = p_object_key
    RETURNING so.size_bytes INTO v_after;

    v_delta := v_after - v_prior;
  END IF;

  INSERT INTO cd.storage_usage (organization_id) VALUES (k.organization_id)
  ON CONFLICT (organization_id) DO UPDATE SET updated_at = now();
  UPDATE cd.storage_usage u
     SET committed_bytes = u.committed_bytes + v_delta, updated_at = now()
   WHERE u.organization_id = k.organization_id;

  IF v_intent IS NOT NULL THEN
    -- All three together, from one event (R74). The constraint above refuses
    -- any row where they disagree about whether there was an observation at all.
    UPDATE cd.upload_intents
       SET provider_observed_at     = now(),
           provider_event_at        = p_event_time,
           observing_observation_id = v_id
     WHERE id = v_intent AND provider_observed_at IS NULL;
  END IF;

  out_row := (v_id, v_intent, p_size_bytes, false, v_intent IS NOT NULL);
  RETURN out_row;
END;
$$;

COMMENT ON FUNCTION app.observe_storage_object(text, text, text, bigint, text, timestamptz, text) IS
  'Records one provider write event, projects current object state, and charges '
  'the byte ledger by the delta in that key''s occupancy (R68). A REDELIVERY '
  'returns the RECORDED decision -- id, intent, size -- and never re-derives it '
  'from current state (R73). Attribution requires the event to postdate the '
  'intent within the skew allowance (R72).';

RESET ROLE;
SET LOCAL ROLE computedriven_migrations;
REVOKE CREATE ON SCHEMA app FROM computedriven_ledger;

-- ---------------------------------------------------------------------------
-- 80. ONE PREDICATE. This is the battery's O0c verbatim -- api OR readonly, no
-- `_for` exemption -- so "the same assertion runs at apply time" is true rather
-- than nearly true.
-- ---------------------------------------------------------------------------
DO $$
DECLARE leaks text;
BEGIN
  SELECT string_agg(p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')', ', '
                    ORDER BY p.proname) INTO leaks
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    JOIN pg_roles     o ON o.oid = p.proowner
   WHERE n.nspname = 'app'
     AND p.prosecdef
     AND o.rolname = 'computedriven_ledger'
     AND pg_get_function_identity_arguments(p.oid) ~ 'uuid'
     AND p.proname ~ '^storage_'
     AND (has_function_privilege('computedriven_api', p.oid, 'EXECUTE')
          OR has_function_privilege('computedriven_readonly', p.oid, 'EXECUTE'));
  IF leaks IS NOT NULL THEN
    RAISE EXCEPTION 'CD-XTENANT-DEFINER: a request role can name a tenant through %', leaks;
  END IF;
END
$$;

DO $$
DECLARE writers text[];
BEGIN
  SELECT array_agg(p.proname ORDER BY p.proname) INTO writers
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'app'
     AND p.prosrc ~ 'UPDATE cd\.storage_usage[^;]*SET[^;]*committed_bytes[[:space:]]*=';
  IF writers IS DISTINCT FROM ARRAY['observe_storage_object'] THEN
    RAISE EXCEPTION 'CD-LEDGER-WRITERS: committed_bytes is written by % (R68 allows only observe_storage_object)',
      coalesce(array_to_string(writers, ', '), 'nothing');
  END IF;
END
$$;

COMMIT;
