-- 0026 — provider order, projection provenance, and the authority channel
--
-- Findings 82, 83 and 84 from outside review 2026-08-23 (the same pass that
-- produced 0025's three). All three reproduced against 0025 before this file
-- was written. A fourth hypothesis of my own is recorded at the bottom because
-- it was REFUTED by the measurement, and a refuted hypothesis is worth as much
-- shelf space as a confirmed one when the next session is deciding what to
-- re-derive.
--
-- ===========================================================================
-- 82. AT EQUAL eventTime, PROVIDER OCCUPANCY STILL DEPENDED ON OUR DELIVERY
--     ORDER.
--
-- R68 exists to say that a number describing the provider may only be moved by
-- the provider. 0021's projection guarded against a STALE event with
--
--     CASE WHEN p_event_time >= so.last_event_at THEN <arriving> ELSE <held> END
--
-- which is sound for 09:59 < 10:00 and silent at 10:00 == 10:00, where `>=` is
-- true and the LAST DELIVERED wins. Cloudflare documents eventTime as the time
-- the triggering action occurred, at millisecond resolution; it does not
-- document it as a sequence number or a total order, so equality is a state the
-- provider can genuinely produce.
--
-- MEASURED against 0025 (worker/test/tenant-isolation.sh group O now pins it;
-- the standalone repro is in the round-4 bundle §2.7). Two genuine writes to one
-- key, identical eventTime, delivered to two keys in the two orders:
--
--     key    delivered   projected etag   projected size
--     tie1   A -> B      "B"              20
--     tie2   B -> A      "A"              10
--     committed_bytes for BOTH keys together: 30
--
-- 30 is neither of the two order-independent answers. The same provider facts
-- produced two different truths, and the ledger charged the average of a
-- coin-flip. O5 could not see this: it varies which event is OLDER, and this is
-- the case where neither is.
--
--     R75 -- A PROJECTION OF A SET OF OBSERVATIONS IS A FUNCTION OF THE SET,
--     NOT OF THE ORDER WE SAW THEM IN.
--
-- The fix is not a tiebreak. A lexical tiebreak on etag or message id would buy
-- determinism and spend correctness: it would state, in a column the rest of
-- the system reads as provider truth, an answer we invented. What is actually
-- true is that at a tied maximum eventTime with disagreeing object states, WE
-- DO NOT KNOW which write is current, and only R2 does.
--
-- So the projection is DERIVED from the observation set rather than patched
-- incrementally, which makes order-independence structural instead of
-- defended -- the same move as 0023 dropping `reserved_bytes` in favour of a
-- derivation, where the bug stopped existing rather than getting a guard:
--
--   * size_bytes  = max(size) over the tied tip. Conservative for quota, and
--                   max() is a set function so both delivery orders converge.
--   * etag        = NULL when the tip disagrees. Nullable now, because NOT NULL
--                   was forcing the column to assert something we do not have.
--   * current_observation_id = NULL when the tip disagrees, for the same reason:
--                   *which* observation is current is exactly the open question.
--   * ambiguous_event_at = the tied provider instant. NULL means the tip is one
--                   state. It is DERIVED, so a later event with a strictly
--                   greater eventTime clears it without anything resolving it.
--
-- The ambiguity is a refusable divergence, not a silent one: it is surfaced in
-- app.storage_divergence() as `ambiguous`, and reconcile can settle it with a
-- HEAD against the real object. If case C later proves `If-None-Match: *` makes
-- ordinary content-addressed chunks write-once through the presigned path, this
-- state should be UNREACHABLE for normal chunks and becomes a useful alarm.
--
-- ---------------------------------------------------------------------------
-- 83. R74's CLAIM WAS STRONGER THAN THE SCHEMA'S PROOF OF IT.
--
-- 0025 added `observing_observation_id` and said: the two clocks are that
-- observation's projection. What PostgreSQL actually enforced was weaker --
--
--     FK     observing_observation_id -> SOME storage_observations.id
--     CHECK  the three fields are all NULL or all non-NULL
--
-- and NOT that the named observation belongs to THIS intent, nor that the
-- copied timestamps are that row's. O21 is a positive witness: one correctly
-- created row has matching values. It is not a negative proof. Since
-- `computedriven_ledger` retains direct INSERT/UPDATE on both tables, and the
-- write-once trigger only stops a SECOND assignment, the FIRST assignment could
-- name the wrong observation and nothing would refuse it.
--
--     R76 -- A COLUMN THAT COPIES ANOTHER TABLE'S FACT MUST BE A FOREIGN KEY TO
--     THAT FACT. OTHERWISE IT IS NOT A COPY; IT IS A SECOND INDEPENDENT CLAIM
--     THAT HAPPENS TO AGREE TODAY.
--
-- A four-column composite foreign key states the projection as a database
-- truth, so O24/O25 below are probes of a structure rather than of a
-- convention. This is cheaper and stricter than a constraint trigger and it
-- needs no new code path:
--
--     (observing_observation_id, id, provider_event_at, provider_observed_at)
--       -> storage_observations (id, intent_id, event_time, observed_at)
--
-- Note what the second column does. `id` is the intent's own primary key, so
-- the FK reads: the observation you name must have YOUR id in its intent_id.
-- An observation belonging to intent B is unnameable by intent A, and an
-- unattributed observation (intent_id NULL) is unnameable by anyone, because
-- NULL never equals anything in an FK match.
--
-- The observer is also changed to copy `observed_at` out of the row it just
-- inserted rather than calling now() a second time. Those agree today -- both
-- are the transaction timestamp -- and agreeing by coincidence is the thing
-- R76 is about.
--
-- ---------------------------------------------------------------------------
-- 84. A MESSAGE ID WITHOUT ITS QUEUE IS NOT A DELIVERY IDENTITY.
--
-- R57 narrowed "event identity" to DELIVERY identity because R2's notification
-- body carries no event id at all. 0022 then stored `message_id` alone and made
-- it unique alone. Cloudflare describes Message.id as "a unique,
-- system-generated ID for the message" and documents no cross-queue uniqueness
-- scope, while MessageBatch.queue names the channel on every batch. So the
-- uniqueness the accounting rests on is scoped to something the row does not
-- record.
--
--     R77 -- DELIVERY IDENTITY NAMES THE CHANNEL THAT DELIVERED IT. AUTHORITY
--     CARRIES ITS PROVENANCE; IT DOES NOT MERELY ARRIVE BEARING PLAUSIBLE DATA.
--
-- This is the schema half. The architectural half -- that the provider
-- notification queue is a dedicated R2-only authority channel, because
-- Cloudflare documents that ANY Worker with a producer binding can write to a
-- queue and the consumer has no cryptographic R2 provenance inside the body --
-- is ruled in CLOUD_V1.md §6.8 and CHECKED by scripts/check-queue-authority.mjs
-- against the live account. It is a provisioning gate, not a database
-- constraint, and it runs BEFORE live falsifier case D.
--
-- The seven-argument observer is DROPPED rather than overloaded. An overload
-- with a defaulted queue would let a caller that forgot the channel keep
-- resolving, and the whole finding is that a forgotten channel is invisible.

BEGIN;

SET LOCAL ROLE computedriven_migrations;

-- ---------------------------------------------------------------------------
-- 82. The columns "we do not know" needs in order to be sayable.
-- ---------------------------------------------------------------------------
ALTER TABLE cd.storage_objects ADD COLUMN ambiguous_event_at timestamptz;
ALTER TABLE cd.storage_objects ALTER COLUMN etag DROP NOT NULL;

COMMENT ON COLUMN cd.storage_objects.ambiguous_event_at IS
  'The provider instant at which two or more observations of this key disagree '
  'about its state, and therefore the instant at which we do not know what is '
  'current. NULL means the newest eventTime carries exactly one (etag, size). '
  'DERIVED from the observation set, so a later event with a strictly greater '
  'eventTime clears it (R75, finding 82).';

COMMENT ON COLUMN cd.storage_objects.etag IS
  'NULL exactly when ambiguous_event_at is set. NOT NULL until 0026, which '
  'meant the column had to name one of two etags we cannot choose between; a '
  'lexical tiebreak would have been determinism bought with a fabricated fact.';

-- ---------------------------------------------------------------------------
-- The projection, defined ONCE, as a function of the observation set.
--
-- Every value here is an aggregate or a min/max over a set, so it cannot depend
-- on insertion order. That is the whole point: order-independence is a property
-- of the expression rather than a guard bolted onto an incremental update.
--
-- current_observation_id uses min(id) over the tip rather than "the one we just
-- inserted" or "the last one observed". The tip rows agree on (etag, size) when
-- it is unambiguous, so the choice is semantically immaterial -- but min() is a
-- set function and `observed_at DESC` is our delivery history, which is exactly
-- what R68 says must not decide provider truth.
-- ---------------------------------------------------------------------------
CREATE FUNCTION app.project_object_state(p_bucket text, p_object_key text)
RETURNS TABLE (
  etag                   text,
  size_bytes             bigint,
  first_event_at         timestamptz,
  last_event_at          timestamptz,
  event_count            integer,
  overwrite_count        integer,
  current_observation_id uuid,
  ambiguous_event_at     timestamptz
)
LANGUAGE sql
STABLE
SET search_path = cd, pg_temp
AS $$
  WITH obs AS (
    SELECT o.id, o.etag, o.size_bytes, o.event_time
      FROM cd.storage_observations o
     WHERE o.bucket = p_bucket AND o.object_key = p_object_key
  ),
  tip AS (
    SELECT * FROM obs WHERE event_time = (SELECT max(event_time) FROM obs)
  ),
  verdict AS (
    SELECT count(DISTINCT (etag, size_bytes)) > 1 AS ambiguous,
           max(size_bytes)                        AS size_bytes,
           max(event_time)                        AS at
      FROM tip
  )
  SELECT CASE WHEN v.ambiguous THEN NULL ELSE (SELECT min(t.etag) FROM tip t) END,
         v.size_bytes,
         (SELECT min(event_time) FROM obs),
         (SELECT max(event_time) FROM obs),
         (SELECT count(*) FROM obs)::integer,
         (SELECT greatest(count(DISTINCT etag) - 1, 0) FROM obs)::integer,
         -- ORDER BY id LIMIT 1 rather than min(): PostgreSQL has no min(uuid).
         -- Still a set function -- the smallest id in the tip, not the first one
         -- we happened to store.
         CASE WHEN v.ambiguous THEN NULL
              ELSE (SELECT t.id FROM tip t ORDER BY t.id LIMIT 1) END,
         CASE WHEN v.ambiguous THEN v.at ELSE NULL END
    FROM verdict v
   WHERE EXISTS (SELECT 1 FROM obs);
$$;

COMMENT ON FUNCTION app.project_object_state(text, text) IS
  'Current state of one key, as a pure function of its observation set. Returns '
  'no row when the key has no observations. size_bytes is max() over the newest '
  'eventTime, which is conservative for quota AND order-independent; etag and '
  'current_observation_id go NULL when that tip disagrees with itself, because '
  'the honest answer is that only R2 knows (R75, finding 82).';

-- 0018's event trigger strips PUBLIC EXECUTE from everything created in app, so
-- a new helper is unreachable until it is named. INVOKER rights deliberately:
-- it reads cd.storage_observations under the caller's RLS, and the only caller
-- that needs to see every tenant's rows is the SECURITY DEFINER observer, which
-- runs as its owner.
GRANT EXECUTE ON FUNCTION app.project_object_state(text, text)
  TO computedriven_ledger, computedriven_jobs;

-- Re-derive every existing row through the new projection, and move the ledger
-- by exactly what the re-derivation changed. On a from-scratch apply this
-- touches nothing; on a populated database it is the difference between the
-- coin-flip answer and the order-independent one, and leaving committed_bytes
-- un-adjusted would make R68's own invariant false at the moment we ruled it.
CREATE TEMP TABLE _prior_object_sizes ON COMMIT DROP AS
  SELECT bucket, object_key, organization_id, size_bytes FROM cd.storage_objects;

UPDATE cd.storage_objects so SET
  etag                   = s.etag,
  size_bytes             = s.size_bytes,
  first_event_at         = s.first_event_at,
  last_event_at          = s.last_event_at,
  event_count            = s.event_count,
  overwrite_count        = s.overwrite_count,
  current_observation_id = s.current_observation_id,
  ambiguous_event_at     = s.ambiguous_event_at,
  updated_at             = now()
FROM (
  SELECT o.bucket, o.object_key, p.*
    FROM (SELECT bucket, object_key FROM cd.storage_objects) o
    CROSS JOIN LATERAL app.project_object_state(o.bucket, o.object_key) p
) s
WHERE so.bucket = s.bucket AND so.object_key = s.object_key;

UPDATE cd.storage_usage u
   SET committed_bytes = u.committed_bytes + d.delta, updated_at = now()
  FROM (SELECT so.organization_id, sum(so.size_bytes - p.size_bytes) AS delta
          FROM cd.storage_objects so
          JOIN _prior_object_sizes p
            ON p.bucket = so.bucket AND p.object_key = so.object_key
         GROUP BY so.organization_id) d
 WHERE u.organization_id = d.organization_id AND d.delta <> 0;

-- An object row with no observations would survive the re-derivation untouched
-- and then violate the CHECK below with a message about a constraint rather
-- than about the cause. It cannot happen -- the observer inserts the
-- observation first -- so say so here, where the failure names itself.
DO $$
DECLARE orphans bigint;
BEGIN
  SELECT count(*) INTO orphans FROM cd.storage_objects so
   WHERE NOT EXISTS (SELECT 1 FROM cd.storage_observations o
                      WHERE o.bucket = so.bucket AND o.object_key = so.object_key);
  IF orphans > 0 THEN
    RAISE EXCEPTION 'CD-OBJECT-UNOBSERVED: % object row(s) have no observation to project from; '
                    'storage_objects is supposed to be derived and these are not', orphans;
  END IF;
END
$$;

ALTER TABLE cd.storage_objects
  ADD CONSTRAINT storage_objects_ambiguity_ck
  CHECK ((etag IS NULL) = (ambiguous_event_at IS NOT NULL)
     AND (current_observation_id IS NULL) = (ambiguous_event_at IS NOT NULL));

-- ---------------------------------------------------------------------------
-- 83. The projection, as a database truth rather than an observer convention.
--
-- The repair first. 0025's re-backfill set observing_observation_id and
-- provider_event_at together but left provider_observed_at wherever it already
-- was, so a migrated row can disagree with the observation it now names -- and
-- the write-once trigger, correctly, refuses to let anyone fix that. Disabling
-- it for one statement is the narrow exception; re-enabling is not optional and
-- E5 below proves it happened.
-- ---------------------------------------------------------------------------
ALTER TABLE cd.upload_intents DISABLE TRIGGER upload_intents_observed_final;

UPDATE cd.upload_intents i
   SET provider_observed_at = o.observed_at
  FROM cd.storage_observations o
 WHERE o.id = i.observing_observation_id
   AND i.provider_observed_at IS DISTINCT FROM o.observed_at;

ALTER TABLE cd.upload_intents ENABLE TRIGGER upload_intents_observed_final;

ALTER TABLE cd.storage_observations
  ADD CONSTRAINT storage_observations_projection_uq
  UNIQUE (id, intent_id, event_time, observed_at);

COMMENT ON CONSTRAINT storage_observations_projection_uq ON cd.storage_observations IS
  'Exists only so upload_intents can foreign-key the whole projection at once. '
  'id alone is already unique; the other three columns are here to be the '
  'referenced tuple (R76, finding 83).';

-- The single-column FK 0025 added is subsumed by the composite one. Dropped by
-- name, and the DO block after it fails loudly if the name was different --
-- which is the only way a stale FK could survive this file unnoticed.
ALTER TABLE cd.upload_intents
  DROP CONSTRAINT IF EXISTS upload_intents_observing_observation_id_fkey;

ALTER TABLE cd.upload_intents
  ADD CONSTRAINT upload_intents_observation_projection_fk
  FOREIGN KEY (observing_observation_id, id, provider_event_at, provider_observed_at)
  REFERENCES cd.storage_observations (id, intent_id, event_time, observed_at)
  ON DELETE RESTRICT;

COMMENT ON CONSTRAINT upload_intents_observation_projection_fk ON cd.upload_intents IS
  'The observation this intent names must have THIS intent''s id in its '
  'intent_id, and the two copied clocks must be that row''s. Column 2 is the '
  'intent''s own primary key, which is what turns a plain reference into a '
  'relational proof (R76, finding 83).';

DO $$
DECLARE stale text;
BEGIN
  SELECT string_agg(c.conname, ', ') INTO stale
    FROM pg_constraint c
   WHERE c.conrelid = 'cd.upload_intents'::regclass
     AND c.contype = 'f'
     AND c.confrelid = 'cd.storage_observations'::regclass
     AND array_length(c.conkey, 1) = 1;
  IF stale IS NOT NULL THEN
    RAISE EXCEPTION 'CD-PROJECTION-WEAK-FK: % still references storage_observations by id alone; '
                    'the composite FK is the proof and a single-column one beside it is a door', stale;
  END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- 84. Delivery identity gains its channel.
-- ---------------------------------------------------------------------------
ALTER TABLE cd.storage_observations ADD COLUMN queue_name text;

COMMENT ON COLUMN cd.storage_observations.queue_name IS
  'The Cloudflare Queue that delivered this message -- MessageBatch.queue, not '
  'anything the producer put in the body. Message.id is documented as unique '
  'but with no stated cross-queue scope, so (queue_name, message_id) is the '
  'identity the exactly-once accounting actually rests on (R77, finding 84).';

ALTER TABLE cd.storage_observations
  ADD CONSTRAINT storage_observations_delivery_channel_ck
  CHECK (message_id IS NULL OR (queue_name IS NOT NULL AND btrim(queue_name) <> ''));

DROP INDEX cd.storage_observations_message_uq;

CREATE UNIQUE INDEX storage_observations_delivery_uq
  ON cd.storage_observations (queue_name, message_id) WHERE message_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- The observer.
-- ---------------------------------------------------------------------------
GRANT CREATE ON SCHEMA app TO computedriven_ledger;
SET LOCAL ROLE computedriven_ledger;

DROP FUNCTION app.observe_storage_object(text, text, text, bigint, text, timestamptz, text);

CREATE FUNCTION app.observe_storage_object(
  p_bucket     text,
  p_object_key text,
  p_etag       text,
  p_size_bytes bigint,
  p_action     text,
  p_event_time timestamptz,
  p_message_id text DEFAULT NULL,
  -- The channel reads better BEFORE the id it scopes, and it is second anyway,
  -- on purpose. With the channel first, an un-updated seven-argument call binds
  -- its message id to p_queue and records a fallback observation with a queue
  -- name -- wrong, and silent. Second, the same call leaves p_queue NULL and
  -- hits CD-OBSERVE-CHANNEL. Signature order chosen so the stale caller is the
  -- one that breaks.
  p_queue      text DEFAULT NULL
)
RETURNS app.observation_result
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cd, pg_temp
AS $$
DECLARE
  k          record;
  v_intent   uuid;
  i          cd.upload_intents;
  v_id       uuid;
  v_observed timestamptz;
  prior      record;
  v_prior    bigint;
  v_after    bigint;
  v_delta    bigint;
  out_row    app.observation_result;
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
  -- R77. A message id whose channel is unnamed is a string that was unique
  -- somewhere. Refused here rather than at the CHECK so the caller gets the
  -- reason instead of a constraint name.
  IF p_message_id IS NOT NULL AND (p_queue IS NULL OR btrim(p_queue) = '') THEN
    RAISE EXCEPTION USING ERRCODE = '22023',
      MESSAGE = 'CD-OBSERVE-CHANNEL: a delivery identity must name the queue that delivered it';
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

  -- THE REPLAY CHECK COMES FIRST (R73). Every returned field is the recorded
  -- one; nothing here consults current state. The lookup uses the whole key its
  -- uniqueness is built on -- now (queue_name, message_id) for a delivery, and
  -- (bucket, key, etag, event_time) for a caller that has no delivery at all.
  SELECT o.id, o.intent_id, o.size_bytes INTO prior
    FROM cd.storage_observations o
   WHERE (p_message_id IS NOT NULL AND o.queue_name = p_queue AND o.message_id = p_message_id)
      OR (p_message_id IS NULL AND o.message_id IS NULL
          AND o.bucket = p_bucket AND o.object_key = p_object_key
          AND o.etag = p_etag AND o.event_time = p_event_time)
   LIMIT 1;
  IF FOUND THEN
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
     action, event_time, queue_name, message_id)
  VALUES (k.organization_id, k.world_id, v_intent, p_bucket, p_object_key, p_etag,
          p_size_bytes, p_action, p_event_time, p_queue, p_message_id)
  ON CONFLICT DO NOTHING
  RETURNING id, observed_at INTO v_id, v_observed;

  IF v_id IS NULL THEN
    -- A concurrent observer inserted the same delivery between the read above
    -- and this insert. Same rule: read the row that won, do not re-decide.
    SELECT o.id, o.intent_id, o.size_bytes INTO prior
      FROM cd.storage_observations o
     WHERE (p_message_id IS NOT NULL AND o.queue_name = p_queue AND o.message_id = p_message_id)
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

  -- THE PROJECTION (R75). Derived from the observation set both times, so the
  -- insert branch and the update branch are the same rule rather than two
  -- similar ones -- 0023 lost 0016's whole contribution to a CREATE OR REPLACE
  -- written from an older body, and two near-identical arms is how that
  -- happens.
  INSERT INTO cd.storage_objects
    (bucket, object_key, organization_id, world_id, etag, size_bytes,
     first_event_at, last_event_at, event_count, overwrite_count,
     current_observation_id, ambiguous_event_at)
  SELECT p_bucket, p_object_key, k.organization_id, k.world_id,
         s.etag, s.size_bytes, s.first_event_at, s.last_event_at,
         s.event_count, s.overwrite_count, s.current_observation_id,
         s.ambiguous_event_at
    FROM app.project_object_state(p_bucket, p_object_key) s
  ON CONFLICT (bucket, object_key) DO NOTHING
  RETURNING size_bytes INTO v_after;

  IF v_after IS NOT NULL THEN
    v_prior := 0;
  ELSE
    -- The row lock is what serialises two observers of the same key. Taken
    -- before the projection is re-evaluated, so the UPDATE's snapshot includes
    -- whatever the competitor committed while we waited.
    SELECT size_bytes INTO v_prior FROM cd.storage_objects
     WHERE bucket = p_bucket AND object_key = p_object_key
     FOR UPDATE;

    UPDATE cd.storage_objects so SET
      etag                   = s.etag,
      size_bytes             = s.size_bytes,
      first_event_at         = s.first_event_at,
      last_event_at          = s.last_event_at,
      event_count            = s.event_count,
      overwrite_count        = s.overwrite_count,
      current_observation_id = s.current_observation_id,
      ambiguous_event_at     = s.ambiguous_event_at,
      updated_at             = now()
      FROM app.project_object_state(p_bucket, p_object_key) s
     WHERE so.bucket = p_bucket AND so.object_key = p_object_key
    RETURNING so.size_bytes INTO v_after;
  END IF;

  IF v_after IS NULL THEN
    -- Unreachable: the observation above is in this transaction, so the
    -- projection has at least one row to work from. Named rather than left to
    -- become `committed_bytes = NULL` three statements later.
    RAISE EXCEPTION USING ERRCODE = 'XX000',
      MESSAGE = 'CD-OBSERVE-PROJECTION: the projection returned no state for a key we just observed';
  END IF;
  v_delta := v_after - v_prior;

  INSERT INTO cd.storage_usage (organization_id) VALUES (k.organization_id)
  ON CONFLICT (organization_id) DO UPDATE SET updated_at = now();
  UPDATE cd.storage_usage u
     SET committed_bytes = u.committed_bytes + v_delta, updated_at = now()
   WHERE u.organization_id = k.organization_id;

  IF v_intent IS NOT NULL THEN
    -- All four together, from one row (R74/R76). provider_observed_at is COPIED
    -- out of the observation rather than being a second now(): they agree today
    -- because both are the transaction timestamp, and agreeing by coincidence
    -- is exactly what the composite FK is there to stop being load-bearing.
    UPDATE cd.upload_intents
       SET provider_observed_at     = v_observed,
           provider_event_at        = p_event_time,
           observing_observation_id = v_id
     WHERE id = v_intent AND provider_observed_at IS NULL;
  END IF;

  out_row := (v_id, v_intent, p_size_bytes, false, v_intent IS NOT NULL);
  RETURN out_row;
END;
$$;

COMMENT ON FUNCTION app.observe_storage_object(text, text, text, bigint, text, timestamptz, text, text) IS
  'Records one provider write event, DERIVES current object state from that '
  'key''s whole observation set (R75), and charges the byte ledger by the delta '
  'in occupancy (R68). A redelivery returns the RECORDED decision and never '
  're-derives it (R73). Attribution requires the event to postdate the intent '
  'within the skew allowance (R72). A message id must name its queue (R77).';

-- ---------------------------------------------------------------------------
-- Divergence has to SEE the ambiguity, not drop it.
--
-- 0024 joined the object through `so.current_observation_id = ob.id`. Under R75
-- that column goes NULL exactly when the key is ambiguous, which would have
-- silently removed the ambiguous object from observed_bytes -- an ambiguity
-- report that hides ambiguity, in the one query whose job is surfacing
-- divergence. The join now runs on the key, and `ambiguous` is a column.
--
-- (A hypothesis that this join was ALREADY dropping objects -- via an
-- unattributed overwrite moving current_observation_id off the attributed row
-- -- was REFUTED by measurement: attribution is by object_key and is stable, so
-- a later write to the same key attributes to the same intent. Recorded so the
-- next reader does not spend the same hour on it.)
-- ---------------------------------------------------------------------------
RESET ROLE;
SET LOCAL ROLE computedriven_migrations;

-- DROP + CREATE DISCARDS THE ACL. `CREATE OR REPLACE` keeps a function's grants;
-- dropping it and creating a new signature does not, and 0017's
-- `GRANT ... TO computedriven_jobs` was five files back. MEASURED, before this
-- block existed: 33 battery failures, every one of them
-- `permission denied for function observe_storage_object`, from a migration
-- that applied cleanly. Sibling of 0023's CREATE-OR-REPLACE trap from the other
-- side -- there, replacing kept too much; here, dropping kept too little.
REVOKE EXECUTE ON FUNCTION
  app.observe_storage_object(text, text, text, bigint, text, timestamptz, text, text)
FROM PUBLIC;

-- The consumer is a JOB, not a request. The API role must not be able to tell
-- the ledger that bytes landed -- that is the client-asserted path R68 replaced.
GRANT EXECUTE ON FUNCTION
  app.observe_storage_object(text, text, text, bigint, text, timestamptz, text, text)
TO computedriven_jobs;

DO $$
BEGIN
  IF NOT has_function_privilege('computedriven_jobs',
       'app.observe_storage_object(text,text,text,bigint,text,timestamptz,text,text)', 'EXECUTE') THEN
    RAISE EXCEPTION 'CD-OBSERVE-UNREACHABLE: the queue consumer cannot call the observer';
  END IF;
  IF has_function_privilege('computedriven_api',
       'app.observe_storage_object(text,text,text,bigint,text,timestamptz,text,text)', 'EXECUTE') THEN
    RAISE EXCEPTION 'CD-OBSERVE-CLIENTPATH: the API role can assert provider observations';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
              WHERE n.nspname = 'app' AND p.proname = 'observe_storage_object'
                AND p.pronargs <> 8) THEN
    RAISE EXCEPTION 'CD-OBSERVE-OVERLOAD: an observer overload without the channel survives';
  END IF;
END
$$;

DROP FUNCTION app.storage_divergence();
DROP FUNCTION app.storage_divergence_for(uuid);

SET LOCAL ROLE computedriven_ledger;

CREATE FUNCTION app.storage_divergence_for(p_organization_id uuid DEFAULT NULL)
RETURNS TABLE (
  reservation_id  uuid,
  organization_id uuid,
  asserted_bytes  bigint,
  observed_bytes  bigint,
  delta           bigint,
  overwrites      bigint,
  ambiguous       bigint
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = cd, pg_temp
STABLE
AS $$
  SELECT r.id, r.organization_id,
         coalesce(r.asserted_bytes, 0)::bigint AS asserted_bytes,
         coalesce(o.total, 0)::bigint          AS observed_bytes,
         (coalesce(o.total, 0) - coalesce(r.asserted_bytes, 0))::bigint AS delta,
         coalesce(o.overwrites, 0)::bigint     AS overwrites,
         coalesce(o.ambiguous, 0)::bigint      AS ambiguous
  FROM cd.storage_reservations r
  LEFT JOIN LATERAL (
    SELECT sum(so.size_bytes)      AS total,
           sum(so.overwrite_count) AS overwrites,
           count(*) FILTER (WHERE so.ambiguous_event_at IS NOT NULL) AS ambiguous
      FROM (SELECT DISTINCT ob.bucket, ob.object_key
              FROM cd.upload_intents i
              JOIN cd.storage_observations ob ON ob.intent_id = i.id
             WHERE i.reservation_id = r.id) keys
      JOIN cd.storage_objects so
        ON so.bucket = keys.bucket AND so.object_key = keys.object_key
  ) o ON true
  WHERE (p_organization_id IS NULL OR r.organization_id = p_organization_id)
    AND (coalesce(o.total, 0)      IS DISTINCT FROM coalesce(r.asserted_bytes, 0)
         OR coalesce(o.overwrites, 0) > 0
         OR coalesce(o.ambiguous, 0) > 0);
$$;

COMMENT ON FUNCTION app.storage_divergence_for(uuid) IS
  'CROSS-TENANT, and NULL means EVERY tenant -- which is why this is jobs-only '
  'and why the API form has no argument (0024, finding 72). Joins object to '
  'reservation BY KEY, not through current_observation_id, which goes NULL on '
  'an ambiguous tip and would have hidden exactly the rows this exists to show '
  '(0026, R75).';

CREATE FUNCTION app.storage_divergence()
RETURNS TABLE (
  reservation_id  uuid,
  organization_id uuid,
  asserted_bytes  bigint,
  observed_bytes  bigint,
  delta           bigint,
  overwrites      bigint,
  ambiguous       bigint
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = cd, pg_temp
STABLE
AS $$ SELECT * FROM app.storage_divergence_for(app.current_organization_id()); $$;

COMMENT ON FUNCTION app.storage_divergence() IS
  'Where THIS tenant''s client assertions and provider occupancy disagree, plus '
  'how many of its objects the provider has left ambiguous. No organization '
  'argument, for the reason in app.storage_ledger() (0024).';

RESET ROLE;
SET LOCAL ROLE computedriven_migrations;
REVOKE CREATE ON SCHEMA app FROM computedriven_ledger;

REVOKE EXECUTE ON FUNCTION app.storage_divergence_for(uuid) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION app.storage_divergence()        FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION app.storage_divergence_for(uuid) TO computedriven_jobs;
GRANT  EXECUTE ON FUNCTION app.storage_divergence()         TO computedriven_api, computedriven_readonly;

-- ---------------------------------------------------------------------------
-- Apply-time assertions. Same predicates the battery runs, verbatim, because
-- 0025's finding 80 was two copies of "the same" gate that were not the same.
-- ---------------------------------------------------------------------------

-- O0c, unchanged: no ledger-owned SECURITY DEFINER storage function taking a
-- uuid may be reachable by a request role. `storage_divergence_for(uuid)` was
-- just recreated, so this is not a formality.
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

-- R75, stated as a gate rather than as a comment: nothing in the request or job
-- path may decide current object state with a comparison against the state it
-- is replacing. The pattern `>= so.last_event_at` IS the finding-82 defect, and
-- a future CREATE OR REPLACE written from an older body would reintroduce it
-- silently -- which is exactly how 0023 reverted 0016.
DO $$
DECLARE offenders text;
BEGIN
  SELECT string_agg(p.proname, ', ' ORDER BY p.proname) INTO offenders
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'app'
     AND p.prosrc ~ '>=[[:space:]]*so\.last_event_at';
  IF offenders IS NOT NULL THEN
    RAISE EXCEPTION 'CD-ORDER-DEPENDENT: % projects object state by comparing against the row '
                    'it is replacing; at equal eventTime that is last-delivered-wins (R75)', offenders;
  END IF;
END
$$;

-- R76, stated as a gate: the projection FK must exist and must carry all four
-- columns. A three-column version would still prove intent ownership and
-- silently stop proving the clocks.
DO $$
DECLARE n integer;
BEGIN
  SELECT array_length(c.conkey, 1) INTO n
    FROM pg_constraint c
   WHERE c.conname = 'upload_intents_observation_projection_fk'
     AND c.conrelid = 'cd.upload_intents'::regclass;
  IF n IS DISTINCT FROM 4 THEN
    RAISE EXCEPTION 'CD-PROJECTION-FK: the observation projection FK covers % column(s), not 4 (R76)',
      coalesce(n::text, 'no');
  END IF;
END
$$;

-- E5's apply-time half: the write-once trigger was disabled for one repair
-- statement above and a migration that forgot to re-enable it would leave
-- provider truth revisable with nothing complaining.
DO $$
DECLARE st "char";
BEGIN
  SELECT t.tgenabled INTO st FROM pg_trigger t
   WHERE t.tgrelid = 'cd.upload_intents'::regclass
     AND t.tgname = 'upload_intents_observed_final';
  IF st IS DISTINCT FROM 'O' THEN
    RAISE EXCEPTION 'CD-TRIGGER-LEFT-OFF: upload_intents_observed_final is %, not enabled; '
                    '0026 disables it for one repair statement and must put it back',
      coalesce(st::text, 'missing');
  END IF;
END
$$;

COMMIT;
