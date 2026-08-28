-- 0021 — an event log is not an inventory (R32, still OPEN)
--
-- ---------------------------------------------------------------------------
-- THE DEFECT
--
-- 0017 stores provider evidence in cd.storage_observations, keyed
--
--     UNIQUE (bucket, object_key, etag)
--
-- which is exactly right for what it was built for: Cloudflare Queues delivers
-- AT LEAST ONCE, so the same write can arrive twice and the unique key is what
-- turns redelivery into a no-op instead of a second charge.
--
-- Then app.storage_divergence() computed provider bytes by SUMMING those rows.
-- That is a different question, and the answer is wrong whenever a key is
-- written more than once. Cloudflare documents that an object-create
-- notification also fires when an existing object is OVERWRITTEN:
--
--     chunk/foo   PUT       10 bytes, etag A
--     chunk/foo   overwrite 12 bytes, etag B
--
--     sum of observations   22 bytes      <- what 0017 reported
--     actual R2 occupancy   12 bytes      <- what is true
--
-- Keying by etag makes the LOG correct and does nothing for the INVENTORY. Two
-- rows is the right answer to "what happened" and the wrong answer to "what is
-- stored".
--
--     AN APPEND-ONLY LOG OF WRITE EVENTS CANNOT BE READ AS CURRENT OCCUPANCY,
--     AND THE UNIQUENESS KEY THAT MAKES THE LOG CORRECT IS PRECISELY WHAT
--     STOPS IT FROM BEING AN INVENTORY.
--
-- So the two are separated:
--
--     cd.storage_observations   append-only provider evidence   (bucket,key,etag)
--     cd.storage_objects        current provider state          (bucket,key)
--
--     billing / occupancy   ->  storage_objects
--     audit / provenance    ->  storage_observations
--
-- ---------------------------------------------------------------------------
-- WHY NOT JUST RULE OVERWRITE ILLEGAL?
--
-- It was the other option on the table, and for content-addressed chunks it is
-- tempting: if the key IS the hash, a different-etag overwrite is a hash
-- collision, a client writing content that does not match the key it asked for,
-- or a multipart upload -- and multipart is not authorized. All three are alarms
-- rather than normal operation.
--
-- It is not taken as the whole answer for two reasons.
--
--   1. app.parse_object_key() accepts `org/<uuid>/world/<uuid>/` followed by ANY
--      non-empty remainder. Nothing in this schema requires that remainder to be
--      a digest. Content addressing is a convention of the client today, and
--      building the accounting on a convention the database does not enforce is
--      how the last four rounds' findings happened.
--
--   2. Refusing to record an overwrite would not stop R2 accepting it. The same
--      R8 lesson as R31: the write is on a wire we do not see, so our options are
--      to MEASURE it or to be wrong about it.
--
-- So: the projection is correct arithmetic either way, AND a different-etag
-- overwrite is counted and surfaced rather than silently absorbed. If R32's live
-- falsifier shows write-once cannot be enforced through the presigned path, the
-- number is already being collected.
--
-- ---------------------------------------------------------------------------
-- ORDERING, which the review did not raise and which breaks this if ignored
--
-- Queues guarantees at-least-once delivery. It does NOT guarantee order. A
-- projection that blindly takes the newest message as current state will happily
-- apply a redelivered older write on top of a newer one and report stale bytes
-- forever. Every field that represents "now" is therefore guarded by
-- event_time, and the guard is the reason this is an UPSERT with a CASE rather
-- than a plain DO UPDATE SET.
--
-- ---------------------------------------------------------------------------
-- WHAT THIS STILL CANNOT SEE
--
-- Deletion. observe_storage_object() accepts only PutObject / CopyObject /
-- CompleteMultipartUpload; no delete event is consumed anywhere, so an object
-- removed out of band stays in this table. cd.storage_objects is therefore
-- current state FOR OBJECTS THAT WERE CREATED, and occupancy is a high-water
-- mark against deletion.
--
-- There is deliberately no `present boolean` column standing in for the part
-- that is not built. A column that is always true is a claim the code does not
-- support -- the same shape as the 'abandoned' state that nothing could reach
-- until 0019 gave it app.abandon_upload().

-- ---------------------------------------------------------------------------
-- FINDING 59, found by writing the checks below rather than by reading anything.
-- THE ENTIRE R32 CONSUMER PATH WAS UNREACHABLE.
--
-- app.observe_storage_object() is SECURITY DEFINER owned by computedriven_ledger
-- and it asks:
--
--     IF NOT EXISTS (SELECT 1 FROM cd.organizations o WHERE o.id = ...) THEN
--       RAISE 'CD-OBSERVE-ORG: the key names an organization that does not exist'
--
-- cd.organizations has FORCE ROW LEVEL SECURITY and exactly three policies:
--
--     organizations_tenant      id = app.current_organization_id()
--     organizations_owner       true   (computedriven_migrations)
--     organizations_bootstrap   status = 'active'   (computedriven_bootstrap)
--
-- None of them names computedriven_ledger. 0014 granted the ledger SELECT on
-- cd.organizations and gave cd.worlds a `worlds_ledger` policy to match -- and
-- did not give cd.organizations one. So the ledger holds a GRANT that returns
-- zero rows, and the consumer runs deliberately WITHOUT tenant context because
-- a queue consumer is cross-tenant by nature, which means current_organization_id()
-- cannot save it either.
--
--     EVERY R2 EVENT, INCLUDING EVERY VALID ONE, WOULD HAVE BEEN REFUSED
--     WITH "the key names an organization that does not exist".
--
-- Measured on 17.10: as computedriven_ledger, `SELECT count(*) FROM
-- cd.organizations` returns 0 with a row present.
--
-- 0017 shipped with 137 SQL checks and 226 Worker tests and not one of them
-- called observe_storage_object() with an organization that exists. The refusal
-- paths were tested; the ACCEPT path never was. 0017's header states the trust
-- boundary carefully -- "an event for a key we did not mint parses to nothing
-- and is refused" -- and the sentence it needed was that an event for a key we
-- DID mint was refused too.
--
--     A GRANT WITHOUT A POLICY IS NOT A NARROW PERMISSION. IT IS A PERMISSION
--     THAT SILENTLY RETURNS NOTHING, AND EVERY QUERY BUILT ON IT IS WRONG IN
--     THE DIRECTION THAT LOOKS LIKE ABSENCE.
--
-- Check O0 in tenant-isolation.sh generalizes it: any table with row security
-- that the ledger has a GRANT on must also have a policy admitting the ledger.
-- ---------------------------------------------------------------------------

BEGIN;

SET LOCAL ROLE computedriven_migrations;

-- FOR SELECT only, and USING (true) because the ledger is the named cross-tenant
-- role -- the same shape as worlds_ledger in 0014, which is the policy this one
-- should have been written beside.
CREATE POLICY organizations_ledger ON cd.organizations
  FOR SELECT TO computedriven_ledger USING (true);

CREATE TABLE cd.storage_objects (
  bucket          text   NOT NULL,
  object_key      text   NOT NULL,
  organization_id uuid   NOT NULL REFERENCES cd.organizations(id) ON DELETE RESTRICT,
  world_id        uuid,

  -- Current, as of last_event_at.
  etag            text   NOT NULL,
  size_bytes      bigint NOT NULL CHECK (size_bytes >= 0),

  first_event_at  timestamptz NOT NULL,
  last_event_at   timestamptz NOT NULL,

  -- Distinct write events seen for this key, and how many of them changed the
  -- etag. overwrite_count > 0 on a content-addressed key is the alarm: the same
  -- name now holds different bytes.
  event_count     integer NOT NULL DEFAULT 1 CHECK (event_count >= 1),
  overwrite_count integer NOT NULL DEFAULT 0 CHECK (overwrite_count >= 0),

  updated_at      timestamptz NOT NULL DEFAULT now(),

  PRIMARY KEY (bucket, object_key)
);

CREATE INDEX storage_objects_org_ix ON cd.storage_objects (organization_id);
CREATE INDEX storage_objects_key_ix ON cd.storage_objects (object_key);

COMMENT ON TABLE cd.storage_objects IS
  'Current provider state, one row per (bucket, object_key). The inventory. '
  'cd.storage_observations is the append-only log the rows are derived from; '
  'summing that log is not occupancy, because R2 fires an object-create event '
  'on overwrite too. No delete event is consumed, so this is a high-water mark '
  'against deletion.';

COMMENT ON COLUMN cd.storage_objects.overwrite_count IS
  'Write events that CHANGED the etag. Non-zero on a content-addressed key means '
  'one name has held two different bodies -- collision, a client ignoring its own '
  'digest, or multipart. R32 collects this rather than assuming it cannot happen.';

ALTER TABLE cd.storage_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE cd.storage_objects FORCE  ROW LEVEL SECURITY;

CREATE POLICY storage_objects_tenant ON cd.storage_objects FOR ALL
  TO computedriven_api, computedriven_jobs, computedriven_readonly
  USING (organization_id = app.current_organization_id())
  WITH CHECK (organization_id = app.current_organization_id());
CREATE POLICY storage_objects_owner ON cd.storage_objects FOR ALL
  TO computedriven_migrations USING (true) WITH CHECK (true);
CREATE POLICY storage_objects_ledger ON cd.storage_objects FOR ALL
  TO computedriven_ledger USING (true) WITH CHECK (true);

GRANT SELECT ON cd.storage_objects
  TO computedriven_api, computedriven_readonly, computedriven_jobs;
GRANT SELECT, INSERT, UPDATE ON cd.storage_objects TO computedriven_ledger;

-- ---------------------------------------------------------------------------
-- Backfill, so the projection is not empty for evidence already collected.
--
-- Two aggregates JOINED ON THE KEY, not one pass with window functions. The
-- first attempt used count(DISTINCT etag) OVER (PARTITION BY ...) and PostgreSQL
-- refused it outright -- "DISTINCT is not implemented for window functions" --
-- which is the good outcome. The tempting repair is to keep the single pass and
-- line the two result sets up by position; joining on (bucket, object_key) is
-- the only version that cannot silently attach one key's counts to another's row.
-- ---------------------------------------------------------------------------
WITH agg AS (
  SELECT s.bucket, s.object_key,
         min(s.event_time) AS first_event_at,
         max(s.event_time) AS last_event_at,
         count(*)          AS event_count,
         -- N distinct bodies under one name is N-1 overwrites. A redelivery
         -- never reaches this table, so distinct etags is distinct writes.
         greatest(count(DISTINCT s.etag) - 1, 0) AS overwrite_count
    FROM cd.storage_observations s
   GROUP BY s.bucket, s.object_key
),
latest AS (
  SELECT DISTINCT ON (s.bucket, s.object_key)
         s.bucket, s.object_key, s.organization_id, s.world_id, s.etag, s.size_bytes
    FROM cd.storage_observations s
   ORDER BY s.bucket, s.object_key, s.event_time DESC, s.observed_at DESC
)
INSERT INTO cd.storage_objects
  (bucket, object_key, organization_id, world_id, etag, size_bytes,
   first_event_at, last_event_at, event_count, overwrite_count)
SELECT l.bucket, l.object_key, l.organization_id, l.world_id, l.etag, l.size_bytes,
       a.first_event_at, a.last_event_at, a.event_count, a.overwrite_count
  FROM latest l
  JOIN agg a ON a.bucket = l.bucket AND a.object_key = l.object_key;

GRANT CREATE ON SCHEMA app TO computedriven_ledger;
SET LOCAL ROLE computedriven_ledger;

-- ---------------------------------------------------------------------------
-- observe_storage_object(), now writing BOTH: the event to the log and the
-- projection to the inventory.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.observe_storage_object(
  p_bucket     text,
  p_object_key text,
  p_etag       text,
  p_size_bytes bigint,
  p_action     text,
  p_event_time timestamptz
)
RETURNS app.observation_result
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cd, pg_temp
AS $$
DECLARE
  k        record;
  v_intent uuid;
  v_id     uuid;
  existing uuid;
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
    -- Delete events are a different question and are not accounted here.
    RAISE EXCEPTION USING ERRCODE = '22023',
      MESSAGE = format('CD-OBSERVE-ACTION: %L is not an object-create action', p_action);
  END IF;
  IF p_event_time IS NULL THEN
    -- The projection is ordered BY this field. A null would make "which write is
    -- current" unanswerable, and answering it wrongly is silent.
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

  SELECT id INTO v_intent FROM cd.upload_intents WHERE object_key = p_object_key;

  INSERT INTO cd.storage_observations
    (organization_id, world_id, intent_id, bucket, object_key, etag, size_bytes, action, event_time)
  VALUES (k.organization_id, k.world_id, v_intent, p_bucket, p_object_key, p_etag,
          p_size_bytes, p_action, p_event_time)
  ON CONFLICT (bucket, object_key, etag) DO NOTHING
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN
    -- A redelivery. Queues is at-least-once, so this is normal operation and the
    -- correct response is to do nothing -- INCLUDING to the projection, which
    -- must not count one write twice -- and to say so.
    SELECT id INTO existing FROM cd.storage_observations
     WHERE bucket = p_bucket AND object_key = p_object_key AND etag = p_etag;
    out_row := (existing, v_intent, p_size_bytes, true, v_intent IS NOT NULL);
    RETURN out_row;
  END IF;

  -- =========================================================================
  -- THE PROJECTION. Guarded by event_time, because Queues does not guarantee
  -- order: a redelivered OLDER write must not overwrite a NEWER current state.
  -- The counters advance either way -- the event did happen, whenever it
  -- happened -- and only the "what is stored now" fields are ordered.
  -- =========================================================================
  INSERT INTO cd.storage_objects
    (bucket, object_key, organization_id, world_id, etag, size_bytes,
     first_event_at, last_event_at)
  VALUES (p_bucket, p_object_key, k.organization_id, k.world_id, p_etag, p_size_bytes,
          p_event_time, p_event_time)
  ON CONFLICT (bucket, object_key) DO UPDATE SET
    etag = CASE WHEN EXCLUDED.last_event_at >= cd.storage_objects.last_event_at
                THEN EXCLUDED.etag ELSE cd.storage_objects.etag END,
    size_bytes = CASE WHEN EXCLUDED.last_event_at >= cd.storage_objects.last_event_at
                THEN EXCLUDED.size_bytes ELSE cd.storage_objects.size_bytes END,
    first_event_at  = LEAST   (cd.storage_objects.first_event_at, EXCLUDED.first_event_at),
    last_event_at   = GREATEST(cd.storage_objects.last_event_at,  EXCLUDED.last_event_at),
    event_count     = cd.storage_objects.event_count + 1,
    overwrite_count = cd.storage_objects.overwrite_count
                      + CASE WHEN cd.storage_objects.etag IS DISTINCT FROM EXCLUDED.etag
                             THEN 1 ELSE 0 END,
    updated_at      = now();

  IF v_intent IS NOT NULL THEN
    UPDATE cd.upload_intents
       SET state = 'observed', settled_at = now()
     WHERE id = v_intent AND state IN ('offered', 'expired');
  END IF;

  out_row := (v_id, v_intent, p_size_bytes, false, v_intent IS NOT NULL);
  RETURN out_row;
END;
$$;

COMMENT ON FUNCTION app.observe_storage_object(text, text, text, bigint, text, timestamptz) IS
  'Records one provider write event and projects current object state from it. '
  'Idempotent by unique constraint, not by delivery guarantee. The projection is '
  'ordered by event_time because Queues does not guarantee order (0021).';

-- ---------------------------------------------------------------------------
-- Divergence, now against the INVENTORY rather than the log.
--
-- This is the number R32 will be ruled with, so it had better be the right
-- number: how far the client's finalize is from what the provider currently
-- holds -- not from the sum of everything the provider has ever accepted for
-- these keys.
-- ---------------------------------------------------------------------------
-- DROP, not CREATE OR REPLACE: the `overwrites` column changes the OUT-parameter
-- row type and PostgreSQL refuses to replace a function's return shape in place.
-- The grants go with it and are re-issued at the bottom of this file.
DROP FUNCTION IF EXISTS app.storage_divergence(uuid);

CREATE FUNCTION app.storage_divergence(p_organization_id uuid DEFAULT NULL)
RETURNS TABLE (
  reservation_id  uuid,
  organization_id uuid,
  asserted_bytes  bigint,
  observed_bytes  bigint,
  delta           bigint,
  overwrites      bigint
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = cd, pg_temp
STABLE
AS $$
  SELECT r.id, r.organization_id,
         coalesce(r.committed_bytes, 0)::bigint AS asserted_bytes,
         coalesce(o.total, 0)::bigint           AS observed_bytes,
         (coalesce(o.total, 0) - coalesce(r.committed_bytes, 0))::bigint AS delta,
         coalesce(o.overwrites, 0)::bigint      AS overwrites
  FROM cd.storage_reservations r
  LEFT JOIN (
    -- Joined through the INTENT, which is what ties an object key to a
    -- reservation, and against storage_objects, which is what ties a key to the
    -- bytes it currently holds.
    SELECT i.reservation_id,
           sum(so.size_bytes)      AS total,
           sum(so.overwrite_count) AS overwrites
      FROM cd.storage_objects so
      JOIN cd.upload_intents i ON i.object_key = so.object_key
     GROUP BY i.reservation_id
  ) o ON o.reservation_id = r.id
  WHERE (p_organization_id IS NULL OR r.organization_id = p_organization_id)
    AND (coalesce(o.total, 0)      IS DISTINCT FROM coalesce(r.committed_bytes, 0)
         OR coalesce(o.overwrites, 0) > 0);
$$;

COMMENT ON FUNCTION app.storage_divergence(uuid) IS
  'Where client-asserted finalize bytes and CURRENT provider occupancy disagree. '
  'Reads cd.storage_objects, not the observation log -- summing the log double '
  'counts an overwritten key (0021). `overwrites` is reported alongside because '
  'on a content-addressed key it is a defect, not a measurement. R32 OPEN.';

RESET ROLE;
SET LOCAL ROLE computedriven_migrations;
REVOKE CREATE ON SCHEMA app FROM computedriven_ledger;

REVOKE EXECUTE ON FUNCTION
  app.observe_storage_object(text, text, text, bigint, text, timestamptz),
  app.storage_divergence(uuid)
FROM PUBLIC;

GRANT EXECUTE ON FUNCTION app.storage_divergence(uuid)
  TO computedriven_api, computedriven_jobs;
GRANT EXECUTE ON FUNCTION
  app.observe_storage_object(text, text, text, bigint, text, timestamptz)
  TO computedriven_jobs;

DO $$
BEGIN
  IF has_function_privilege('computedriven_api',
       'app.observe_storage_object(text,text,text,bigint,text,timestamptz)', 'EXECUTE') THEN
    RAISE EXCEPTION 'CD-OBSERVE-CLIENTPATH: the API role can assert provider observations';
  END IF;
END
$$;

COMMIT;
