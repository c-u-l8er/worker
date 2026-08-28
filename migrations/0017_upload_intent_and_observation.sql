-- 0017 — upload intents (M2 shape) and provider-observed storage (R31/R32, both PROPOSED)
--
-- TWO PROPOSED RULINGS ARE BEING BUILT AGAINST, NOT ASSUMED. Neither is ruled;
-- both are recorded in REVISION_REGISTER.md as OPEN, and the capability rungs say
-- so. What this migration does is make them TESTABLE before they are decided,
-- which is the opposite of the usual order and deliberately so.
--
-- ---------------------------------------------------------------------------
-- R31 (PROPOSED) — storage authority may never authorize more bytes than the
--                  reservation that produced it.
--
-- M1.5 is admission-safe and is NOT hard-quota-safe, and the difference matters
-- because R8 puts the bytes on a wire the Worker never sees:
--
--     reserve 1 MB  ->  receive PutObject authority  ->  upload 500 MB
--         ->  R2 HAS ALREADY ACCEPTED 500 MB  ->  finalize(500 MB) refused
--
-- The database refusal is correct and it is too late. Cloudflare's temporary-
-- credential scope constrains bucket, operations, object/prefix and TTL. It does
-- not document a maximum byte count, and the presigned-URL page documents
-- Content-Type as signed and enforced while saying nothing about Content-Length.
--
--     https://developers.cloudflare.com/r2/api/s3/temporary-credentials/
--     https://developers.cloudflare.com/r2/api/s3/presigned-urls/
--
-- SO R31 IS NOT CLAIMED. Whether a presigned PUT can be made byte-exact is an
-- experiment (worker/test/live-falsifier.mjs, case B), not an assumption. If it
-- cannot, we have learned something architectural rather than shipped something
-- untrue: hard pre-write quota and fully direct client->R2 uploads cannot both be
-- claimed with the current grant primitive, and the choice between a small
-- controlled data plane and softer asynchronous quota becomes conscious.
--
-- ---------------------------------------------------------------------------
-- R32 (PROPOSED) — committed storage is provider-observed, never client-asserted.
--
-- `finalize(actualBytes)` trusts the uploader, bounded above by its reservation.
-- R2 event notifications carry the real numbers -- `object.size` and
-- `object.eTag`, on PutObject / CopyObject / CompleteMultipartUpload -- delivered
-- over Queues.
--
--     https://developers.cloudflare.com/r2/buckets/event-notifications/
--
-- Queues is AT-LEAST-ONCE, so the same event can arrive twice and exactly-once
-- accounting has to come from a uniqueness key rather than from delivery. That is
-- what storage_observations' unique index is.
--
-- Until R32 is ruled, a client finalize stays a COMPLETION HINT that is recorded
-- and compared, and `app.storage_divergence()` reports where the two disagree.
-- Replacing finalize outright before there is a single real event to test against
-- would be trading a measured mechanism for an unmeasured one.
--
-- ---------------------------------------------------------------------------
-- THE TRUST BOUNDARY, stated because it is the only reason this is safe
--
-- An event names an object key. Nothing else in it is trusted:
--
--     R2 is authoritative for WHAT WAS WRITTEN         (size, etag)
--     the key prefix is authoritative for WHOSE IT IS  (org/<uuid>/world/<uuid>/)
--     and WE MINTED THAT PREFIX                        (scopeForWorld)
--
-- So the organization is DERIVED from the key by this migration's parser and
-- checked against cd.organizations. It is never taken from a field in the
-- message. An event for a key we did not mint parses to nothing and is refused.

BEGIN;

SET LOCAL ROLE computedriven_migrations;

-- ---------------------------------------------------------------------------
-- Upload intents. THE M2 WRITE SHAPE, and it is deliberately small:
--
--     one bounded content-addressed chunk
--       -> one reservation
--       -> one EXACT object key
--       -> one short-lived write artifact
--
-- A 2 TB world is not a 2 TB object. R2 recommends ordinary PutObject below
-- ~100 MB and single PUT supports up to 5 GiB, so tens of thousands of ordinary
-- puts carry a multi-terabyte world -- and the session may last days while each
-- individual authorization lasts minutes.
--
--     THE SESSION CAN LIVE FOR DAYS; A CHUNK GRANT DOES NOT.
--
-- That is also what dissolves round 6's unanswerable question about whether a
-- reservation should last an hour or a week. It was unanswerable because it was
-- asking one object to be both.
--
-- `object_key` is exact and unique, never a prefix. That is what makes an R2
-- event attributable to the intent that authorized it, and it is why multipart is
-- NOT authorized here: CreateMultipartUpload/UploadPart/ListParts/Complete/Abort
-- are five more capabilities than one PutObject needs, and nothing has yet
-- measured a chunk large enough to require them.
-- ---------------------------------------------------------------------------
CREATE TABLE cd.upload_intents (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid   NOT NULL,
  world_id        uuid   NOT NULL,
  reservation_id  uuid   NOT NULL REFERENCES cd.storage_reservations(id) ON DELETE RESTRICT,
  object_key      text   NOT NULL,
  expected_bytes  bigint NOT NULL CHECK (expected_bytes > 0),
  content_digest  text   NOT NULL CHECK (btrim(content_digest) <> ''),
  state           text   NOT NULL DEFAULT 'offered'
                  CHECK (state IN ('offered', 'observed', 'expired', 'abandoned')),
  created_at      timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz NOT NULL,
  settled_at      timestamptz,

  CONSTRAINT upload_intents_world_fk
    FOREIGN KEY (world_id, organization_id)
    REFERENCES cd.worlds (id, organization_id) ON DELETE RESTRICT,

  -- One intent per object key. A second intent for the same key would make an
  -- arriving event ambiguous about which reservation it settles.
  CONSTRAINT upload_intents_key_uq UNIQUE (object_key),

  CONSTRAINT upload_intents_settled_ck
    CHECK ((state = 'offered') = (settled_at IS NULL))
);

CREATE INDEX upload_intents_reservation_ix ON cd.upload_intents (reservation_id);

COMMENT ON TABLE cd.upload_intents IS
  'One chunk, one object key, one short-lived write artifact. The exact key is '
  'what makes an R2 object-create event attributable. M2 shape; R31 PROPOSED.';

-- ---------------------------------------------------------------------------
-- Observations. What R2 says actually landed.
--
-- The unique index is the exactly-once mechanism. Queues delivers at least once,
-- so a duplicate notification is normal operation and must be a no-op rather than
-- a second charge. `(bucket, object_key, etag)` is the natural key: for a
-- content-addressed chunk the key already is the hash, and the etag distinguishes
-- an overwrite of the same key from a redelivery of the same write.
-- ---------------------------------------------------------------------------
CREATE TABLE cd.storage_observations (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid   NOT NULL REFERENCES cd.organizations(id) ON DELETE RESTRICT,
  world_id        uuid,
  intent_id       uuid REFERENCES cd.upload_intents(id) ON DELETE RESTRICT,
  bucket          text   NOT NULL,
  object_key      text   NOT NULL,
  etag            text   NOT NULL,
  size_bytes      bigint NOT NULL CHECK (size_bytes >= 0),
  action          text   NOT NULL
                  CHECK (action IN ('PutObject', 'CopyObject', 'CompleteMultipartUpload')),
  event_time      timestamptz NOT NULL,
  observed_at     timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT storage_observations_uq UNIQUE (bucket, object_key, etag)
);

COMMENT ON TABLE cd.storage_observations IS
  'Provider-observed object writes. The unique constraint turns Cloudflare '
  'Queues at-least-once delivery into exactly-once accounting. R32 PROPOSED: '
  'until it is ruled, this is compared against client finalize rather than '
  'replacing it.';

ALTER TABLE cd.upload_intents        ENABLE ROW LEVEL SECURITY;
ALTER TABLE cd.upload_intents        FORCE  ROW LEVEL SECURITY;
ALTER TABLE cd.storage_observations  ENABLE ROW LEVEL SECURITY;
ALTER TABLE cd.storage_observations  FORCE  ROW LEVEL SECURITY;

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['upload_intents', 'storage_observations'] LOOP
    EXECUTE format(
      'CREATE POLICY %I ON cd.%I FOR ALL '
      'TO computedriven_api, computedriven_jobs, computedriven_readonly '
      'USING (organization_id = app.current_organization_id()) '
      'WITH CHECK (organization_id = app.current_organization_id())',
      t || '_tenant', t);
    EXECUTE format(
      'CREATE POLICY %I ON cd.%I FOR ALL TO computedriven_migrations '
      'USING (true) WITH CHECK (true)', t || '_owner', t);
    EXECUTE format(
      'CREATE POLICY %I ON cd.%I FOR ALL TO computedriven_ledger '
      'USING (true) WITH CHECK (true)', t || '_ledger', t);
  END LOOP;
END
$$;

GRANT SELECT ON cd.upload_intents, cd.storage_observations
  TO computedriven_api, computedriven_readonly, computedriven_jobs;
GRANT SELECT, INSERT, UPDATE ON cd.upload_intents, cd.storage_observations
  TO computedriven_ledger;

CREATE TYPE app.upload_offer AS (
  intent_id      uuid,
  reservation_id uuid,
  object_key     text,
  expected_bytes bigint,
  content_digest text,
  expires_at     timestamptz,
  replayed       boolean
);

CREATE TYPE app.observation_result AS (
  observation_id uuid,
  intent_id      uuid,
  size_bytes     bigint,
  duplicate      boolean,
  attributed     boolean
);

GRANT CREATE ON SCHEMA app TO computedriven_ledger;
SET LOCAL ROLE computedriven_ledger;

-- ---------------------------------------------------------------------------
-- The key parser. The ONLY thing an event is trusted to tell us is which object
-- it is about; whose it is comes from the prefix WE minted.
--
-- Kept in SQL rather than in the consumer so the parse that decides tenancy and
-- the constraint that stores it cannot be in two languages with two opinions --
-- the r2creds.mjs prefix format is the other copy, and check M4 pins them
-- together.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.parse_object_key(p_key text)
RETURNS TABLE (organization_id uuid, world_id uuid)
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE m text[];
BEGIN
  -- Anchored at both ends, uuids only, and a mandatory non-empty remainder.
  -- `org/<uuid>/world/<uuid>/` with nothing after it is a prefix, not an object.
  m := regexp_match(p_key,
    '^org/([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})'
    '/world/([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})/.+$');
  IF m IS NULL THEN
    RETURN;                             -- zero rows: not a key we minted
  END IF;
  organization_id := m[1]::uuid;
  world_id        := m[2]::uuid;
  RETURN NEXT;
END;
$$;

COMMENT ON FUNCTION app.parse_object_key(text) IS
  'Derives the tenant from an object key. The prefix was minted by scopeForWorld(); '
  'an event is never trusted to name its own organization.';

-- ---------------------------------------------------------------------------
-- Offer an upload. Requires a live reservation, and the intent may not promise
-- more bytes than remain unspoken-for in it.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.offer_upload(
  p_reservation_id uuid,
  p_object_key     text,
  p_expected_bytes bigint,
  p_content_digest text,
  p_ttl            interval DEFAULT interval '15 minutes'
)
RETURNS app.upload_offer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cd, pg_temp
AS $$
DECLARE
  v_org      uuid;
  r          record;
  k          record;
  v_spoken   bigint;
  v_id       uuid;
  v_expires  timestamptz;
  existing   record;
  out_row    app.upload_offer;
BEGIN
  v_org := app.current_organization_id();

  SELECT * INTO r FROM cd.storage_reservations
   WHERE id = p_reservation_id AND organization_id = v_org;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501',
      MESSAGE = 'CD-OFFER-NOTFOUND: no such reservation in this organization';
  END IF;
  IF r.state <> 'reserved' THEN
    RAISE EXCEPTION USING ERRCODE = '55000',
      MESSAGE = format('CD-OFFER-STATE: reservation %s is %s and cannot back an upload', r.id, r.state);
  END IF;
  IF r.expires_at <= now() THEN
    RAISE EXCEPTION USING ERRCODE = '55000',
      MESSAGE = format('CD-OFFER-EXPIRED: reservation %s expired at %s', r.id, r.expires_at);
  END IF;

  -- The key must be inside THIS reservation's world. Not checked afterwards:
  -- an unparseable or foreign key is refused before anything is written.
  SELECT * INTO k FROM app.parse_object_key(p_object_key);
  IF NOT FOUND OR k.organization_id <> v_org OR k.world_id <> r.world_id THEN
    RAISE EXCEPTION USING ERRCODE = '42501',
      MESSAGE = format('CD-OFFER-KEY: %L is not an object key inside this world', p_object_key);
  END IF;

  IF p_expected_bytes IS NULL OR p_expected_bytes <= 0 THEN
    RAISE EXCEPTION USING ERRCODE = '22023',
      MESSAGE = 'CD-OFFER-BYTES: expected bytes must be a positive count';
  END IF;
  IF p_content_digest IS NULL OR btrim(p_content_digest) = '' THEN
    -- Content addressing is the point of the chunk. An intent with no digest
    -- cannot be checked against what arrived.
    RAISE EXCEPTION USING ERRCODE = '22023',
      MESSAGE = 'CD-OFFER-DIGEST: a content digest is required';
  END IF;
  IF p_ttl IS NULL OR p_ttl <= interval '0' OR p_ttl > interval '1 hour' THEN
    RAISE EXCEPTION USING ERRCODE = '22023',
      MESSAGE = 'CD-OFFER-TTL: an upload offer lives at most an hour';
  END IF;

  -- Idempotent on the key: re-offering the same chunk returns the same intent.
  SELECT * INTO existing FROM cd.upload_intents WHERE object_key = p_object_key;
  IF FOUND THEN
    IF existing.organization_id <> v_org THEN
      -- Should be unreachable given the key parse above; if it ever fires, the
      -- key format and the tenancy check have diverged.
      RAISE EXCEPTION USING ERRCODE = '42501',
        MESSAGE = 'CD-OFFER-KEY: that object key belongs to another organization';
    END IF;
    IF existing.expected_bytes <> p_expected_bytes
       OR existing.content_digest <> p_content_digest THEN
      RAISE EXCEPTION USING ERRCODE = '22023',
        MESSAGE = format('CD-OFFER-MISMATCH: %L is already offered at %s bytes / %s',
                         p_object_key, existing.expected_bytes, existing.content_digest);
    END IF;
    out_row := (existing.id, existing.reservation_id, existing.object_key,
                existing.expected_bytes, existing.content_digest, existing.expires_at, true);
    RETURN out_row;
  END IF;

  -- THE R31 ARITHMETIC, enforced on OUR side of the boundary. It does not stop
  -- R2 accepting a larger body -- nothing in the current grant primitive does --
  -- but it stops US from ever offering authority for bytes the reservation has
  -- not got. That distinction is the whole of R31's open question.
  SELECT coalesce(sum(expected_bytes), 0) INTO v_spoken
    FROM cd.upload_intents
   WHERE reservation_id = r.id AND state IN ('offered', 'observed');
  IF v_spoken + p_expected_bytes > r.bytes THEN
    RAISE EXCEPTION USING ERRCODE = '53100',
      MESSAGE = format('CD-OFFER-OVERCOMMIT: reservation %s holds %s bytes, %s already offered, %s requested',
                       r.id, r.bytes, v_spoken, p_expected_bytes);
  END IF;

  v_expires := LEAST(now() + p_ttl, r.expires_at);
  INSERT INTO cd.upload_intents
    (organization_id, world_id, reservation_id, object_key, expected_bytes, content_digest, expires_at)
  VALUES (v_org, r.world_id, r.id, p_object_key, p_expected_bytes, p_content_digest, v_expires)
  RETURNING id INTO v_id;

  out_row := (v_id, r.id, p_object_key, p_expected_bytes, p_content_digest, v_expires, false);
  RETURN out_row;
END;
$$;

-- ---------------------------------------------------------------------------
-- Observe what R2 says landed. Runs WITHOUT tenant context: a queue consumer is
-- cross-tenant by nature, and this is the THIRD named cross-tenant exemption in
-- the schema after the bootstrap resolvers and the ledger functions.
--
-- Idempotent by unique constraint, not by delivery guarantee.
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
    -- correct response is to do nothing and say so.
    SELECT id INTO existing FROM cd.storage_observations
     WHERE bucket = p_bucket AND object_key = p_object_key AND etag = p_etag;
    out_row := (existing, v_intent, p_size_bytes, true, v_intent IS NOT NULL);
    RETURN out_row;
  END IF;

  IF v_intent IS NOT NULL THEN
    UPDATE cd.upload_intents
       SET state = 'observed', settled_at = now()
     WHERE id = v_intent AND state = 'offered';
  END IF;

  out_row := (v_id, v_intent, p_size_bytes, false, v_intent IS NOT NULL);
  RETURN out_row;
END;
$$;

-- ---------------------------------------------------------------------------
-- Divergence. WHERE THE CLIENT AND THE PROVIDER DISAGREE.
--
-- This is the whole point of building R32 before ruling it: rather than
-- asserting that client-reported bytes are wrong, measure how wrong they are
-- against real events, and rule with a number.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.storage_divergence(p_organization_id uuid DEFAULT NULL)
RETURNS TABLE (
  reservation_id  uuid,
  organization_id uuid,
  asserted_bytes  bigint,
  observed_bytes  bigint,
  delta           bigint
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = cd, pg_temp
STABLE
AS $$
  SELECT r.id, r.organization_id,
         coalesce(r.committed_bytes, 0)::bigint AS asserted_bytes,
         coalesce(o.total, 0)::bigint           AS observed_bytes,
         (coalesce(o.total, 0) - coalesce(r.committed_bytes, 0))::bigint AS delta
  FROM cd.storage_reservations r
  LEFT JOIN (
    SELECT i.reservation_id, sum(s.size_bytes) AS total
    FROM cd.storage_observations s
    JOIN cd.upload_intents i ON i.id = s.intent_id
    GROUP BY i.reservation_id
  ) o ON o.reservation_id = r.id
  WHERE (p_organization_id IS NULL OR r.organization_id = p_organization_id)
    AND coalesce(o.total, 0) IS DISTINCT FROM coalesce(r.committed_bytes, 0);
$$;

COMMENT ON FUNCTION app.storage_divergence(uuid) IS
  'Where client-asserted finalize bytes and provider-observed object sizes '
  'disagree. R32 is PROPOSED, not ruled: this measures the gap rather than '
  'assuming which side is wrong.';

RESET ROLE;
SET LOCAL ROLE computedriven_migrations;
REVOKE CREATE ON SCHEMA app FROM computedriven_ledger;

REVOKE EXECUTE ON FUNCTION
  app.offer_upload(uuid, text, bigint, text, interval),
  app.observe_storage_object(text, text, text, bigint, text, timestamptz),
  app.storage_divergence(uuid),
  app.parse_object_key(text)
FROM PUBLIC;

GRANT EXECUTE ON FUNCTION app.offer_upload(uuid, text, bigint, text, interval) TO computedriven_api;
GRANT EXECUTE ON FUNCTION app.storage_divergence(uuid) TO computedriven_api, computedriven_jobs;

-- The consumer is a JOB, not a request. The API role must not be able to tell the
-- ledger that bytes landed -- that is precisely the client-asserted path R32
-- exists to replace.
GRANT EXECUTE ON FUNCTION
  app.observe_storage_object(text, text, text, bigint, text, timestamptz)
TO computedriven_jobs;

DO $$
BEGIN
  IF has_function_privilege('computedriven_api',
       'app.observe_storage_object(text,text,text,bigint,text,timestamptz)', 'EXECUTE') THEN
    RAISE EXCEPTION 'CD-OBSERVE-CLIENTPATH: the API role can assert provider observations';
  END IF;
  IF has_function_privilege('public',
       'app.offer_upload(uuid,text,bigint,text,interval)', 'EXECUTE') THEN
    RAISE EXCEPTION 'CD-ACL-PUBLIC: PUBLIC holds EXECUTE on app.offer_upload';
  END IF;
END
$$;

COMMIT;
