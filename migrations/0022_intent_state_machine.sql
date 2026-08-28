-- 0022 — one lock order, monotonic provider truth, and an abandon that stops
--        pretending it can revoke a capability it already gave away
--
-- Findings 60, 61 and 64, from outside review 2026-08-22. All reproduced in
-- concurrency group R BEFORE this file was written.
--
-- ---------------------------------------------------------------------------
-- 60. THE FIRST RACE IN THIS SYSTEM BETWEEN TWO DIFFERENT SUBSYSTEMS.
--
-- Groups N, P and Q each race one function against itself: two logins, two
-- reservations, two offers. Every fix so far was "serialize that function", and
-- 0019 did exactly that by making the reservation row the boundary for its own
-- intents.
--
-- Only one of the two parties ever agreed to that boundary.
--
--     offer_upload / abandon_upload   an HTTP request. Tenant-scoped. Takes the
--                                     reservation row.
--     observe_storage_object          a QUEUE CONSUMER. Cross-tenant, no tenant
--                                     context, and it took NO LOCK AT ALL.
--
-- So:
--
--     offer_upload                     the observer
--     ------------                     ------------
--                                      BEGIN; intent -> observed  (uncommitted)
--     lock reservation
--     read intent  -> 'offered'        (the old committed row)
--     decide: this is a replay
--     UPDATE intent SET state='offered'   <- BLOCKS on the observer's row lock
--                                      COMMIT
--     ...unblocks and OVERWRITES
--
-- MEASURED, group R against 0019/0021: `state=offered`, and the caller received
-- `disposition=replayed` -- FRESH WRITE AUTHORITY FOR AN OBJECT R2 ALREADY HOLDS.
--
-- The revive UPDATE carried no state predicate, so there was nothing for it to
-- re-evaluate when it woke up. A blocked UPDATE re-checks its WHERE clause
-- against the winner's committed row; a WHERE clause that only names a primary
-- key has nothing to re-check.
--
--     R54 -- PROVIDER-OBSERVED TRUTH IS MONOTONIC. `observed` IS A FACT ABOUT
--     THE WORLD, NOT A STAGE IN OUR WORKFLOW, AND NO LOCAL TRANSITION MAY WALK
--     IT BACK.
--
-- Two things are needed and neither is sufficient alone. ONE LOCK ORDER --
-- reservation, then intent, then decide -- so every party queues at the same
-- gate; and CAS-shaped transitions under that lock, so a statement that waited
-- re-reads what it waited for. The order alone would not have saved abandon
-- (see 61); the guard alone would leave the observer outside the protocol.
--
-- ---------------------------------------------------------------------------
-- 61. ABANDON WAS SPENDING AUTHORITY IT HAD ALREADY GIVEN AWAY.
--
-- Two defects, and the second is worse than the first.
--
-- The concurrency one: abandon_upload() read the intent BEFORE taking the
-- reservation lock, so it waited on a lock and then decided from a snapshot
-- older than the wait. MEASURED, group R: `observed` became `abandoned`.
--
--     A DECISION MADE FROM A READ TAKEN BEFORE THE LOCK IS A DECISION MADE
--     ABOUT THE PAST. THE LOCK IS NOT THE POINT; THE RE-READ IS.
--
-- The authority one needs no concurrency at all, and R40 as written invited it.
-- R40 said an intent's bytes are released by an explicit abandon or by its
-- reservation dying. But abandon_upload() is a row in our database. It sends
-- nothing to Cloudflare, and a presigned URL authorizes its holder until the URL
-- expires. So:
--
--     reserve 100
--     offer object A for 100   ->  receive a presigned PUT URL
--     abandon A                ->  100 bytes released under R40
--     offer object B for 100   ->  admitted, because the 100 came back
--     USE THE STILL-LIVE URL FOR A
--     ->  200 bytes stored against a 100-byte reservation
--
-- That is precisely what R31 exists to forbid, reached without racing anything.
--
--     R55 (amends R40) -- A CLIENT ABANDON REVOKES OUR WILLINGNESS TO MINT MORE
--     AUTHORITY. IT DOES NOT REVOKE AUTHORITY ALREADY ISSUED, AND THEREFORE
--     RELEASES NOTHING.
--
-- So the state is renamed `client_abandoned`, because `abandoned` reads like a
-- release and this is a DECLARATION. Its bytes keep counting. R40's other half
-- survives intact and for the same reason it was written: the clock does not
-- release bytes either, because R2's clock is not ours.
--
-- What this leaves is that the ONLY thing which releases an intent's bytes is
-- the reservation itself dying -- which is honest, and it collapses the byte
-- arithmetic to `sum over every intent`, with no state predicate to get wrong.
--
--     THE ACCOUNTING GOT SIMPLER BY ADMITTING WE CONTROL LESS THAN WE THOUGHT.
--
-- The remaining question -- whether OUR expiry instant is an atomic fence
-- against a PUT R2 already admitted -- is not answerable from here. It is
-- live-falsifier case I, and a single HEAD after expiry does not answer it
-- either (HEAD 404 -> in-flight PUT completes -> object appears).
--
-- ---------------------------------------------------------------------------
-- 64. A GHOST STATE AND A WRONG RULING NUMBER.
--
-- `expired` was in the CHECK constraint and in observe_storage_object's WHERE
-- clause, and NOTHING IN ANY MIGRATION EVER SET IT on an upload intent -- the
-- only executable `state='expired'` transition belongs to the parent
-- storage_reservations. 0019 added it in anticipation of a sweeper that R40 then
-- made unnecessary. It is removed rather than implemented: under R55 nothing
-- would be released by reaching it, so it would be a second name for `offered`.
--
-- 0019 also labelled the expiry rule R34 throughout. R34 belongs to a parallel
-- box-and-box session; the Cloud ruling is R40. Corrected in place there.
--
--     THE STATE MACHINE IS NOW THREE STATES AND ONE OF THEM IS TERMINAL.
--
--         offered  ---------> observed        (provider spoke; TERMINAL)
--            |  ^                ^
--            v  |                |
--       client_abandoned --------+            (client spoke; releases nothing)
--
--     Every state counts against its reservation. `observed` accepts no exit.

BEGIN;

SET LOCAL ROLE computedriven_migrations;

-- ---------------------------------------------------------------------------
-- The vocabulary. Renamed and narrowed in one step, with the data moved first
-- so the new CHECK can be strict rather than tolerant of what it replaced.
-- ---------------------------------------------------------------------------
ALTER TABLE cd.upload_intents DROP CONSTRAINT upload_intents_state_check;

UPDATE cd.upload_intents SET state = 'client_abandoned' WHERE state = 'abandoned';
-- Defensive and expected to affect zero rows: `expired` was unreachable. If this
-- ever moves a row, something set it that no migration in this tree contains.
UPDATE cd.upload_intents SET state = 'offered', settled_at = NULL WHERE state = 'expired';

ALTER TABLE cd.upload_intents
  ADD CONSTRAINT upload_intents_state_check
  CHECK (state IN ('offered', 'observed', 'client_abandoned'));

COMMENT ON COLUMN cd.upload_intents.state IS
  'offered | observed | client_abandoned. `observed` is TERMINAL -- the provider '
  'has said the object landed and no local transition may walk that back (R54). '
  '`client_abandoned` is a DECLARATION, not a release: it does not revoke a '
  'presigned URL already issued, so its bytes keep counting (R55). EVERY state '
  'counts against the reservation; only the reservation dying releases bytes.';

-- ---------------------------------------------------------------------------
-- FINDING 62 — `(bucket, object_key, etag)` IS OBJECT IDENTITY, NOT EVENT
-- IDENTITY, and it was being used as both.
--
-- It is here rather than in its own migration because observe_storage_object()
-- below grows the parameter that carries the answer, and a function referring to
-- a column added by a later file is a migration set that does not apply.
--
-- The constraint was correct for the question 0017 asked it -- "is this the same
-- stored object state?" -- and is wrong for the one it was actually answering:
--
--     "is this the same provider WRITE EVENT?"
--
-- A genuine second PUT of identical bytes to the same key produces the same
-- bucket, the same key and the same etag. 0017 called that a queue redelivery
-- and dropped it. Occupancy stays right, because the bytes really are the same;
-- the append-only PROVENANCE LOG silently loses a write that happened. And once
-- deletes exist it stops being merely lossy:
--
--     PUT hash X        etag E
--     DELETE hash X
--     PUT identical X   etag E      <- dismissed because an ancient row matched
--
-- Cloudflare gives every Queue message a system-generated unique `id`, with
-- `attempts` tracking retries, on top of at-least-once delivery. That is an
-- DELIVERY identity, which is the thing we never had. (NARROWED 0024: this
-- said EVENT identity, and R2's notification body carries no event id at all --
-- what the queue message id answers is "is this the same delivery?", not "is
-- this the same provider event?". Finding 67, second pass.)
--
--     delivery identity  ->  the queue message id
--     provider event id  ->  NOT EXPOSED by R2
--     object identity    ->  bucket + key
--     object state       ->  etag, event_time
--
-- The same lesson as user identity vs binding, WORLD vs VERSION vs GRAPH, and
-- request idempotence vs content dedup. Three different questions had been
-- sharing one key for the fourth time.
--
-- The fallback index is deliberate and narrow. A caller with no message id is
-- not a queue consumer -- a backfill, a battery, an operator replaying a capture
-- -- and for those `(bucket, key, etag, event_time)` at least distinguishes two
-- writes that happened at different moments. It is NOT offered as an equivalent:
-- without a message id, redelivery and a genuine identical re-PUT at the same
-- instant remain indistinguishable, and that is a property of having no event
-- identity rather than a choice made here.
-- ---------------------------------------------------------------------------
ALTER TABLE cd.storage_observations ADD COLUMN message_id text;

ALTER TABLE cd.storage_observations DROP CONSTRAINT storage_observations_uq;

CREATE UNIQUE INDEX storage_observations_message_uq
  ON cd.storage_observations (message_id) WHERE message_id IS NOT NULL;

CREATE UNIQUE INDEX storage_observations_fallback_uq
  ON cd.storage_observations (bucket, object_key, etag, event_time)
  WHERE message_id IS NULL;

COMMENT ON COLUMN cd.storage_observations.message_id IS
  'The Cloudflare Queue message id: DELIVERY identity, which is what turns '
  'at-least-once delivery into exactly-once accounting. (bucket, key) is OBJECT '
  'identity and etag/event_time are object STATE -- 0017 used the second to '
  'answer the first, so a genuine identical re-PUT vanished from the log (0022).';

GRANT CREATE ON SCHEMA app TO computedriven_ledger;
SET LOCAL ROLE computedriven_ledger;

-- ---------------------------------------------------------------------------
-- The lock protocol, in one function, because three copies of a lock order is
-- how three copies come to disagree about it -- and a disagreement between two
-- lock orders is a deadlock rather than a wrong answer, which is harder to read
-- in production than it is here.
--
--     reservation row   ->   intent row   ->   decide
--
-- Returns the intent as it is AFTER both locks are held. Every caller below
-- decides from this row and never from one it read earlier.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.lock_intent(p_intent_id uuid)
RETURNS cd.upload_intents
LANGUAGE plpgsql
AS $$
DECLARE i cd.upload_intents;
BEGIN
  -- The reservation is found through an UNLOCKED read, and that is safe for
  -- exactly one reason: R43 makes reservation_id part of the intent's immutable
  -- promise, so it cannot change under us. If an intent were ever allowed to
  -- move between reservations, this read would have to be locked too and the
  -- lock order would become circular.
  PERFORM 1
     FROM cd.storage_reservations r
    WHERE r.id = (SELECT reservation_id FROM cd.upload_intents WHERE id = p_intent_id)
      FOR UPDATE;

  SELECT * INTO i FROM cd.upload_intents WHERE id = p_intent_id FOR UPDATE;
  RETURN i;
END;
$$;

COMMENT ON FUNCTION app.lock_intent(uuid) IS
  'THE lock order for every upload-intent transition: reservation, then intent, '
  'then decide. Returns the intent as it is after both locks are held -- callers '
  'must decide from this row, never from one read before the wait (0022).';

-- ---------------------------------------------------------------------------
-- Offer an upload.
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
  existing   cd.upload_intents;
  out_row    app.upload_offer;
BEGIN
  v_org := app.current_organization_id();

  IF p_expected_bytes IS NULL OR p_expected_bytes <= 0 THEN
    RAISE EXCEPTION USING ERRCODE = '22023',
      MESSAGE = 'CD-OFFER-BYTES: expected bytes must be a positive count';
  END IF;
  IF p_content_digest IS NULL OR btrim(p_content_digest) = '' THEN
    RAISE EXCEPTION USING ERRCODE = '22023',
      MESSAGE = 'CD-OFFER-DIGEST: a content digest is required';
  END IF;
  IF p_ttl IS NULL OR p_ttl <= interval '0' OR p_ttl > interval '1 hour' THEN
    RAISE EXCEPTION USING ERRCODE = '22023',
      MESSAGE = 'CD-OFFER-TTL: an upload offer lives at most an hour';
  END IF;

  -- Lock 1 of 2. Concurrent offers against this reservation queue here.
  SELECT * INTO r FROM cd.storage_reservations
   WHERE id = p_reservation_id AND organization_id = v_org
   FOR UPDATE;
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

  SELECT * INTO k FROM app.parse_object_key(p_object_key);
  IF NOT FOUND OR k.organization_id <> v_org OR k.world_id <> r.world_id THEN
    RAISE EXCEPTION USING ERRCODE = '42501',
      MESSAGE = format('CD-OFFER-KEY: %L is not an object key inside this world', p_object_key);
  END IF;

  -- Lock 2 of 2, and THE RE-READ. The row this returns is the row after the
  -- wait, which is the entire difference between 0022 and 0019: the previous
  -- version read the intent under the reservation lock alone, and the observer
  -- was never holding that lock.
  SELECT * INTO existing FROM cd.upload_intents WHERE object_key = p_object_key;
  IF FOUND THEN
    existing := app.lock_intent(existing.id);

    IF existing.organization_id <> v_org THEN
      RAISE EXCEPTION USING ERRCODE = '42501',
        MESSAGE = 'CD-OFFER-KEY: that object key belongs to another organization';
    END IF;
    PERFORM app.assert_intent_matches(existing.id, existing.reservation_id,
              existing.expected_bytes, existing.content_digest,
              p_reservation_id, p_expected_bytes, p_content_digest);

    IF existing.state = 'observed' THEN
      -- TERMINAL, and checked after the lock rather than before it. R2 holds this
      -- object; handing back a live window would mint write authority for content
      -- that is already written.
      out_row := (existing.id, existing.reservation_id, existing.object_key,
                  existing.expected_bytes, existing.content_digest,
                  existing.expires_at, true, 'already_observed');
      RETURN out_row;
    END IF;

    -- 'offered' and 'client_abandoned' both land here, and neither needs new
    -- arithmetic: under R55 an abandoned intent never stopped counting, so its
    -- bytes are already spoken for and re-offering the SAME promise moves no
    -- numbers. That is the whole simplification 61 bought.
    v_expires := LEAST(now() + p_ttl, r.expires_at);
    UPDATE cd.upload_intents
       SET state      = 'offered',
           settled_at = NULL,
           expires_at = GREATEST(expires_at, v_expires)
     WHERE id = existing.id
       -- The guard 0019 did not have. Belt as well as braces: the lock above
       -- already makes this unreachable, and a transition that can only be wrong
       -- in one direction should say so in the statement that performs it.
       AND state <> 'observed'
    RETURNING expires_at INTO v_expires;

    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE = '40001',
        MESSAGE = format('CD-OFFER-OBSERVED: intent %s became observed while this offer '
                         'was being decided; retry to receive already_observed', existing.id);
    END IF;

    out_row := (existing.id, existing.reservation_id, existing.object_key,
                existing.expected_bytes, existing.content_digest,
                v_expires, true, 'replayed');
    RETURN out_row;
  END IF;

  -- =========================================================================
  -- THE R31 ARITHMETIC, under the reservation lock.
  --
  -- NO STATE PREDICATE. Under R55 every intent counts, whatever it says about
  -- itself, because neither the clock nor a client abandon revokes a presigned
  -- URL already issued. The only thing that releases these bytes is the
  -- reservation dying, which takes its children with it.
  -- =========================================================================
  SELECT coalesce(sum(expected_bytes), 0) INTO v_spoken
    FROM cd.upload_intents
   WHERE reservation_id = r.id;
  IF v_spoken + p_expected_bytes > r.bytes THEN
    RAISE EXCEPTION USING ERRCODE = '53100',
      MESSAGE = format('CD-OFFER-OVERCOMMIT: reservation %s holds %s bytes, %s already offered, %s requested',
                       r.id, r.bytes, v_spoken, p_expected_bytes);
  END IF;

  v_expires := LEAST(now() + p_ttl, r.expires_at);

  INSERT INTO cd.upload_intents
    (organization_id, world_id, reservation_id, object_key, expected_bytes, content_digest, expires_at)
  VALUES (v_org, r.world_id, r.id, p_object_key, p_expected_bytes, p_content_digest, v_expires)
  ON CONFLICT (object_key) DO NOTHING
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN
    SELECT * INTO existing FROM cd.upload_intents WHERE object_key = p_object_key;
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE = '40001',
        MESSAGE = 'CD-OFFER-CONCURRENT: the competing intent vanished; retry';
    END IF;
    PERFORM app.assert_intent_matches(existing.id, existing.reservation_id,
              existing.expected_bytes, existing.content_digest,
              p_reservation_id, p_expected_bytes, p_content_digest);
    out_row := (existing.id, existing.reservation_id, existing.object_key,
                existing.expected_bytes, existing.content_digest,
                existing.expires_at, true,
                CASE WHEN existing.state = 'observed' THEN 'already_observed' ELSE 'replayed' END);
    RETURN out_row;
  END IF;

  out_row := (v_id, r.id, p_object_key, p_expected_bytes, p_content_digest,
              v_expires, false, 'fresh');
  RETURN out_row;
END;
$$;

-- ---------------------------------------------------------------------------
-- Abandon. RELEASES NOTHING (R55), and the name says so now.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.abandon_upload(p_intent_id uuid)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cd, pg_temp
AS $$
DECLARE
  v_org uuid;
  i     cd.upload_intents;
BEGIN
  v_org := app.current_organization_id();

  -- Tenancy is checked on an unlocked read, because refusing a caller who has no
  -- business here should not queue behind a reservation lock. NOTHING IS DECIDED
  -- from this row -- 0019 decided from it, and group R measured `observed`
  -- becoming `abandoned` because of it.
  SELECT * INTO i FROM cd.upload_intents
   WHERE id = p_intent_id AND organization_id = v_org;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501',
      MESSAGE = 'CD-ABANDON-NOTFOUND: no such upload intent in this organization';
  END IF;

  i := app.lock_intent(p_intent_id);      -- the re-read, and the decision below

  IF i.state = 'observed' THEN
    RAISE EXCEPTION USING ERRCODE = '55000',
      MESSAGE = format('CD-ABANDON-OBSERVED: intent %s has already been written to '
                       'the provider and cannot be abandoned', i.id);
  END IF;
  IF i.state = 'client_abandoned' THEN
    RETURN false;                          -- idempotent, and says so
  END IF;

  UPDATE cd.upload_intents
     SET state = 'client_abandoned', settled_at = now()
   WHERE id = i.id AND state <> 'observed';
  RETURN true;
END;
$$;

COMMENT ON FUNCTION app.abandon_upload(uuid) IS
  'Records that the CLIENT will not use an upload authority. It releases NO '
  'bytes and revokes NOTHING: a presigned URL already issued authorizes its '
  'holder until it expires, and this function sends nothing to Cloudflare '
  '(R55, amending R40). Only the reservation dying releases an intent''s bytes.';

-- ---------------------------------------------------------------------------
-- Observe. Now INSIDE the lock protocol it used to sit outside.
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

  -- ENTER THE LOCK PROTOCOL. A queue consumer is cross-tenant and takes no
  -- tenant context, and 0021 let it conclude that meant it was outside the
  -- concurrency protocol too. It is not: it mutates an intent, so it queues at
  -- the same gate as everyone who mutates an intent, in the same order.
  SELECT id INTO v_intent FROM cd.upload_intents WHERE object_key = p_object_key;
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
    -- A redelivery. Queues is at-least-once, so this is normal operation and the
    -- correct response is to do nothing -- including to the projection -- and say so.
    SELECT id INTO existing FROM cd.storage_observations
     WHERE (p_message_id IS NOT NULL AND message_id = p_message_id)
        OR (p_message_id IS NULL AND bucket = p_bucket
            AND object_key = p_object_key AND etag = p_etag)
     ORDER BY observed_at DESC LIMIT 1;
    out_row := (existing, v_intent, p_size_bytes, true, v_intent IS NOT NULL);
    RETURN out_row;
  END IF;

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
    -- MONOTONIC. Every non-terminal state may become observed -- including
    -- client_abandoned, which is the whole of finding 61: the client said it
    -- would not upload, the URL was still live, and the object landed anyway.
    -- The provider is authoritative about that and we are not.
    UPDATE cd.upload_intents
       SET state = 'observed', settled_at = now()
     WHERE id = v_intent AND state <> 'observed';
  END IF;

  out_row := (v_id, v_intent, p_size_bytes, false, v_intent IS NOT NULL);
  RETURN out_row;
END;
$$;

RESET ROLE;
SET LOCAL ROLE computedriven_migrations;
REVOKE CREATE ON SCHEMA app FROM computedriven_ledger;

-- 0021's six-argument form is gone: the seventh parameter has a DEFAULT, so
-- leaving the old signature in place would give two overloads and make every
-- unqualified call ambiguous.
DROP FUNCTION IF EXISTS app.observe_storage_object(text, text, text, bigint, text, timestamptz);

REVOKE EXECUTE ON FUNCTION
  app.offer_upload(uuid, text, bigint, text, interval),
  app.abandon_upload(uuid),
  app.lock_intent(uuid),
  app.observe_storage_object(text, text, text, bigint, text, timestamptz, text)
FROM PUBLIC;

GRANT EXECUTE ON FUNCTION
  app.offer_upload(uuid, text, bigint, text, interval),
  app.abandon_upload(uuid)
TO computedriven_api;

GRANT EXECUTE ON FUNCTION app.lock_intent(uuid) TO computedriven_ledger;

GRANT EXECUTE ON FUNCTION
  app.observe_storage_object(text, text, text, bigint, text, timestamptz, text)
TO computedriven_jobs;

DO $$
BEGIN
  IF has_function_privilege('computedriven_api',
       'app.observe_storage_object(text,text,text,bigint,text,timestamptz,text)', 'EXECUTE') THEN
    RAISE EXCEPTION 'CD-OBSERVE-CLIENTPATH: the API role can assert provider observations';
  END IF;
  -- lock_intent takes locks on behalf of SECURITY DEFINER callers and is not
  -- itself an authorization boundary. The request roles must not reach it.
  IF has_function_privilege('computedriven_api', 'app.lock_intent(uuid)', 'EXECUTE') THEN
    RAISE EXCEPTION 'CD-LOCKINTENT-REACHABLE: the API role can take intent locks directly';
  END IF;
END
$$;

COMMIT;
