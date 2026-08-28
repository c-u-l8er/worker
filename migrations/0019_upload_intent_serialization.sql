-- 0019 — the upload intent is serialized on its reservation, and an object key
--        stops being an idempotency key that binds nothing
--
-- THREE DEFECTS, found by outside review 2026-08-22, all in app.offer_upload(),
-- all reproduced in concurrency group Q BEFORE this file was written.
--
-- ---------------------------------------------------------------------------
-- 1. THE READ/CHECK/WRITE RACE, FOR THE THIRD TIME.
--
-- 0017 summed the bytes a reservation's intents had already spoken for, decided,
-- and then inserted. Nothing serialized the sum against the insert.
--
--     M1.5, before 0014      read quota  -> decide -> write
--     M2 shape, in 0017      sum offers  -> decide -> insert
--
--     reservation = 100
--     A: sum=0, 80 <= 100, INSERT 80     B: sum=0, 80 <= 100, INSERT 80
--                    -> 160 bytes of authority against a 100 byte hold
--
-- MEASURED, group Q against 0017: `OVERSUBSCRIBED: 160 > 100`. The unique
-- constraint on object_key cannot help, because the two keys differ -- which is
-- the entire point of a chunked upload.
--
-- The fix is not a new counter. It is the lock finalize_storage() and
-- abort_storage() have taken since 0014:
--
--     SELECT * FROM cd.storage_reservations WHERE id = ... FOR UPDATE
--
-- offer_upload was the ONLY function in the storage family that read that row
-- without it. The reservation is the serialization boundary for its own child
-- intents; different reservations stay fully parallel. If thousands of
-- concurrent chunk offers ever make one reservation row hot, that is a measured
-- problem with a measured fix, and it is not this one.
--
-- ---------------------------------------------------------------------------
-- 2. SEQUENTIALLY IDEMPOTENT, CONCURRENTLY A 500. AGAIN.
--
-- 0016 fixed exactly this for reservations and 0017 rebuilt it one layer up:
-- SELECT the intent by key, and if it is missing, INSERT. Two callers offering
-- the same fresh chunk both miss, one inserts, and the other gets
--
--     ERROR: duplicate key value violates unique constraint "upload_intents_key_uq"
--
-- which is what group Q measured. The client that retried on a timeout -- the
-- normal reason to send the same chunk twice -- is the one that gets the 500.
--
--     "THE LOSER MAY ERROR" IS NOT IDEMPOTENCE.
--
-- The reservation lock already fixes this for same-reservation callers. The
-- INSERT is ON CONFLICT DO NOTHING anyway, because two callers offering ONE key
-- against TWO reservations are not serialized by either reservation's lock.
--
-- ---------------------------------------------------------------------------
-- 3. AN OBJECT KEY WAS BEING MADE TO MEAN TWO DIFFERENT THINGS.
--
-- 0017's replay path checked organization, expected_bytes and content_digest --
-- and then returned `existing.reservation_id`, whatever it was. So:
--
--     reservation A offers chunk/hash123, A expires
--     reservation B offers the identical chunk/hash123
--         -> B receives A's intent, bound to A
--
-- MEASURED, group Q against 0017: the second offer returned an intent id instead
-- of refusing. Write authority minted under a dead hold was handed to a live one.
--
-- That is two product semantics wearing one key:
--
--     REQUEST IDEMPOTENCE      (reservation, key, bytes, digest) -> same intent
--     CONTENT DEDUPLICATION    this content already exists       -> do not upload
--
-- They are kept apart here. The immutable tuple now includes reservation_id, so
-- the first case is exact and the second is a REFUSAL rather than a silent
-- substitution. Deduplication is a real and desirable thing to build -- it needs
-- proof that the object is present in R2, which is R32's business and not a
-- replay at all -- and it is NOT built here.
--
-- ---------------------------------------------------------------------------
-- R40 — AN INTENT'S BYTES ARE RELEASED BY AN EXPLICIT ABANDON OR BY ITS
--       RESERVATION DYING. NEVER BY THE CLOCK.
--
-- ***  TWO CORRECTIONS, BOTH FROM ROUND 7.2. READ THEM BEFORE THE PARAGRAPH.  ***
--
--   1. THIS FILE CALLED THE RULE R34 THROUGHOUT. It is R40. R34 belongs to a
--      parallel box-and-box session that was numbering into the same register on
--      the same day -- the exact collision REVISION_REGISTER.md already carries a
--      note about, repeated by the session that wrote the note.
--
--   2. THE "EXPLICIT ABANDON" HALF IS WRONG AND 0022 AMENDS IT (R55).
--      (This said R51 -- an unrelated binding/authentication ruling -- in both
--      places it appears in this file, which is the SECOND wrong ruling number
--      corrected here after R34. The denylist that catches a duplicated fact
--      does not catch a citation pointing at the wrong row.)
--      abandon_upload() is a row in our database. It sends nothing to Cloudflare,
--      and a presigned URL authorizes its holder until the URL expires -- so
--      abandoning released bytes while the authority to spend them was still in
--      the client's hands:
--
--          reserve 100 -> offer A for 100 -> receive URL -> abandon A
--          -> 100 released -> offer B for 100 -> USE THE STILL-LIVE URL FOR A
--          -> 200 bytes stored against a 100-byte reservation
--
--      The "never by the clock" half survives, for the reason given below. Under
--      0022 NOTHING but the reservation dying releases an intent's bytes.
--
-- The obvious reading of "expired" is that a dead grant should stop speaking for
-- its bytes. It must not, and the reason is R8: the bytes are on a wire we do not
-- see. A grant that expired one second ago may have a PUT in flight against a
-- presigned URL that R2 will still honour, because R2's clock is not ours. If
-- expiry released the bytes, a fresh offer could take them and both writes land.
--
--     THE WINDOW GOVERNS WHETHER WE MINT A URL.
--     IT DOES NOT GOVERN WHETHER THE BYTES ARE SPOKEN FOR.
--
-- So every state except 'abandoned' counts against the reservation, and the only
-- ways bytes come back are app.abandon_upload() -- a decision -- and the
-- reservation itself expiring, which takes its children with it. This is why
-- there is no grace period anywhere in this file: a grace period is an attempt
-- to guess a clock skew, and guessing is what R40 refuses to do.

BEGIN;

SET LOCAL ROLE computedriven_migrations;

-- ---------------------------------------------------------------------------
-- `replayed boolean` could say "you have seen this before" and could not say
-- WHICH KIND of before. Three outcomes need three names, because the Worker must
-- behave differently for each and a boolean would make it guess:
--
--     fresh             mint a presigned PUT
--     replayed          mint a presigned PUT for the SAME grant
--     already_observed  DO NOT MINT ANYTHING; R2 already has this object
--
-- The boolean stays, so nothing that reads it breaks; it is now derived.
-- ---------------------------------------------------------------------------
DROP FUNCTION IF EXISTS app.offer_upload(uuid, text, bigint, text, interval);
ALTER TYPE app.upload_offer ADD ATTRIBUTE disposition text CASCADE;

COMMENT ON TYPE app.upload_offer IS
  'The answer to an offer. `disposition` is fresh | replayed | already_observed; '
  '`replayed` is the boolean shadow of it. already_observed means R2 holds the '
  'object and no write authority is being granted.';

-- ---------------------------------------------------------------------------
-- The promise validator, in ONE place, for the same reason
-- assert_reservation_matches() is: this rule is consulted from the fast replay
-- path and from the lost-the-race path, and two copies is how two copies come to
-- disagree.
--
-- reservation_id is IN the tuple. That is defect 3, in one line.
-- ---------------------------------------------------------------------------
GRANT CREATE ON SCHEMA app TO computedriven_ledger;
SET LOCAL ROLE computedriven_ledger;

CREATE OR REPLACE FUNCTION app.assert_intent_matches(
  p_intent_id        uuid,
  p_stored_res       uuid,
  p_stored_bytes     bigint,
  p_stored_digest    text,
  p_reservation_id   uuid,
  p_expected_bytes   bigint,
  p_content_digest   text
)
RETURNS void
LANGUAGE plpgsql
IMMUTABLE
AS $$
BEGIN
  IF p_stored_res    IS DISTINCT FROM p_reservation_id
     OR p_stored_bytes  IS DISTINCT FROM p_expected_bytes
     OR p_stored_digest IS DISTINCT FROM p_content_digest THEN
    RAISE EXCEPTION USING ERRCODE = '22023',
      MESSAGE = format(
        'CD-OFFER-MISMATCH: that object key already names intent %s '
        '(reservation %s, %s bytes, %s); this request is '
        '(reservation %s, %s bytes, %s)',
        p_intent_id, p_stored_res, p_stored_bytes, p_stored_digest,
        p_reservation_id, p_expected_bytes, p_content_digest);
  END IF;
END;
$$;

COMMENT ON FUNCTION app.assert_intent_matches(uuid, uuid, bigint, text, uuid, bigint, text) IS
  'An object key names a complete immutable promise {reservation, key, bytes, '
  'digest}, not just a row. Reuse that disagrees on any field is refused. An '
  'intent may NOT change reservation: that would move write authority minted '
  'under one hold onto another.';

-- ---------------------------------------------------------------------------
-- Release an intent's bytes. The ONLY path that gives them back (R40) -- SUPERSEDED
-- by 0022/R55, which establishes that it gives back nothing. Kept as written so
-- the amendment has something to point at. This is
-- why it exists at all: without it 'abandoned' is a state nothing can reach and
-- the accounting has no exit.
--
-- An OBSERVED intent may not be abandoned. The provider has already written the
-- object; forgetting that we asked for it does not unwrite it, and pretending
-- otherwise is how a tenant gets storage it is not billed for.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.abandon_upload(p_intent_id uuid)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cd, pg_temp
AS $$
DECLARE
  v_org uuid;
  i     record;
BEGIN
  v_org := app.current_organization_id();

  SELECT * INTO i FROM cd.upload_intents
   WHERE id = p_intent_id AND organization_id = v_org;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501',
      MESSAGE = 'CD-ABANDON-NOTFOUND: no such upload intent in this organization';
  END IF;

  -- Same order as offer_upload: reservation first, then the intent. Two
  -- functions taking these two locks in opposite orders is a deadlock, and the
  -- fact that both are short is not a defence.
  PERFORM 1 FROM cd.storage_reservations
   WHERE id = i.reservation_id AND organization_id = v_org FOR UPDATE;

  IF i.state = 'observed' THEN
    RAISE EXCEPTION USING ERRCODE = '55000',
      MESSAGE = format('CD-ABANDON-OBSERVED: intent %s has already been written to '
                       'the provider and cannot be abandoned', i.id);
  END IF;
  IF i.state = 'abandoned' THEN
    RETURN false;                      -- idempotent, and says so
  END IF;

  UPDATE cd.upload_intents
     SET state = 'abandoned', settled_at = now()
   WHERE id = i.id;
  RETURN true;
END;
$$;

COMMENT ON FUNCTION app.abandon_upload(uuid) IS
  'Releases an intent''s bytes back to its reservation. R40: this and the '
  'reservation dying are the only two ways bytes come back -- never the clock.';

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
  existing   record;
  out_row    app.upload_offer;
BEGIN
  v_org := app.current_organization_id();

  -- Argument shape first. These need no lock, and taking a row lock to discover
  -- that a caller sent zero bytes would hold up every other offer on the
  -- reservation while we found out.
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

  -- =========================================================================
  -- THE SERIALIZATION BOUNDARY.
  --
  -- Everything from here to COMMIT -- the byte arithmetic, the replay lookup and
  -- the insert -- happens with this reservation's row held. Concurrent offers
  -- against THIS reservation queue; offers against every other reservation are
  -- untouched.
  --
  -- FOR UPDATE and not an advisory lock: Hyperdrive does not support advisory
  -- locks (0013 -> 0015 learned that the expensive way) and a row lock is
  -- ordinary MVCC that any pooler forwards.
  -- =========================================================================
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

  -- The key must be inside THIS reservation's world. Not checked afterwards:
  -- an unparseable or foreign key is refused before anything is written.
  SELECT * INTO k FROM app.parse_object_key(p_object_key);
  IF NOT FOUND OR k.organization_id <> v_org OR k.world_id <> r.world_id THEN
    RAISE EXCEPTION USING ERRCODE = '42501',
      MESSAGE = format('CD-OFFER-KEY: %L is not an object key inside this world', p_object_key);
  END IF;

  -- =========================================================================
  -- REPLAY. The whole promise is checked, including which reservation it
  -- belongs to, before anything is handed back.
  -- =========================================================================
  SELECT * INTO existing FROM cd.upload_intents WHERE object_key = p_object_key;
  IF FOUND THEN
    IF existing.organization_id <> v_org THEN
      -- Should be unreachable given the key parse above; if it ever fires, the
      -- key format and the tenancy check have diverged.
      RAISE EXCEPTION USING ERRCODE = '42501',
        MESSAGE = 'CD-OFFER-KEY: that object key belongs to another organization';
    END IF;
    PERFORM app.assert_intent_matches(existing.id, existing.reservation_id,
              existing.expected_bytes, existing.content_digest,
              p_reservation_id, p_expected_bytes, p_content_digest);

    IF existing.state = 'observed' THEN
      -- NOT a replay. R2 holds this object. Handing back a live window here
      -- would mint write authority for content that is already written, which
      -- is the dedup/idempotence conflation this file exists to separate.
      out_row := (existing.id, existing.reservation_id, existing.object_key,
                  existing.expected_bytes, existing.content_digest,
                  existing.expires_at, true, 'already_observed');
      RETURN out_row;
    END IF;

    IF existing.state = 'abandoned' THEN
      -- The bytes were given back (R40). Taking them again is a fresh admission
      -- decision, so fall through to the arithmetic rather than reviving for
      -- free -- the reservation may have been spent in the meantime.
      SELECT coalesce(sum(expected_bytes), 0) INTO v_spoken
        FROM cd.upload_intents
       WHERE reservation_id = r.id AND state <> 'abandoned';
      IF v_spoken + p_expected_bytes > r.bytes THEN
        RAISE EXCEPTION USING ERRCODE = '53100',
          MESSAGE = format('CD-OFFER-OVERCOMMIT: reservation %s holds %s bytes, %s already offered, %s requested',
                           r.id, r.bytes, v_spoken, p_expected_bytes);
      END IF;
    END IF;

    -- 'offered' (live or past its window) and 'abandoned' that just passed the
    -- arithmetic both land here. Re-issue a window on the SAME row: same
    -- promise, same bytes, same reservation, so the key stays unique and an
    -- arriving R2 event stays attributable to exactly one intent.
    v_expires := LEAST(now() + p_ttl, r.expires_at);
    UPDATE cd.upload_intents
       SET state      = 'offered',
           settled_at = NULL,
           expires_at = GREATEST(expires_at, v_expires)
     WHERE id = existing.id
    RETURNING expires_at INTO v_expires;

    out_row := (existing.id, existing.reservation_id, existing.object_key,
                existing.expected_bytes, existing.content_digest,
                v_expires, true, 'replayed');
    RETURN out_row;
  END IF;

  -- =========================================================================
  -- THE R31 ARITHMETIC, under the lock. It does not stop R2 accepting a larger
  -- body -- nothing in the current grant primitive does -- but it stops US from
  -- ever offering authority for bytes the reservation has not got. That
  -- distinction is the whole of R31's open question.
  --
  -- `state <> 'abandoned'` and not `state IN ('offered','observed')`: R40. An
  -- intent whose window closed still speaks for its bytes, because its PUT may
  -- be in flight against a clock that is not ours.
  -- =========================================================================
  SELECT coalesce(sum(expected_bytes), 0) INTO v_spoken
    FROM cd.upload_intents
   WHERE reservation_id = r.id AND state <> 'abandoned';
  IF v_spoken + p_expected_bytes > r.bytes THEN
    RAISE EXCEPTION USING ERRCODE = '53100',
      MESSAGE = format('CD-OFFER-OVERCOMMIT: reservation %s holds %s bytes, %s already offered, %s requested',
                       r.id, r.bytes, v_spoken, p_expected_bytes);
  END IF;

  v_expires := LEAST(now() + p_ttl, r.expires_at);

  -- ON CONFLICT, not a bare INSERT. The reservation lock already serializes
  -- same-reservation callers, so this fires only for two callers offering ONE
  -- key against TWO reservations -- who hold different locks and are not
  -- ordered by either. Under READ COMMITTED the loser WAITS on the winner's
  -- uncommitted row rather than raising, which is the serialization 0015 relies
  -- on for identity and 0016 for reservations, doing the same job a third time.
  INSERT INTO cd.upload_intents
    (organization_id, world_id, reservation_id, object_key, expected_bytes, content_digest, expires_at)
  VALUES (v_org, r.world_id, r.id, p_object_key, p_expected_bytes, p_content_digest, v_expires)
  ON CONFLICT (object_key) DO NOTHING
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN
    SELECT * INTO existing FROM cd.upload_intents WHERE object_key = p_object_key;
    IF NOT FOUND THEN
      -- The winner rolled back between our conflict and this read. Retryable,
      -- and named rather than returned as a NULL row.
      RAISE EXCEPTION USING ERRCODE = '40001',
        MESSAGE = 'CD-OFFER-CONCURRENT: the competing intent vanished; retry';
    END IF;
    -- Almost certainly a MISMATCH -- a different reservation claiming this key --
    -- and the validator says which field, rather than this branch guessing.
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

COMMENT ON FUNCTION app.offer_upload(uuid, text, bigint, text, interval) IS
  'Offers write authority for one chunk. Serialized on its reservation row '
  '(0019), so concurrent offers cannot oversubscribe it. An object key binds the '
  'whole promise {reservation, key, bytes, digest}; concurrent same-promise '
  'callers ALL succeed with one intent.';

-- ---------------------------------------------------------------------------
-- observe_storage_object() settled only intents in state 'offered'. An intent
-- whose window closed is still 'offered' today, but R40 makes 'expired' a state
-- the sweeper may legitimately set, and a provider event for such an intent is
-- the MOST important one to record -- it is the late write the window was too
-- short for. Widened so the object landing is never dropped on the floor.
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
     WHERE id = v_intent AND state IN ('offered', 'expired');
  END IF;

  out_row := (v_id, v_intent, p_size_bytes, false, v_intent IS NOT NULL);
  RETURN out_row;
END;
$$;

RESET ROLE;
SET LOCAL ROLE computedriven_migrations;
REVOKE CREATE ON SCHEMA app FROM computedriven_ledger;

-- Explicit, because the explicit REVOKEs are what has actually been holding the
-- line (0018) and because offer_upload was DROPped above, taking its ACL with
-- it. 0020 adds the default-privilege net underneath this; it does not replace
-- the habit of saying so.
REVOKE EXECUTE ON FUNCTION
  app.offer_upload(uuid, text, bigint, text, interval),
  app.abandon_upload(uuid),
  app.assert_intent_matches(uuid, uuid, bigint, text, uuid, bigint, text),
  app.observe_storage_object(text, text, text, bigint, text, timestamptz)
FROM PUBLIC;

GRANT EXECUTE ON FUNCTION
  app.offer_upload(uuid, text, bigint, text, interval),
  app.abandon_upload(uuid)
TO computedriven_api;

GRANT EXECUTE ON FUNCTION
  app.assert_intent_matches(uuid, uuid, bigint, text, uuid, bigint, text)
TO computedriven_ledger;

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
  IF has_function_privilege('public', 'app.abandon_upload(uuid)', 'EXECUTE') THEN
    RAISE EXCEPTION 'CD-ACL-PUBLIC: PUBLIC holds EXECUTE on app.abandon_upload';
  END IF;
END
$$;

COMMIT;
