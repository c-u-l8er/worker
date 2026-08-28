-- 0023 — settlement: a number about the provider may only be moved by the
--        provider, and our clock is not the provider's clock
--
-- Findings 65, 66, 68, 69 from outside review 2026-08-22, and finding 71 found
-- by reproducing 65. All five reproduced against 0001-0022 BEFORE this file was
-- written; the reproductions are concurrency group S.
--
-- ===========================================================================
-- ONE LESSON IN FIVE PLACES: A LOCAL FACT AND A PROVIDER FACT WERE SHARING
-- ONE SLOT.
--
-- 0022 ruled R54 -- provider-observed truth is monotonic, `observed` is a fact
-- about the world and not a stage in our workflow -- and applied it to the
-- intent STATE. It did not apply it to the BYTE LEDGER, which is where the
-- money is, and the ledger had the client as sole author of a column
-- documented as "bytes actually in R2".
--
--     storage_usage.committed_bytes    "bytes actually in R2"
--     written by                        app.finalize_storage()   <- the CLIENT
--
-- Everything below follows from closing that one gap.
--
-- ---------------------------------------------------------------------------
-- 65. THE PROVIDER SAID THE BYTES LANDED, AND EXPIRY MADE THEM FREE.
--
-- MEASURED against 0022, deterministically, with no race and nothing in flight:
--
--     organization limit             100
--     reserve_storage(100)           committed 0   reserved 100
--     offer chunk A for 100          intent offered
--     R2 event arrives, committed    storage_objects: A = 100 bytes
--                                    intent -> observed
--     client crashes before finalize_storage()
--     reservation TTL passes
--     expire_storage_reservations()  committed 0   reserved 0      <- HERE
--     reserve_storage(100)           ADMITTED
--     R2 may now hold               200 against a 100 byte limit
--
-- The R2 event was fully committed BEFORE expiry. No clock skew, no delayed
-- queue message, no in-flight PUT. The provider had already spoken and the
-- ledger threw the statement away.
--
-- And the reproduction found the half that is worse than the finding: after
-- expiry there is NO PATH LEFT TO EVER CHARGE THEM. finalize_storage() refuses
-- a terminal reservation --
--
--     CD-FINALIZE-STATE: reservation ... is expired and cannot be finalized
--
-- -- and finalize was the only writer of committed_bytes. So the drift is not
-- a lag that reconciliation catches up with later. It is permanent, and the
-- quota is permanently wrong in the direction that gives storage away.
--
-- app.storage_divergence() reported delta=100 the whole time. The system had
-- the number. Nothing was wired to act on it.
--
-- ---------------------------------------------------------------------------
-- 71. THE SAME DEFECT WITH NO CLOCK AT ALL, IN THE FUNCTION NEXT DOOR.
--
-- Found by reproducing 65 and reading what else writes reserved_bytes.
-- app.abort_storage() is R55 at the RESERVATION level, and R55 fixed only the
-- INTENT level:
--
--     reserve 100  ->  offer 100  ->  the client holds a live presigned URL
--     R2 event arrives, 100 bytes land
--     abort_storage()              reserved 100 -> 0        MEASURED
--     reserve_storage(100)         ADMITTED                 MEASURED
--
-- R55 established that a client abandon revokes our willingness to mint more
-- authority and revokes nothing already issued. abort_storage() is the same
-- sentence one level up and was left saying the opposite: it is a row in our
-- database that gives back bytes R2 is already holding. It needs no TTL, no
-- concurrency and no crash -- one synchronous client call, and the second
-- reservation is admitted in the same second.
--
--     THE FIX FOR A CLASS OF DEFECT IS NOT APPLIED UNTIL EVERY MEMBER OF THE
--     CLASS HAS BEEN LOOKED AT. R55 WAS RULED AS A GENERAL PRINCIPLE AND
--     APPLIED AT ONE CALL SITE.
--
-- ---------------------------------------------------------------------------
-- THE RULINGS
--
--     R68 -- A NUMBER THAT DESCRIBES THE PROVIDER MAY ONLY BE MOVED BY THE
--     PROVIDER. storage_usage.committed_bytes is written by the observer and
--     by nothing else. finalize_storage() records what the CLIENT ASSERTS, for
--     comparison, and moves no bytes.
--
--     R69 (extends R55 to the clock) -- OUR CLOCK ENDS OUR OWN WILLINGNESS TO
--     MINT AUTHORITY. IT DOES NOT END THE AUTHORITY AND IT DOES NOT SETTLE THE
--     ACCOUNT. Expiry, abort and finalize are all LOCAL declarations; none of
--     them is evidence about what R2 holds, so none of them releases bytes.
--
--     R70 -- ATTRIBUTION IS ESTABLISHED BY AN OBSERVATION, NEVER BY A KEY. A
--     later intent may not claim an earlier write (finding 68).
--
--     R71 -- INDEPENDENT FACTS GET INDEPENDENT COLUMNS. A lifecycle enum that
--     can hold only one of two orthogonal facts destroys the other one
--     (finding 66).
--
-- R55 and R69 are the same theorem about the two different ways a reservation
-- can end, which is the sign it was the right theorem: BOTH of our local
-- "this is over" events turn out to end only our own future behaviour, and
-- neither of them is evidence about the provider.
--
-- ===========================================================================
-- WHAT REPLACES THE RELEASE PATH
--
-- Under R69 nothing local releases bytes, so the question becomes: what does?
-- The answer is that the hold was never a stored quantity to begin with. It is
-- a DERIVED one, and deriving it makes finding 65 stop existing rather than
-- get patched:
--
--     occupancy(org)    = sum of current provider-held bytes    storage_objects
--     outstanding(org)  = sum over unsettled reservations of
--                           GREATEST(0, bytes - observed-and-attributed)
--     used              = occupancy + outstanding
--
-- A reservation that has been fully observed contributes 0 to outstanding
-- WITHOUT anything having released it, because its bytes are already counted
-- in occupancy. A reservation that expired unobserved keeps holding, because
-- our clock passing is not evidence the bytes did not land.
--
-- cd.storage_usage.reserved_bytes is therefore DROPPED. It was a counter that
-- four functions incremented and decremented, and every finding in this file
-- is one of those four getting it wrong. The table now holds exactly ONE
-- number and exactly one thing writes it.
--
--     THE ACCOUNTING GOT SIMPLER, AGAIN, BY ADMITTING WE CONTROL LESS THAN WE
--     THOUGHT. THAT IS TWICE. IT IS PROBABLY THE SHAPE OF THE WHOLE PROBLEM.
--
-- WHY OUTSTANDING IS CHEAP AND OCCUPANCY IS NOT. outstanding() ranges over
-- unsettled RESERVATIONS -- bounded, short-lived, at most a handful per tenant
-- because the TTL ceiling is 6 hours. Occupancy would range over OBJECTS,
-- which for a 10 TB world at 4 MB chunks is ~2.6M rows, so it stays an
-- incrementally maintained column. That asymmetry is the reason for the split
-- and is the thing to re-check if either bound moves.
--
-- ---------------------------------------------------------------------------
-- THE RELEASE VALVE, AND THE CONSTANT NOBODY HAS MEASURED
--
-- If nothing local releases, a client that asserts a finalize R2 never
-- confirms holds quota forever. So there is one more reservation state:
--
--     reserved   live; may back new offers
--     finalized  the client says it is done          still holds the remainder
--     aborted    the client says it gave up          still holds the remainder
--     expired    our clock passed                    still holds the remainder
--     settled    reconciled after a quiet period     RELEASES the remainder
--
-- Settlement is the only thing that releases, it is explicit, and it requires
-- that `expires_at + quiet` has passed. The quiet period exists because a PUT
-- R2 admitted before our expiry instant may still be landing, and the R2 ->
-- Queue -> consumer path has a latency nobody here has measured.
--
--     THE DEFAULT IS 1 HOUR AND IT IS A GUESS. It is declared as a function
--     rather than a literal so that live falsifier case I has exactly one
--     place to write its answer, and so that grep finds it.
--
-- Authority never outlives its reservation -- offer_upload() clamps every
-- offer window with LEAST(now() + ttl, r.expires_at) -- so the quiet period
-- has to cover provider latency and an in-flight body, not a second TTL.
--
-- ===========================================================================

BEGIN;

SET LOCAL ROLE computedriven_migrations;

-- ---------------------------------------------------------------------------
-- 66. `client_abandoned` AND `observed` ARE ORTHOGONAL FACTS, AND THE ENUM WAS
--     MAKING THEM DESTROY EACH OTHER.
--
--     the client abandoned the upload at T1
--     R2 nevertheless accepted a write at T2
--
-- The second does not make the first untrue. It is the most interesting
-- anomaly record this system can produce -- a live presigned URL used after
-- the client said it would not -- and 0022 overwrote it, because `state` holds
-- one value and `settled_at` holds one timestamp.
--
-- So the two facts get two columns, and `state` becomes a GENERATED projection
-- of them. That is not cosmetic. A generated column CANNOT BE WRITTEN, so
-- every `SET state = ...` in this schema is now a hard error rather than a
-- convention, and R54's "no local transition may walk provider truth back" is
-- enforced by the column definition instead of by remembering to add
-- `AND state <> 'observed'` to a WHERE clause.
--
--     THE GUARD 0022 HAD TO REMEMBER IN THREE PLACES IS NOW UNSPEAKABLE.
-- ---------------------------------------------------------------------------
ALTER TABLE cd.upload_intents
  ADD COLUMN client_abandoned_at  timestamptz,
  ADD COLUMN provider_observed_at timestamptz;

UPDATE cd.upload_intents SET provider_observed_at = coalesce(settled_at, now())
 WHERE state = 'observed';
UPDATE cd.upload_intents SET client_abandoned_at = coalesce(settled_at, now())
 WHERE state = 'client_abandoned';

ALTER TABLE cd.upload_intents DROP CONSTRAINT upload_intents_state_check;
ALTER TABLE cd.upload_intents DROP CONSTRAINT upload_intents_settled_ck;
ALTER TABLE cd.upload_intents DROP COLUMN state;
ALTER TABLE cd.upload_intents DROP COLUMN settled_at;

ALTER TABLE cd.upload_intents
  ADD COLUMN state text GENERATED ALWAYS AS (
    CASE WHEN provider_observed_at IS NOT NULL THEN 'observed'
         WHEN client_abandoned_at  IS NOT NULL THEN 'client_abandoned'
         ELSE 'offered' END) STORED,
  ADD COLUMN settled_at timestamptz GENERATED ALWAYS AS (
    coalesce(provider_observed_at, client_abandoned_at)) STORED;

COMMENT ON COLUMN cd.upload_intents.provider_observed_at IS
  'When R2 told us this object landed. WRITE-ONCE, enforced by trigger: this is '
  'a fact about the world and no local transition may walk it back (R54).';
COMMENT ON COLUMN cd.upload_intents.client_abandoned_at IS
  'When the CLIENT declared it would not use this authority. Releases nothing '
  '(R55) and is NOT cleared by a provider observation -- an intent carrying both '
  'timestamps is the anomaly record "abandoned at T1, written anyway at T2" '
  '(R71). A later re-offer of the same promise does clear it: that is the client '
  'withdrawing its own declaration, which is the one party entitled to.';
COMMENT ON COLUMN cd.upload_intents.state IS
  'DERIVED, and therefore UNWRITABLE. observed > client_abandoned > offered, '
  'projected from the two timestamps above. Kept so every existing query and '
  'check still reads a state; it is no longer a place a transition can be '
  'recorded, which is the point (R71).';

-- Monotonicity as a trigger rather than as three remembered WHERE clauses.
-- A generated `state` cannot be written at all, but the column it is generated
-- FROM can, and "no local transition may walk provider truth back" has to hold
-- for the base column or it holds nowhere.
CREATE FUNCTION app.upload_intent_observed_is_final() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.provider_observed_at IS NOT NULL
     AND NEW.provider_observed_at IS DISTINCT FROM OLD.provider_observed_at THEN
    RAISE EXCEPTION USING ERRCODE = '55000',
      MESSAGE = format('CD-INTENT-OBSERVED-FINAL: intent %s was observed at %s; '
                       'provider truth is monotonic (R54)', OLD.id, OLD.provider_observed_at);
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER upload_intents_observed_final
  BEFORE UPDATE ON cd.upload_intents
  FOR EACH ROW EXECUTE FUNCTION app.upload_intent_observed_is_final();

-- ---------------------------------------------------------------------------
-- 68. AN UNATTRIBUTED WRITE COULD BECOME ATTRIBUTED BY A LATER INTENT.
--
-- MEASURED against 0022:
--
--     T1  an out-of-band write lands under a valid key   attributed = false
--         storage_divergence(): 0 rows                   correct
--     T2  a LATER control-plane operation creates an intent for that key
--         nothing new arrives from R2
--     T3  storage_divergence(): 1 row, observed = 70
--
-- The past changed because a row appeared in a different table. The
-- observation itself still says intent_id IS NULL -- the provenance log was
-- right the whole time -- and the divergence query went around it:
--
--     FROM cd.storage_objects so
--     JOIN cd.upload_intents i ON i.object_key = so.object_key
--
-- An object key is a NAME. Two things may hold the same name at different
-- times and one of them may be ours. What ties provider bytes to a reservation
-- is the OBSERVATION that carried them, and that row already records its
-- intent correctly.
--
--     R70 -- ATTRIBUTION IS ESTABLISHED BY AN OBSERVATION, NEVER BY A KEY.
--
-- So the inventory records WHICH observation established its current state,
-- and attribution is derived through that. An unattributed write stays
-- unattributed until another real provider event says otherwise.
-- ---------------------------------------------------------------------------
ALTER TABLE cd.storage_objects
  ADD COLUMN current_observation_id uuid REFERENCES cd.storage_observations(id) ON DELETE RESTRICT;

-- Backfill: the observation that is current for a key is the one this
-- projection would have chosen -- newest event_time, newest observed_at as the
-- tiebreak. Same ordering as 0021's own backfill, for the same reason.
WITH latest AS (
  SELECT DISTINCT ON (o.bucket, o.object_key) o.id, o.bucket, o.object_key
    FROM cd.storage_observations o
   ORDER BY o.bucket, o.object_key, o.event_time DESC, o.observed_at DESC
)
UPDATE cd.storage_objects so
   SET current_observation_id = l.id
  FROM latest l
 WHERE l.bucket = so.bucket AND l.object_key = so.object_key;

COMMENT ON COLUMN cd.storage_objects.current_observation_id IS
  'The provider event that established this row''s CURRENT etag and size. '
  'Attribution to a reservation is derived through it and never by joining an '
  'intent on object_key -- a key is a name, and a later intent must not be able '
  'to claim an earlier write (R70).';

-- ---------------------------------------------------------------------------
-- 69. overwrite_count DEPENDED ON DELIVERY ORDER.
--
-- 0021 guards etag and size_bytes with event_time, correctly, and then
-- increments overwrite_count whenever the ARRIVING etag differs from whatever
-- happens to be current AT DELIVERY TIME. Queues does not guarantee order, so
-- the same provider history counts differently depending on the order it is
-- delivered in. MEASURED against 0022, same three events both times:
--
--     provider chronology   t1 A   t2 A   t3 B        one content overwrite
--     delivered t1,t2,t3    etag B   overwrite_count 1        correct
--     delivered t1,t3,t2    etag B   overwrite_count 2        WRONG
--
-- 0021's own BACKFILL computes this correctly:
--
--     greatest(count(DISTINCT s.etag) - 1, 0)
--
-- and the incremental path it installed in the same file does not. The
-- backfill is order-independent because it reads the append-only log; the
-- increment is order-dependent because it reads the projection. So the
-- incremental path is replaced by the backfill's own expression, evaluated
-- against the log after the arriving observation has been inserted into it.
--
-- Cost is bounded by events-per-key, which on a content-addressed key is 1 and
-- on a key with more than 1 is already an alarm someone is reading.
--
--     WHEN TWO PATHS IN ONE FILE COMPUTE THE SAME QUANTITY AND ONLY ONE IS
--     ORDER-INDEPENDENT, THAT IS NOT TWO IMPLEMENTATIONS. IT IS THE ANSWER AND
--     A BUG, SHIPPED TOGETHER.
-- ---------------------------------------------------------------------------
UPDATE cd.storage_objects so
   SET overwrite_count = (
     SELECT greatest(count(DISTINCT o.etag) - 1, 0)
       FROM cd.storage_observations o
      WHERE o.bucket = so.bucket AND o.object_key = so.object_key);

COMMENT ON COLUMN cd.storage_objects.overwrite_count IS
  'Distinct bodies seen under this name, minus one. Computed from the '
  'append-only log so it is INDEPENDENT OF DELIVERY ORDER -- Queues does not '
  'guarantee order, and counting against the projection made the same provider '
  'history score differently depending on arrival sequence (0023). Non-zero on '
  'a content-addressed key is an alarm: collision, a client ignoring its own '
  'digest, or multipart.';

-- ---------------------------------------------------------------------------
-- The reservation, which is now a record of DECLARATIONS plus one state that
-- is a record of RECONCILIATION.
--
-- `committed_bytes` is renamed. It never held bytes anyone had observed: it
-- held the number the client passed to finalize_storage(). Two columns in this
-- schema were called committed_bytes and only one of them is about the
-- provider, which is most of how finding 65 stayed invisible.
-- ---------------------------------------------------------------------------
ALTER TABLE cd.storage_reservations DROP CONSTRAINT storage_reservations_commit_ck;
ALTER TABLE cd.storage_reservations RENAME COLUMN committed_bytes TO asserted_bytes;

ALTER TABLE cd.storage_reservations DROP CONSTRAINT storage_reservations_state_check;
ALTER TABLE cd.storage_reservations
  ADD CONSTRAINT storage_reservations_state_check
  CHECK (state IN ('reserved', 'finalized', 'aborted', 'expired', 'settled'));

ALTER TABLE cd.storage_reservations
  ADD CONSTRAINT storage_reservations_assert_ck
  CHECK ((asserted_bytes IS NULL) OR
         (state IN ('finalized', 'settled') AND asserted_bytes >= 0 AND asserted_bytes <= bytes));

COMMENT ON COLUMN cd.storage_reservations.asserted_bytes IS
  'What the CLIENT said it wrote, at finalize. An assertion to be compared '
  'against app.storage_divergence(), NOT a quantity anyone has observed and no '
  'longer anything the byte ledger reads (R68). Was `committed_bytes`, which is '
  'also the name of the provider-derived column in cd.storage_usage -- one name '
  'for a client claim and a provider fact is how finding 65 stayed invisible.';

COMMENT ON COLUMN cd.storage_reservations.state IS
  'reserved | finalized | aborted | expired | settled. The first four are LOCAL '
  'declarations and NONE of them releases bytes (R69): our clock and our client '
  'both speak only about us. `settled` is the one reconciled state and the only '
  'release path -- reached by app.settle_storage_reservations() once the quiet '
  'period past expires_at has elapsed.';

-- ---------------------------------------------------------------------------
-- The ledger. One number, one writer.
-- ---------------------------------------------------------------------------
ALTER TABLE cd.storage_usage DROP COLUMN reserved_bytes;

COMMENT ON TABLE cd.storage_usage IS
  'Provider-observed occupancy, one row per organization, and NOTHING ELSE. '
  'reserved_bytes was dropped in 0023: it was a counter four functions '
  'incremented and decremented, and every finding in that round was one of the '
  'four getting it wrong. The hold is now DERIVED by app.storage_outstanding().';

COMMENT ON COLUMN cd.storage_usage.committed_bytes IS
  'Bytes R2 is observed to hold. Moved ONLY by app.observe_storage_object() '
  '(R68). Before 0023 this said the same thing and was written only by the '
  'client, which is finding 65.';

GRANT CREATE ON SCHEMA app TO computedriven_ledger;
SET LOCAL ROLE computedriven_ledger;

-- ---------------------------------------------------------------------------
-- The quiet period. A guess, named so it can be found and replaced.
-- ---------------------------------------------------------------------------
CREATE FUNCTION app.settlement_quiet_period() RETURNS interval
LANGUAGE sql IMMUTABLE AS $$ SELECT interval '1 hour' $$;

COMMENT ON FUNCTION app.settlement_quiet_period() IS
  'How long after a reservation''s expires_at we wait before releasing its '
  'unobserved remainder. UNMEASURED -- it has to cover a PUT R2 admitted just '
  'before our expiry instant plus R2 -> Queue -> consumer latency, and neither '
  'is documented. Live falsifier case I writes the real number here. Authority '
  'never outlives its reservation (offer_upload clamps to r.expires_at), so this '
  'covers provider lag and an in-flight body, not a second TTL.';

-- ---------------------------------------------------------------------------
-- OUTSTANDING AUTHORITY. The derived hold.
--
-- Per reservation: what it authorized, minus what has been OBSERVED AND
-- CAUSALLY ATTRIBUTED to it, floored at zero.
--
-- The join is the whole of R70 and reads in the only direction that is sound:
--
--     reservation -> its intents -> observations THAT NAMED those intents
--                 -> the objects those observations currently establish
--
-- Never `storage_objects JOIN upload_intents ON object_key`, which is finding
-- 68 and lets a new row change the past. Each storage_objects row has one
-- current_observation_id and each observation names at most one intent, so no
-- object can be counted twice.
--
-- GREATEST(..., 0) because observed bytes CAN exceed the reservation: falsifier
-- case B is open precisely because nothing has shown R2 refuses a body larger
-- than we reserved. The excess is a divergence for storage_divergence() to
-- report, not a negative hold to hand back as free quota.
-- ---------------------------------------------------------------------------
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
        FROM cd.upload_intents i
        JOIN cd.storage_observations ob ON ob.intent_id = i.id
        JOIN cd.storage_objects     so ON so.current_observation_id = ob.id
       WHERE i.reservation_id = r.id
    ) o ON true
   WHERE r.organization_id = p_organization_id
     AND r.state <> 'settled';
$$;

COMMENT ON FUNCTION app.storage_outstanding(uuid) IS
  'Bytes authorized and not yet accounted for by a provider observation. '
  'DERIVED, never stored: a reservation fully observed contributes zero without '
  'anything having released it, and one that expired unobserved keeps holding '
  'because our clock passing is not evidence the bytes did not land (R69). '
  'Ranges over reservations, which are few and short-lived -- occupancy ranges '
  'over objects and therefore stays an incremented column.';

CREATE FUNCTION app.storage_ledger(p_organization_id uuid)
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

COMMENT ON FUNCTION app.storage_ledger(uuid) IS
  'The whole quota position: provider-observed occupancy + outstanding '
  'authority. This is what an entitlement is checked against.';

-- ---------------------------------------------------------------------------
-- RESERVE, with the same admission property and a different mechanism.
--
-- 0014 was atomic by folding the arithmetic into an UPDATE ... WHERE, so the
-- loser re-evaluated the predicate against the winner's committed row. That
-- works for a STORED counter and cannot work for a DERIVED one: a subquery in
-- that WHERE would be evaluated against the statement snapshot taken before
-- the wait, which is the read-then-write window group P exists to catch,
-- wearing a lock.
--
-- So the lock is taken FIRST, in its own statement, and the arithmetic runs in
-- the NEXT one:
--
--     INSERT ... ON CONFLICT DO UPDATE   creates-or-LOCKS the ledger row
--     app.storage_outstanding(org)       fresh snapshot: sees the winner
--     INSERT the reservation             under the lock, held to COMMIT
--
-- Three things this depends on, all of which are easy to break by tidying:
--
--   1. ON CONFLICT DO UPDATE, not DO NOTHING. DO NOTHING does not block, so
--      two reservers for an organization with no ledger row yet would both
--      proceed unserialized. DO UPDATE takes the row lock in every case.
--   2. READ COMMITTED gives each STATEMENT a new snapshot, which is why the
--      outstanding sum must not be folded back into the locking statement.
--   3. This function must stay VOLATILE. Marking it STABLE would freeze the
--      snapshot for its whole body and silently restore the window.
--
-- THE BODY BELOW IS 0016's, NOT 0014's, AND THAT WAS A MISTAKE FIRST. The first
-- draft of this file was written from 0014 -- the version this function had
-- when the ledger arithmetic was written -- and silently reverted everything
-- 0016 added: authority checked BEFORE the replay branch, the
-- assert_reservation_matches() on replay, and the ON CONFLICT that lets four
-- simultaneous retries all succeed. Nothing about the byte accounting looked
-- wrong. Concurrency group P failed with 1 success and 3 errors, which is the
-- only reason it was noticed.
--
--     CREATE OR REPLACE OVERWRITES WHATEVER IS THERE. THE BASE FOR AN EDIT IS
--     THE LATEST DEFINITION, NOT THE ONE THAT INTRODUCED THE PART YOU ARE
--     CHANGING.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.reserve_storage(
  p_world_id        uuid,
  p_principal_id    uuid,
  p_bytes           bigint,
  p_idempotency_key text,
  p_ttl             interval DEFAULT interval '1 hour'
)
RETURNS app.storage_admission
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cd, pg_temp
AS $$
DECLARE
  v_org        uuid;
  v_role       text;
  v_wstatus    text;
  v_tier       text;
  v_limit      bigint;
  v_committed  bigint;
  v_reserved   bigint;
  v_id         uuid;
  v_expires    timestamptz;
  r            record;
  out_row      app.storage_admission;
BEGIN
  v_org := app.current_organization_id();

  IF p_bytes IS NULL OR p_bytes <= 0 THEN
    RAISE EXCEPTION USING ERRCODE = '22023',
      MESSAGE = 'CD-RESERVE-BYTES: bytes must be a positive count';
  END IF;
  IF p_idempotency_key IS NULL OR btrim(p_idempotency_key) = '' THEN
    RAISE EXCEPTION USING ERRCODE = '22023',
      MESSAGE = 'CD-RESERVE-IDEMPOTENCY: an idempotency key is required';
  END IF;
  IF p_ttl IS NULL OR p_ttl <= interval '0' OR p_ttl > app.max_reservation_ttl() THEN
    RAISE EXCEPTION USING ERRCODE = '22023',
      MESSAGE = format('CD-RESERVE-TTL: ttl must be in (0, %s]', app.max_reservation_ttl());
  END IF;

  -- AUTHORITY FIRST, ALWAYS, INCLUDING ON A REPLAY (0016). This block sits
  -- above the replay branch so that presenting a key is not a way of not being
  -- asked. Everything here is re-derived from the database on every call.
  v_role := app.membership_role(p_principal_id, v_org);
  IF v_role IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = '42501',
      MESSAGE = 'CD-RESERVE-NOTMEMBER: principal holds no active membership in this organization';
  END IF;
  IF v_role NOT IN ('owner', 'admin', 'member') THEN
    RAISE EXCEPTION USING ERRCODE = '42501',
      MESSAGE = format('CD-RESERVE-ROLE: role %s may not reserve storage', v_role);
  END IF;

  SELECT w.status INTO v_wstatus
    FROM cd.worlds w WHERE w.id = p_world_id AND w.organization_id = v_org;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501',
      MESSAGE = 'CD-RESERVE-WORLD: no such world in this organization';
  END IF;
  IF v_wstatus <> 'active' THEN
    RAISE EXCEPTION USING ERRCODE = '55000',
      MESSAGE = format('CD-RESERVE-WORLDSTATUS: world is %s, not active', v_wstatus);
  END IF;

  SELECT e.tier, e.byte_limit INTO v_tier, v_limit
    FROM cd.entitlements e
   WHERE e.organization_id = v_org
     AND e.status = 'active'
     AND e.effective_at <= now()
     AND (e.expires_at IS NULL OR e.expires_at > now());
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501',
      MESSAGE = 'CD-RESERVE-NOENTITLEMENT: no active entitlement for this organization';
  END IF;

  -- REPLAY, fast path. Only reachable once authority above has passed.
  SELECT * INTO r FROM cd.storage_reservations
   WHERE organization_id = v_org AND idempotency_key = p_idempotency_key;
  IF FOUND THEN
    PERFORM app.assert_reservation_matches(r.id, r.principal_id, r.world_id, r.bytes,
                                           p_principal_id, p_world_id, p_bytes);
    IF r.state <> 'reserved' THEN
      RAISE EXCEPTION USING ERRCODE = '55000',
        MESSAGE = format('CD-RESERVE-SETTLED: reservation %s for this key is already %s',
                         r.id, r.state);
    END IF;
    SELECT l.committed_bytes, l.outstanding_bytes INTO v_committed, v_reserved
      FROM app.storage_ledger(v_org) l;
    out_row := (r.id, v_org, r.world_id, r.bytes, r.expires_at,
                v_tier, v_limit, v_committed, v_reserved, true);
    RETURN out_row;
  END IF;

  -- Two sweeps, and they do different things now. Expiry stops a dead
  -- reservation backing new offers; settlement is what actually releases the
  -- unobserved remainder, and only for reservations past the quiet period.
  PERFORM app.expire_storage_reservations(v_org);
  PERFORM app.settle_storage_reservations(v_org);

  -- THE GATE. Creates the ledger row if it is missing and LOCKS it either way;
  -- a concurrent reserver blocks here and not one statement later.
  INSERT INTO cd.storage_usage (organization_id) VALUES (v_org)
  ON CONFLICT (organization_id) DO UPDATE SET updated_at = now()
  RETURNING cd.storage_usage.committed_bytes INTO v_committed;

  -- New statement, new snapshot, and therefore the winner's reservation row is
  -- visible to this sum. This is the line the comment above is about.
  v_reserved := app.storage_outstanding(v_org);

  IF v_committed + v_reserved + p_bytes > v_limit THEN
    RAISE EXCEPTION USING ERRCODE = '53100',
      MESSAGE = format('CD-QUOTA-EXCEEDED: %s bytes would exceed the %s limit '
                       '(%s committed + %s reserved)',
                       p_bytes, v_limit, v_committed, v_reserved);
  END IF;

  v_expires := now() + p_ttl;

  -- ON CONFLICT, not a bare INSERT (0016). Two callers presenting one key both
  -- reach here; exactly one row is created and BOTH must succeed.
  INSERT INTO cd.storage_reservations
    (organization_id, world_id, principal_id, bytes, idempotency_key, expires_at)
  VALUES (v_org, p_world_id, p_principal_id, p_bytes, p_idempotency_key, v_expires)
  ON CONFLICT (organization_id, idempotency_key) DO NOTHING
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN
    -- We lost the race. 0016 had to give back EXACTLY the bytes this call had
    -- charged, because the charge happened before the insert and a refund that
    -- used the winner's number would be wrong. There is no refund here AT ALL:
    -- nothing was charged, because the hold is derived from the reservation row
    -- and this call did not create one.
    --
    --     A RACE WITH NOTHING TO UNDO CANNOT UNDO IT WRONG.
    SELECT * INTO r FROM cd.storage_reservations
     WHERE organization_id = v_org AND idempotency_key = p_idempotency_key;
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE = '40001',
        MESSAGE = 'CD-RESERVE-CONCURRENT: the competing reservation vanished; retry';
    END IF;
    PERFORM app.assert_reservation_matches(r.id, r.principal_id, r.world_id, r.bytes,
                                           p_principal_id, p_world_id, p_bytes);
    SELECT l.committed_bytes, l.outstanding_bytes INTO v_committed, v_reserved
      FROM app.storage_ledger(v_org) l;
    out_row := (r.id, v_org, r.world_id, r.bytes, r.expires_at,
                v_tier, v_limit, v_committed, v_reserved, true);
    RETURN out_row;
  END IF;

  -- Reported AFTER the insert, so a client that just reserved sees its own
  -- bytes in the position it is shown.
  v_reserved := app.storage_outstanding(v_org);

  out_row := (v_id, v_org, p_world_id, p_bytes, v_expires,
              v_tier, v_limit, v_committed, v_reserved, false);
  RETURN out_row;
END;
$$;

-- ---------------------------------------------------------------------------
-- FINALIZE. Records an ASSERTION. Moves no bytes (R68).
--
-- The behaviour that goes away here is the one finding 65 depended on: this
-- was the only writer of storage_usage.committed_bytes, and it wrote a number
-- the client chose. What replaces it is that a finalized reservation KEEPS
-- HOLDING its unobserved remainder -- because "the client says it is done" is
-- not evidence R2 has it -- until settlement.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.finalize_storage(
  p_reservation_id uuid,
  p_actual_bytes   bigint
)
RETURNS app.storage_admission
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cd, pg_temp
AS $$
DECLARE
  v_org       uuid;
  r           record;
  v_committed bigint;
  v_reserved  bigint;
  v_tier      text;
  v_limit     bigint;
  out_row     app.storage_admission;
BEGIN
  v_org := app.current_organization_id();

  IF p_actual_bytes IS NULL OR p_actual_bytes < 0 THEN
    RAISE EXCEPTION USING ERRCODE = '22023',
      MESSAGE = 'CD-FINALIZE-BYTES: actual bytes must be zero or more';
  END IF;

  SELECT * INTO r FROM cd.storage_reservations
   WHERE id = p_reservation_id AND organization_id = v_org
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501',
      MESSAGE = 'CD-FINALIZE-NOTFOUND: no such reservation in this organization';
  END IF;

  SELECT e.tier, e.byte_limit INTO v_tier, v_limit
    FROM cd.entitlements e WHERE e.organization_id = v_org AND e.status = 'active';

  IF r.state IN ('finalized', 'settled') THEN
    IF r.asserted_bytes = p_actual_bytes THEN
      SELECT l.committed_bytes, l.outstanding_bytes INTO v_committed, v_reserved
        FROM app.storage_ledger(v_org) l;
      out_row := (r.id, v_org, r.world_id, r.bytes, r.expires_at,
                  v_tier, v_limit, v_committed, v_reserved, true);
      RETURN out_row;
    END IF;
    RAISE EXCEPTION USING ERRCODE = '55000',
      MESSAGE = format('CD-FINALIZE-CONFLICT: reservation %s already asserted %s bytes, not %s',
                       r.id, r.asserted_bytes, p_actual_bytes);
  END IF;

  IF r.state <> 'reserved' THEN
    -- Still refused, and now for a reason that is true. Before 0023 the message
    -- said the bytes "have already been given back to the quota"; under R69
    -- nothing gave them back, and what this refuses is a LATE ASSERTION about a
    -- window that has closed. The bytes are held by outstanding() either way,
    -- so refusing here no longer loses them.
    RAISE EXCEPTION USING ERRCODE = '55000',
      MESSAGE = format('CD-FINALIZE-STATE: reservation %s is %s; its authority window '
                       'has closed and a client assertion can no longer be recorded '
                       'against it', r.id, r.state);
  END IF;

  IF p_actual_bytes > r.bytes THEN
    RAISE EXCEPTION USING ERRCODE = '53100',
      MESSAGE = format('CD-FINALIZE-OVERRUN: %s bytes written against a %s byte reservation',
                       p_actual_bytes, r.bytes);
  END IF;

  UPDATE cd.storage_reservations
     SET state = 'finalized', settled_at = now(), asserted_bytes = p_actual_bytes
   WHERE id = r.id AND state = 'reserved';

  -- NO cd.storage_usage WRITE. That is the finding.
  SELECT l.committed_bytes, l.outstanding_bytes INTO v_committed, v_reserved
    FROM app.storage_ledger(v_org) l;

  out_row := (r.id, v_org, r.world_id, r.bytes, r.expires_at,
              v_tier, v_limit, v_committed, v_reserved, false);
  RETURN out_row;
END;
$$;

COMMENT ON FUNCTION app.finalize_storage(uuid, bigint) IS
  'Records what the CLIENT asserts it wrote. Moves no bytes (R68): the ledger '
  'is provider-derived and a client is not the provider. The reservation keeps '
  'holding its unobserved remainder until settlement.';

-- ---------------------------------------------------------------------------
-- ABORT. Finding 71. A declaration, exactly like R55's abandon, and it now
-- says so.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.abort_storage(p_reservation_id uuid)
RETURNS app.storage_admission
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cd, pg_temp
AS $$
DECLARE
  v_org       uuid;
  r           record;
  v_committed bigint;
  v_reserved  bigint;
  v_tier      text;
  v_limit     bigint;
  out_row     app.storage_admission;
BEGIN
  v_org := app.current_organization_id();

  SELECT * INTO r FROM cd.storage_reservations
   WHERE id = p_reservation_id AND organization_id = v_org
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501',
      MESSAGE = 'CD-ABORT-NOTFOUND: no such reservation in this organization';
  END IF;

  SELECT e.tier, e.byte_limit INTO v_tier, v_limit
    FROM cd.entitlements e WHERE e.organization_id = v_org AND e.status = 'active';

  IF r.state IN ('aborted', 'expired', 'settled') THEN
    SELECT l.committed_bytes, l.outstanding_bytes INTO v_committed, v_reserved
      FROM app.storage_ledger(v_org) l;
    out_row := (r.id, v_org, r.world_id, r.bytes, r.expires_at,
                v_tier, v_limit, v_committed, v_reserved, true);
    RETURN out_row;
  END IF;

  IF r.state = 'finalized' THEN
    RAISE EXCEPTION USING ERRCODE = '55000',
      MESSAGE = format('CD-ABORT-FINALIZED: reservation %s is finalized and cannot be aborted', r.id);
  END IF;

  UPDATE cd.storage_reservations
     SET state = 'aborted', settled_at = now()
   WHERE id = r.id AND state = 'reserved';

  -- NO cd.storage_usage WRITE. Finding 71: this used to give back bytes R2 was
  -- already holding, with no clock and no race involved.
  SELECT l.committed_bytes, l.outstanding_bytes INTO v_committed, v_reserved
    FROM app.storage_ledger(v_org) l;

  out_row := (r.id, v_org, r.world_id, r.bytes, r.expires_at,
              v_tier, v_limit, v_committed, v_reserved, false);
  RETURN out_row;
END;
$$;

COMMENT ON FUNCTION app.abort_storage(uuid) IS
  'Records that the CLIENT gave up. Releases NOTHING (R69, and R55 one level '
  'up): it is a row in our database and every presigned URL minted under this '
  'reservation authorizes its holder until it expires. Settlement releases.';

-- ---------------------------------------------------------------------------
-- EXPIRE. Ends our willingness to mint authority. Releases nothing (R69).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.expire_storage_reservations(p_organization_id uuid DEFAULT NULL)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cd, pg_temp
AS $$
DECLARE
  n bigint := 0;
BEGIN
  WITH due AS (
    UPDATE cd.storage_reservations
       SET state = 'expired', settled_at = now()
     WHERE state = 'reserved'
       AND expires_at <= now()
       AND (p_organization_id IS NULL OR organization_id = p_organization_id)
    RETURNING 1 AS one
  )
  SELECT count(*) INTO n FROM due;
  RETURN n;
END;
$$;

COMMENT ON FUNCTION app.expire_storage_reservations(uuid) IS
  'Marks reservations whose window has closed. RELEASES NOTHING (R69) -- before '
  '0023 this subtracted the whole reservation from reserved_bytes, including '
  'bytes R2 had already told us it was holding, and finalize then refused to '
  'record them, so the drift was permanent (finding 65). Their unobserved '
  'remainder keeps counting via app.storage_outstanding() until settlement.';

-- ---------------------------------------------------------------------------
-- SETTLE. The only release path in the system.
--
-- Reconciliation, not a clock reading: it may run only once the quiet period
-- past expires_at has elapsed, because a PUT R2 admitted before our expiry
-- instant may still be landing and the queue path has an unmeasured latency.
--
-- What it releases is the UNOBSERVED REMAINDER, and it releases it by making
-- the reservation drop out of app.storage_outstanding() -- there is no
-- subtraction anywhere, which is why there is no double-release to get wrong.
-- Observed bytes are already in committed_bytes and stay there.
--
-- An observation arriving for a SETTLED reservation still charges occupancy;
-- it just no longer reduces a hold, because there is none. That is the correct
-- direction to be wrong in: late provider truth costs the tenant quota rather
-- than being discarded.
-- ---------------------------------------------------------------------------
CREATE FUNCTION app.settle_storage_reservations(
  p_organization_id uuid DEFAULT NULL,
  p_quiet           interval DEFAULT NULL
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cd, pg_temp
AS $$
DECLARE
  n     bigint := 0;
  quiet interval := coalesce(p_quiet, app.settlement_quiet_period());
BEGIN
  WITH due AS (
    UPDATE cd.storage_reservations
       SET state = 'settled'
     WHERE state IN ('finalized', 'aborted', 'expired')
       AND expires_at + quiet <= now()
       AND (p_organization_id IS NULL OR organization_id = p_organization_id)
    RETURNING 1 AS one
  )
  SELECT count(*) INTO n FROM due;
  RETURN n;
END;
$$;

COMMENT ON FUNCTION app.settle_storage_reservations(uuid, interval) IS
  'The ONLY path that releases held bytes. Requires expires_at + the quiet '
  'period to have passed, because our expiry instant is not known to be a fence '
  'against a PUT R2 already admitted (falsifier case I). Releases by omission '
  'from app.storage_outstanding(), so there is no subtraction to double-fire.';

-- ---------------------------------------------------------------------------
-- OBSERVE. Now the only writer of the byte ledger (R68).
--
-- Three changes on top of 0022's lock protocol:
--
--   1. It charges occupancy, by the DELTA in this key's stored bytes. Delta
--      rather than "add the event's size" because R2 fires an object-create
--      event on overwrite too, and a key that goes 10 -> 12 bytes added 2.
--   2. It records WHICH observation established the current state (R70).
--   3. It writes provider_observed_at rather than state, which is now a
--      generated column and refuses to be written at all (R71).
--
-- THE DELTA IS COMPUTED UNDER A ROW LOCK, and the two branches are not
-- stylistic. `INSERT ... ON CONFLICT DO NOTHING RETURNING` tells us which case
-- we are in atomically: if it returns a row we created the key and the whole
-- size is new occupancy; if it does not, the row exists -- possibly created by
-- a concurrent observer a microsecond ago -- and prior and after must BOTH be
-- read under the lock. Reading `prior` before the upsert instead would be the
-- same read-then-write window group P was built to catch.
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

  -- The lock protocol, unchanged from 0022: reservation, then intent, then
  -- decide. The inventory row is locked below, AFTER the intent, so the order
  -- stays total and acyclic.
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
    -- Redelivery. Queues is at-least-once, so this is normal operation: change
    -- nothing, charge nothing, say so.
    SELECT id INTO existing FROM cd.storage_observations
     WHERE (p_message_id IS NOT NULL AND message_id = p_message_id)
        OR (p_message_id IS NULL AND bucket = p_bucket
            AND object_key = p_object_key AND etag = p_etag)
     ORDER BY observed_at DESC LIMIT 1;
    out_row := (existing, v_intent, p_size_bytes, true, v_intent IS NOT NULL);
    RETURN out_row;
  END IF;

  -- Case 1: a key we had never seen. The insert IS the projection.
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
    -- Case 2: the row exists. Lock it, then read prior and after under that
    -- lock so the delta cannot straddle another observer's commit.
    SELECT size_bytes INTO v_prior FROM cd.storage_objects
     WHERE bucket = p_bucket AND object_key = p_object_key
     FOR UPDATE;

    UPDATE cd.storage_objects so SET
      -- Every field that represents "now" stays guarded by event_time: Queues
      -- does not guarantee order and a redelivered older write must not replace
      -- a newer one (0021).
      etag = CASE WHEN p_event_time >= so.last_event_at THEN p_etag ELSE so.etag END,
      size_bytes = CASE WHEN p_event_time >= so.last_event_at
                        THEN p_size_bytes ELSE so.size_bytes END,
      current_observation_id = CASE WHEN p_event_time >= so.last_event_at
                        THEN v_id ELSE so.current_observation_id END,
      first_event_at = LEAST   (so.first_event_at, p_event_time),
      last_event_at  = GREATEST(so.last_event_at,  p_event_time),
      event_count    = so.event_count + 1,
      -- Recomputed from the append-only log, which the arriving observation is
      -- already in. Order-independent by construction (finding 69).
      overwrite_count = (SELECT greatest(count(DISTINCT o.etag) - 1, 0)
                           FROM cd.storage_observations o
                          WHERE o.bucket = p_bucket AND o.object_key = p_object_key),
      updated_at = now()
     WHERE so.bucket = p_bucket AND so.object_key = p_object_key
    RETURNING so.size_bytes INTO v_after;

    v_delta := v_after - v_prior;
  END IF;

  -- THE CHARGE. The only write to the byte ledger in this schema (R68).
  INSERT INTO cd.storage_usage (organization_id) VALUES (k.organization_id)
  ON CONFLICT (organization_id) DO UPDATE SET updated_at = now();
  UPDATE cd.storage_usage u
     SET committed_bytes = u.committed_bytes + v_delta, updated_at = now()
   WHERE u.organization_id = k.organization_id;

  IF v_intent IS NOT NULL THEN
    -- Write-once, and the trigger enforces it independently. client_abandoned_at
    -- is deliberately NOT touched: an intent carrying both timestamps is the
    -- record that the client said it would not upload and the object landed
    -- anyway, which is the most interesting row this table can hold (R71).
    UPDATE cd.upload_intents
       SET provider_observed_at = now()
     WHERE id = v_intent AND provider_observed_at IS NULL;
  END IF;

  out_row := (v_id, v_intent, p_size_bytes, false, v_intent IS NOT NULL);
  RETURN out_row;
END;
$$;

COMMENT ON FUNCTION app.observe_storage_object(text, text, text, bigint, text, timestamptz, text) IS
  'Records one provider write event, projects current object state from it, and '
  'CHARGES the byte ledger by the delta in that key''s occupancy. The only '
  'writer of cd.storage_usage.committed_bytes (R68). Idempotent by unique '
  'constraint, not by delivery guarantee.';

-- ---------------------------------------------------------------------------
-- OFFER. Two mechanical changes: `state` cannot be assigned any more, and
-- withdrawing a client abandon is done by clearing the fact rather than by
-- overwriting an enum.
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

    IF existing.provider_observed_at IS NOT NULL THEN
      out_row := (existing.id, existing.reservation_id, existing.object_key,
                  existing.expected_bytes, existing.content_digest,
                  existing.expires_at, true, 'already_observed');
      RETURN out_row;
    END IF;

    v_expires := LEAST(now() + p_ttl, r.expires_at);
    UPDATE cd.upload_intents
       SET client_abandoned_at = NULL,          -- the client withdraws its own declaration
           expires_at = GREATEST(expires_at, v_expires)
     WHERE id = existing.id
       AND provider_observed_at IS NULL         -- the guard, now on the base fact
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

  -- R31, under the reservation lock. No state predicate: every intent counts,
  -- because neither the clock nor a client abandon revokes a presigned URL
  -- already issued (R55/R69).
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
                CASE WHEN existing.provider_observed_at IS NOT NULL
                     THEN 'already_observed' ELSE 'replayed' END);
    RETURN out_row;
  END IF;

  out_row := (v_id, r.id, p_object_key, p_expected_bytes, p_content_digest,
              v_expires, false, 'fresh');
  RETURN out_row;
END;
$$;

-- ---------------------------------------------------------------------------
-- ABANDON. Same ruling, written against the fact instead of the enum.
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

  SELECT * INTO i FROM cd.upload_intents
   WHERE id = p_intent_id AND organization_id = v_org;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501',
      MESSAGE = 'CD-ABANDON-NOTFOUND: no such upload intent in this organization';
  END IF;

  i := app.lock_intent(p_intent_id);        -- the re-read, and the decision below

  IF i.provider_observed_at IS NOT NULL THEN
    RAISE EXCEPTION USING ERRCODE = '55000',
      MESSAGE = format('CD-ABANDON-OBSERVED: intent %s has already been written to '
                       'the provider and cannot be abandoned', i.id);
  END IF;
  IF i.client_abandoned_at IS NOT NULL THEN
    RETURN false;                            -- idempotent, and says so
  END IF;

  UPDATE cd.upload_intents
     SET client_abandoned_at = now()
   WHERE id = i.id AND provider_observed_at IS NULL;
  RETURN true;
END;
$$;

-- ---------------------------------------------------------------------------
-- DIVERGENCE, now joined causally (R70) and reading the renamed assertion.
-- ---------------------------------------------------------------------------
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
         coalesce(r.asserted_bytes, 0)::bigint AS asserted_bytes,
         coalesce(o.total, 0)::bigint          AS observed_bytes,
         (coalesce(o.total, 0) - coalesce(r.asserted_bytes, 0))::bigint AS delta,
         coalesce(o.overwrites, 0)::bigint     AS overwrites
  FROM cd.storage_reservations r
  LEFT JOIN LATERAL (
    -- reservation -> its intents -> the observations that NAMED those intents
    -- -> the objects those observations currently establish. Never
    -- storage_objects JOIN upload_intents ON object_key, which is finding 68.
    SELECT sum(so.size_bytes)      AS total,
           sum(so.overwrite_count) AS overwrites
      FROM cd.upload_intents i
      JOIN cd.storage_observations ob ON ob.intent_id = i.id
      JOIN cd.storage_objects     so ON so.current_observation_id = ob.id
     WHERE i.reservation_id = r.id
  ) o ON true
  WHERE (p_organization_id IS NULL OR r.organization_id = p_organization_id)
    AND (coalesce(o.total, 0)      IS DISTINCT FROM coalesce(r.asserted_bytes, 0)
         OR coalesce(o.overwrites, 0) > 0);
$$;

COMMENT ON FUNCTION app.storage_divergence(uuid) IS
  'Where the CLIENT''S ASSERTION and current provider occupancy disagree. '
  'Attribution runs through the observation that established each object''s '
  'current state, so a later intent cannot claim an earlier write (R70). Since '
  '0023 the ledger no longer depends on this being watched -- occupancy is '
  'charged by the observer -- so this is an alarm rather than the only defence.';

RESET ROLE;
SET LOCAL ROLE computedriven_migrations;
REVOKE CREATE ON SCHEMA app FROM computedriven_ledger;

REVOKE EXECUTE ON FUNCTION
  app.storage_outstanding(uuid),
  app.storage_ledger(uuid),
  app.settlement_quiet_period(),
  app.settle_storage_reservations(uuid, interval),
  app.storage_divergence(uuid)
FROM PUBLIC;

GRANT EXECUTE ON FUNCTION
  app.storage_outstanding(uuid),
  app.storage_ledger(uuid),
  app.settlement_quiet_period()
TO computedriven_api, computedriven_jobs;

GRANT EXECUTE ON FUNCTION app.storage_divergence(uuid)
  TO computedriven_api, computedriven_jobs;

-- Settlement is a JOB, not a request. An API caller that could settle could
-- release its own unobserved remainder on demand, which is finding 71 with
-- extra steps.
GRANT EXECUTE ON FUNCTION app.settle_storage_reservations(uuid, interval)
  TO computedriven_jobs;

DO $$
BEGIN
  IF has_function_privilege('computedriven_api',
       'app.settle_storage_reservations(uuid,interval)', 'EXECUTE') THEN
    RAISE EXCEPTION 'CD-SETTLE-CLIENTPATH: the API role can release its own held bytes';
  END IF;
  IF has_function_privilege('computedriven_api',
       'app.observe_storage_object(text,text,text,bigint,text,timestamptz,text)', 'EXECUTE') THEN
    RAISE EXCEPTION 'CD-OBSERVE-CLIENTPATH: the API role can assert provider observations';
  END IF;
END
$$;

-- The whole point of 0023, stated as a runtime assertion rather than as a
-- comment: exactly one function in this schema writes the byte ledger, and it
-- is the one the provider drives. If a later migration adds a second writer,
-- this fails at apply time.
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
