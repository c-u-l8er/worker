-- 0024 — capability closure: 0023 shipped a cross-tenant read, a caller-chosen
--        safety constant, and two clocks under one name
--
-- Findings 72, 73, 74 and 76 from outside review 2026-08-23, and a correction to
-- this tree's own claim about finding 75. All four reproduced against 0023
-- BEFORE this file was written.
--
-- ===========================================================================
-- 72. A SECURITY DEFINER FUNCTION THAT TAKES A TENANT ID IS A CROSS-TENANT
--     CAPABILITY, WHATEVER ITS NAME SAYS.
--
-- 0023 added three functions that accept an organization uuid and are granted
-- to computedriven_api. They are SECURITY DEFINER owned by computedriven_ledger,
-- which holds `USING (true)` policies BY DESIGN because a queue consumer is
-- cross-tenant. So the definer reads every tenant and returns whatever the
-- caller named.
--
-- MEASURED, org A's API connection against org B:
--
--     app.storage_ledger(B)         -> committed=0 outstanding=777 used=777
--     app.storage_outstanding(B)    -> 777
--     app.storage_divergence(B)     -> B's row
--     app.storage_divergence(NULL)  -> EVERY TENANT'S rows
--
-- and the control that makes it a finding rather than a misreading:
--
--     SELECT ... FROM cd.storage_usage WHERE organization_id = B   ->  0 rows
--
-- RLS refuses the direct read. The definer is the ONLY door, and 0023 built it.
--
--     THE REQUEST SUPPLIES INTENT, NOT AUTHORITY. `reserve_storage()` HAS TAKEN
--     NO ORGANIZATION ARGUMENT SINCE 0014 FOR EXACTLY THIS REASON, AND 0023 ADDED
--     THREE READ PATHS THAT DO.
--
-- Worse, the parameter made the wrong thing easy: `p_organization_id uuid
-- DEFAULT NULL` meant the most convenient call an API caller could write was
-- also the one that returns the whole cluster.
--
-- So the interface splits, and the split is in the NAME rather than in a
-- comment about who should call which:
--
--     app.storage_ledger()          no argument, derives the tenant   API + jobs
--     app.storage_divergence()      no argument, derives the tenant   API + jobs
--     app.storage_ledger_for(uuid)      names a tenant               JOBS ONLY
--     app.storage_divergence_for(uuid)  NULL = all tenants           JOBS ONLY
--     app.storage_outstanding(uuid)     internal helper              JOBS ONLY
--
-- `storage_outstanding` loses its API grant outright. `reserve_storage()` still
-- calls it, and still may: that function is SECURITY DEFINER owned by
-- computedriven_ledger, which OWNS storage_outstanding, so the grant was never
-- what made the internal call work. It only ever exposed it.
--
--     A GRANT THAT NOTHING NEEDS IS NOT A HARMLESS GRANT. IT IS AN UNUSED DOOR.
--
-- WHAT THIS SAYS ABOUT CHECK O0b. That check enumerates "known cross-tenant
-- capabilities" and requires each to have a positive accept witness. It passed
-- on 0023 while 0023 was manufacturing a new cross-tenant capability, because a
-- hand-maintained list cannot contain a capability nobody realised they had
-- created. **O0c** below is the derived form: any SECURITY DEFINER function
-- owned by a role with cross-tenant policies, taking an organization uuid, and
-- granted to a request role, is a finding unless it is named as jobs-only.
--
-- ---------------------------------------------------------------------------
-- 73. THE ONLY RELEASE PATH LET ITS CALLER CHOOSE THE SAFETY CONSTANT.
--
--     quiet := coalesce(p_quiet, app.settlement_quiet_period());
--
-- with no lower bound. MEASURED: a reservation that expired ONE SECOND ago,
-- against a one-hour quiet period —
--
--     settle_storage_reservations(A)                  ->  0 released
--     settle_storage_reservations(A, interval '0')    ->  1 released, hold 500 -> 0
--
-- R69 made settlement the single release path in the system precisely because
-- our clock is not the provider's, and case I exists because the correct quiet
-- period is NOT KNOWN. A parameter that discards it hands a routine caller the
-- one decision this round said could not be made locally.
--
--     A CALLER MAY ASK THE SYSTEM TO SETTLE. THE CALLER MAY NOT CHOOSE THE
--     SETTLEMENT LAW.
--
-- `p_quiet` is removed rather than validated. A floor check would still leave a
-- knob whose safe range nobody has measured. Tests move `expires_at` backwards,
-- which is what the battery already does everywhere else.
--
-- ---------------------------------------------------------------------------
-- 74. R70 CLOSED DATABASE ORDER AND LEFT PROVIDER ORDER OPEN.
--
-- The observer finds its intent by key alone, so a DELAYED notification is
-- attributed to whatever intent holds that key when it finally arrives.
--
--     T1  provider writes the object; no intent exists
--     T2  the notification sits in the queue
--     T3  an intent for that key is created
--     T4  the T1 notification arrives  ->  attributed to the T3 intent
--
-- MEASURED against 0023: an event whose `event_time` predates the intent's
-- `created_at` **by three hours** was attributed to it. O10/O10b could not see
-- this — they vary the order rows are INSERTED, and this varies the order the
-- PROVIDER's events arrive, which is the seam that actually exists.
--
--     R72 -- AN INTENT MAY ONLY BE CREDITED WITH A WRITE THAT COULD HAVE
--     HAPPENED AFTER IT. An event known to predate the authority cannot have
--     been caused by it, and is recorded UNATTRIBUTED rather than assigned.
--
-- The comparison is between two different machines' clocks, so it carries an
-- allowance, and the allowance is named and open like the quiet period rather
-- than buried as a literal. Without one, ordinary skew would strip attribution
-- from a legitimate chunk uploaded moments after its offer — a refusal that
-- looks exactly like the defect it is meant to prevent.
--
-- WHAT THIS DELIBERATELY DOES NOT DO. It does not decide what a pre-existing
-- object MEANS. A content-addressed chunk may legitimately be in R2 before we
-- decide we want it; that is dedup/reuse, and reuse is not "this reservation
-- caused this write". Treating the two as one is an M2.1 question and is
-- recorded as open rather than guessed at here.
--
-- ---------------------------------------------------------------------------
-- 76. TWO CLOCKS UNDER ONE NAME.
--
-- `provider_observed_at` was set to `now()` — OUR clock, at the moment the
-- queue consumer ran — while the provider's own `event_time` was sitting in the
-- same function's arguments. MEASURED on the delayed event above:
--
--     provider_observed_at = 11:08:47      (ours)
--     event_time           = 08:08:47      (R2's)
--
-- So the anomaly record R71 was built to preserve — "client abandoned at T1,
-- object written at T2" — was storing *queue-consumed-at* T2 and calling it the
-- write. Two facts, both wanted, one column.
--
--     provider_event_at     when R2 says it happened
--     provider_observed_at  when we consumed the notification
--
-- Same shape as R71 one level down, which is why it is in this file: a column
-- that answers two questions answers neither.

BEGIN;

SET LOCAL ROLE computedriven_migrations;

-- ---------------------------------------------------------------------------
-- 76. The provider's clock gets its own column.
-- ---------------------------------------------------------------------------
ALTER TABLE cd.upload_intents ADD COLUMN provider_event_at timestamptz;

-- Backfill from the observation that attributed each intent. Existing rows
-- recorded only our consumption time, so the provider time is recovered from
-- the log rather than invented -- and stays NULL where no observation names the
-- intent, which is the honest answer for a row we cannot reconstruct.
UPDATE cd.upload_intents i
   SET provider_event_at = o.event_time
  FROM (SELECT DISTINCT ON (intent_id) intent_id, event_time
          FROM cd.storage_observations
         WHERE intent_id IS NOT NULL
         ORDER BY intent_id, event_time ASC) o
 WHERE o.intent_id = i.id AND i.provider_observed_at IS NOT NULL;

COMMENT ON COLUMN cd.upload_intents.provider_event_at IS
  'When R2 says the write happened -- its `eventTime`, the provider''s clock. '
  'WRITE-ONCE. Distinct from provider_observed_at, which is when WE consumed '
  'the notification: those were three hours apart on a delayed message, and '
  'before 0024 only the second was stored and the first was what we claimed to '
  'have (finding 76).';

COMMENT ON COLUMN cd.upload_intents.provider_observed_at IS
  'When this control plane CONSUMED the notification -- our clock. WRITE-ONCE, '
  'enforced by trigger. It is not when the write happened; see '
  'provider_event_at for that (0024).';

-- The write-once rule now covers both. R54 is about provider truth, and the
-- provider's own timestamp is the more purely provider-sourced of the two.
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
  RETURN NEW;
END;
$$;

GRANT CREATE ON SCHEMA app TO computedriven_ledger;
SET LOCAL ROLE computedriven_ledger;

-- ---------------------------------------------------------------------------
-- 74. The skew allowance. Named, open, and findable -- the same treatment
-- app.settlement_quiet_period() gets, for the same reason: it is a constant
-- about somebody else's clock and nobody has measured it.
-- ---------------------------------------------------------------------------
CREATE FUNCTION app.provider_clock_skew_allowance() RETURNS interval
LANGUAGE sql IMMUTABLE AS $$ SELECT interval '5 minutes' $$;

COMMENT ON FUNCTION app.provider_clock_skew_allowance() IS
  'How far R2''s eventTime may precede an intent''s created_at and still be '
  'credited to it. UNMEASURED. It exists because the comparison is between two '
  'machines'' clocks: with no allowance, ordinary skew would strip attribution '
  'from a legitimate chunk uploaded seconds after its offer, which looks exactly '
  'like the defect it prevents. Live falsifier case D writes the real number.';

-- ---------------------------------------------------------------------------
-- 73. Settlement, with the law no longer a parameter.
-- ---------------------------------------------------------------------------
DROP FUNCTION IF EXISTS app.settle_storage_reservations(uuid, interval);

CREATE FUNCTION app.settle_storage_reservations(p_organization_id uuid DEFAULT NULL)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cd, pg_temp
AS $$
DECLARE n bigint := 0;
BEGIN
  WITH due AS (
    UPDATE cd.storage_reservations
       SET state = 'settled'
     WHERE state IN ('finalized', 'aborted', 'expired')
       -- NOT a parameter. 0023 accepted `p_quiet` and a jobs caller passing
       -- interval '0' released a reservation one second past expiry (finding 73).
       AND expires_at + app.settlement_quiet_period() <= now()
       AND (p_organization_id IS NULL OR organization_id = p_organization_id)
    RETURNING 1 AS one
  )
  SELECT count(*) INTO n FROM due;
  RETURN n;
END;
$$;

COMMENT ON FUNCTION app.settle_storage_reservations(uuid) IS
  'The ONLY path that releases held bytes. The quiet period is read from '
  'app.settlement_quiet_period() and CANNOT be supplied by the caller: a caller '
  'may ask the system to settle, but may not choose the settlement law (0024). '
  'To settle early in a test, move expires_at backwards.';

-- ---------------------------------------------------------------------------
-- 72. The read interface, split by name.
--
-- The tenant-derived forms take no argument at all, so "read another tenant" is
-- not refused -- it is unspeakable, which is the same shape reserve_storage()
-- has had since 0014.
-- ---------------------------------------------------------------------------
DROP FUNCTION IF EXISTS app.storage_ledger(uuid);
DROP FUNCTION IF EXISTS app.storage_divergence(uuid);

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
  'CROSS-TENANT. Reads whichever organization the caller names, so it is a JOBS '
  'capability and must never be granted to a request role -- that grant was '
  'finding 72. The API form is app.storage_ledger(), which takes no argument.';

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

CREATE FUNCTION app.storage_divergence_for(p_organization_id uuid DEFAULT NULL)
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

COMMENT ON FUNCTION app.storage_divergence_for(uuid) IS
  'CROSS-TENANT, and NULL means EVERY tenant -- which is why this is jobs-only '
  'and why the API form has no argument. Granted to computedriven_api in 0023, '
  'where the most convenient call a request could write was also the one that '
  'returned the whole cluster (finding 72).';

CREATE FUNCTION app.storage_divergence()
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
AS $$ SELECT * FROM app.storage_divergence_for(app.current_organization_id()); $$;

COMMENT ON FUNCTION app.storage_divergence() IS
  'Where THIS tenant''s client assertions and provider occupancy disagree. No '
  'organization argument, for the reason in app.storage_ledger() (0024).';

-- ---------------------------------------------------------------------------
-- The three admission functions read the ledger through the _for form, which
-- they may: they are SECURITY DEFINER owned by this role and already hold the
-- tenant in v_org. Re-created here only because the function they called was
-- dropped above.
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

  -- AUTHORITY FIRST, ALWAYS, INCLUDING ON A REPLAY (0016).
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
      FROM app.storage_ledger_for(v_org) l;
    out_row := (r.id, v_org, r.world_id, r.bytes, r.expires_at,
                v_tier, v_limit, v_committed, v_reserved, true);
    RETURN out_row;
  END IF;

  PERFORM app.expire_storage_reservations(v_org);
  PERFORM app.settle_storage_reservations(v_org);

  -- THE GATE (0023). Creates-or-LOCKS; a concurrent reserver blocks here.
  INSERT INTO cd.storage_usage (organization_id) VALUES (v_org)
  ON CONFLICT (organization_id) DO UPDATE SET updated_at = now()
  RETURNING cd.storage_usage.committed_bytes INTO v_committed;

  -- New statement, new snapshot: this sum sees the winner's reservation.
  v_reserved := app.storage_outstanding(v_org);

  IF v_committed + v_reserved + p_bytes > v_limit THEN
    RAISE EXCEPTION USING ERRCODE = '53100',
      MESSAGE = format('CD-QUOTA-EXCEEDED: %s bytes would exceed the %s limit '
                       '(%s committed + %s reserved)',
                       p_bytes, v_limit, v_committed, v_reserved);
  END IF;

  v_expires := now() + p_ttl;

  INSERT INTO cd.storage_reservations
    (organization_id, world_id, principal_id, bytes, idempotency_key, expires_at)
  VALUES (v_org, p_world_id, p_principal_id, p_bytes, p_idempotency_key, v_expires)
  ON CONFLICT (organization_id, idempotency_key) DO NOTHING
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN
    -- Nothing to refund: the hold is derived and this call created no row.
    SELECT * INTO r FROM cd.storage_reservations
     WHERE organization_id = v_org AND idempotency_key = p_idempotency_key;
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE = '40001',
        MESSAGE = 'CD-RESERVE-CONCURRENT: the competing reservation vanished; retry';
    END IF;
    PERFORM app.assert_reservation_matches(r.id, r.principal_id, r.world_id, r.bytes,
                                           p_principal_id, p_world_id, p_bytes);
    SELECT l.committed_bytes, l.outstanding_bytes INTO v_committed, v_reserved
      FROM app.storage_ledger_for(v_org) l;
    out_row := (r.id, v_org, r.world_id, r.bytes, r.expires_at,
                v_tier, v_limit, v_committed, v_reserved, true);
    RETURN out_row;
  END IF;

  v_reserved := app.storage_outstanding(v_org);

  out_row := (v_id, v_org, p_world_id, p_bytes, v_expires,
              v_tier, v_limit, v_committed, v_reserved, false);
  RETURN out_row;
END;
$$;

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
        FROM app.storage_ledger_for(v_org) l;
      out_row := (r.id, v_org, r.world_id, r.bytes, r.expires_at,
                  v_tier, v_limit, v_committed, v_reserved, true);
      RETURN out_row;
    END IF;
    RAISE EXCEPTION USING ERRCODE = '55000',
      MESSAGE = format('CD-FINALIZE-CONFLICT: reservation %s already asserted %s bytes, not %s',
                       r.id, r.asserted_bytes, p_actual_bytes);
  END IF;

  IF r.state <> 'reserved' THEN
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

  SELECT l.committed_bytes, l.outstanding_bytes INTO v_committed, v_reserved
    FROM app.storage_ledger_for(v_org) l;

  out_row := (r.id, v_org, r.world_id, r.bytes, r.expires_at,
              v_tier, v_limit, v_committed, v_reserved, false);
  RETURN out_row;
END;
$$;

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
      FROM app.storage_ledger_for(v_org) l;
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

  SELECT l.committed_bytes, l.outstanding_bytes INTO v_committed, v_reserved
    FROM app.storage_ledger_for(v_org) l;

  out_row := (r.id, v_org, r.world_id, r.bytes, r.expires_at,
              v_tier, v_limit, v_committed, v_reserved, false);
  RETURN out_row;
END;
$$;

-- ---------------------------------------------------------------------------
-- 74 + 76. The observer: causal attribution against the PROVIDER's clock, and
-- both timestamps recorded.
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

  -- THE CAUSAL TEST (R72). The key alone is not enough: a delayed notification
  -- arrives long after the write, and by then a different intent may hold that
  -- name. An event the provider says happened BEFORE the intent existed cannot
  -- have been caused by it, so it is recorded unattributed -- the same state as
  -- any other write we did not authorize.
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

    -- THE DELTA, and finding 75 is a property of it rather than of the unique
    -- index: a redelivery under a NEW message id gets past the constraint, but
    -- 100 -> 100 is a delta of ZERO. Unstable queue ids duplicate the provenance
    -- log; they do not double-charge occupancy. MEASURED. Check K36 pins it.
    v_delta := v_after - v_prior;
  END IF;

  INSERT INTO cd.storage_usage (organization_id) VALUES (k.organization_id)
  ON CONFLICT (organization_id) DO UPDATE SET updated_at = now();
  UPDATE cd.storage_usage u
     SET committed_bytes = u.committed_bytes + v_delta, updated_at = now()
   WHERE u.organization_id = k.organization_id;

  IF v_intent IS NOT NULL THEN
    -- BOTH clocks (0024). provider_event_at is R2's; provider_observed_at is
    -- ours. Storing only the second and calling it the write was finding 76.
    UPDATE cd.upload_intents
       SET provider_observed_at = now(),
           provider_event_at    = p_event_time
     WHERE id = v_intent AND provider_observed_at IS NULL;
  END IF;

  out_row := (v_id, v_intent, p_size_bytes, false, v_intent IS NOT NULL);
  RETURN out_row;
END;
$$;

RESET ROLE;
SET LOCAL ROLE computedriven_migrations;
REVOKE CREATE ON SCHEMA app FROM computedriven_ledger;

REVOKE EXECUTE ON FUNCTION
  app.storage_ledger(),
  app.storage_ledger_for(uuid),
  app.storage_divergence(),
  app.storage_divergence_for(uuid),
  app.storage_outstanding(uuid),
  app.settle_storage_reservations(uuid),
  app.provider_clock_skew_allowance()
FROM PUBLIC;

-- FROM PUBLIC IS NOT FROM EVERYONE. `storage_outstanding(uuid)` survives this
-- file -- only the ledger functions around it were dropped and recreated -- so
-- it still carries the grant 0023 gave computedriven_api, and revoking PUBLIC
-- does nothing to a grant held by a named role.
--
-- The first draft of this migration stopped exactly here and O0c below REFUSED
-- IT, naming storage_outstanding. The gate caught the file that introduced it.
REVOKE EXECUTE ON FUNCTION app.storage_outstanding(uuid) FROM computedriven_api;

-- Tenant-derived reads: a request role may have these, because they cannot
-- name another tenant.
GRANT EXECUTE ON FUNCTION app.storage_ledger(), app.storage_divergence()
  TO computedriven_api, computedriven_jobs;
GRANT EXECUTE ON FUNCTION app.settlement_quiet_period(),
                          app.provider_clock_skew_allowance()
  TO computedriven_api, computedriven_jobs;

-- Cross-tenant reads and the release path: jobs only.
GRANT EXECUTE ON FUNCTION
  app.storage_ledger_for(uuid),
  app.storage_divergence_for(uuid),
  app.storage_outstanding(uuid),
  app.settle_storage_reservations(uuid)
TO computedriven_jobs;

-- ---------------------------------------------------------------------------
-- O0c, as an apply-time assertion as well as a battery check. THE DERIVED FORM
-- of the question O0b asks from a hand-maintained list.
--
-- Any SECURITY DEFINER function owned by a role with cross-tenant policies,
-- taking an organization uuid, and reachable by a REQUEST role, is a
-- cross-tenant read the request never proved it was entitled to. 0023 added
-- three and every gate stayed green.
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
     AND p.prosecdef                                    -- SECURITY DEFINER
     AND o.rolname = 'computedriven_ledger'             -- owner sees every tenant
     AND pg_get_function_identity_arguments(p.oid) ~ 'uuid'
     AND p.proname ~ '^storage_'                        -- the ledger surface
     AND p.proname !~ '_for$'                           -- named as cross-tenant
     AND has_function_privilege('computedriven_api', p.oid, 'EXECUTE');
  IF leaks IS NOT NULL THEN
    RAISE EXCEPTION 'CD-XTENANT-DEFINER: the API role can name a tenant through %', leaks;
  END IF;
END
$$;

-- R68 still holds: one writer of the byte ledger, and 0024 re-created the
-- observer, so re-assert it here rather than trusting that 0023's check covered
-- a function this file replaced.
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
