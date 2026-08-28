-- 0016 — reservation idempotency: request-idempotent, not merely accounting-idempotent
--
-- THREE DEFECTS, found by outside review 2026-08-22, all in the same function and
-- all reproduced before fixing.
--
-- ---------------------------------------------------------------------------
-- 1. P4 PROVED THE WRONG PROPERTY, AND IT IS THE SAME MISTAKE ROUND 6 JUST FIXED
--    FOR IDENTITY.
--
-- The check is named "four simultaneous retries of one idempotency key hold 50
-- bytes, not 200" and it asserted
--
--     distinct reservation ids <= 1     AND     reserved_bytes <= 50
--
-- with a comment saying a duplicate-key error from a loser was acceptable. So it
-- proved ACCOUNTING idempotence -- the quota is charged once -- and not REQUEST
-- idempotence, which is what a retrying client actually needs:
--
--     four callers, four SUCCESSES, one reservation id, zero errors.
--
-- Round 6 had just finished fixing exactly this shape one table over: a check
-- named "idempotent" that could not express the case that matters. Writing the
-- new one, I reproduced the old mistake inside it.
--
--     "THE LOSER MAY ERROR" IS NOT IDEMPOTENCE. IT IS IDEMPOTENT BOOKKEEPING
--     WITH A NON-IDEMPOTENT API IN FRONT OF IT.
--
-- 0014 could not do better: it checked for the key, then charged quota, then
-- inserted -- so two callers with one key both passed the check, both charged,
-- and the second INSERT raised. Now the INSERT is ON CONFLICT DO NOTHING and the
-- loser RELEASES the bytes it charged and returns the winner's reservation.
--
-- ---------------------------------------------------------------------------
-- 2. REPLAY HAPPENED BEFORE AUTHORITY.
--
-- 0014's own comment said membership is "re-derived here rather than trusted from
-- the caller ... must not depend on having been called politely" -- and the replay
-- branch returned an existing reservation ABOVE that check. So a principal who
-- had been demoted to viewer, removed from the organization, or suspended could
-- still retrieve a live reservation by presenting its key, and the world could be
-- archived underneath it.
--
-- Authority is now checked FIRST, unconditionally, on every call including
-- replays. A replay is a cheaper answer to the same question, never a way of
-- skipping it.
--
-- ---------------------------------------------------------------------------
-- 3. A KEY WAS A NAME, NOT A PROMISE.
--
-- `idempotency_key` was unique per organization and bound to nothing else, so
-- reusing it with different bytes, a different world or a different principal
-- returned the ORIGINAL reservation and silently ignored what was asked for. A
-- client retrying with a corrected size would receive the old, wrong hold and
-- believe it had the new one.
--
-- An idempotency key now identifies a complete immutable request tuple
--
--     { organization, principal, world, bytes, key }
--
-- and a replay that disagrees on any of them is CD-RESERVE-IDEMPOTENCY-MISMATCH
-- rather than a silent substitution.

BEGIN;

SET LOCAL ROLE computedriven_migrations;
GRANT CREATE ON SCHEMA app TO computedriven_ledger;
SET LOCAL ROLE computedriven_ledger;

-- The tuple check, in one place because it is called from both the fast replay
-- path and the lost-the-race path, and two copies of a rule is how the two
-- copies come to disagree.
--
-- Scalars rather than a record parameter on purpose: a `record` argument would
-- make the function accept any row shape and discover the mismatch at runtime,
-- which is the opposite of what a validator is for.
CREATE OR REPLACE FUNCTION app.assert_reservation_matches(
  p_reservation_id    uuid,
  p_stored_principal  uuid,
  p_stored_world      uuid,
  p_stored_bytes      bigint,
  p_principal_id      uuid,
  p_world_id          uuid,
  p_bytes             bigint
)
RETURNS void
LANGUAGE plpgsql
IMMUTABLE
AS $$
BEGIN
  IF p_stored_principal IS DISTINCT FROM p_principal_id
     OR p_stored_world  IS DISTINCT FROM p_world_id
     OR p_stored_bytes  IS DISTINCT FROM p_bytes THEN
    -- Name every field that differs. A client retrying with a corrected size
    -- needs to be told that is what happened, not handed the old hold.
    RAISE EXCEPTION USING ERRCODE = '22023',
      MESSAGE = format(
        'CD-RESERVE-IDEMPOTENCY-MISMATCH: key already names reservation %s '
        '(principal %s, world %s, %s bytes); this request is (principal %s, world %s, %s bytes)',
        p_reservation_id, p_stored_principal, p_stored_world, p_stored_bytes,
        p_principal_id, p_world_id, p_bytes);
  END IF;
END;
$$;

COMMENT ON FUNCTION app.assert_reservation_matches(uuid, uuid, uuid, bigint, uuid, uuid, bigint) IS
  'An idempotency key names a complete immutable request tuple, not just a row. '
  'Reuse with different bytes/world/principal is a refusal, never a silent '
  'substitution of the original reservation.';

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
  -- No organization parameter. This raises when context is missing, and the
  -- raise is the point: a reservation without a tenant is not a reservation.
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

  -- =========================================================================
  -- AUTHORITY FIRST, ALWAYS, INCLUDING ON A REPLAY.
  --
  -- This block used to sit BELOW the replay branch, so presenting a key was a way
  -- of not being asked. Everything here is re-derived from the database on every
  -- call; none of it is trusted from the caller.
  -- =========================================================================
  v_role := app.membership_role(p_principal_id, v_org);
  IF v_role IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = '42501',
      MESSAGE = 'CD-RESERVE-NOTMEMBER: principal holds no active membership in this organization';
  END IF;
  IF v_role NOT IN ('owner', 'admin', 'member') THEN
    -- A viewer may read a world. A viewer may not cause bytes to be billed
    -- against it. Same ladder as permissionFor(), enforced at the other end.
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
    -- Not "quota exceeded". There is no quota, because nobody is entitled to
    -- anything, and the two need different operator responses.
    RAISE EXCEPTION USING ERRCODE = '42501',
      MESSAGE = 'CD-RESERVE-NOENTITLEMENT: no active entitlement for this organization';
  END IF;

  -- =========================================================================
  -- REPLAY, fast path. Only reachable once authority above has passed.
  -- =========================================================================
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
    SELECT u.committed_bytes, u.reserved_bytes INTO v_committed, v_reserved
      FROM cd.storage_usage u WHERE u.organization_id = v_org;
    out_row := (r.id, v_org, r.world_id, r.bytes, r.expires_at,
                v_tier, v_limit, v_committed, v_reserved, true);
    RETURN out_row;
  END IF;

  -- Sweep this tenant's dead reservations before charging. Otherwise a client
  -- that crashed an hour ago is still holding the quota that would let its retry
  -- succeed, and the refusal would be correct arithmetic about a fiction.
  PERFORM app.expire_storage_reservations(v_org);

  INSERT INTO cd.storage_usage (organization_id) VALUES (v_org)
  ON CONFLICT (organization_id) DO NOTHING;

  -- THE ATOMIC ADMISSION. One statement: the row lock serializes concurrent
  -- reservers and the loser re-evaluates this WHERE against the winner's
  -- committed numbers. There is no read-then-write window because there is no
  -- read.
  UPDATE cd.storage_usage u
     SET reserved_bytes = u.reserved_bytes + p_bytes, updated_at = now()
   WHERE u.organization_id = v_org
     AND u.committed_bytes + u.reserved_bytes + p_bytes <= v_limit
  RETURNING u.committed_bytes, u.reserved_bytes INTO v_committed, v_reserved;

  IF NOT FOUND THEN
    SELECT u.committed_bytes, u.reserved_bytes INTO v_committed, v_reserved
      FROM cd.storage_usage u WHERE u.organization_id = v_org;
    RAISE EXCEPTION USING ERRCODE = '53100',
      MESSAGE = format('CD-QUOTA-EXCEEDED: %s bytes would exceed the %s limit '
                       '(%s committed + %s reserved)',
                       p_bytes, v_limit, v_committed, v_reserved);
  END IF;

  v_expires := now() + p_ttl;

  -- ON CONFLICT, not a bare INSERT. Two callers presenting one key both reach
  -- here; exactly one row is created and BOTH must succeed. Under READ COMMITTED
  -- a conflicting-but-uncommitted row makes this statement WAIT for the other
  -- transaction rather than raise -- which is the serialization 0015 relies on
  -- for identity, doing the same job here.
  INSERT INTO cd.storage_reservations
    (organization_id, world_id, principal_id, bytes, idempotency_key, expires_at)
  VALUES (v_org, p_world_id, p_principal_id, p_bytes, p_idempotency_key, v_expires)
  ON CONFLICT (organization_id, idempotency_key) DO NOTHING
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN
    -- We lost the race. Give back EXACTLY what this call charged -- p_bytes, the
    -- number we just added, not the winner's -- and return the winner's
    -- reservation so this caller succeeds too.
    UPDATE cd.storage_usage u
       SET reserved_bytes = u.reserved_bytes - p_bytes, updated_at = now()
     WHERE u.organization_id = v_org
    RETURNING u.committed_bytes, u.reserved_bytes INTO v_committed, v_reserved;

    SELECT * INTO r FROM cd.storage_reservations
     WHERE organization_id = v_org AND idempotency_key = p_idempotency_key;
    IF NOT FOUND THEN
      -- The winner rolled back between our conflict and this read. Retryable,
      -- and named rather than returned as a NULL row.
      RAISE EXCEPTION USING ERRCODE = '40001',
        MESSAGE = 'CD-RESERVE-CONCURRENT: the competing reservation vanished; retry';
    END IF;
    PERFORM app.assert_reservation_matches(r.id, r.principal_id, r.world_id, r.bytes,
                                           p_principal_id, p_world_id, p_bytes);
    out_row := (r.id, v_org, r.world_id, r.bytes, r.expires_at,
                v_tier, v_limit, v_committed, v_reserved, true);
    RETURN out_row;
  END IF;

  out_row := (v_id, v_org, p_world_id, p_bytes, v_expires,
              v_tier, v_limit, v_committed, v_reserved, false);
  RETURN out_row;
END;
$$;

COMMENT ON FUNCTION app.reserve_storage(uuid, uuid, bigint, text, interval) IS
  'Admits a storage write, or refuses it. Takes NO organization argument: the '
  'tenant comes from transaction context. Authority is checked before replay, and '
  'an idempotency key binds the whole request tuple (R24; 0016). Concurrent '
  'same-key callers ALL succeed with one reservation.';

RESET ROLE;
SET LOCAL ROLE computedriven_migrations;
REVOKE CREATE ON SCHEMA app FROM computedriven_ledger;

COMMIT;
