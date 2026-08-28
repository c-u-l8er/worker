-- 0014 — M1.5, storage admission: entitlement, usage ledger, reservation
--
-- R24. Storage admission is AUTHORIZATION, not commerce, so it sits between M1
-- and M2 rather than in M6. The sentence it exists to make true:
--
--     NO WRITE CREDENTIAL IS ISSUED WITHOUT AN ACTIVE ENTITLEMENT AND
--     RESERVED BYTES.
--
-- Round 5 shipped a credential minter whose scope was narrow in every dimension
-- except the one that costs money: nothing anywhere said how many bytes the
-- holder was allowed to put through it. R8 sends bulk bytes client -> R2
-- directly, so by the time an over-quota upload is visible it is already an R2
-- invoice. The reservation is the only place that can refuse it.
--
-- ---------------------------------------------------------------------------
-- THE PROPERTY THAT IS HARD, AND THE ONLY ONE WORTH BUILDING FOR
--
--     limit  100 GB        used  90 GB
--     request A  8 GB   ┐  arrive simultaneously
--     request B  8 GB   ┘
--
--     NEVER:  both accepted  ->  106 GB
--
-- A read-then-write in application code cannot give this. Two Workers both read
-- 90, both compute 98 <= 100, both write. The admission is therefore ONE
-- statement --
--
--     UPDATE cd.storage_usage
--        SET reserved_bytes = reserved_bytes + n
--      WHERE organization_id = ...
--        AND committed_bytes + reserved_bytes + n <= limit
--
-- -- which takes a row lock, and under READ COMMITTED the loser re-evaluates its
-- WHERE against the WINNER'S committed row before deciding. That re-evaluation
-- is the whole mechanism. `IF NOT FOUND` is then the refusal, and there is no
-- window between the check and the write because there is no check.
--
-- ---------------------------------------------------------------------------
-- WHY THERE IS NO ORGANIZATION PARAMETER
--
-- reserve_storage() takes no organization id. It reads
-- app.current_organization_id(), which RAISES when context is absent (§6.1).
-- So a caller cannot reserve against another tenant's quota -- not because the
-- argument is validated, but because the argument does not exist. Same shape as
-- scopeForWorld() building its prefix from the org id rather than checking one:
--
--     the wrong answer is not rejected, it is unspeakable.
--
-- ---------------------------------------------------------------------------
-- WHY THE API ROLE GETS NO DML HERE
--
-- Round 5's law: a comment is not an enforcement mechanism. The API role holds
-- SELECT on these three tables and nothing else -- no UPDATE to revoke a column
-- of, because there is no UPDATE. Every state transition is a SECURITY DEFINER
-- function owned by computedriven_ledger, a role that can reach these three
-- tables and nothing else in the schema.

BEGIN;

-- ---------------------------------------------------------------------------
-- The ledger role. Same reasoning as computedriven_bootstrap in 0001: a
-- SECURITY DEFINER function runs as its owner, so the owner's reach IS the
-- function's blast radius, and "owned by the migration role" would mean every
-- one of these functions could touch every table in cd.
--
-- Created BEFORE the SET ROLE below, like 0001 does: computedriven_migrations
-- is NOCREATEROLE on purpose, so the migration runner cannot mint itself new
-- authority halfway through a file.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'computedriven_ledger') THEN
    CREATE ROLE computedriven_ledger NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END
$$;
GRANT computedriven_ledger TO computedriven_migrations;

SET LOCAL ROLE computedriven_migrations;

-- ---------------------------------------------------------------------------
-- Entitlement. What an organization is allowed to store, and why.
--
-- `source` records where the entitlement came from. Today every row is 'manual'
-- because M6 does not exist; the column is here so that when commerce arrives a
-- paid entitlement is distinguishable from one an operator typed, rather than
-- both being indistinguishable rows someone has to reconstruct from an invoice.
-- ---------------------------------------------------------------------------
CREATE TABLE cd.entitlements (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES cd.organizations(id) ON DELETE RESTRICT,
  tier            text NOT NULL CHECK (tier IN ('driver', 'fleet', 'factory')),
  byte_limit      bigint NOT NULL CHECK (byte_limit > 0),
  status          text NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active', 'suspended', 'expired')),
  source          text NOT NULL DEFAULT 'manual'
                  CHECK (source IN ('manual', 'subscription', 'trial')),
  effective_at    timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now()
);

-- At most one ACTIVE entitlement per organization. Two would make "the limit" a
-- question with two answers, and whichever the query happened to pick would be
-- the quota -- which is how a limit silently becomes the larger of two.
CREATE UNIQUE INDEX entitlements_active_uq
  ON cd.entitlements (organization_id) WHERE status = 'active';

COMMENT ON TABLE cd.entitlements IS
  'What an organization may store. Tier bytes match CLOUD_V1.md §5: driver '
  '100 GB, fleet 500 GB, factory 2 TB. R24 / M1.5.';

-- ---------------------------------------------------------------------------
-- The usage ledger. ONE row per organization, and it is the row every
-- concurrent admission serializes on.
--
-- Two numbers, not one, and the split is the point:
--
--   committed_bytes   bytes that are actually in R2
--   reserved_bytes    bytes a live reservation is holding but has not written
--
-- Quota is charged against the SUM. A reservation that is never finalized costs
-- quota until it expires and then costs nothing -- which is the correct
-- behaviour for a client that crashed mid-upload, and the reason the numbers
-- cannot be collapsed into one.
-- ---------------------------------------------------------------------------
CREATE TABLE cd.storage_usage (
  organization_id uuid PRIMARY KEY REFERENCES cd.organizations(id) ON DELETE RESTRICT,
  committed_bytes bigint NOT NULL DEFAULT 0 CHECK (committed_bytes >= 0),
  reserved_bytes  bigint NOT NULL DEFAULT 0 CHECK (reserved_bytes  >= 0),
  updated_at      timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE cd.storage_usage IS
  'Authoritative byte ledger, one row per organization. The CHECKs are not '
  'decoration: a release path that double-fires drives reserved_bytes negative, '
  'and a negative reservation is free quota. The constraint turns that into a '
  'failed transaction instead of a discount.';

-- ---------------------------------------------------------------------------
-- Reservations. The state machine, and it is deliberately small.
--
--     reserved ──► finalized      the bytes landed
--              ├─► aborted        the client gave up and said so
--              └─► expired        the client gave up and did not
--
-- Terminal states are terminal. There is no path back to `reserved`, so a
-- finalize arriving after an expiry is a refusal rather than a resurrection --
-- otherwise a slow client could commit bytes against quota that has already
-- been handed to somebody else.
-- ---------------------------------------------------------------------------
CREATE TABLE cd.storage_reservations (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid   NOT NULL,
  world_id        uuid   NOT NULL,
  principal_id    uuid   NOT NULL REFERENCES cd.principals(id) ON DELETE RESTRICT,
  bytes           bigint NOT NULL CHECK (bytes > 0),
  state           text   NOT NULL DEFAULT 'reserved'
                  CHECK (state IN ('reserved', 'finalized', 'aborted', 'expired')),
  idempotency_key text   NOT NULL CHECK (btrim(idempotency_key) <> ''),
  created_at      timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz NOT NULL,
  settled_at      timestamptz,
  committed_bytes bigint,

  -- The composite FK, same trick as 0004: it is not enough that the world
  -- exists, it must be THIS organization's world. A plain FK on world_id alone
  -- would let a reservation point across tenants.
  CONSTRAINT storage_reservations_world_fk
    FOREIGN KEY (world_id, organization_id)
    REFERENCES cd.worlds (id, organization_id) ON DELETE RESTRICT,

  -- A settled row has a settled_at and an open one does not. Stated as a
  -- constraint because it is the invariant every transition function relies on
  -- when it reads `state` alone.
  CONSTRAINT storage_reservations_settled_ck
    CHECK ((state = 'reserved') = (settled_at IS NULL)),

  -- Only a finalize commits bytes, and never more than were reserved. This is
  -- the oversubscription hole stated as a constraint rather than trusted to the
  -- function: a client that reserves 1 byte and reports 10 GB written must fail
  -- at the database, not at whoever reviews the function next.
  CONSTRAINT storage_reservations_commit_ck
    CHECK ((committed_bytes IS NULL) OR
           (state = 'finalized' AND committed_bytes >= 0 AND committed_bytes <= bytes))
);

-- Idempotency is per organization, not global: two tenants may legitimately
-- generate the same key and neither should see the other's reservation.
CREATE UNIQUE INDEX storage_reservations_idem_uq
  ON cd.storage_reservations (organization_id, idempotency_key);

-- The expiry sweep's access path. Partial, because only live reservations can
-- expire and the finished ones are the ones that accumulate.
CREATE INDEX storage_reservations_due_ix
  ON cd.storage_reservations (expires_at) WHERE state = 'reserved';

COMMENT ON TABLE cd.storage_reservations IS
  'An expiring claim on quota. Held bytes are charged from reserve until the '
  'row leaves the reserved state exactly once. R24 / M1.5.';

-- ---------------------------------------------------------------------------
-- RLS. Same shape as 0007: enable AND force, policies scoped to named roles,
-- an owner policy so migrations can still work.
-- ---------------------------------------------------------------------------
ALTER TABLE cd.entitlements          ENABLE ROW LEVEL SECURITY;
ALTER TABLE cd.entitlements          FORCE  ROW LEVEL SECURITY;
ALTER TABLE cd.storage_usage         ENABLE ROW LEVEL SECURITY;
ALTER TABLE cd.storage_usage         FORCE  ROW LEVEL SECURITY;
ALTER TABLE cd.storage_reservations  ENABLE ROW LEVEL SECURITY;
ALTER TABLE cd.storage_reservations  FORCE  ROW LEVEL SECURITY;

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['entitlements', 'storage_usage', 'storage_reservations'] LOOP
    EXECUTE format(
      'CREATE POLICY %I ON cd.%I FOR ALL '
      'TO computedriven_api, computedriven_jobs, computedriven_readonly '
      'USING (organization_id = app.current_organization_id()) '
      'WITH CHECK (organization_id = app.current_organization_id())',
      t || '_tenant', t);
    EXECUTE format(
      'CREATE POLICY %I ON cd.%I FOR ALL TO computedriven_migrations '
      'USING (true) WITH CHECK (true)', t || '_owner', t);
    -- The ledger role reaches every tenant's row, because the functions it owns
    -- derive the tenant themselves and must be able to act on whichever one
    -- they derived. This is the second cross-tenant exemption in the schema and
    -- it is named here for the same reason the first one is.
    EXECUTE format(
      'CREATE POLICY %I ON cd.%I FOR ALL TO computedriven_ledger '
      'USING (true) WITH CHECK (true)', t || '_ledger', t);
  END LOOP;
END
$$;

-- SELECT and nothing else. There is no UPDATE grant to revoke a column of,
-- because there is no UPDATE grant.
GRANT SELECT ON cd.entitlements, cd.storage_usage, cd.storage_reservations
  TO computedriven_api, computedriven_readonly, computedriven_jobs;

GRANT USAGE ON SCHEMA cd, app TO computedriven_ledger;
GRANT SELECT, INSERT, UPDATE ON cd.storage_usage, cd.storage_reservations TO computedriven_ledger;
GRANT SELECT ON cd.entitlements, cd.worlds, cd.organizations TO computedriven_ledger;

-- The ledger functions call these; without the grant they would fail at the
-- first membership check, and 0009 has already taken EXECUTE from PUBLIC.
GRANT EXECUTE ON FUNCTION
  app.current_organization_id(),
  app.authorize_membership(uuid, uuid),
  app.membership_role(uuid, uuid)
TO computedriven_ledger;

-- The ledger role must see the tenant tables its policies filter, and the
-- `_ledger` policies above admit it; a policy admits, a GRANT is still required.
CREATE POLICY worlds_ledger ON cd.worlds
  FOR SELECT TO computedriven_ledger USING (true);

-- ---------------------------------------------------------------------------
-- The admission type. A named composite so the Worker gets every fact it needs
-- in one round trip, including the ledger position -- a client that just
-- reserved should be able to say "82 of 100 GB" without a second query.
-- ---------------------------------------------------------------------------
CREATE TYPE app.storage_admission AS (
  reservation_id  uuid,
  organization_id uuid,
  world_id        uuid,
  bytes           bigint,
  expires_at      timestamptz,
  tier            text,
  byte_limit      bigint,
  committed_bytes bigint,
  reserved_bytes  bigint,
  replayed        boolean
);

-- Borrow-and-return, same as 0005/0008/0013: the ledger role needs CREATE on
-- `app` to own these functions and must not keep it. At rest it holds USAGE and
-- can create nothing.
GRANT CREATE ON SCHEMA app TO computedriven_ledger;
SET LOCAL ROLE computedriven_ledger;

-- Reservation lifetimes. The ceiling exists because held bytes are unavailable
-- bytes: a 30-day reservation is a quota leak with a timestamp on it.
CREATE OR REPLACE FUNCTION app.max_reservation_ttl() RETURNS interval
LANGUAGE sql IMMUTABLE AS $$ SELECT interval '6 hours' $$;

-- ---------------------------------------------------------------------------
-- Expiry. Releases held bytes for reservations whose time is up, EXACTLY ONCE.
--
-- The data-modifying CTE is what makes "exactly once" true rather than hoped
-- for: only rows this statement actually transitioned out of `reserved` appear
-- in RETURNING, so only their bytes are released. A concurrent sweep re-checks
-- state = 'reserved' against the committed row and transitions nothing.
--
-- Takes an optional organization so the reserve path can sweep just its own
-- tenant without touching the rest of the cluster.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.expire_storage_reservations(p_organization_id uuid DEFAULT NULL)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cd, pg_temp
AS $$
DECLARE
  released bigint := 0;
BEGIN
  WITH due AS (
    UPDATE cd.storage_reservations
       SET state = 'expired', settled_at = now()
     WHERE state = 'reserved'
       AND expires_at <= now()
       AND (p_organization_id IS NULL OR organization_id = p_organization_id)
    RETURNING organization_id, bytes
  ), per_org AS (
    SELECT organization_id, sum(bytes) AS total, count(*) AS n
    FROM due GROUP BY organization_id
  ), applied AS (
    UPDATE cd.storage_usage u
       SET reserved_bytes = u.reserved_bytes - p.total, updated_at = now()
      FROM per_org p
     WHERE u.organization_id = p.organization_id
    RETURNING p.n
  )
  SELECT coalesce(sum(n), 0) INTO released FROM applied;
  RETURN released;
END;
$$;

COMMENT ON FUNCTION app.expire_storage_reservations(uuid) IS
  'Releases quota held by reservations past their expiry. Exactly once per row: '
  'only rows this statement transitioned appear in the CTE that pays them back.';

-- ---------------------------------------------------------------------------
-- RESERVE. The admission itself.
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

  -- Sweep this tenant's dead reservations FIRST. Otherwise a client that
  -- crashed an hour ago is still holding the quota that would let its retry
  -- succeed, and the refusal would be correct arithmetic about a fiction.
  PERFORM app.expire_storage_reservations(v_org);

  -- Idempotent replay. A retried request must return the SAME reservation, not
  -- a second one -- otherwise a client retrying on a timeout doubles its own
  -- quota consumption and the first reservation leaks until it expires.
  SELECT * INTO r FROM cd.storage_reservations
   WHERE organization_id = v_org AND idempotency_key = p_idempotency_key;
  IF FOUND THEN
    IF r.state <> 'reserved' THEN
      RAISE EXCEPTION USING ERRCODE = '55000',
        MESSAGE = format('CD-RESERVE-SETTLED: reservation %s for this key is already %s',
                         r.id, r.state);
    END IF;
    SELECT e.tier, e.byte_limit INTO v_tier, v_limit
      FROM cd.entitlements e
     WHERE e.organization_id = v_org AND e.status = 'active';
    SELECT u.committed_bytes, u.reserved_bytes INTO v_committed, v_reserved
      FROM cd.storage_usage u WHERE u.organization_id = v_org;
    out_row := (r.id, v_org, r.world_id, r.bytes, r.expires_at,
                v_tier, v_limit, v_committed, v_reserved, true);
    RETURN out_row;
  END IF;

  -- Membership, re-derived here rather than trusted from the caller. The Worker
  -- checked it too; this function is reachable by anything holding EXECUTE and
  -- must not depend on having been called politely.
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
  INSERT INTO cd.storage_reservations
    (organization_id, world_id, principal_id, bytes, idempotency_key, expires_at)
  VALUES (v_org, p_world_id, p_principal_id, p_bytes, p_idempotency_key, v_expires)
  RETURNING id INTO v_id;

  out_row := (v_id, v_org, p_world_id, p_bytes, v_expires,
              v_tier, v_limit, v_committed, v_reserved, false);
  RETURN out_row;
END;
$$;

COMMENT ON FUNCTION app.reserve_storage(uuid, uuid, bigint, text, interval) IS
  'Admits a storage write, or refuses it. Takes NO organization argument: the '
  'tenant comes from transaction context, so reserving against another tenant '
  'is unspeakable rather than merely forbidden. R24 / M1.5.';

-- ---------------------------------------------------------------------------
-- FINALIZE. reserved -> finalized, exactly once, idempotent on retry.
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

  -- FOR UPDATE, so a second finalize BLOCKS here rather than racing. When it
  -- wakes, READ COMMITTED re-fetches the row it locked and it sees `finalized`
  -- -- which is what makes the idempotent branch below reachable instead of
  -- theoretical.
  SELECT * INTO r FROM cd.storage_reservations
   WHERE id = p_reservation_id AND organization_id = v_org
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501',
      MESSAGE = 'CD-FINALIZE-NOTFOUND: no such reservation in this organization';
  END IF;

  IF r.state = 'finalized' THEN
    IF r.committed_bytes = p_actual_bytes THEN
      SELECT u.committed_bytes, u.reserved_bytes INTO v_committed, v_reserved
        FROM cd.storage_usage u WHERE u.organization_id = v_org;
      SELECT e.tier, e.byte_limit INTO v_tier, v_limit
        FROM cd.entitlements e WHERE e.organization_id = v_org AND e.status = 'active';
      out_row := (r.id, v_org, r.world_id, r.bytes, r.expires_at,
                  v_tier, v_limit, v_committed, v_reserved, true);
      RETURN out_row;                       -- exactly-once: replay, no double count
    END IF;
    -- Same reservation, two different byte counts. One of them is wrong and the
    -- database cannot tell which, so it commits neither.
    RAISE EXCEPTION USING ERRCODE = '55000',
      MESSAGE = format('CD-FINALIZE-CONFLICT: reservation %s was already finalized at %s bytes, not %s',
                       r.id, r.committed_bytes, p_actual_bytes);
  END IF;

  IF r.state <> 'reserved' THEN
    -- Terminal is terminal. An expired reservation's bytes have already been
    -- given back to the quota; letting it finalize would spend them twice.
    RAISE EXCEPTION USING ERRCODE = '55000',
      MESSAGE = format('CD-FINALIZE-STATE: reservation %s is %s and cannot be finalized',
                       r.id, r.state);
  END IF;

  IF p_actual_bytes > r.bytes THEN
    RAISE EXCEPTION USING ERRCODE = '53100',
      MESSAGE = format('CD-FINALIZE-OVERRUN: %s bytes written against a %s byte reservation',
                       p_actual_bytes, r.bytes);
  END IF;

  UPDATE cd.storage_reservations
     SET state = 'finalized', settled_at = now(), committed_bytes = p_actual_bytes
   WHERE id = r.id AND state = 'reserved';

  UPDATE cd.storage_usage u
     SET reserved_bytes  = u.reserved_bytes  - r.bytes,
         committed_bytes = u.committed_bytes + p_actual_bytes,
         updated_at      = now()
   WHERE u.organization_id = v_org
  RETURNING u.committed_bytes, u.reserved_bytes INTO v_committed, v_reserved;

  SELECT e.tier, e.byte_limit INTO v_tier, v_limit
    FROM cd.entitlements e WHERE e.organization_id = v_org AND e.status = 'active';

  out_row := (r.id, v_org, r.world_id, r.bytes, r.expires_at,
              v_tier, v_limit, v_committed, v_reserved, false);
  RETURN out_row;
END;
$$;

-- ---------------------------------------------------------------------------
-- ABORT. reserved -> aborted, releasing exactly once.
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

  IF r.state IN ('aborted', 'expired') THEN
    -- Already released. Returning success here is what makes abort safe to
    -- retry; releasing again is what would make quota appear from nowhere.
    SELECT u.committed_bytes, u.reserved_bytes INTO v_committed, v_reserved
      FROM cd.storage_usage u WHERE u.organization_id = v_org;
    SELECT e.tier, e.byte_limit INTO v_tier, v_limit
      FROM cd.entitlements e WHERE e.organization_id = v_org AND e.status = 'active';
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

  UPDATE cd.storage_usage u
     SET reserved_bytes = u.reserved_bytes - r.bytes, updated_at = now()
   WHERE u.organization_id = v_org
  RETURNING u.committed_bytes, u.reserved_bytes INTO v_committed, v_reserved;

  SELECT e.tier, e.byte_limit INTO v_tier, v_limit
    FROM cd.entitlements e WHERE e.organization_id = v_org AND e.status = 'active';

  out_row := (r.id, v_org, r.world_id, r.bytes, r.expires_at,
              v_tier, v_limit, v_committed, v_reserved, false);
  RETURN out_row;
END;
$$;

RESET ROLE;
SET LOCAL ROLE computedriven_migrations;
REVOKE CREATE ON SCHEMA app FROM computedriven_ledger;

-- ---------------------------------------------------------------------------
-- ACL. 0009 took EXECUTE from PUBLIC by default privilege for functions created
-- by the migration role -- these were created by computedriven_ledger, which
-- that ALTER DEFAULT PRIVILEGES does not cover. Closing it here explicitly
-- rather than assuming, which is exactly the assumption 0009 exists because of.
-- ---------------------------------------------------------------------------
REVOKE EXECUTE ON FUNCTION
  app.reserve_storage(uuid, uuid, bigint, text, interval),
  app.finalize_storage(uuid, bigint),
  app.abort_storage(uuid),
  app.expire_storage_reservations(uuid),
  app.max_reservation_ttl()
FROM PUBLIC;

GRANT EXECUTE ON FUNCTION
  app.reserve_storage(uuid, uuid, bigint, text, interval),
  app.finalize_storage(uuid, bigint),
  app.abort_storage(uuid)
TO computedriven_api;

-- The sweep is a maintenance job and runs without tenant context, so it is the
-- one function here the jobs role holds and the API role does not.
GRANT EXECUTE ON FUNCTION app.expire_storage_reservations(uuid) TO computedriven_jobs;

DO $$
BEGIN
  IF has_function_privilege('public',
       'app.reserve_storage(uuid,uuid,bigint,text,interval)', 'EXECUTE') THEN
    RAISE EXCEPTION 'CD-ACL-PUBLIC: PUBLIC holds EXECUTE on app.reserve_storage';
  END IF;
  IF has_function_privilege('computedriven_readonly',
       'app.reserve_storage(uuid,uuid,bigint,text,interval)', 'EXECUTE') THEN
    RAISE EXCEPTION 'CD-ACL-WIDE: computedriven_readonly can reserve storage';
  END IF;
  IF has_table_privilege('computedriven_api', 'cd.storage_usage', 'UPDATE') THEN
    RAISE EXCEPTION 'CD-LEDGER-WRITABLE: the API role can UPDATE the byte ledger directly';
  END IF;
  IF has_table_privilege('computedriven_api', 'cd.entitlements', 'INSERT') THEN
    RAISE EXCEPTION 'CD-ENTITLEMENT-WRITABLE: the API role can grant itself an entitlement';
  END IF;
END
$$;

COMMIT;
