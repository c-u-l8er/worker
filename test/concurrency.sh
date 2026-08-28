#!/usr/bin/env bash
# Concurrency battery — the half of "correct" the other battery cannot see.
#
#   ./worker/test/concurrency.sh                    exit = number of failures
#   CD_SABOTAGE=lock  ./worker/test/concurrency.sh  exit 0 iff it BREAKS
#   CD_SABOTAGE=quota ./worker/test/concurrency.sh  exit 0 iff it BREAKS
#   CD_SABOTAGE=offer ./worker/test/concurrency.sh  exit 0 iff it BREAKS
#   CD_SABOTAGE=observe ./worker/test/concurrency.sh  exit 0 iff it BREAKS
#
#   N   concurrent first login       app.resolve_principal   (0013 -> 0015)
#   P   concurrent quota admission   app.reserve_storage     (0014 -> 0016)
#   Q   concurrent upload intents    app.offer_upload        (0017 -> 0019)
#   R   observer vs control plane    the whole intent state machine   (0021 -> 0022)
#
# N, P and Q each race ONE function against itself. R is the first group where
# the two sides are different subsystems -- an HTTP request and a queue consumer
# -- and it is the seam none of the others can reach.
#
# WHY THIS IS A SEPARATE FILE. tenant-isolation.sh runs one psql session against
# one connection, so every check it can express is SEQUENTIAL. F1 there proves
#
#     resolve_principal(x) = resolve_principal(x)
#
# called twice in a row, which is a real property and not the one that matters at
# a login endpoint. Two browsers, two tabs, a client that retries on timeout --
# the first request has not committed when the second one starts, and no amount
# of calling the function twice in one session will ever produce that state.
#
#     SERIAL CORRECTNESS IS NOT CONCURRENT CORRECTNESS.
#
# Group P is the same lesson about money instead of identity. A quota check that
# reads, decides, and then writes is correct in every sequential test and wrong
# whenever two requests arrive together -- and "together" at an HTTP endpoint is
# the normal case, not the edge one.
#
# The interleaving below is DETERMINISTIC, not a race the test hopes to hit. Two
# sessions are held open on FIFOs and stepped by hand:
#
#     S1  BEGIN; resolve_principal(sub)      inserts, does NOT commit
#     S2  BEGIN; resolve_principal(sub)      cannot see S1's row
#     S1  COMMIT                             S2 unblocks
#     S2  ...                                <- the whole question
#
# Unserialized, S2's SELECT finds nothing, it inserts its own principal, and its
# INSERT into principal_identities blocks on the unique partial index until S1
# commits -- at which point it raises unique_violation and the login 500s.
# Serialized, S2 ends up reading S1's committed row and both sessions return the
# same principal.
#
# "THE ADVISORY LOCK" IS THE WRONG NAME FOR THAT MECHANISM AND HAS BEEN SINCE
# 0015. Hyperdrive does not support advisory locks, so 0013's pg_advisory_xact_lock
# was replaced by a unique partial index plus an EXCEPTION block, and 0019 uses
# SELECT ... FOR UPDATE for the same reason. The CD_SABOTAGE=lock mode name is
# kept because it is a documented entry point; what it removes is serialization,
# not an advisory lock.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MIGRATIONS="${CD_MIGRATIONS:-$ROOT/worker/migrations}"

# Same rule as tenant-isolation.sh: R33 targets 17.x, so the target build is the
# default when it exists. A PATH prepend rather than a variable in front of every
# call -- this file invokes initdb/pg_ctl/createdb/psql in a dozen places and a
# dozen chances to forget one is a dozen chances to measure the wrong server.
DEFAULT_PGBIN=/opt/pgsql-17/bin
CONC_PGBIN="${CD_PGBIN-}"
if [ -z "${CD_PGBIN+set}" ] && [ -x "$DEFAULT_PGBIN/initdb" ]; then
  CONC_PGBIN="$DEFAULT_PGBIN"
fi
if [ -n "$CONC_PGBIN" ]; then
  [ -x "$CONC_PGBIN/initdb" ] || { printf 'CD_PGBIN=%s has no initdb\n' "$CONC_PGBIN"; exit 99; }
  PATH="$CONC_PGBIN:$PATH"
fi

PORT="${CD_PGPORT:-55433}"

# The authority channel a simulated delivery names (R77, 0026).
Q=computedriven-r2-notifications
PGROOT="${CD_PGROOT:-/tmp/cd-conc-$$}"
PGDATA="$PGROOT/data"
DB=computedriven
ISS=https://auth.computedriven.com/realms/cd

PASS=0; FAIL=0
if [ -t 1 ]; then G=$'\033[32m'; R=$'\033[31m'; D=$'\033[2m'; Z=$'\033[0m'; else G=; R=; D=; Z=; fi
ok()  { PASS=$((PASS+1)); printf '  %sPASS%s  %s\n' "$G" "$Z" "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  %sFAIL%s  %s\n' "$R" "$Z" "$1"
        [ -n "${2:-}" ] && printf '        %s%s%s\n' "$D" "$(printf '%s' "$2" | tr '\n' ' ' | cut -c1-200)" "$Z"; return 0; }

cleanup() {
  exec 3>&- 4>&- 2>/dev/null || true
  kill %1 %2 2>/dev/null
  pg_ctl -D "$PGDATA" -m immediate stop >/dev/null 2>&1
  rm -rf "$PGROOT"
}
trap cleanup EXIT

printf '\n%s== cluster ==%s\n' "$D" "$Z"
mkdir -p "$PGDATA"
initdb -D "$PGDATA" -A trust -U cdtest --no-sync >/dev/null 2>&1 || { echo "initdb failed"; exit 99; }
pg_ctl -D "$PGDATA" -l "$PGROOT/pg.log" -w \
  -o "-p $PORT -c listen_addresses=127.0.0.1 -c unix_socket_directories='' -c fsync=off" \
  start >/dev/null 2>&1 || { echo "pg_ctl start failed"; tail -20 "$PGROOT/pg.log"; exit 99; }
createdb -h 127.0.0.1 -p "$PORT" -U cdtest "$DB" || exit 99
printf '  postgres %s on 127.0.0.1:%s\n' \
  "$(psql -h 127.0.0.1 -p "$PORT" -U cdtest -d "$DB" -tAc 'show server_version')" "$PORT"

for f in "$MIGRATIONS"/*.sql; do
  psql -h 127.0.0.1 -p "$PORT" -U cdtest -d "$DB" -v ON_ERROR_STOP=1 -tAq -f "$f" >/dev/null 2>&1 \
    || { printf '  %sFAIL%s  migration %s\n' "$R" "$Z" "$(basename "$f")"; exit 98; }
done
printf '  %sok%s    %s migrations applied\n' "$G" "$Z" "$(ls "$MIGRATIONS"/*.sql | wc -l)"

# Each CD_SABOTAGE mode reinstalls ONE pre-fix function. Its own group must then
# break and the other two must not; a sabotage run reporting zero failures means
# this file is measuring nothing.
if [ "${CD_SABOTAGE:-}" = "quota" ]; then
  printf '\n  %sSABOTAGE MODE (quota)%s  reinstalling reserve_storage as READ-THEN-WRITE\n' "$R" "$Z"
  printf '  %sGroup P failures below are the EXPECTED result -- read the control verdict.%s\n' "$D" "$Z"
  # The naive form: read the ledger, decide in the function, then write, with no
  # lock taken first. It is correct in every sequential test and oversubscribes
  # the moment two requests overlap.
  #
  # 0014 was atomic by folding the arithmetic into UPDATE ... WHERE; 0023 cannot
  # (the hold is derived, and a subquery in that WHERE would be evaluated
  # against the pre-wait snapshot), so the serialization moved to an explicit
  # locking statement AHEAD of the read. What this sabotage removes is exactly
  # that statement -- everything else, including 0016's idempotency handling, is
  # left current so the failure isolates THE GATE and nothing else.
  psql -h 127.0.0.1 -p "$PORT" -U cdtest -d "$DB" -tAq >/dev/null 2>&1 <<'SQL'
SET ROLE computedriven_migrations;
GRANT CREATE ON SCHEMA app TO computedriven_ledger;
SET ROLE computedriven_ledger;
CREATE OR REPLACE FUNCTION app.reserve_storage(
  p_world_id uuid, p_principal_id uuid, p_bytes bigint,
  p_idempotency_key text, p_ttl interval DEFAULT interval '1 hour')
RETURNS app.storage_admission LANGUAGE plpgsql SECURITY DEFINER
SET search_path = cd, pg_temp AS $$
DECLARE
  v_org uuid; v_limit bigint; v_tier text; r record;
  v_committed bigint; v_reserved bigint; v_id uuid; v_expires timestamptz;
  out_row app.storage_admission;
BEGIN
  v_org := app.current_organization_id();
  SELECT e.tier, e.byte_limit INTO v_tier, v_limit FROM cd.entitlements e
   WHERE e.organization_id = v_org AND e.status = 'active';

  SELECT * INTO r FROM cd.storage_reservations
   WHERE organization_id = v_org AND idempotency_key = p_idempotency_key;
  IF FOUND THEN
    PERFORM app.assert_reservation_matches(r.id, r.principal_id, r.world_id, r.bytes,
                                           p_principal_id, p_world_id, p_bytes);
    SELECT l.committed_bytes, l.outstanding_bytes INTO v_committed, v_reserved
      FROM app.storage_ledger_for(v_org) l;
    out_row := (r.id, v_org, r.world_id, r.bytes, r.expires_at,
                v_tier, v_limit, v_committed, v_reserved, true);
    RETURN out_row;
  END IF;

  -- NO LOCKING STATEMENT. This is the defect: DO NOTHING does not take the row
  -- lock, so two reservers both read below without either having waited.
  INSERT INTO cd.storage_usage (organization_id) VALUES (v_org) ON CONFLICT DO NOTHING;
  -- READ...
  SELECT u.committed_bytes INTO v_committed
    FROM cd.storage_usage u WHERE u.organization_id = v_org;
  v_reserved := app.storage_outstanding(v_org);
  -- ...DECIDE...
  IF coalesce(v_committed,0) + v_reserved + p_bytes > v_limit THEN
    RAISE EXCEPTION USING ERRCODE='53100', MESSAGE='CD-QUOTA-EXCEEDED: naive';
  END IF;
  PERFORM pg_sleep(0.02);   -- the window every read-then-write has, made visible
  -- ...THEN WRITE.
  v_expires := now() + p_ttl;
  INSERT INTO cd.storage_reservations
    (organization_id, world_id, principal_id, bytes, idempotency_key, expires_at)
  VALUES (v_org, p_world_id, p_principal_id, p_bytes, p_idempotency_key, v_expires)
  ON CONFLICT (organization_id, idempotency_key) DO NOTHING
  RETURNING id INTO v_id;
  IF v_id IS NULL THEN
    SELECT * INTO r FROM cd.storage_reservations
     WHERE organization_id = v_org AND idempotency_key = p_idempotency_key;
    PERFORM app.assert_reservation_matches(r.id, r.principal_id, r.world_id, r.bytes,
                                           p_principal_id, p_world_id, p_bytes);
    SELECT l.committed_bytes, l.outstanding_bytes INTO v_committed, v_reserved
      FROM app.storage_ledger_for(v_org) l;
    out_row := (r.id, v_org, r.world_id, r.bytes, r.expires_at,
                v_tier, v_limit, v_committed, v_reserved, true);
    RETURN out_row;
  END IF;
  SELECT l.committed_bytes, l.outstanding_bytes INTO v_committed, v_reserved
    FROM app.storage_ledger_for(v_org) l;
  out_row := (v_id, v_org, p_world_id, p_bytes, v_expires, v_tier, v_limit,
              v_committed, v_reserved, false);
  RETURN out_row;
END $$;
RESET ROLE;
SET ROLE computedriven_migrations;
REVOKE CREATE ON SCHEMA app FROM computedriven_ledger;
SQL
elif [ "${CD_SABOTAGE:-}" = "observe" ]; then
  printf '\n  %sSABOTAGE MODE (observe)%s  putting the queue consumer back OUTSIDE the lock protocol\n' "$R" "$Z"
  printf '  %sGroup R failures below are the EXPECTED result -- read the control verdict.%s\n' "$D" "$Z"
  # 0021/0019's arrangement on 0023's signatures. Three things come back out and
  # each is a finding: the observer takes no lock, offer_upload decides from a
  # read it took without locking the intent, and abandon_upload decides from a
  # read it took before waiting. Everything else stays current so this isolates
  # the LOCK PROTOCOL and nothing else.
  #
  # WHAT THIS MODE CATCHES CHANGED IN 0023, AND THE CHANGE IS THE POINT. It used
  # to break four checks; it now breaks TWO -- R1c and R2d, the DISPOSITION the
  # caller is handed. R1b and R2c, which assert the intent is still `observed`,
  # now PASS EVEN UNDER SABOTAGE, because `state` is a generated projection of
  # provider_observed_at and cannot be assigned by anything, correct or naive.
  #
  #     R54 USED TO BE A RULE THREE FUNCTIONS HAD TO REMEMBER. R71 MADE IT A
  #     PROPERTY OF THE COLUMN, SO THE SABOTAGE CANNOT REACH IT ANY MORE.
  #
  # A future session reading "2 failures" here should not conclude the sabotage
  # got weaker. The state corruption became unreachable; what an unlocked
  # observer still costs you is fresh write authority minted for an object R2
  # already holds, which is R1c, and that is still very much a defect.
  psql -h 127.0.0.1 -p "$PORT" -U cdtest -d "$DB" -tAq >/dev/null 2>&1 <<'SQL'
SET ROLE computedriven_migrations;
GRANT CREATE ON SCHEMA app TO computedriven_ledger;
SET ROLE computedriven_ledger;

CREATE OR REPLACE FUNCTION app.observe_storage_object(
  p_bucket text, p_object_key text, p_etag text, p_size_bytes bigint,
  p_action text, p_event_time timestamptz, p_message_id text DEFAULT NULL,
  p_queue text DEFAULT NULL)
RETURNS app.observation_result LANGUAGE plpgsql SECURITY DEFINER
SET search_path = cd, pg_temp AS $$
DECLARE k record; v_intent uuid; v_id uuid; v_observed timestamptz;
        existing uuid; out_row app.observation_result;
BEGIN
  SELECT * INTO k FROM app.parse_object_key(p_object_key);
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='CD-OBSERVE-KEY: naive';
  END IF;
  -- NO app.lock_intent(). This is the defect.
  SELECT id INTO v_intent FROM cd.upload_intents WHERE object_key = p_object_key;
  -- queue_name and observed_at are carried for the same reason all three intent
  -- columns are set below: 0026 added a CHECK that a message id names its queue
  -- (R77) and a composite FK that the copied clocks are the named observation's
  -- (R76). A sabotage missing either raises on a CONSTRAINT and this mode goes
  -- back to measuring "the naive observer is malformed" instead of "the naive
  -- observer takes no lock". Third round in a row this has had to be said.
  INSERT INTO cd.storage_observations
    (organization_id, world_id, intent_id, bucket, object_key, etag, size_bytes,
     action, event_time, message_id, queue_name)
  VALUES (k.organization_id, k.world_id, v_intent, p_bucket, p_object_key, p_etag,
          p_size_bytes, p_action, p_event_time, p_message_id, p_queue)
  ON CONFLICT DO NOTHING RETURNING id, observed_at INTO v_id, v_observed;
  IF v_id IS NULL THEN
    SELECT id INTO existing FROM cd.storage_observations
     WHERE bucket=p_bucket AND object_key=p_object_key AND etag=p_etag
     ORDER BY observed_at DESC LIMIT 1;
    out_row := (existing, v_intent, p_size_bytes, true, v_intent IS NOT NULL);
    RETURN out_row;
  END IF;
  INSERT INTO cd.storage_objects
    (bucket, object_key, organization_id, world_id, etag, size_bytes,
     first_event_at, last_event_at, current_observation_id)
  VALUES (p_bucket, p_object_key, k.organization_id, k.world_id, p_etag, p_size_bytes,
          p_event_time, p_event_time, v_id)
  ON CONFLICT (bucket, object_key) DO UPDATE SET
    etag = EXCLUDED.etag, size_bytes = EXCLUDED.size_bytes,
    current_observation_id = EXCLUDED.current_observation_id,
    last_event_at = GREATEST(cd.storage_objects.last_event_at, EXCLUDED.last_event_at),
    event_count = cd.storage_objects.event_count + 1, updated_at = now();
  IF v_intent IS NOT NULL THEN
    -- provider_observed_at, because `state` is generated since 0023 and refuses
    -- to be assigned. The IS NULL guard stays: it is the write-once rule, not
    -- the lock protocol, and this mode isolates the lock protocol.
    --
    -- ALL THREE COLUMNS, and that is not cosmetic. 0025 added
    -- upload_intents_observed_together_ck (R74), so a naive observer setting
    -- only provider_observed_at RAISES -- and this mode then measured "the
    -- sabotage crashes on a constraint" instead of "the sabotage takes no
    -- lock". It printed CAUGHT and isolated, at 6 failures instead of 2, with
    -- R1b reporting state=offered because the observer had never got that far.
    --
    --     A CONTROL THAT BREAKS FOR THE WRONG REASON IS A FALSE GREEN ABOUT
    --     ITS OWN MEANING, AND IT LOOKS EXACTLY LIKE A GOOD ONE.
    UPDATE cd.upload_intents
       SET provider_observed_at = v_observed,
           provider_event_at = p_event_time,
           observing_observation_id = v_id
     WHERE id = v_intent AND provider_observed_at IS NULL;
  END IF;
  out_row := (v_id, v_intent, p_size_bytes, false, v_intent IS NOT NULL);
  RETURN out_row;
END $$;

CREATE OR REPLACE FUNCTION app.offer_upload(
  p_reservation_id uuid, p_object_key text, p_expected_bytes bigint,
  p_content_digest text, p_ttl interval DEFAULT interval '15 minutes')
RETURNS app.upload_offer LANGUAGE plpgsql SECURITY DEFINER
SET search_path = cd, pg_temp AS $$
DECLARE
  v_org uuid; r record; k record; v_spoken bigint; v_id uuid;
  v_expires timestamptz; existing cd.upload_intents; out_row app.upload_offer;
BEGIN
  v_org := app.current_organization_id();
  SELECT * INTO r FROM cd.storage_reservations
   WHERE id = p_reservation_id AND organization_id = v_org FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='CD-OFFER-NOTFOUND: naive';
  END IF;
  SELECT * INTO k FROM app.parse_object_key(p_object_key);
  IF NOT FOUND OR k.organization_id <> v_org OR k.world_id <> r.world_id THEN
    RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='CD-OFFER-KEY: naive';
  END IF;
  -- NO app.lock_intent(): the intent is read under the RESERVATION lock alone,
  -- which the observer never takes.
  SELECT * INTO existing FROM cd.upload_intents WHERE object_key = p_object_key;
  IF FOUND THEN
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
    -- ...and NO observed guard, so a blocked UPDATE has nothing to re-evaluate.
    UPDATE cd.upload_intents
       SET client_abandoned_at=NULL, expires_at=GREATEST(expires_at, v_expires)
     WHERE id = existing.id
    RETURNING expires_at INTO v_expires;
    out_row := (existing.id, existing.reservation_id, existing.object_key,
                existing.expected_bytes, existing.content_digest, v_expires, true, 'replayed');
    RETURN out_row;
  END IF;
  SELECT coalesce(sum(expected_bytes), 0) INTO v_spoken
    FROM cd.upload_intents WHERE reservation_id = r.id;
  IF v_spoken + p_expected_bytes > r.bytes THEN
    RAISE EXCEPTION USING ERRCODE='53100',
      MESSAGE=format('CD-OFFER-OVERCOMMIT: reservation %s holds %s bytes, %s already offered, %s requested',
                     r.id, r.bytes, v_spoken, p_expected_bytes);
  END IF;
  v_expires := LEAST(now() + p_ttl, r.expires_at);
  INSERT INTO cd.upload_intents
    (organization_id, world_id, reservation_id, object_key, expected_bytes, content_digest, expires_at)
  VALUES (v_org, r.world_id, r.id, p_object_key, p_expected_bytes, p_content_digest, v_expires)
  ON CONFLICT (object_key) DO NOTHING RETURNING id INTO v_id;
  IF v_id IS NULL THEN
    SELECT * INTO existing FROM cd.upload_intents WHERE object_key = p_object_key;
    PERFORM app.assert_intent_matches(existing.id, existing.reservation_id,
              existing.expected_bytes, existing.content_digest,
              p_reservation_id, p_expected_bytes, p_content_digest);
    out_row := (existing.id, existing.reservation_id, existing.object_key,
                existing.expected_bytes, existing.content_digest,
                existing.expires_at, true, 'replayed');
    RETURN out_row;
  END IF;
  out_row := (v_id, r.id, p_object_key, p_expected_bytes, p_content_digest, v_expires, false, 'fresh');
  RETURN out_row;
END $$;

CREATE OR REPLACE FUNCTION app.abandon_upload(p_intent_id uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path = cd, pg_temp AS $$
DECLARE v_org uuid; i cd.upload_intents;
BEGIN
  v_org := app.current_organization_id();
  -- THE STALE READ: taken before the wait, and used for the decision after it.
  SELECT * INTO i FROM cd.upload_intents
   WHERE id = p_intent_id AND organization_id = v_org;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='CD-ABANDON-NOTFOUND: naive';
  END IF;
  PERFORM 1 FROM cd.storage_reservations
   WHERE id = i.reservation_id AND organization_id = v_org FOR UPDATE;
  IF i.provider_observed_at IS NOT NULL THEN
    RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='CD-ABANDON-OBSERVED: naive';
  END IF;
  IF i.client_abandoned_at IS NOT NULL THEN RETURN false; END IF;
  UPDATE cd.upload_intents SET client_abandoned_at=now() WHERE id = i.id;
  RETURN true;
END $$;
RESET ROLE;
SET ROLE computedriven_migrations;
REVOKE CREATE ON SCHEMA app FROM computedriven_ledger;
SQL
elif [ "${CD_SABOTAGE:-}" = "offer" ]; then
  printf '\n  %sSABOTAGE MODE (offer)%s  reinstalling offer_upload as SUM-THEN-INSERT\n' "$R" "$Z"
  printf '  %sGroup Q failures below are the EXPECTED result -- read the control verdict.%s\n' "$D" "$Z"
  # 0017's body, carried forward onto the current return type. Three things are
  # taken back out and each one is a finding: FOR UPDATE on the reservation,
  # reservation_id in the promise, and ON CONFLICT on the insert.
  psql -h 127.0.0.1 -p "$PORT" -U cdtest -d "$DB" -tAq >/dev/null 2>&1 <<'SQL'
SET ROLE computedriven_migrations;
GRANT CREATE ON SCHEMA app TO computedriven_ledger;
SET ROLE computedriven_ledger;
CREATE OR REPLACE FUNCTION app.offer_upload(
  p_reservation_id uuid, p_object_key text, p_expected_bytes bigint,
  p_content_digest text, p_ttl interval DEFAULT interval '15 minutes')
RETURNS app.upload_offer LANGUAGE plpgsql SECURITY DEFINER
SET search_path = cd, pg_temp AS $$
DECLARE
  v_org uuid; r record; k record; v_spoken bigint; v_id uuid;
  v_expires timestamptz; existing record; out_row app.upload_offer;
BEGIN
  v_org := app.current_organization_id();
  -- NO FOR UPDATE. This is the defect.
  SELECT * INTO r FROM cd.storage_reservations
   WHERE id = p_reservation_id AND organization_id = v_org;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='CD-OFFER-NOTFOUND: naive';
  END IF;
  SELECT * INTO k FROM app.parse_object_key(p_object_key);
  IF NOT FOUND OR k.organization_id <> v_org OR k.world_id <> r.world_id THEN
    RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='CD-OFFER-KEY: naive';
  END IF;
  -- Replay WITHOUT reservation_id in the promise: hands back whatever row has
  -- that key, bound to whatever reservation minted it. That is finding 56.
  --
  -- The INTENT lock protocol is deliberately KEPT. An earlier draft of this mode
  -- reinstalled 0017's whole body, which also removed lock_intent() and the
  -- state guard, so it broke group R too and the verdict reported MISDIRECTED --
  -- correctly.
  --
  --     A CONTROL THAT BREAKS TWO THINGS MEASURES NEITHER OF THEM.
  SELECT * INTO existing FROM cd.upload_intents WHERE object_key = p_object_key;
  IF FOUND THEN
    existing := app.lock_intent(existing.id);
    IF existing.expected_bytes <> p_expected_bytes
       OR existing.content_digest <> p_content_digest THEN
      RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='CD-OFFER-MISMATCH: naive';
    END IF;
    out_row := (existing.id, existing.reservation_id, existing.object_key,
                existing.expected_bytes, existing.content_digest,
                existing.expires_at, true,
                CASE WHEN existing.state='observed' THEN 'already_observed' ELSE 'replayed' END);
    RETURN out_row;
  END IF;
  -- SUM...
  SELECT coalesce(sum(expected_bytes), 0) INTO v_spoken FROM cd.upload_intents
   WHERE reservation_id = r.id AND state IN ('offered','observed');
  -- ...DECIDE...
  IF v_spoken + p_expected_bytes > r.bytes THEN
    RAISE EXCEPTION USING ERRCODE='53100',
      MESSAGE=format('CD-OFFER-OVERCOMMIT: reservation %s holds %s bytes, %s already offered, %s requested',
                     r.id, r.bytes, v_spoken, p_expected_bytes);
  END IF;
  PERFORM pg_sleep(0.02);   -- the window every read-then-write has, made visible
  v_expires := LEAST(now() + p_ttl, r.expires_at);
  -- ...THEN INSERT, with no ON CONFLICT: the loser raises.
  INSERT INTO cd.upload_intents
    (organization_id, world_id, reservation_id, object_key, expected_bytes, content_digest, expires_at)
  VALUES (v_org, r.world_id, r.id, p_object_key, p_expected_bytes, p_content_digest, v_expires)
  RETURNING id INTO v_id;
  out_row := (v_id, r.id, p_object_key, p_expected_bytes, p_content_digest,
              v_expires, false, 'fresh');
  RETURN out_row;
END $$;
RESET ROLE;
SET ROLE computedriven_migrations;
REVOKE CREATE ON SCHEMA app FROM computedriven_ledger;
SQL
elif [ "${CD_SABOTAGE:-}" = "lock" ]; then
  printf '\n  %sSABOTAGE MODE (lock)%s  reinstalling resolve_principal WITHOUT serialization\n' "$R" "$Z"
  printf '  %sFailures below are the EXPECTED result -- read the control verdict.%s\n' "$D" "$Z"
  psql -h 127.0.0.1 -p "$PORT" -U cdtest -d "$DB" -tAq >/dev/null 2>&1 <<'SQL'
SET ROLE computedriven_migrations;
CREATE OR REPLACE FUNCTION app.resolve_principal(p_provider text, p_issuer text, p_subject text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = cd, pg_temp AS $$
DECLARE found uuid; fresh uuid;
BEGIN
  SELECT pi.principal_id INTO found FROM cd.principal_identities pi
   WHERE pi.provider = p_provider AND pi.issuer = p_issuer
     AND pi.subject = p_subject AND pi.status = 'active';
  IF found IS NOT NULL THEN RETURN found; END IF;
  INSERT INTO cd.principals DEFAULT VALUES RETURNING id INTO fresh;
  INSERT INTO cd.principal_identities (principal_id, provider, issuer, subject)
  VALUES (fresh, p_provider, p_issuer, p_subject);
  RETURN fresh;
END $$;
ALTER FUNCTION app.resolve_principal(text,text,text) OWNER TO computedriven_bootstrap;
SQL
fi

# ---------------------------------------------------------------------------
# Two hand-stepped sessions.
#
# psql reads from a FIFO that stays open on a shell fd, so the session survives
# between statements instead of exiting at EOF. Output is tailed from a file
# rather than read from a pipe, because a blocked session writes nothing and a
# blocking read would deadlock the test rather than measure the block.
# ---------------------------------------------------------------------------
mkfifo "$PGROOT/in1" "$PGROOT/in2"
: > "$PGROOT/out1"; : > "$PGROOT/out2"
psql -h 127.0.0.1 -p "$PORT" -U cdtest -d "$DB" -tAq < "$PGROOT/in1" > "$PGROOT/out1" 2>&1 &
psql -h 127.0.0.1 -p "$PORT" -U cdtest -d "$DB" -tAq < "$PGROOT/in2" > "$PGROOT/out2" 2>&1 &
exec 3> "$PGROOT/in1"
exec 4> "$PGROOT/in2"

s1() { printf '%s\n' "$*" >&3; }
s2() { printf '%s\n' "$*" >&4; }

# Wait until a session's output file has at least N non-blank lines, or time out.
# The timeout is what tells "still blocked" apart from "finished"; both look like
# silence and only one of them is a defect.
await() { # file, want-lines, seconds
  local f="$1" want="$2" secs="${3:-5}" i=0
  while [ "$i" -lt "$((secs * 20))" ]; do
    [ "$(grep -ac . "$f")" -ge "$want" ] && return 0
    sleep 0.05; i=$((i+1))
  done
  return 1
}

# The non-blank lines a session has produced SINCE a recorded baseline.
#
# `-a` is not defensive habit. These files are read while a psql process holds
# them open, and a single NUL anywhere makes grep treat the whole file as binary
# and print "binary file matches" instead of the line -- at which point every
# content assertion below silently stops matching anything.
since() { # file, baseline-line-count
  grep -a . "$1" | tail -n "+$(( $2 + 1 ))"
}

printf '\n%s== N. concurrent first login (R30) ==%s\n' "$D" "$Z"

SUB=race-sub-1
s1 "BEGIN; SELECT app.resolve_principal('keycloak','$ISS','$SUB');"
if ! await "$PGROOT/out1" 1 5; then
  bad "N0  session 1 resolved inside an open transaction" "S1 never returned"
else
  P1=$(grep . "$PGROOT/out1" | tail -1)
  ok "N0  session 1 resolved inside an open transaction"
fi

# S2 enters the SAME call while S1 is still uncommitted. This is the state a
# sequential test cannot construct.
s2 "BEGIN; SELECT app.resolve_principal('keycloak','$ISS','$SUB');"

# It MUST block -- on the advisory lock after the fix, on the unique index
# before it. If it returns here, it minted a second principal for one identity.
if await "$PGROOT/out2" 1 2; then
  EARLY=$(grep . "$PGROOT/out2" | tail -1)
  bad "N1  session 2 blocks while session 1 is uncommitted" "returned early: $EARLY"
else
  ok "N1  session 2 blocks while session 1 is uncommitted"
fi

s1 "COMMIT;"
await "$PGROOT/out1" 1 5

# The whole question. After S1 commits, does S2 succeed with the SAME principal?
if ! await "$PGROOT/out2" 1 8; then
  bad "N2  session 2 returns after session 1 commits" "still blocked after 8s"
  P2="<none>"
else
  # Read the WHOLE output, not its last line. A postgres error is four lines
  # (ERROR/DETAIL/CONTEXT/PL-pgSQL) and `tail -1` lands on the CONTEXT line,
  # which matches none of the patterns below -- so the first draft of this check
  # scored a duplicate-key failure as a PASS.
  ALL2=$(cat "$PGROOT/out2")
  P2=$(grep . "$PGROOT/out2" | tail -1)
  case "$ALL2" in
    *ERROR*|*duplicate\ key*|*principal_identities_active_uq*)
      bad "N2  session 2 returns after session 1 commits" "$(printf '%s' "$ALL2" | head -2)" ;;
    *) ok "N2  session 2 returns after session 1 commits" ;;
  esac
fi

if [ "${P1:-x}" = "${P2:-y}" ]; then
  ok "N3  both sessions resolved to the SAME principal  ${D}${P1}${Z}"
else
  bad "N3  both sessions resolved to the SAME principal" "s1=$P1  s2=$P2"
fi

s2 "COMMIT;"
await "$PGROOT/out2" 2 5

# One identity, one principal, and no orphan left behind by the loser.
COUNT=$(psql -h 127.0.0.1 -p "$PORT" -U cdtest -d "$DB" -tAq <<SQL
SET ROLE computedriven_migrations;
SELECT count(*) FROM cd.principal_identities
 WHERE subject='$SUB' AND status='active';
SQL
)
if [ "$COUNT" = "1" ]; then ok "N4  exactly one active binding exists for the subject"
else bad "N4  exactly one active binding exists for the subject" "count=$COUNT"; fi

# The loser must not leave a principal row with no identity attached. Under the
# fix no loser exists at all; this is the check that would catch a "handle the
# unique violation and carry on" fix that forgot to undo its own INSERT.
ORPHANS=$(psql -h 127.0.0.1 -p "$PORT" -U cdtest -d "$DB" -tAq <<SQL
SET ROLE computedriven_migrations;
SELECT count(*) FROM cd.principals p
 WHERE NOT EXISTS (SELECT 1 FROM cd.principal_identities i WHERE i.principal_id = p.id);
SQL
)
if [ "$ORPHANS" = "0" ]; then ok "N5  no orphaned principal was left behind"
else bad "N5  no orphaned principal was left behind" "orphans=$ORPHANS"; fi

# ---------------------------------------------------------------------------
# N6 -- the unstructured version, because the hand-stepped one proves a single
# interleaving and a login endpoint does not get to pick its interleaving.
# ---------------------------------------------------------------------------
printf '\n%s== N6. unstructured burst ==%s\n' "$D" "$Z"
BURST_FAIL=0; ROUNDS=12; WORKERS=4
for r in $(seq 1 $ROUNDS); do
  BURST_PIDS=()
  for w in $(seq 1 $WORKERS); do
    psql -h 127.0.0.1 -p "$PORT" -U cdtest -d "$DB" -tAq \
      -c "SELECT app.resolve_principal('keycloak','$ISS','burst-$r');" \
      > "$PGROOT/burst-$r-$w" 2>&1 &
    BURST_PIDS+=($!)
  done
  # Named pids, NOT a bare `wait`. The two hand-stepped sessions above are still
  # background jobs on their FIFOs and never exit, so `wait` with no argument
  # hangs the battery forever -- which it did, and looked exactly like the
  # cluster being slow.
  wait "${BURST_PIDS[@]}"
  RESULTS=$(cat "$PGROOT/burst-$r-"* | grep . | sort -u)
  if [ "$(printf '%s\n' "$RESULTS" | wc -l)" -ne 1 ] || printf '%s' "$RESULTS" | grep -qi 'error'; then
    BURST_FAIL=$((BURST_FAIL+1))
    [ "$BURST_FAIL" = 1 ] && FIRST=$(printf '%s' "$RESULTS" | tr '\n' ' ' | cut -c1-160)
  fi
done
if [ "$BURST_FAIL" = 0 ]; then
  ok "N6  ${ROUNDS} rounds x ${WORKERS} simultaneous first logins, one principal each"
else
  bad "N6  ${ROUNDS} rounds x ${WORKERS} simultaneous first logins, one principal each" \
      "$BURST_FAIL/$ROUNDS rounds diverged; first: ${FIRST:-}"
fi

NFAIL=$FAIL

# ---------------------------------------------------------------------------
# P. concurrent quota admission (R24 / M1.5)
#
# The property, stated as CLOUD_V1.md states it:
#
#     limit 100 · used 90 · A wants 8 · B wants 8 · arrive together
#     NEVER   both accepted  ->  106
#
# Everything below uses small round numbers rather than gigabytes, because the
# arithmetic is the assertion and 1000/100 is checkable by eye.
# ---------------------------------------------------------------------------
printf '\n%s== P. concurrent quota admission (R24) ==%s\n' "$D" "$Z"

ORG=aaaaaaaa-0000-4000-8000-000000000001
WORLD=11111111-0000-4000-8000-00000000000a

if ! seed=$(psql -h 127.0.0.1 -p "$PORT" -U cdtest -d "$DB" -v ON_ERROR_STOP=1 -tAq 2>&1 <<SQL
SET ROLE computedriven_migrations;
INSERT INTO cd.organizations (id, slug, display_name) VALUES ('$ORG','org-a','Org A');
INSERT INTO cd.worlds (id, organization_id, name) VALUES ('$WORLD','$ORG','workstation');
INSERT INTO cd.principals (id) VALUES ('cccccccc-0000-4000-8000-00000000000c');
INSERT INTO cd.organization_principals (organization_id, principal_id, app_role)
VALUES ('$ORG','cccccccc-0000-4000-8000-00000000000c','owner');
-- 1000 bytes, and nothing used. Tier name is real; the number is not, on
-- purpose -- a battery that has to reason about 107374182400 is a battery whose
-- arithmetic errors hide.
INSERT INTO cd.entitlements (organization_id, tier, byte_limit) VALUES ('$ORG','driver',1000);
SQL
); then
  bad "P0  seed" "$seed"; PRIN=; else
  ok "P0  entitlement seeded: 1000 bytes, 0 used"
  PRIN=cccccccc-0000-4000-8000-00000000000c
fi

# One worker: open a tenant transaction, reserve, commit. This is exactly what
# the Worker does per request, so N of them is exactly N simultaneous requests.
reserve() { # bytes, idempotency-key, outfile
  psql -h 127.0.0.1 -p "$PORT" -U cdtest -d "$DB" -tAq > "$3" 2>&1 <<SQL
BEGIN;
SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$ORG');
SELECT reservation_id FROM app.reserve_storage('$WORLD','$PRIN',$1,'$2');
COMMIT;
SQL
}

usage() { # column
  psql -h 127.0.0.1 -p "$PORT" -U cdtest -d "$DB" -tAq <<SQL
SET ROLE computedriven_migrations;
SELECT coalesce((SELECT $1 FROM cd.storage_usage WHERE organization_id='$ORG'), 0);
SQL
}

# The hold, which since 0023 is DERIVED rather than a column. Kept as its own
# accessor so a call site reads the same either way and the arithmetic below is
# unchanged -- what changed is where the number comes from, not what it means.
outstanding() {
  psql -h 127.0.0.1 -p "$PORT" -U cdtest -d "$DB" -tAq <<SQL
SET ROLE computedriven_migrations;
SELECT app.storage_outstanding('$ORG');
SQL
}

# Reset the tenant's ledger between P checks. THIS USED TO SAY state='aborted',
# and under R69 that releases nothing -- abort is a declaration by our client,
# not evidence about R2. The only state that gives bytes back is `settled`, so
# a fixture that wants a clean ledger has to say so. P5 failed with
# CD-QUOTA-EXCEEDED before this was understood: the reset had stopped resetting
# and every later check inherited 1000 held bytes.
pledger() { # committed
  psql -h 127.0.0.1 -p "$PORT" -U cdtest -d "$DB" -tAq >/dev/null 2>&1 <<SQL
SET ROLE computedriven_migrations;
UPDATE cd.storage_reservations SET state='settled', settled_at=now()
 WHERE organization_id='$ORG' AND state <> 'settled';
UPDATE cd.storage_usage SET committed_bytes=$1 WHERE organization_id='$ORG';
SQL
}

# P1 -- the headline case. 20 requests for 100 bytes each against a 1000 byte
# limit, all launched at once. Exactly 10 may win. Not "about 10".
PIDS=(); for i in $(seq 1 20); do
  reserve 100 "burst-$i" "$PGROOT/res-$i" & PIDS+=($!)
done
wait "${PIDS[@]}"
WON=0; LOST=0; ODD=0
for i in $(seq 1 20); do
  if grep -qE '^[0-9a-f]{8}-' "$PGROOT/res-$i"; then WON=$((WON+1))
  elif grep -q 'CD-QUOTA-EXCEEDED' "$PGROOT/res-$i"; then LOST=$((LOST+1))
  else ODD=$((ODD+1)); fi
done
if [ "$WON" = 10 ] && [ "$LOST" = 10 ]; then
  ok "P1  20 simultaneous 100-byte requests against 1000: exactly 10 admitted, 10 refused"
else
  bad "P1  20 simultaneous 100-byte requests against 1000: exactly 10 admitted, 10 refused" \
      "admitted=$WON refused=$LOST other=$ODD"
fi

# P2 -- the invariant itself, which is the check that matters even if the counts
# above ever change. Oversubscription is committed+reserved > limit, full stop.
RES=$(outstanding); COM=$(usage committed_bytes)
if [ "$((COM + RES))" -le 1000 ]; then
  ok "P2  committed + reserved <= limit  ${D}(${COM} + ${RES} <= 1000)${Z}"
else
  bad "P2  committed + reserved <= limit" "OVERSUBSCRIBED: $COM + $RES > 1000"
fi

# P3 -- the exact CLOUD_V1.md example, at the boundary where only one can win.
# 900 already held, two simultaneous requests for 80. 900+80+80 = 1060.
pledger 900
reserve 80 "edge-a" "$PGROOT/edge-a" & EA=$!
reserve 80 "edge-b" "$PGROOT/edge-b" & EB=$!
wait $EA $EB
EWON=0
grep -qE '^[0-9a-f]{8}-' "$PGROOT/edge-a" && EWON=$((EWON+1))
grep -qE '^[0-9a-f]{8}-' "$PGROOT/edge-b" && EWON=$((EWON+1))
RES=$(outstanding)
if [ "$EWON" = 1 ] && [ "$((900 + RES))" -le 1000 ]; then
  ok "P3  900 used, two simultaneous 80s: exactly one admitted"
else
  bad "P3  900 used, two simultaneous 80s: exactly one admitted" \
      "admitted=$EWON reserved=$RES (900+$RES must be <= 1000)"
fi

# P4 -- REQUEST idempotence, not accounting idempotence.
#
# THE FIRST VERSION OF THIS CHECK PROVED THE WRONG PROPERTY, and it was the exact
# mistake round 6 had just finished fixing one table over. It asserted
#
#     distinct reservation ids <= 1   AND   reserved_bytes <= 50
#
# with a comment saying a duplicate-key error from a losing caller was fine. That
# is idempotent BOOKKEEPING with a non-idempotent API in front of it: the quota is
# charged once, and one of four retrying clients gets a 500.
#
#     "THE LOSER MAY ERROR" IS NOT IDEMPOTENCE.
#
# What a retrying client needs is four successes, one reservation, and no errors.
pledger 0
PIDS=(); for i in 1 2 3 4; do
  reserve 50 "one-key" "$PGROOT/idem-$i" & PIDS+=($!)
done
wait "${PIDS[@]}"
IDS=$(cat "$PGROOT/idem-"* | grep -E '^[0-9a-f]{8}-' | sort -u | wc -l)
OKS=0; ERRS=0
for i in 1 2 3 4; do
  if grep -qE '^[0-9a-f]{8}-' "$PGROOT/idem-$i"; then OKS=$((OKS+1)); fi
  if grep -qi 'ERROR' "$PGROOT/idem-$i"; then ERRS=$((ERRS+1)); fi
done
RES=$(outstanding)
if [ "$OKS" = 4 ] && [ "$ERRS" = 0 ] && [ "$IDS" = 1 ] && [ "$RES" = 50 ]; then
  ok "P4  four simultaneous retries: 4 successes, 1 reservation, 50 bytes, 0 errors"
else
  bad "P4  four simultaneous retries: 4 successes, 1 reservation, 50 bytes, 0 errors" \
      "successes=$OKS errors=$ERRS distinct-ids=$IDS reserved=$RES"
fi

# P5 -- an idempotency key names a REQUEST, not just a row. Reusing it with
# different bytes must refuse rather than hand back the original hold, or a
# client retrying with a corrected size believes it holds the new one.
reserve 999 "one-key" "$PGROOT/mismatch"
if grep -q 'CD-RESERVE-IDEMPOTENCY-MISMATCH' "$PGROOT/mismatch"; then
  ok "P5  reusing a key with different bytes is refused, not silently substituted"
else
  bad "P5  reusing a key with different bytes is refused, not silently substituted" \
      "$(head -2 "$PGROOT/mismatch")"
fi

PFAIL=$((FAIL - NFAIL))

# ---------------------------------------------------------------------------
# Q. concurrent upload-intent admission (R31 substrate / M2)
#
# THE SAME BUG ONE LAYER UP. 0017's offer_upload() reads the reservation, sums
# the bytes its intents have already spoken for, decides, and then inserts:
#
#     M1.5, before 0014:      read quota   -> decide -> write
#     M2 shape, in 0017:      sum offers   -> decide -> insert
#
# Nothing serializes the sum against the insert, so two offers for DIFFERENT
# object keys against one reservation both see the old sum and both win. The
# unique constraint on object_key cannot help: the keys differ, which is the
# whole point of a chunked upload.
#
#     reservation = 100
#     A: sum=0, 80 <= 100, INSERT 80      B: sum=0, 80 <= 100, INSERT 80
#                     -> 160 bytes of write authority against a 100 byte hold
#
# Group P learned this about money and group N about identity. This is the third
# time, and the fix is the one finalize_storage() and abort_storage() have used
# since 0014: LOCK THE RESERVATION ROW. offer_upload was the only function in the
# storage family that read that row without FOR UPDATE.
#
# Q1 is hand-stepped for the same reason N1 is -- a deterministic interleaving,
# not a race the test hopes to hit.
# ---------------------------------------------------------------------------
printf '\n%s== Q. concurrent upload intents (R31 / M2) ==%s\n' "$D" "$Z"

ORGQ=aaaaaaaa-0000-4000-8000-000000000002
WORLDQ=11111111-0000-4000-8000-00000000000b
PRINQ=cccccccc-0000-4000-8000-00000000000d
PFX="org/$ORGQ/world/$WORLDQ"

# Every Q check that can consume reservation bytes gets its OWN 100-byte
# reservation, so a failure in one is never read as failures in four.
newres() { # idempotency-key -> reservation uuid on stdout
  psql -h 127.0.0.1 -p "$PORT" -U cdtest -d "$DB" -tAq 2>&1 <<SQL | grep -E '^[0-9a-f]{8}-' | tail -1
BEGIN;
SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$ORGQ');
SELECT reservation_id FROM app.reserve_storage('$WORLDQ','$PRINQ',100,'$1');
COMMIT;
SQL
}

# A separate tenant from group P on purpose: P mutates its usage row in place,
# and a Q assertion that depended on P's leftovers would be measuring the order
# the file happens to be written in.
if ! qseed=$(psql -h 127.0.0.1 -p "$PORT" -U cdtest -d "$DB" -v ON_ERROR_STOP=1 -tAq 2>&1 <<SQL
SET ROLE computedriven_migrations;
INSERT INTO cd.organizations (id, slug, display_name) VALUES ('$ORGQ','org-q','Org Q');
INSERT INTO cd.worlds (id, organization_id, name) VALUES ('$WORLDQ','$ORGQ','workstation');
INSERT INTO cd.principals (id) VALUES ('$PRINQ');
INSERT INTO cd.organization_principals (organization_id, principal_id, app_role)
VALUES ('$ORGQ','$PRINQ','owner');
-- Deliberately far above the reservation. The question here is whether an
-- INTENT can overcommit its RESERVATION, not whether a reservation can
-- overcommit the entitlement -- group P already owns that one.
INSERT INTO cd.entitlements (organization_id, tier, byte_limit) VALUES ('$ORGQ','driver',100000);
SQL
); then
  bad "Q0  seed" "$qseed"; RESQ=
else
  RESQ=$(newres q-res)
  if [ -n "$RESQ" ]; then
    ok "Q0  reservation seeded: 100 bytes  ${D}${RESQ}${Z}"
  else
    bad "Q0  reservation seeded: 100 bytes" "no reservation id"
  fi
fi

offer() { # reservation, key-suffix, bytes, digest, outfile
  psql -h 127.0.0.1 -p "$PORT" -U cdtest -d "$DB" -tAq > "$5" 2>&1 <<SQL
BEGIN;
SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$ORGQ');
SELECT intent_id FROM app.offer_upload('$1','$PFX/$2',$3,'$4');
COMMIT;
SQL
}

# Sum of every intent that speaks for bytes against the reservation -- which is
# ALL of them, with no state predicate. R55: neither the clock nor a client
# abandon revokes a presigned URL already issued, so nothing but the reservation
# dying gives bytes back. A predicate here would be a second opinion about that.
spoken() {
  psql -h 127.0.0.1 -p "$PORT" -U cdtest -d "$DB" -tAq <<SQL
SET ROLE computedriven_migrations;
SELECT coalesce(sum(expected_bytes), 0) FROM cd.upload_intents
 WHERE reservation_id = '$RESQ';
SQL
}

# ---------------------------------------------------------------------------
# Q1 -- THE HEADLINE. Two different 80-byte chunks, one 100-byte reservation,
# hand-stepped so the second offer runs while the first is uncommitted.
# ---------------------------------------------------------------------------
#
# TWO COUNTING TRAPS, both of which scored a green line over a broken run before
# they were understood.
#
# 1. `SELECT 'ready'` is not decoration. app.set_organization_context() RETURNS
#    void, so psql -tAq emits a BLANK line for it and `grep -c .` does not count
#    it. Without an explicit sentinel every await here is off by one.
#
# 2. DO NOT TRUNCATE out1/out2 TO REUSE THEM. psql still holds those files open
#    at its own offset, so `: > file` does not rewind the writer -- it leaves a
#    HOLE, and a hole reads back as NUL bytes. grep then calls the file binary,
#    reports "binary file matches" instead of the matching line, and every
#    content assertion below quietly stops matching. Record a BASELINE and count
#    forward from it instead.
QB1=$(grep -ac . "$PGROOT/out1"); QB2=$(grep -ac . "$PGROOT/out2")
s1 "BEGIN; SET LOCAL ROLE computedriven_api; SELECT app.set_organization_context('$ORGQ'); SELECT 'ready';"
s2 "BEGIN; SET LOCAL ROLE computedriven_api; SELECT app.set_organization_context('$ORGQ'); SELECT 'ready';"
await "$PGROOT/out1" $((QB1 + 1)) 5; await "$PGROOT/out2" $((QB2 + 1)) 5

s1 "SELECT intent_id FROM app.offer_upload('$RESQ','$PFX/chunk/aaaa',80,'sha256:aaaa');"
if ! await "$PGROOT/out1" $((QB1 + 2)) 5; then
  bad "Q1a session 1 offers 80 of 100 inside an open transaction" "S1 never returned"
else
  case "$(since "$PGROOT/out1" "$QB1")" in
    *ERROR*) bad "Q1a session 1 offers 80 of 100 inside an open transaction" \
                 "$(since "$PGROOT/out1" "$QB1" | grep -i error | head -1)" ;;
    *) ok "Q1a session 1 offers 80 of 100 inside an open transaction" ;;
  esac
fi

# The whole question. S2 offers a DIFFERENT key while S1 is uncommitted. Under
# 0017 its SUM cannot see S1's row, so it succeeds and the reservation is
# oversubscribed. Under the fix it blocks on the reservation row.
s2 "SELECT intent_id FROM app.offer_upload('$RESQ','$PFX/chunk/bbbb',80,'sha256:bbbb');"
if await "$PGROOT/out2" $((QB2 + 2)) 3; then
  EARLY=$(since "$PGROOT/out2" "$QB2" | tail -1)
  bad "Q1b session 2 blocks while session 1 is uncommitted" "returned early: $EARLY"
else
  ok "Q1b session 2 blocks while session 1 is uncommitted"
fi

s1 "COMMIT;"
await "$PGROOT/out1" $((QB1 + 2)) 5

# After S1 commits, S2 must re-evaluate against 80 already spoken for and REFUSE.
if ! await "$PGROOT/out2" $((QB2 + 2)) 8; then
  bad "Q1c session 2 is refused once session 1 commits" "still blocked after 8s"
else
  case "$(since "$PGROOT/out2" "$QB2")" in
    *CD-OFFER-OVERCOMMIT*) ok "Q1c session 2 is refused once session 1 commits" ;;
    *) bad "Q1c session 2 is refused once session 1 commits" \
           "second 80 was ADMITTED against a 100-byte reservation" ;;
  esac
fi
s2 "COMMIT;"

SPOKEN=$(spoken)
if [ "${SPOKEN:-0}" -le 100 ]; then
  ok "Q1d reservation is not oversubscribed  ${D}(${SPOKEN} <= 100)${Z}"
else
  bad "Q1d reservation is not oversubscribed" "OVERSUBSCRIBED: $SPOKEN > 100"
fi

# ---------------------------------------------------------------------------
# Q2 -- concurrent REQUEST idempotence, the property P4 proves for reservations.
# Four callers, one chunk: four successes, one intent, zero errors.
#
# On its OWN reservation. The first draft ran Q2-Q5 against the reservation Q1
# had just filled, so every one of them failed with CD-OFFER-OVERCOMMIT and the
# battery reported five defects where there was one. A cascade is not evidence.
# ---------------------------------------------------------------------------
RESQ2=$(newres q-res-2)

# Q2a -- HAND-STEPPED, and it has to be.
#
# The unstructured version of this check (Q2b below) PASSED against the broken
# function on the first run, because four psql processes racing for one key
# usually do not actually overlap: three of them find the winner's committed row
# in the opening SELECT and take the replay path. The window is real and small,
# and a test that only fires when it happens to land inside it is a test that
# reports green over a defect.
#
#     A RACE YOU CANNOT STEP IS A RACE YOU CANNOT CLAIM TO HAVE CLOSED.
#
# Stepped, it is deterministic: S2 enters the same call while S1 is uncommitted,
# so its SELECT-by-key MUST miss, and what happens next is the whole property.
QC1=$(grep -ac . "$PGROOT/out1"); QC2=$(grep -ac . "$PGROOT/out2")
s1 "BEGIN; SET LOCAL ROLE computedriven_api; SELECT app.set_organization_context('$ORGQ'); SELECT 'ready';"
s2 "BEGIN; SET LOCAL ROLE computedriven_api; SELECT app.set_organization_context('$ORGQ'); SELECT 'ready';"
await "$PGROOT/out1" $((QC1 + 1)) 5; await "$PGROOT/out2" $((QC2 + 1)) 5

s1 "SELECT intent_id FROM app.offer_upload('$RESQ2','$PFX/chunk/cccc',10,'sha256:cccc');"
await "$PGROOT/out1" $((QC1 + 2)) 5
s2 "SELECT intent_id FROM app.offer_upload('$RESQ2','$PFX/chunk/cccc',10,'sha256:cccc');"

# THE ORDERING GATE, and it is load-bearing. Writing to S2's fifo does not mean
# S2 has executed; without this wait S1's COMMIT can land first, S2 then finds a
# COMMITTED row in its opening SELECT and takes the ordinary replay path, and the
# check passes having never constructed the race at all. It did exactly that.
# Under 0017 S2 blocks on the unique index; under 0019 it blocks on the
# reservation row -- this check cannot tell those apart, and Q2b is what does.
if await "$PGROOT/out2" $((QC2 + 2)) 3; then
  bad "Q2a session 2 blocks entering the same call" \
      "returned before session 1 committed: $(since "$PGROOT/out2" "$QC2" | tail -1)"
else
  ok "Q2a session 2 blocks entering the same call"
fi

s1 "COMMIT;"
await "$PGROOT/out1" $((QC1 + 2)) 5

if ! await "$PGROOT/out2" $((QC2 + 2)) 8; then
  bad "Q2b the blocked retry succeeds with the SAME intent, not a 500" "still blocked after 8s"
else
  A=$(since "$PGROOT/out1" "$QC1" | tail -1)
  B=$(since "$PGROOT/out2" "$QC2" | tail -1)
  case "$(since "$PGROOT/out2" "$QC2")" in
    *ERROR*|*duplicate\ key*|*upload_intents_key_uq*)
      bad "Q2b the blocked retry succeeds with the SAME intent, not a 500" \
          "$(since "$PGROOT/out2" "$QC2" | grep -ai 'ERROR' | head -1)" ;;
    *) if [ "$A" = "$B" ]; then
         ok "Q2b the blocked retry succeeds with the SAME intent, not a 500  ${D}${A}${Z}"
       else
         bad "Q2b the blocked retry succeeds with the SAME intent, not a 500" "s1=$A s2=$B"
       fi ;;
  esac
fi
s2 "COMMIT;"

# Q2c -- the unstructured form, kept because a client retry does not get to pick
# its interleaving either. It is a WEAKER check than Q2b and is labelled as one.
PIDS=(); for i in 1 2 3 4; do
  offer "$RESQ2" "chunk/cccc" 10 "sha256:cccc" "$PGROOT/q2-$i" & PIDS+=($!)
done
wait "${PIDS[@]}"
QOK=0; QERR=0
for i in 1 2 3 4; do
  grep -qE '^[0-9a-f]{8}-' "$PGROOT/q2-$i" && QOK=$((QOK+1))
  grep -qi 'ERROR'         "$PGROOT/q2-$i" && QERR=$((QERR+1))
done
QIDS=$(cat "$PGROOT/q2-"* | grep -E '^[0-9a-f]{8}-' | sort -u | wc -l)
QROWS=$(psql -h 127.0.0.1 -p "$PORT" -U cdtest -d "$DB" -tAq <<SQL
SET ROLE computedriven_migrations;
SELECT count(*) FROM cd.upload_intents WHERE object_key = '$PFX/chunk/cccc';
SQL
)
if [ "$QOK" = 4 ] && [ "$QERR" = 0 ] && [ "$QIDS" = 1 ] && [ "$QROWS" = 1 ]; then
  ok "Q2c four simultaneous identical offers: 4 successes, 1 intent, 0 errors"
else
  bad "Q2c four simultaneous identical offers: 4 successes, 1 intent, 0 errors" \
      "successes=$QOK errors=$QERR distinct-ids=$QIDS rows=$QROWS"
fi

# ---------------------------------------------------------------------------
# Q3/Q4/Q5 -- an object key is not an idempotency key on its own. The promise is
# {reservation, key, bytes, digest} and a replay that disagrees on ANY of them is
# a refusal, never a silent substitution. Same law as P5, one layer up.
# ---------------------------------------------------------------------------
offer "$RESQ2" "chunk/cccc" 11 "sha256:cccc" "$PGROOT/q3"
if grep -q 'CD-OFFER-MISMATCH' "$PGROOT/q3"; then
  ok "Q3  same key, different byte count: refused"
else
  bad "Q3  same key, different byte count: refused" "$(head -2 "$PGROOT/q3")"
fi

offer "$RESQ2" "chunk/cccc" 10 "sha256:dddd" "$PGROOT/q4"
if grep -q 'CD-OFFER-MISMATCH' "$PGROOT/q4"; then
  ok "Q4  same key, different digest: refused"
else
  bad "Q4  same key, different digest: refused" "$(head -2 "$PGROOT/q4")"
fi

# Q5 is the one 0017 got wrong in a way no single-reservation test could see: it
# returned the OLD intent's reservation_id to a caller asking about a NEW
# reservation, so write authority minted under a dead hold was handed to a live
# one.
RESQ3=$(newres q-res-3)
offer "$RESQ3" "chunk/cccc" 10 "sha256:cccc" "$PGROOT/q5"
if grep -q 'CD-OFFER-MISMATCH' "$PGROOT/q5"; then
  ok "Q5  same key, different reservation: refused"
else
  bad "Q5  same key, different reservation: refused" \
      "$(head -2 "$PGROOT/q5")  [an intent may not change reservation]"
fi

# ---------------------------------------------------------------------------
# Q6 -- the invariant itself, checked after everything above has run. This is the
# assertion that survives the individual counts changing.
# ---------------------------------------------------------------------------
WORST=$(psql -h 127.0.0.1 -p "$PORT" -U cdtest -d "$DB" -tAq <<SQL
SET ROLE computedriven_migrations;
SELECT coalesce(max(spoken - bytes), 0) FROM (
  SELECT r.id, r.bytes, coalesce(sum(i.expected_bytes), 0) AS spoken
    FROM cd.storage_reservations r
    LEFT JOIN cd.upload_intents i ON i.reservation_id = r.id
   GROUP BY r.id, r.bytes) t;
SQL
)
if [ "${WORST:-1}" -le 0 ]; then
  ok "Q6  no reservation has more bytes offered than it holds  ${D}(worst margin ${WORST})${Z}"
else
  bad "Q6  no reservation has more bytes offered than it holds" \
      "one reservation is over by $WORST bytes"
fi

QFAIL=$((FAIL - NFAIL - PFAIL))

# ---------------------------------------------------------------------------
# R. the provider observer vs the control plane (R54 / M2)
#
# GROUPS N, P AND Q ALL RACE ONE SUBSYSTEM AGAINST ITSELF. Two logins, two
# reservations, two offers. Every one of those races is between two callers of
# the same function, and the fix each time was to serialize that function.
#
# This group is the first one where the two sides are DIFFERENT SUBSYSTEMS, and
# it is the seam none of the others can see:
#
#     offer_upload / abandon_upload      an HTTP request, tenant-scoped, holds
#                                        the reservation row
#     observe_storage_object             a QUEUE CONSUMER, cross-tenant, no
#                                        tenant context, took NO lock at all
#
# So the reservation row was a serialization boundary that one of the two parties
# had never agreed to. The provider says "the object landed"; the request path
# then says "you may upload it".
#
#     PROVIDER-OBSERVED TRUTH IS MONOTONIC. `observed` IS A FACT ABOUT THE
#     WORLD, NOT A STAGE IN OUR WORKFLOW, AND NOTHING LOCAL MAY WALK IT BACK.
#
# Both races below are DETERMINISTIC, and each is deterministic for a different
# reason -- which is worth knowing, because the first draft of this group tried
# to step R1 the way R2 steps and could not.
#
#     R1  offer_upload's revive UPDATE carries NO state predicate, so it blocks
#         on the observer's uncommitted row lock and then overwrites whatever it
#         finds. The step is: observer first, uncommitted.
#     R2  abandon_upload reads the intent BEFORE it takes the reservation lock,
#         so its decision is made from a snapshot older than the lock it waits
#         for. The step is: hold the lock from a third session.
# ---------------------------------------------------------------------------
printf '\n%s== R. provider observer vs control plane (R54) ==%s\n' "$D" "$Z"

RESR=$(newres r-res)
RKEY="$PFX/chunk/rrrr"
observed_state() {
  psql -h 127.0.0.1 -p "$PORT" -U cdtest -d "$DB" -tAq <<SQL
SET ROLE computedriven_migrations;
SELECT state FROM cd.upload_intents WHERE object_key = '$1';
SQL
}

if [ -z "$RESR" ]; then
  bad "R0  reservation seeded" "no reservation id"
else
  offer "$RESR" "chunk/rrrr" 10 "sha256:rrrr" "$PGROOT/r0"
  if grep -qE '^[0-9a-f]{8}-' "$PGROOT/r0"; then
    ok "R0  an intent exists and is offered"
  else
    bad "R0  an intent exists and is offered" "$(head -2 "$PGROOT/r0")"
  fi
fi

# ---------------------------------------------------------------------------
# R1 -- observed must not become offered.
#
# S2 is the observer and goes FIRST, uncommitted. S1 then calls offer_upload:
# it takes the reservation lock (which the observer does not hold), reads the
# intent at the OLD committed state 'offered', decides this is a replay, and its
# UPDATE blocks on S2's row lock. When S2 commits, S1's UPDATE re-evaluates --
# except it has no state predicate to re-evaluate, so it simply overwrites.
# ---------------------------------------------------------------------------
RB1=$(grep -ac . "$PGROOT/out1"); RB2=$(grep -ac . "$PGROOT/out2")
s2 "BEGIN; SET LOCAL ROLE computedriven_jobs; SELECT intent_id IS NOT NULL FROM app.observe_storage_object('cd-worlds','$RKEY','etag-R1',10,'PutObject', now());"
await "$PGROOT/out2" $((RB2 + 1)) 5

s1 "BEGIN; SET LOCAL ROLE computedriven_api; SELECT app.set_organization_context('$ORGQ'); SELECT 'ready';"
await "$PGROOT/out1" $((RB1 + 1)) 5
s1 "SELECT disposition FROM app.offer_upload('$RESR','$RKEY',10,'sha256:rrrr');"

# It MUST block: the observer holds the intent's row lock uncommitted.
if await "$PGROOT/out1" $((RB1 + 2)) 3; then
  bad "R1a the replaying offer blocks on the observer's uncommitted row" \
      "returned early: $(since "$PGROOT/out1" "$RB1" | tail -1)"
else
  ok "R1a the replaying offer blocks on the observer's uncommitted row"
fi

s2 "COMMIT;"
await "$PGROOT/out2" $((RB2 + 1)) 5
await "$PGROOT/out1" $((RB1 + 2)) 8
s1 "COMMIT;"
await "$PGROOT/out1" $((RB1 + 2)) 5
sleep 0.3

ST=$(observed_state "$RKEY")
if [ "$ST" = "observed" ]; then
  ok "R1b the intent is still OBSERVED after the offer commits  ${D}(${ST})${Z}"
else
  bad "R1b the intent is still OBSERVED after the offer commits" \
      "provider truth was overwritten: state=$ST"
fi

DISP=$(since "$PGROOT/out1" "$RB1" | grep -E 'already_observed|replayed|fresh' | tail -1)
if [ "$DISP" = "already_observed" ]; then
  ok "R1c ...and the caller was told already_observed, not handed authority"
else
  bad "R1c ...and the caller was told already_observed, not handed authority" \
      "disposition=${DISP:-<none>} — write authority minted for an object R2 already holds"
fi

# ---------------------------------------------------------------------------
# R2 -- observed must not become client_abandoned.
#
# THE FIRST VERSION OF THIS CHECK DEADLOCKED THE BATTERY, and the reason is worth
# more than the check. It held the reservation row from a THIRD session so that
# abandon would block after its read, and then ran the observer -- which under
# 0021 needed no reservation lock and sailed past. Under 0022 the observer is
# INSIDE the lock protocol, so it queued behind the third session's lock, on a
# foreground psql with no timeout, forever.
#
#     A REPRODUCTION THAT DEPENDS ON THE BUG'S MECHANISM STOPS BEING A TEST THE
#     MOMENT THE BUG IS FIXED. It has to reproduce through something both
#     versions do.
#
# Both versions block on the INTENT row, so that is the gate: the observer goes
# first and uncommitted, exactly as in R1. Under 0019 abandon read the intent
# before waiting and its UPDATE carried no state guard, so it clobbered on wake.
# Under 0022 it re-reads after the lock and refuses.
# ---------------------------------------------------------------------------
RKEY2="$PFX/chunk/ssss"
offer "$RESR" "chunk/ssss" 10 "sha256:ssss" "$PGROOT/r2-offer"
RINTENT=$(grep -E '^[0-9a-f]{8}-' "$PGROOT/r2-offer" | tail -1)

RB1=$(grep -ac . "$PGROOT/out1"); RB2=$(grep -ac . "$PGROOT/out2")
s2 "BEGIN; SET LOCAL ROLE computedriven_jobs; SELECT intent_id IS NOT NULL FROM app.observe_storage_object('cd-worlds','$RKEY2','etag-R2',10,'PutObject', now(), 'msg-R2','$Q');"
await "$PGROOT/out2" $((RB2 + 1)) 5
MID=$(observed_state "$RKEY2")
if [ "$MID" = "offered" ]; then
  ok "R2a the observer holds the intent row, uncommitted  ${D}(committed state still ${MID})${Z}"
else
  bad "R2a the observer holds the intent row, uncommitted" "committed state=$MID"
fi

s1 "BEGIN; SET LOCAL ROLE computedriven_api; SELECT app.set_organization_context('$ORGQ'); SELECT 'ready';"
await "$PGROOT/out1" $((RB1 + 1)) 5
s1 "SELECT app.abandon_upload('$RINTENT');"
if await "$PGROOT/out1" $((RB1 + 2)) 3; then
  bad "R2b abandon blocks on the observer's uncommitted intent row" \
      "returned early: $(since "$PGROOT/out1" "$RB1" | tail -1)"
else
  ok "R2b abandon blocks on the observer's uncommitted intent row"
fi

s2 "COMMIT;"
await "$PGROOT/out2" $((RB2 + 1)) 5
await "$PGROOT/out1" $((RB1 + 2)) 8
s1 "COMMIT;"
sleep 0.3

ST=$(observed_state "$RKEY2")
if [ "$ST" = "observed" ]; then
  ok "R2c the intent is still OBSERVED after abandon unblocks  ${D}(${ST})${Z}"
else
  bad "R2c the intent is still OBSERVED after abandon unblocks" \
      "abandon decided from a snapshot older than the lock it waited for: state=$ST"
fi

if since "$PGROOT/out1" "$RB1" | grep -q 'CD-ABANDON-OBSERVED'; then
  ok "R2d ...and the caller was told so by name, not silently ignored"
else
  bad "R2d ...and the caller was told so by name, not silently ignored" \
      "$(since "$PGROOT/out1" "$RB1" | tail -2 | tr '\n' ' ')"
fi

# ---------------------------------------------------------------------------
# R3 -- the invariant behind both. Once the provider has said an object landed,
# no local transition may take it back, whatever order things arrive in.
# ---------------------------------------------------------------------------
WALKED=$(psql -h 127.0.0.1 -p "$PORT" -U cdtest -d "$DB" -tAq <<SQL
SET ROLE computedriven_migrations;
SELECT count(*) FROM cd.upload_intents i
 WHERE EXISTS (SELECT 1 FROM cd.storage_observations s WHERE s.intent_id = i.id)
   AND i.state <> 'observed';
SQL
)
if [ "${WALKED:-1}" = "0" ]; then
  ok "R3  no intent with a provider observation is in any other state"
else
  bad "R3  no intent with a provider observation is in any other state" \
      "$WALKED intent(s) were walked back after the provider spoke"
fi

RFAIL=$((FAIL - NFAIL - PFAIL - QFAIL))

printf '\n  %s%s passed%s   %s%s failed%s   %s(N %s, P %s, Q %s, R %s)%s\n' "$G" "$PASS" "$Z" \
  "$([ "$FAIL" -gt 0 ] && echo "$R" || echo "$D")" "$FAIL" "$Z" "$D" "$NFAIL" "$PFAIL" "$QFAIL" "$RFAIL" "$Z"

# The verdict is PER GROUP, not a bare failure count. Sabotaging the advisory
# lock must break N and leave P alone, and sabotaging the quota statement must
# break P and leave N alone -- a mode that breaks the OTHER group is measuring
# something, but not the thing it claims to.
if [ -n "${CD_SABOTAGE:-}" ]; then
  printf '\n  %scontrol verdict:%s ' "$D" "$Z"
  case "${CD_SABOTAGE}" in
    lock)    WANT=$NFAIL; QUIET=$((PFAIL + QFAIL + RFAIL)); WHAT="serialized identity";  OTHER="P+Q+R" ;;
    quota)   WANT=$PFAIL; QUIET=$((NFAIL + QFAIL + RFAIL)); WHAT="the atomic admission"; OTHER="N+Q+R" ;;
    offer)   WANT=$QFAIL; QUIET=$((NFAIL + PFAIL + RFAIL)); WHAT="the reservation lock"; OTHER="N+P+R" ;;
    observe) WANT=$RFAIL; QUIET=$((NFAIL + PFAIL + QFAIL)); WHAT="the intent lock protocol"; OTHER="N+P+Q" ;;
    *)       WANT=$FAIL;  QUIET=0;                          WHAT="the fix";              OTHER="-"     ;;
  esac
  if [ "$WANT" -gt 0 ] && [ "$QUIET" -eq 0 ]; then
    printf '%sCAUGHT%s  the battery breaks without %s (%s failures), and group %s is unaffected\n' \
      "$G" "$Z" "$WHAT" "$WANT" "$OTHER"
    exit 0
  fi
  if [ "$WANT" -eq 0 ]; then
    printf '%sMISSED%s  the battery passed WITHOUT %s -- it is measuring nothing\n' "$R" "$Z" "$WHAT"
  else
    printf '%sMISDIRECTED%s  group %s also failed (%s); the sabotage is not isolated\n' \
      "$R" "$Z" "$OTHER" "$QUIET"
  fi
  exit 1
fi
exit "$FAIL"
