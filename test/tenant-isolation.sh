#!/usr/bin/env bash
# Tenant-isolation battery — R14, and the cross-tenant gate from CLOUD_V1.md §6.1.
#
# Stands up a THROWAWAY PostgreSQL cluster, applies worker/migrations/ in order,
# and runs the negative battery against it. Touches no system Postgres instance
# and needs no superuser on one.
#
#   ./worker/test/tenant-isolation.sh              exit = number of failures
#   CD_SABOTAGE=1 ./worker/test/tenant-isolation.sh   exit 0 iff the battery BREAKS
#
# TWO MODES, AND THE EXIT CODE MEANS OPPOSITE THINGS IN EACH. Both are release
# gates and both should exit 0 in a healthy tree:
#
#   normal    0 failures. Any failure is a real defect.
#   sabotage  the fail-closed function is replaced with the naive one, so
#             failures are the point. It prints a "control verdict" and exits 0
#             when it CAUGHT the sabotage, 1 when it missed. A sabotage run
#             showing "0 failed" is the worst outcome available, not the best.
#
# Read the verdict line, not the pass/fail tally, when CD_SABOTAGE is set.
#
# The battery is deliberately mostly NEGATIVE. A happy-path suite here would pass
# against a schema with no RLS at all, which is the whole reason this file exists.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# Overridable so a regression proof can point at a migration set with the fixes
# removed -- see the note on D12-D17 and group G.
MIGRATIONS="${CD_MIGRATIONS:-$ROOT/worker/migrations}"

# TCP rather than a unix socket: the scratchpad path is long enough to risk the
# ~107-byte sockaddr_un limit, and a port is one less thing to debug.
PORT="${CD_PGPORT:-55432}"
PGROOT="${CD_PGROOT:-/tmp/cd-pgtest-$$}"
PGDATA="$PGROOT/data"
DB=computedriven

# CD_PGBIN points the battery at a specific PostgreSQL build.
#
# Hyperdrive documents known support for PostgreSQL 9.0-17.x, and R33 targets
# 17.x for v1. So THE TARGET VERSION IS THE DEFAULT when it is installed --
# /opt/pgsql-17/bin, which is where Arch's `postgresql-old-upgrade` puts it.
#
# This used to default to the system build (18.4 here) and leave L7 WARNing on
# every run. That was honest while no 17 existed on the box. Once one does,
# defaulting to a major the production transport does not claim would mean the
# gate command and the PUBLISHED number disagree about what was measured -- and
# the published one would be the optimistic half.
#
#   CD_PGBIN=/usr/bin ./worker/test/tenant-isolation.sh    force the system build
#
# Everything below goes through these variables, so the same battery runs
# unchanged against either, and the banner prints which one it got.
DEFAULT_PGBIN=/opt/pgsql-17/bin
PGBIN="${CD_PGBIN-}"
if [ -z "${CD_PGBIN+set}" ] && [ -x "$DEFAULT_PGBIN/initdb" ]; then
  PGBIN="$DEFAULT_PGBIN"
fi
if [ -n "$PGBIN" ] && [ ! -x "$PGBIN/initdb" ]; then
  printf 'CD_PGBIN=%s has no initdb\n' "$PGBIN"; exit 99
fi
INITDB="${PGBIN:+$PGBIN/}initdb"
PGCTL="${PGBIN:+$PGBIN/}pg_ctl"
PSQLBIN="${PGBIN:+$PGBIN/}psql"
CREATEDB="${PGBIN:+$PGBIN/}createdb"

# The authority channel every simulated delivery names (R77, 0026). One
# constant, because a battery that spells the queue differently in two places is
# asserting the tuple identity it is supposed to be testing.
Q=computedriven-r2-notifications

PASS=0; FAIL=0; WARN=0
if [ -t 1 ]; then G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; D=$'\033[2m'; Z=$'\033[0m'; else G=; R=; Y=; D=; Z=; fi

ok()  { PASS=$((PASS+1)); printf '  %sPASS%s  %s\n' "$G" "$Z" "$1"; }

# Accept-path witnesses. Finding 59 existed because every check that touched
# app.observe_storage_object() exercised a REFUSAL, and none ever called it with
# an organization that exists. A refusal proves a function can say no.
#
# A check that exercises a cross-tenant capability's ACCEPT path records itself
# here, and O0b at the bottom of this file fails if any named capability has no
# witness. Recorded by the check rather than declared in a list, because a list
# would be updated by the same hand that forgot the test.
ACCEPT_WITNESSES=""
witness() { ACCEPT_WITNESSES="$ACCEPT_WITNESSES $1"; }
bad() { FAIL=$((FAIL+1)); printf '  %sFAIL%s  %s\n' "$R" "$Z" "$1"
        [ -n "${2:-}" ] && printf '        %s%s%s\n' "$D" "$(printf '%s' "$2" | tr '\n' ' ' | cut -c1-160)" "$Z"; return 0; }

cleanup() {
  "$PGCTL" -D "$PGDATA" -m immediate stop >/dev/null 2>&1
  rm -rf "$PGROOT"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# cluster
# ---------------------------------------------------------------------------
printf '\n%s== cluster ==%s\n' "$D" "$Z"
mkdir -p "$PGDATA"
"$INITDB" -D "$PGDATA" -A trust -U cdtest --no-sync >/dev/null 2>&1 || { echo "initdb failed"; exit 99; }
"$PGCTL" -D "$PGDATA" -l "$PGROOT/pg.log" -w \
  -o "-p $PORT -c listen_addresses=127.0.0.1 -c unix_socket_directories='' -c fsync=off" \
  start >/dev/null 2>&1 || { echo "pg_ctl start failed"; tail -20 "$PGROOT/pg.log"; exit 99; }

PSQL=("$PSQLBIN" -h 127.0.0.1 -p "$PORT" -U cdtest -d "$DB" -v ON_ERROR_STOP=1 -tAq)
"$CREATEDB" -h 127.0.0.1 -p "$PORT" -U cdtest "$DB" || exit 99
printf '  postgres %s on 127.0.0.1:%s\n' "$("$PSQLBIN" -h 127.0.0.1 -p "$PORT" -U cdtest -d "$DB" -tAc 'show server_version')" "$PORT"

printf '\n%s== migrations ==%s\n' "$D" "$Z"
for f in "$MIGRATIONS"/*.sql; do
  if out=$("${PSQL[@]}" -f "$f" 2>&1); then
    printf '  %sok%s    %s\n' "$G" "$Z" "$(basename "$f")"
  else
    printf '  %sFAIL%s  %s\n%s\n' "$R" "$Z" "$(basename "$f")" "$out"; exit 98
  fi
done

# ---------------------------------------------------------------------------
# sabotage mode — the control that proves the battery is not vacuous
#
#   CD_SABOTAGE=1 ./worker/test/tenant-isolation.sh
#
# Swaps the fail-closed function for the naive form this whole design exists to
# refuse. A battery that still reports 0 failures under sabotage is measuring
# nothing, and the exit code would be lying.
# ---------------------------------------------------------------------------
# CD_SABOTAGE=verbs re-grants the mutating verbs 0011 revoked. Group I must then
# break -- otherwise the append-only claim is being asserted by nothing.
if [ "${CD_SABOTAGE:-}" = "columns" ]; then
  printf '\n  %sSABOTAGE MODE (columns)%s  re-granting table-wide UPDATE\n' "$R" "$Z"
  printf '  %sGroup J failures below are the EXPECTED result.%s\n' "$D" "$Z"
  "${PSQL[@]}" >/dev/null 2>&1 <<'SQL'
SET ROLE computedriven_migrations;
GRANT UPDATE ON cd.organization_principals, cd.organizations, cd.worlds TO computedriven_api;
SQL
elif [ "${CD_SABOTAGE:-}" = "verbs" ]; then
  printf '\n  %sSABOTAGE MODE (verbs)%s  re-granting UPDATE/DELETE on the append-only tables\n' "$R" "$Z"
  printf '  %sGroup I failures below are the EXPECTED result.%s\n' "$D" "$Z"
  "${PSQL[@]}" >/dev/null 2>&1 <<'SQL'
SET ROLE computedriven_migrations;
GRANT UPDATE, DELETE ON cd.world_versions, cd.audit_events, cd.worlds TO computedriven_api;
SQL
elif [ -n "${CD_SABOTAGE:-}" ]; then
  printf '\n  %sSABOTAGE MODE%s  installing the naive NULL-returning current_organization_id()\n' "$R" "$Z"
  printf '  %sFailures below are the EXPECTED result. This run is asking the battery\n' "$D"
  printf '  to break, and judges itself at the bottom -- read "control verdict",\n'
  printf '  not the pass/fail line.%s\n' "$Z"
  "${PSQL[@]}" >/dev/null 2>&1 <<'SQL'
SET ROLE computedriven_migrations;
CREATE OR REPLACE FUNCTION app.current_organization_id() RETURNS uuid
LANGUAGE sql STABLE AS $$ SELECT current_setting('app.organization_id', true)::uuid $$;
SQL
fi

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
# Both read SQL on stdin so a whole transaction can be handed over verbatim.
expect_ok() {   # desc, expected-last-line, [accept-witness-capability]
  local desc="$1" want="$2" cap="${3:-}" out rc
  out=$("${PSQL[@]}" 2>&1); rc=$?
  local got; got=$(printf '%s' "$out" | grep -v '^$' | tail -1)
  if [ $rc -ne 0 ]; then bad "$desc" "unexpected error: $out"
  elif [ "$got" = "$want" ]; then
    ok "$desc"
    # Recorded only on a PASS. A witness from a failing check would be a claim
    # that an accept path works, made by the run that just showed it does not.
    [ -n "$cap" ] && witness "$cap"
  else bad "$desc" "expected [$want] got [$got]"; fi
}
expect_err() {  # desc, marker
  local desc="$1" marker="$2" out rc
  out=$("${PSQL[@]}" 2>&1); rc=$?
  if [ $rc -eq 0 ]; then bad "$desc" "expected a refusal, statement SUCCEEDED: $out"
  elif printf '%s' "$out" | grep -qF "$marker"; then ok "$desc"
  else bad "$desc" "wrong error (wanted $marker): $out"; fi
}

# ---------------------------------------------------------------------------
# seed — as the owner, which is the only place RLS is legitimately not in play
# ---------------------------------------------------------------------------
if ! seed_out=$("${PSQL[@]}" 2>&1 <<'SQL'
SET ROLE computedriven_migrations;
INSERT INTO cd.organizations (id, slug, display_name) VALUES
  ('aaaaaaaa-0000-4000-8000-000000000001', 'org-a', 'Org A'),
  ('bbbbbbbb-0000-4000-8000-000000000002', 'org-b', 'Org B');
INSERT INTO cd.organization_identities (organization_id, provider, issuer, provider_org_id, provider_alias)
VALUES ('aaaaaaaa-0000-4000-8000-000000000001','keycloak','https://auth.computedriven.com/realms/cd','kc-org-a','Org A');
INSERT INTO cd.worlds (id, organization_id, name) VALUES
  ('11111111-0000-4000-8000-00000000000a', 'aaaaaaaa-0000-4000-8000-000000000001', 'workstation'),
  ('22222222-0000-4000-8000-00000000000b', 'bbbbbbbb-0000-4000-8000-000000000002', 'workstation');
INSERT INTO cd.world_versions (world_id, organization_id, manifest_root, byte_size, chunk_count) VALUES
  ('11111111-0000-4000-8000-00000000000a','aaaaaaaa-0000-4000-8000-000000000001','blake3:aaa',  107374182400, 25600),
  ('22222222-0000-4000-8000-00000000000b','bbbbbbbb-0000-4000-8000-000000000002','blake3:bbb', 2199023255552, 262144);
SQL
); then
  # A silently-failed seed makes every count-based check pass for the wrong
  # reason. It has to be fatal, not a warning.
  printf '\n%sSEED FAILED%s -- the battery would be measuring an empty database:\n%s\n' "$R" "$Z" "$seed_out"
  exit 97
fi

A=aaaaaaaa-0000-4000-8000-000000000001
B=bbbbbbbb-0000-4000-8000-000000000002

printf '\n%s== A. fail-closed tenant context (R14) ==%s\n' "$D" "$Z"

expect_err "A1  SELECT with no context RAISES (does not return [])" CD-TENANT-MISSING <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT count(*) FROM cd.worlds;
COMMIT;
SQL

expect_err "A2  INSERT with no context RAISES" CD-TENANT-MISSING <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
INSERT INTO cd.worlds (organization_id, name) VALUES ('$A', 'x');
COMMIT;
SQL

expect_err "A3  malformed context RAISES" CD-TENANT-MALFORMED <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT set_config('app.organization_id', 'not-a-uuid', true);
SELECT count(*) FROM cd.worlds;
COMMIT;
SQL

expect_err "A4  empty-string context RAISES" CD-TENANT-MISSING <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT set_config('app.organization_id', '', true);
SELECT count(*) FROM cd.worlds;
COMMIT;
SQL

expect_err "A5  NULL context is refused at the setter" CD-TENANT-NULL <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context(NULL);
COMMIT;
SQL

expect_ok "A6  valid context returns the uuid" "$A" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT app.current_organization_id();
COMMIT;
SQL

# A7/A8 pin the EXACT boundary of the R14 guarantee, because the first write-up
# of it overclaimed. A policy expression is evaluated per row, so a statement the
# planner can prove scans nothing never reaches the function and never raises.
#
# Measured, and narrower than expected -- an EMPTY TABLE still raises, because
# the scan is still planned. Only a constant-false qualifier removes it:
#
#     WHERE false        no raise, returns 0     <- the whole gap
#     empty table        RAISES
#     LIMIT 0            RAISES
#
# So the honest claim is "no row may pass without a valid tenant context", NOT
# "every statement touching a tenant table raises". A7 asserts the limitation on
# purpose so it cannot be quietly rediscovered later.

expect_ok "A7  KNOWN LIMIT: a constant-false qualifier never reaches the policy" "0" <<'SQL'
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT count(*) FROM cd.worlds WHERE false;
COMMIT;
SQL

expect_err "A8  an EMPTY tenant table still raises (the scan is planned)" CD-TENANT-MISSING <<'SQL'
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT count(*) FROM cd.audit_events;
COMMIT;
SQL

expect_err "A9  LIMIT 0 still raises" CD-TENANT-MISSING <<'SQL'
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT * FROM cd.worlds LIMIT 0;
COMMIT;
SQL

printf '\n%s== B. cross-tenant read/write ==%s\n' "$D" "$Z"

expect_ok "B1  org A sees its own world" "1" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT count(*) FROM cd.worlds WHERE organization_id = '$A';
COMMIT;
SQL

expect_ok "B2  org A cannot see org B's world" "0" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT count(*) FROM cd.worlds WHERE organization_id = '$B';
COMMIT;
SQL

expect_ok "B3  org A's unqualified SELECT * returns ONLY its own rows" "1" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT count(*) FROM cd.worlds;
COMMIT;
SQL

expect_err "B4  org A cannot INSERT a world owned by org B" "row-level security" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
INSERT INTO cd.worlds (organization_id, name) VALUES ('$B', 'stolen');
COMMIT;
SQL

expect_ok "B5  org A's UPDATE of org B's world affects 0 rows" "0" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
WITH u AS (UPDATE cd.worlds SET name='pwned' WHERE organization_id='$B' RETURNING 1)
SELECT count(*) FROM u;
COMMIT;
SQL

# Was "affects 0 rows". After 0011 the verb itself is gone, which is a stronger
# statement: the API role cannot DELETE a world of ANY tenant, its own included.
expect_err "B6  org A cannot DELETE a world at all — the verb is not granted" "permission denied" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
DELETE FROM cd.worlds WHERE organization_id='$B';
COMMIT;
SQL

expect_ok "B7  org A cannot read org B's world_versions" "0" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT count(*) FROM cd.world_versions WHERE manifest_root='blake3:bbb';
COMMIT;
SQL

expect_ok "B8  org B still has its world (A's writes really did nothing)" "1" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$B');
SELECT count(*) FROM cd.worlds WHERE name='workstation';
COMMIT;
SQL

printf '\n%s== C. connection reuse — the transaction-pooler concern ==%s\n' "$D" "$Z"
# Every block below is ONE psql session with SEVERAL transactions, which is what
# Hyperdrive/PgBouncer transaction pooling makes happen: consecutive requests can
# land on the same backend.

expect_err "C1  context does not survive COMMIT onto the next transaction" CD-TENANT-MISSING <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT count(*) FROM cd.worlds;
COMMIT;
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT count(*) FROM cd.worlds;
COMMIT;
SQL

expect_ok "C2  a re-used backend re-tenants cleanly (A then B sees only B)" "1" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT count(*) FROM cd.worlds;
COMMIT;
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$B');
SELECT count(*) FROM cd.worlds WHERE organization_id='$B';
COMMIT;
SQL

expect_ok "C3  the setting is genuinely empty after COMMIT" "" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
COMMIT;
SELECT coalesce(current_setting('app.organization_id', true), '');
SQL

expect_err "C4  a ROLLBACK also drops context" CD-TENANT-MISSING <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
ROLLBACK;
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT count(*) FROM cd.worlds;
COMMIT;
SQL

printf '\n%s== D. role and structure hardening ==%s\n' "$D" "$Z"

expect_ok "D1  computedriven_api has NOBYPASSRLS" "f" <<'SQL'
SELECT rolbypassrls FROM pg_roles WHERE rolname='computedriven_api';
SQL

expect_ok "D2  computedriven_api is not SUPERUSER" "f" <<'SQL'
SELECT rolsuper FROM pg_roles WHERE rolname='computedriven_api';
SQL

expect_ok "D3  computedriven_api owns none of the cd tables" "0" <<'SQL'
SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='cd' AND c.relkind='r' AND pg_get_userbyid(c.relowner)='computedriven_api';
SQL

# DERIVED, not counted. This check used to assert the literal 6 and 0014's three
# new tables broke it -- while every one of them DID have ENABLE+FORCE. The check
# was measuring the number of tables in the schema, which is not a security
# property, and it would have failed identically for a table added correctly and
# a table added wrong.
#
# The repository already has this law from the box-and-box law counts: derive the
# total, never hand-type it. Same mistake, different suite.
#
# A tenant table is one carrying an organization_id, plus cd.organizations
# itself. The assertion is that NONE of them lacks ENABLE+FORCE -- so a table
# added next year is covered by this check on the day it is created, and nobody
# has to remember to bump a number.
# The definition of "tenant table" that matters is REACHABLE tenant table. RLS is
# the control only where a request-path role holds a grant; where it holds none,
# the privilege split is the control and a policy would be decoration.
#
# The first derived draft of this check said "every table with an
# organization_id" and immediately produced `organization_identities` -- which
# has one and carries no RLS ON PURPOSE (0007: it is reachable only through the
# SECURITY DEFINER resolvers, and the API role has no grant on it at all). The
# hand-typed `= 6` had been silently excluding it without saying so. D4c below
# now PROVES the exclusion instead of assuming it, so the two checks together
# say: RLS everywhere it is the control, and no grant everywhere it is not.
expect_ok "D4  every REACHABLE tenant table is ENABLE+FORCE RLS (derived)" "" <<'SQL'
SELECT string_agg(c.relname, ', ' ORDER BY c.relname)
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'cd' AND c.relkind = 'r'
  AND (c.relname = 'organizations' OR EXISTS (
        SELECT 1 FROM pg_attribute a
         WHERE a.attrelid = c.oid AND a.attname = 'organization_id' AND a.attnum > 0))
  AND (has_table_privilege('computedriven_api',      n.nspname||'.'||c.relname, 'SELECT')
    OR has_table_privilege('computedriven_jobs',     n.nspname||'.'||c.relname, 'SELECT')
    OR has_table_privilege('computedriven_readonly', n.nspname||'.'||c.relname, 'SELECT'))
  AND NOT (c.relrowsecurity AND c.relforcerowsecurity);
SQL

expect_ok "D4b the count only ever goes up; 0014 took it from six to nine" "t" <<'SQL'
SELECT count(*) >= 9 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='cd' AND c.relrowsecurity AND c.relforcerowsecurity;
SQL

# The generalisation 0018 learned, checked from the catalogue rather than from a
# list. 0009 installed default-privilege rules for the two function-owning roles
# that existed then and said future functions were "covered ... rather than by
# anyone remembering". Default privileges are PER ROLE, so 0014's new ledger role
# arrived outside that promise and leaked one PUBLIC-executable function.
#
# Deriving the owner set means a fourth owning role fails this check on the day
# it is created, which is the only version of this that keeps working.
# D18 is EMPIRICAL, and the first version of it was not.
#
# It began as "every function-owning role has a pg_default_acl rule", which is
# what 0009 claims to have installed. Measured: pg_default_acl is EMPTY, because
# `ALTER DEFAULT PRIVILEGES ... REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC` stores no
# rule at all -- PUBLIC's EXECUTE comes from the built-in default, and there is no
# entry for a REVOKE to remove. Two rounds of that sentence reading like a
# guarantee, carried entirely by later migrations remembering to REVOKE by hand.
#
# So this check no longer asks whether the mechanism is CONFIGURED. It creates a
# function and asks whether PUBLIC can call it, which is the only question that
# was ever being claimed.
expect_ok "D18 a NEWLY created function is not PUBLIC-executable" "f" <<'SQL'
SET ROLE computedriven_migrations;
CREATE FUNCTION app.d18_canary() RETURNS int LANGUAGE sql AS 'SELECT 1';
RESET ROLE;
SELECT has_function_privilege('public','app.d18_canary()','EXECUTE');
SQL

expect_ok "D19 the canary is cleaned up, so a rerun measures the same thing" "0" <<'SQL'
DROP FUNCTION IF EXISTS app.d18_canary();
SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
WHERE n.nspname='app' AND p.proname='d18_canary';
SQL

expect_ok "D4c the tenant table WITHOUT RLS is unreachable by every request role" "f" <<'SQL'
SELECT bool_or(has_table_privilege(r, 'cd.organization_identities', 'SELECT'))
FROM unnest(ARRAY['computedriven_api','computedriven_jobs','computedriven_readonly']) r;
SQL

expect_ok "D5  api role has NO privilege on cd.principals" "f" <<'SQL'
SELECT has_table_privilege('computedriven_api','cd.principals','SELECT');
SQL

expect_ok "D6  api role has NO privilege on cd.principal_identities" "f" <<'SQL'
SELECT has_table_privilege('computedriven_api','cd.principal_identities','SELECT');
SQL

expect_ok "D7  api role has NO privilege on cd.organization_identities" "f" <<'SQL'
SELECT has_table_privilege('computedriven_api','cd.organization_identities','SELECT');
SQL

expect_ok "D8  readonly role cannot write a world" "f" <<'SQL'
SELECT has_table_privilege('computedriven_readonly','cd.worlds','INSERT');
SQL

expect_ok "D9  bootstrap role cannot write anywhere in cd" "0" <<'SQL'
SELECT count(*) FROM information_schema.table_privileges
WHERE grantee='computedriven_bootstrap' AND table_schema='cd'
  AND privilege_type IN ('INSERT','UPDATE','DELETE')
  AND table_name NOT IN ('principals','principal_identities');
SQL

expect_ok "D10 exactly two named cross-tenant exemptions exist" "2" <<'SQL'
SELECT count(*) FROM pg_policies
WHERE schemaname='cd' AND policyname LIKE '%_bootstrap';
SQL

expect_ok "D11 no role holds BYPASSRLS" "0" <<'SQL'
SELECT count(*) FROM pg_roles
WHERE rolname LIKE 'computedriven%' AND (rolbypassrls OR rolsuper);
SQL

# D12-D17 exist because the first pass of this battery asserted TABLE privileges
# and never once asked who could execute a FUNCTION. PostgreSQL grants EXECUTE to
# PUBLIC by default, so the explicit grant matrix in 0007 documented an intent the
# database was not enforcing, and computedriven_readonly could call a SECURITY
# DEFINER resolver and CREATE A PRINCIPAL. These fail against the pre-0009 schema.

expect_ok "D12 PUBLIC holds EXECUTE on nothing in app or cd" "0" <<'SQL'
SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
WHERE n.nspname IN ('app','cd') AND has_function_privilege('public', p.oid, 'EXECUTE');
SQL

expect_ok "D13 readonly cannot execute resolve_principal" "f" <<'SQL'
SELECT has_function_privilege('computedriven_readonly','app.resolve_principal(text,text,text)','EXECUTE');
SQL

expect_ok "D14 jobs cannot execute resolve_principal" "f" <<'SQL'
SELECT has_function_privilege('computedriven_jobs','app.resolve_principal(text,text,text)','EXECUTE');
SQL

expect_ok "D15 readonly CAN still set tenant context (intended matrix)" "t" <<'SQL'
SELECT has_function_privilege('computedriven_readonly','app.set_organization_context(uuid)','EXECUTE');
SQL

# The privilege bit and the actual call are different assertions. This is the one
# that reproduced the escalation: it SUCCEEDED before 0009 and minted a principal.
expect_err "D16 readonly CALLING a resolver is refused, not just unlisted" "permission denied" <<'SQL'
BEGIN; SET LOCAL ROLE computedriven_readonly;
SELECT app.resolve_principal('keycloak','https://iss.invalid','acl-escalation-probe');
COMMIT;
SQL

expect_ok "D17 no principal was created by the refused call" "0" <<'SQL'
SET ROLE computedriven_migrations;
SELECT count(*) FROM cd.principal_identities WHERE subject='acl-escalation-probe';
SQL

printf '\n%s== E. cross-tenant prevented structurally, not just by policy ==%s\n' "$D" "$Z"

expect_err "E1  a world_version whose org != its world's org is a FK violation" "violates foreign key" <<SQL
SET ROLE computedriven_migrations;
INSERT INTO cd.world_versions (world_id, organization_id, manifest_root, byte_size, chunk_count)
VALUES ('11111111-0000-4000-8000-00000000000a', '$B', 'blake3:xxx', 1, 1);
SQL

expect_err "E2  a wrl_head cannot be attached across tenants either" "violates foreign key" <<SQL
SET ROLE computedriven_migrations;
INSERT INTO cd.wrl_heads (world_id, organization_id, wrl_head)
VALUES ('11111111-0000-4000-8000-00000000000a', '$B', 'wrl:zzz');
SQL

expect_err "E3  there is no column named current_head anywhere (R11)" CD-R11 <<'SQL'
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_schema='cd' AND column_name='current_head') THEN
    RAISE EXCEPTION 'CD-R11-OK-unreachable';
  END IF;
  RAISE EXCEPTION 'CD-R11: no current_head column exists, as required';
END $$;
SQL

printf '\n%s== F. identity is a binding, not an id (R10) ==%s\n' "$D" "$Z"
ISS=https://auth.computedriven.com/realms/cd

expect_ok "F1  resolve_principal is idempotent for the same subject" "t" resolve_principal <<SQL
SELECT app.resolve_principal('keycloak','$ISS','sub-1')
     = app.resolve_principal('keycloak','$ISS','sub-1');
SQL

expect_ok "F2  a different subject is a different principal" "f" <<SQL
SELECT app.resolve_principal('keycloak','$ISS','sub-1')
     = app.resolve_principal('keycloak','$ISS','sub-2');
SQL

expect_err "F3  a second ACTIVE binding for one subject is refused" "principal_identities_active_uq" <<SQL
SET ROLE computedriven_migrations;
INSERT INTO cd.principal_identities (principal_id, provider, issuer, subject)
SELECT id, 'keycloak', '$ISS', 'sub-1' FROM cd.principals LIMIT 1;
SQL

# Separate statements, not one CTE: a data-modifying CTE runs against the same
# snapshot as its siblings, so the UPDATE would be invisible to the second
# resolve() and the test would measure nothing. That is how the first draft of
# this check returned an empty string instead of a verdict.
expect_ok "F4  after unbinding, the same subject rebinds to a NEW principal" "f" <<SQL
SET ROLE computedriven_migrations;
CREATE TEMP TABLE f4 AS SELECT app.resolve_principal('keycloak','$ISS','sub-3') AS p1;
UPDATE cd.principal_identities SET status='unbound', unbound_at=now()
 WHERE subject='sub-3' AND status='active';
SELECT (SELECT p1 FROM f4) = app.resolve_principal('keycloak','$ISS','sub-3');
SQL

expect_ok "F5  resolve_organization maps an IdP org to the internal id" "$A" resolve_organization <<SQL
SELECT app.resolve_organization('keycloak','$ISS','kc-org-a');
SQL

expect_err "F6  an unknown IdP organization is refused, not created" CD-ORG-UNBOUND <<SQL
SELECT app.resolve_organization('keycloak','$ISS','kc-org-nope');
SQL

expect_ok "F7  membership is false for a principal that has none" "f" <<SQL
SELECT app.authorize_membership(app.resolve_principal('keycloak','$ISS','sub-9'), '$A');
SQL

expect_ok "F8  resolve_organization did not invent an organization" "2" <<'SQL'
SET ROLE computedriven_migrations;
SELECT count(*) FROM cd.organizations;
SQL

printf '\n%s== G. status is enforced, not decorative ==%s\n' "$D" "$Z"
# 0003 advertises active/suspended/closed. Until 0008 none of it meant anything:
# a suspended principal resolved fine and authorize_membership returned true. A
# schema that names a state with no semantic consequence is worse than one that
# does not name it, because it reads as a control that is not there.

expect_err "G1  a SUSPENDED principal is refused by name" CD-PRINCIPAL-SUSPENDED <<SQL
SET ROLE computedriven_migrations;
CREATE TEMP TABLE g1 AS SELECT app.resolve_principal('keycloak','$ISS','susp-sub') AS p;
UPDATE cd.principals SET status='suspended' WHERE id=(SELECT p FROM g1);
SELECT app.resolve_principal('keycloak','$ISS','susp-sub');
SQL

expect_err "G2  a CLOSED principal is refused by name" CD-PRINCIPAL-CLOSED <<SQL
SET ROLE computedriven_migrations;
CREATE TEMP TABLE g2 AS SELECT app.resolve_principal('keycloak','$ISS','closed-sub') AS p;
UPDATE cd.principals SET status='closed' WHERE id=(SELECT p FROM g2);
SELECT app.resolve_principal('keycloak','$ISS','closed-sub');
SQL

expect_ok "G3  all three active -> membership authorizes" "t" <<SQL
SET ROLE computedriven_migrations;
CREATE TEMP TABLE g3 AS SELECT app.resolve_principal('keycloak','$ISS','member-sub') AS p;
INSERT INTO cd.organization_principals (organization_id, principal_id)
SELECT '$A', p FROM g3 ON CONFLICT DO NOTHING;
SELECT app.authorize_membership((SELECT p FROM g3), '$A');
SQL

expect_ok "G4  a SUSPENDED principal is not authorized despite active membership" "f" <<SQL
SET ROLE computedriven_migrations;
CREATE TEMP TABLE g4 AS SELECT app.resolve_principal('keycloak','$ISS','susp-member') AS p;
INSERT INTO cd.organization_principals (organization_id, principal_id)
SELECT '$A', p FROM g4 ON CONFLICT DO NOTHING;
UPDATE cd.principals SET status='suspended' WHERE id=(SELECT p FROM g4);
SELECT app.authorize_membership((SELECT p FROM g4), '$A');
SQL

expect_ok "G5  a SUSPENDED organization authorizes nobody" "f" <<SQL
SET ROLE computedriven_migrations;
INSERT INTO cd.organizations (id, slug, display_name, status)
VALUES ('cccccccc-0000-4000-8000-000000000003','org-c','Org C','suspended')
ON CONFLICT DO NOTHING;
CREATE TEMP TABLE g5 AS SELECT app.resolve_principal('keycloak','$ISS','org-susp-member') AS p;
INSERT INTO cd.organization_principals (organization_id, principal_id)
SELECT 'cccccccc-0000-4000-8000-000000000003', p FROM g5 ON CONFLICT DO NOTHING;
SELECT app.authorize_membership((SELECT p FROM g5), 'cccccccc-0000-4000-8000-000000000003');
SQL

expect_ok "G6  a revoked MEMBERSHIP is not authorized either" "f" <<SQL
SET ROLE computedriven_migrations;
CREATE TEMP TABLE g6 AS SELECT app.resolve_principal('keycloak','$ISS','revoked-member') AS p;
INSERT INTO cd.organization_principals (organization_id, principal_id, status)
SELECT '$A', p, 'revoked' FROM g6 ON CONFLICT DO NOTHING;
SELECT app.authorize_membership((SELECT p FROM g6), '$A');
SQL

printf '\n%s== H. the authorization answer carries a role (0010) ==%s\n' "$D" "$Z"
# authorize_membership() reduced owner/admin/member/viewer to one boolean, and
# the Worker then took the requested R2 permission from the request body. A
# viewer could ask for -- and be scoped for -- writes. membership_role() is the
# finer answer; H6 is the one that matters most, because two functions that
# disagree about who is a member would be worse than either being wrong alone.

expect_ok "H1  an active member's role comes back" "member" <<SQL
SET ROLE computedriven_migrations;
CREATE TEMP TABLE h1 AS SELECT app.resolve_principal('keycloak','$ISS','role-member') AS p;
INSERT INTO cd.organization_principals (organization_id, principal_id, app_role)
SELECT '$A', p, 'member' FROM h1 ON CONFLICT DO NOTHING;
SELECT app.membership_role((SELECT p FROM h1), '$A');
SQL

expect_ok "H2  a viewer is reported as a viewer, not flattened to true" "viewer" <<SQL
SET ROLE computedriven_migrations;
CREATE TEMP TABLE h2 AS SELECT app.resolve_principal('keycloak','$ISS','role-viewer') AS p;
INSERT INTO cd.organization_principals (organization_id, principal_id, app_role)
SELECT '$A', p, 'viewer' FROM h2 ON CONFLICT DO NOTHING;
SELECT app.membership_role((SELECT p FROM h2), '$A');
SQL

expect_ok "H3  a SUSPENDED principal has no role" "" <<SQL
SET ROLE computedriven_migrations;
CREATE TEMP TABLE h3 AS SELECT app.resolve_principal('keycloak','$ISS','role-susp') AS p;
INSERT INTO cd.organization_principals (organization_id, principal_id, app_role)
SELECT '$A', p, 'owner' FROM h3 ON CONFLICT DO NOTHING;
UPDATE cd.principals SET status='suspended' WHERE id=(SELECT p FROM h3);
SELECT coalesce(app.membership_role((SELECT p FROM h3), '$A'), '');
SQL

expect_ok "H4  a REVOKED membership has no role" "" <<SQL
SET ROLE computedriven_migrations;
CREATE TEMP TABLE h4 AS SELECT app.resolve_principal('keycloak','$ISS','role-revoked') AS p;
INSERT INTO cd.organization_principals (organization_id, principal_id, app_role, status)
SELECT '$A', p, 'owner', 'revoked' FROM h4 ON CONFLICT DO NOTHING;
SELECT coalesce(app.membership_role((SELECT p FROM h4), '$A'), '');
SQL

expect_ok "H5  a non-member has no role" "" <<SQL
SET ROLE computedriven_migrations;
SELECT coalesce(app.membership_role(
  app.resolve_principal('keycloak','$ISS','role-stranger'), '$A'), '');
SQL

expect_ok "H6  membership_role and authorize_membership NEVER disagree" "0" <<SQL
SET ROLE computedriven_migrations;
SELECT count(*) FROM cd.organization_principals op
WHERE (app.membership_role(op.principal_id, op.organization_id) IS NOT NULL)
   <> app.authorize_membership(op.principal_id, op.organization_id);
SQL

expect_ok "H7  PUBLIC cannot execute membership_role" "f" <<'SQL'
SELECT has_function_privilege('public','app.membership_role(uuid,uuid)','EXECUTE');
SQL

expect_ok "H8  readonly cannot execute membership_role" "f" <<'SQL'
SELECT has_function_privilege('computedriven_readonly','app.membership_role(uuid,uuid)','EXECUTE');
SQL

printf '\n%s== I. history is append-only at the authority layer (0011) ==%s\n' "$D" "$Z"
# RLS answers WHOSE row. This group answers WHAT MAY HAPPEN to it. 0004 called
# world_versions immutable while 0007 granted the API role UPDATE and DELETE on
# it, so "history cannot be rewritten" was enforced by nothing. Each refusal is
# proven by ATTEMPTING it and then witnessing the row survived -- a privilege bit
# is not evidence that the data is still there.

expect_ok "I1  api holds no UPDATE on world_versions" "f" <<'SQL'
SELECT has_table_privilege('computedriven_api','cd.world_versions','UPDATE');
SQL

expect_err "I2  rewriting a manifest_root is refused" "permission denied" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
UPDATE cd.world_versions SET manifest_root='blake3:FORGED' WHERE organization_id='$A';
COMMIT;
SQL

expect_ok "I3  ...and the original manifest_root is still there" "blake3:aaa" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT manifest_root FROM cd.world_versions WHERE organization_id='$A';
COMMIT;
SQL

expect_err "I4  deleting a world version is refused" "permission denied" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
DELETE FROM cd.world_versions WHERE organization_id='$A';
COMMIT;
SQL

expect_ok "I5  ...and the version is still there" "1" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT count(*) FROM cd.world_versions;
COMMIT;
SQL

expect_ok "I6  a NEW version can still be appended (append-only is append-ABLE)" "2" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
INSERT INTO cd.world_versions (world_id, organization_id, manifest_root, byte_size, chunk_count)
VALUES ('11111111-0000-4000-8000-00000000000a','$A','blake3:next', 107374182401, 25601);
SELECT count(*) FROM cd.world_versions;
COMMIT;
SQL

expect_err "I7  an audit event cannot be edited by the role that wrote it" "permission denied" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
UPDATE cd.audit_events SET outcome='ok' WHERE organization_id='$A';
COMMIT;
SQL

expect_err "I8  nor deleted" "permission denied" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
DELETE FROM cd.audit_events WHERE organization_id='$A';
COMMIT;
SQL

expect_ok "I9  NO role holds DELETE anywhere in cd" "0" <<'SQL'
SELECT count(*) FROM unnest(ARRAY['computedriven_api','computedriven_jobs','computedriven_readonly']) r,
     pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='cd' AND c.relkind='r' AND has_table_privilege(r, c.oid, 'DELETE');
SQL

# Asked has_table_privilege() until 0012 introduced COLUMN grants -- at which
# point table-level UPDATE correctly became false and this check started failing
# while the capability it describes was intact. The question, not the answer, was
# out of date. J11 proves the capability by actually moving a head.
expect_ok "I10 a wrl_head is still mutable — it is a pointer, not a record" "t" <<'SQL'
SELECT has_column_privilege('computedriven_api','cd.wrl_heads','wrl_head','UPDATE');
SQL

expect_ok "I11 the API cannot enrol itself into an organization" "f" <<'SQL'
SELECT has_table_privilege('computedriven_api','cd.organization_principals','INSERT');
SQL

printf '\n%s== J. which FACTS an operation may change (0012) ==%s\n' "$D" "$Z"
# Measured before the fix: the API role promoted a viewer to owner and revived a
# revoked membership, because 0011 granted table-level UPDATE while its own
# comment said "may only record last-seen". Every refusal below is proven by
# ATTEMPTING the write and witnessing the value did not move.

"${PSQL[@]}" >/dev/null 2>&1 <<SQL
SET ROLE computedriven_migrations;
INSERT INTO cd.principals (id) VALUES ('77777777-0000-4000-8000-00000000000e')
  ON CONFLICT DO NOTHING;
INSERT INTO cd.organization_principals (organization_id, principal_id, app_role)
VALUES ('$A','77777777-0000-4000-8000-00000000000e','viewer') ON CONFLICT DO NOTHING;
SQL

expect_ok "J1  api holds no UPDATE on app_role" "f" <<'SQL'
SELECT has_column_privilege('computedriven_api','cd.organization_principals','app_role','UPDATE');
SQL

expect_err "J2  a viewer cannot promote itself to owner" "permission denied" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
UPDATE cd.organization_principals SET app_role='owner'
 WHERE principal_id='77777777-0000-4000-8000-00000000000e';
COMMIT;
SQL

expect_ok "J3  ...and the role is still viewer" "viewer" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT app_role FROM cd.organization_principals
 WHERE principal_id='77777777-0000-4000-8000-00000000000e';
COMMIT;
SQL

expect_err "J4  a revoked membership cannot revive itself" "permission denied" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
UPDATE cd.organization_principals SET status='active';
COMMIT;
SQL

expect_err "J5  a membership row cannot be reassigned to another principal" "permission denied" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
UPDATE cd.organization_principals SET principal_id='88888888-0000-4000-8000-00000000000e';
COMMIT;
SQL

expect_err "J6  a world cannot be moved to another tenant by UPDATE" "permission denied" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
UPDATE cd.worlds SET organization_id='$B' WHERE organization_id='$A';
COMMIT;
SQL

expect_err "J7  an organization cannot un-suspend itself" "permission denied" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
UPDATE cd.organizations SET status='active' WHERE id='$A';
COMMIT;
SQL

expect_err "J8  a world's id is not a mutable fact" "permission denied" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
UPDATE cd.worlds SET id='99999999-0000-4000-8000-00000000000c' WHERE organization_id='$A';
COMMIT;
SQL

# The other half: a matrix that also breaks the product is not a win.
expect_ok "J9  the API CAN still record last_seen_at" "1" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
WITH u AS (UPDATE cd.organization_principals SET last_seen_at=now()
           WHERE principal_id='77777777-0000-4000-8000-00000000000e' RETURNING 1)
SELECT count(*) FROM u;
COMMIT;
SQL

expect_ok "J10 the API CAN still archive a world" "archived" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
UPDATE cd.worlds SET status='archived' WHERE id='11111111-0000-4000-8000-00000000000a';
SELECT status FROM cd.worlds WHERE id='11111111-0000-4000-8000-00000000000a';
COMMIT;
SQL

expect_ok "J11 the API CAN still move a WRL head" "wrl:moved" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
INSERT INTO cd.wrl_heads (world_id, organization_id, wrl_head)
VALUES ('11111111-0000-4000-8000-00000000000a','$A','wrl:first')
ON CONFLICT (world_id) DO NOTHING;
UPDATE cd.wrl_heads SET wrl_head='wrl:moved' WHERE organization_id='$A';
SELECT wrl_head FROM cd.wrl_heads WHERE organization_id='$A';
COMMIT;
SQL

# ---------------------------------------------------------------------------
# K. storage admission — the state machine and its refusals (R24 / M1.5)
#
# The CONCURRENT property lives in concurrency.sh, because a single psql session
# cannot express it. This group is everything else: entitlement, the four
# reservation states, idempotence, and the privilege split that stops the API
# role from simply editing the ledger.
#
# Its own fixtures. Group J archived world A's world on its way past, and a
# battery whose later groups depend on the side effects of earlier ones is a
# battery that reorders into nonsense.
# ---------------------------------------------------------------------------
printf '\n%s== K. storage admission (R24 / M1.5) ==%s\n' "$D" "$Z"

KW=44444444-0000-4000-8000-000000000044
KARCH=55555555-0000-4000-8000-000000000055
KP=66666666-0000-4000-8000-000000000066
KV=77777777-0000-4000-8000-000000000077
KS=88888888-0000-4000-8000-000000000088

if ! kseed=$("${PSQL[@]}" 2>&1 <<SQL
SET ROLE computedriven_migrations;
INSERT INTO cd.worlds (id, organization_id, name, status) VALUES
  ('$KW','$A','k-world','active'),
  ('$KARCH','$A','k-archived','archived');
INSERT INTO cd.principals (id) VALUES ('$KP'), ('$KV'), ('$KS');
INSERT INTO cd.organization_principals (organization_id, principal_id, app_role) VALUES
  ('$A','$KP','member'),
  ('$A','$KV','viewer');
SQL
); then
  printf '\n%sK SEED FAILED%s\n%s\n' "$R" "$Z" "$kseed"
fi

# K1 first, BEFORE any entitlement exists. "No entitlement" and "over quota" are
# different operator problems and the schema must not flatten them into one.
expect_err "K1  no entitlement is a refusal, not a zero quota" CD-RESERVE-NOENTITLEMENT <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT reservation_id FROM app.reserve_storage('$KW','$KP',100,'k1');
COMMIT;
SQL

"${PSQL[@]}" >/dev/null 2>&1 <<SQL
SET ROLE computedriven_migrations;
INSERT INTO cd.entitlements (organization_id, tier, byte_limit) VALUES ('$A','driver',1000);
SQL

expect_ok "K2  an entitled member reserves, and the ledger moves" "100" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT reserved_bytes FROM app.reserve_storage('$KW','$KP',100,'k2');
COMMIT;
SQL

# The replay must return the SAME reservation and must NOT hold another 100.
# Both halves matter: the id proves it is the same claim, the ledger proves it
# was not charged twice.
expect_ok "K3  replaying an idempotency key returns the same reservation, uncharged" "true|100" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT replayed || '|' || reserved_bytes FROM app.reserve_storage('$KW','$KP',100,'k2');
COMMIT;
SQL

expect_err "K4  a viewer may not cause bytes to be billed" CD-RESERVE-ROLE <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT reservation_id FROM app.reserve_storage('$KW','$KV',10,'k4');
COMMIT;
SQL

expect_err "K5  a stranger with no membership may not reserve" CD-RESERVE-NOTMEMBER <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT reservation_id FROM app.reserve_storage('$KW','$KS',10,'k5');
COMMIT;
SQL

# Org B's world, from inside org A's context. The refusal is CD-RESERVE-WORLD --
# "no such world" -- and that wording is deliberate: a cross-tenant probe learns
# that it cannot see the world, not that the world exists somewhere else.
expect_err "K6  another tenant's world is not reservable" CD-RESERVE-WORLD <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT reservation_id FROM app.reserve_storage('22222222-0000-4000-8000-00000000000b','$KP',10,'k6');
COMMIT;
SQL

expect_err "K7  an archived world accepts no new bytes" CD-RESERVE-WORLDSTATUS <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT reservation_id FROM app.reserve_storage('$KARCH','$KP',10,'k7');
COMMIT;
SQL

expect_err "K8  a request past the limit is refused" CD-QUOTA-EXCEEDED <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT reservation_id FROM app.reserve_storage('$KW','$KP',5000,'k8');
COMMIT;
SQL

# THE ONE WITH NO ORGANIZATION ARGUMENT. There is no way to spell "reserve
# against org B" from here, which is the design; without context the function
# raises before it can do anything at all.
expect_err "K9  reserving without tenant context RAISES" CD-TENANT-MISSING <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT reservation_id FROM app.reserve_storage('$KW','$KP',10,'k9');
COMMIT;
SQL

# R68. THIS CHECK USED TO ASSERT THE OPPOSITE and was green for six rounds:
# "finalize moves reserved bytes to committed, exactly", expecting 100|0.
# finalize_storage() was the only writer of a column documented as "bytes
# actually in R2", and the client chooses its argument. Under R68 a client
# assertion moves nothing: R2 has said nothing about this reservation, so
# occupancy stays 0 and the hold stays up.
expect_ok "K10 finalize moves NO bytes -- a client is not the provider (R68)" "0|100" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT committed_bytes || '|' || reserved_bytes FROM app.finalize_storage(
  (SELECT id FROM cd.storage_reservations WHERE idempotency_key='k2'), 100);
COMMIT;
SQL

# ...and what the client said is still recorded, because it is the thing
# storage_divergence() compares against. Refusing to bill on it is not the same
# as throwing it away.
expect_ok "K10b the assertion is recorded, as an assertion" "100" <<SQL
SET ROLE computedriven_migrations;
SELECT asserted_bytes FROM cd.storage_reservations WHERE idempotency_key='k2';
SQL

expect_ok "K11 finalizing twice with the same count is idempotent" "true|0|100" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT replayed || '|' || committed_bytes || '|' || reserved_bytes FROM app.finalize_storage(
  (SELECT id FROM cd.storage_reservations WHERE idempotency_key='k2'), 100);
COMMIT;
SQL

expect_err "K12 finalizing twice with DIFFERENT counts commits neither" CD-FINALIZE-CONFLICT <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT committed_bytes FROM app.finalize_storage(
  (SELECT id FROM cd.storage_reservations WHERE idempotency_key='k2'), 7);
COMMIT;
SQL

expect_err "K13 a finalized reservation cannot be aborted back" CD-ABORT-FINALIZED <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT reservation_id FROM app.abort_storage(
  (SELECT id FROM cd.storage_reservations WHERE idempotency_key='k2'));
COMMIT;
SQL

expect_err "K14 writing more bytes than were reserved is refused" CD-FINALIZE-OVERRUN <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT reservation_id FROM app.reserve_storage('$KW','$KP',10,'k14');
SELECT committed_bytes FROM app.finalize_storage(
  (SELECT id FROM cd.storage_reservations WHERE idempotency_key='k14'), 900);
COMMIT;
SQL

# FINDING 71, and this check used to assert the defect: "abort releases the
# hold", expecting 0. abort_storage() is a row in OUR database and every
# presigned URL minted under the reservation authorizes its holder until it
# expires -- R55 exactly, one level up, ruled as a general principle in 0022 and
# applied at one call site.
#
# Stated as a DELTA rather than an absolute so it measures the property instead
# of the fixture's accumulated total: abort changes nothing.
expect_ok "K15 abort releases NOTHING (R69; finding 71)" "same" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT reservation_id FROM app.reserve_storage('$KW','$KP',50,'k15');
CREATE TEMP TABLE k15 AS SELECT (SELECT outstanding_bytes FROM app.storage_ledger()) AS before;
SELECT reservation_id FROM app.abort_storage(
  (SELECT id FROM cd.storage_reservations WHERE idempotency_key='k15'));
SELECT CASE WHEN (SELECT outstanding_bytes FROM app.storage_ledger()) = (SELECT before FROM k15)
            THEN 'same' ELSE 'released ' ||
            ((SELECT before FROM k15) - (SELECT outstanding_bytes FROM app.storage_ledger()))::text END;
COMMIT;
SQL

expect_ok "K16 aborting twice is idempotent and still releases nothing" "true|same" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
CREATE TEMP TABLE k16 AS SELECT (SELECT outstanding_bytes FROM app.storage_ledger()) AS before;
SELECT replayed FROM app.abort_storage(
  (SELECT id FROM cd.storage_reservations WHERE idempotency_key='k15'));
SELECT (SELECT replayed FROM app.abort_storage(
          (SELECT id FROM cd.storage_reservations WHERE idempotency_key='k15')))::text
       || '|' || CASE WHEN (SELECT outstanding_bytes FROM app.storage_ledger()) = (SELECT before FROM k16)
                      THEN 'same' ELSE 'released' END;
COMMIT;
SQL

# The sweep still transitions exactly once -- that property was real and is
# kept. What it no longer does is RELEASE, which is the next check.
expect_ok "K17 the sweep transitions an expired reservation exactly once" "1|0" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT reservation_id FROM app.reserve_storage('$KW','$KP',200,'k17');
COMMIT;
SET ROLE computedriven_migrations;
UPDATE cd.storage_reservations SET expires_at = now() - interval '1 minute'
 WHERE idempotency_key='k17';
SELECT app.expire_storage_reservations('$A') || '|' ||
       (SELECT app.expire_storage_reservations('$A'));
SQL

expect_err "K18 an expired reservation cannot finalize" CD-FINALIZE-STATE <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT committed_bytes FROM app.finalize_storage(
  (SELECT id FROM cd.storage_reservations WHERE idempotency_key='k17'), 200);
COMMIT;
SQL

# The privilege split. Round 5's law: the restriction must be a privilege, not a
# sentence. There is no UPDATE grant on the ledger to revoke a column of.
expect_err "K19 the API role cannot edit the byte ledger directly" "permission denied" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
UPDATE cd.storage_usage SET committed_bytes = 0;
COMMIT;
SQL

expect_err "K20 the API role cannot grant itself an entitlement" "permission denied" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
INSERT INTO cd.entitlements (organization_id, tier, byte_limit) VALUES ('$A','factory',99999999);
COMMIT;
SQL

expect_err "K21 the API role cannot raise its own limit" "permission denied" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
UPDATE cd.entitlements SET byte_limit = 99999999 WHERE organization_id='$A';
COMMIT;
SQL

expect_ok "K22 readonly cannot execute reserve_storage" "f" <<'SQL'
SELECT has_function_privilege('computedriven_readonly',
  'app.reserve_storage(uuid,uuid,bigint,text,interval)','EXECUTE');
SQL

expect_ok "K23 PUBLIC cannot execute reserve_storage" "f" <<'SQL'
SELECT has_function_privilege('public',
  'app.reserve_storage(uuid,uuid,bigint,text,interval)','EXECUTE');
SQL

# The constraints, attacked as the OWNER -- which is the only role that could
# reach them at all. If the invariant only holds because nobody has the grant,
# it is not an invariant, it is an access-control accident.
expect_err "K24 committed_bytes cannot go negative, even for the owner" "storage_usage_committed_bytes_check" <<SQL
SET ROLE computedriven_migrations;
UPDATE cd.storage_usage SET committed_bytes = -1 WHERE organization_id='$A';
SQL

# K24 used to guard reserved_bytes against a double-firing release path, and
# that column is gone: the hold is DERIVED, so there is no counter to drive
# negative and no release to fire twice. The invariant did not move to a
# different constraint -- it stopped needing one, which is only true while the
# table holds exactly one byte column. That is what this asserts.
expect_ok "K24b the ledger holds ONE byte column, so a release cannot double-fire" "committed_bytes" <<'SQL'
SELECT string_agg(column_name, ',' ORDER BY column_name)
  FROM information_schema.columns
 WHERE table_schema='cd' AND table_name='storage_usage'
   AND data_type IN ('bigint','integer','numeric');
SQL

expect_err "K25 a reservation cannot assert more than it reserved" "storage_reservations_assert_ck" <<SQL
SET ROLE computedriven_migrations;
UPDATE cd.storage_reservations SET asserted_bytes = bytes + 1
 WHERE idempotency_key='k2';
SQL

expect_err "K26 two active entitlements for one organization are refused" "entitlements_active_uq" <<SQL
SET ROLE computedriven_migrations;
INSERT INTO cd.entitlements (organization_id, tier, byte_limit) VALUES ('$A','factory',2199023255552);
SQL

# ---------------------------------------------------------------------------
# K27-K34 -- SETTLEMENT (0023). Findings 65 and 71, and the ruling that closes
# both: nothing local releases bytes, because neither our clock nor our client
# is evidence about what R2 holds.
#
# A separate organization from A on purpose. A's fixture has accumulated
# reservations across twenty checks, and an assertion about a ledger TOTAL that
# depends on which of those ran first is an assertion about file order.
# ---------------------------------------------------------------------------
KS=aaaaaaaa-0000-4000-8000-0000000000e5
KSW=11111111-0000-4000-8000-0000000000e5
KSP=cccccccc-0000-4000-8000-0000000000e5
KSKEY="org/$KS/world/$KSW/chunk/aaaa"

expect_ok "K27 settlement fixture: 100 byte limit, nothing used" "0|0|0" <<SQL
SET ROLE computedriven_migrations;
INSERT INTO cd.organizations (id, slug, display_name) VALUES ('$KS','org-settle','Settle');
INSERT INTO cd.worlds (id, organization_id, name) VALUES ('$KSW','$KS','workstation');
INSERT INTO cd.principals (id) VALUES ('$KSP');
INSERT INTO cd.organization_principals (organization_id, principal_id, app_role)
VALUES ('$KS','$KSP','owner');
INSERT INTO cd.entitlements (organization_id, tier, byte_limit) VALUES ('$KS','driver',100);
SELECT committed_bytes || '|' || outstanding_bytes || '|' || used_bytes FROM app.storage_ledger_for('$KS');
SQL

expect_ok "K28 a fresh reservation holds its whole size" "0|100|100" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$KS');
SELECT reservation_id FROM app.reserve_storage('$KSW','$KSP',100,'ks1');
SELECT intent_id FROM app.offer_upload(
  (SELECT id FROM cd.storage_reservations WHERE idempotency_key='ks1'),
  '$KSKEY', 100, 'sha256:aaaa');
SELECT committed_bytes || '|' || outstanding_bytes || '|' || used_bytes FROM app.storage_ledger();
COMMIT;
SQL

# The provider speaks. Occupancy becomes real and the hold drops to zero
# WITHOUT anything having released it -- the reservation's observed bytes are
# simply no longer unaccounted for. Total used does not move, which is the
# whole point: the same bytes must not be counted in both terms.
expect_ok "K29 an observation converts hold to occupancy, and the total does not move" "100|0|100" <<SQL
BEGIN; SET LOCAL ROLE computedriven_jobs;
SELECT observation_id FROM app.observe_storage_object(
  'cd-worlds','$KSKEY','"etag-ks"',100,'PutObject', now(), 'msg-ks-1','$Q');
COMMIT;
SELECT committed_bytes || '|' || outstanding_bytes || '|' || used_bytes FROM app.storage_ledger_for('$KS');
SQL

# FINDING 65, AS A CHECK. The client never finalizes; our clock passes. Before
# 0023 this line read 0|0|0 and the next reservation was admitted.
expect_ok "K30 expiry does not release bytes the provider already confirmed (finding 65)" "1|100|0|100" <<SQL
SET ROLE computedriven_migrations;
UPDATE cd.storage_reservations SET expires_at = now() - interval '1 minute'
 WHERE idempotency_key='ks1';
SELECT app.expire_storage_reservations('$KS') || '|' ||
       (SELECT committed_bytes || '|' || outstanding_bytes || '|' || used_bytes
          FROM app.storage_ledger_for('$KS'));
SQL

expect_err "K31 ...and the quota refuses to sell those bytes a second time" "CD-QUOTA-EXCEEDED" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$KS');
SELECT reservation_id FROM app.reserve_storage('$KSW','$KSP',100,'ks2');
COMMIT;
SQL

# Settlement releases the UNOBSERVED remainder only, and refuses to run before
# the quiet period has elapsed. Two calls: one inside the window (releases
# nothing), one past it.
expect_ok "K32 settlement refuses inside the quiet period" "0" <<SQL
SET ROLE computedriven_jobs;
SELECT app.settle_storage_reservations('$KS');
SQL

# A second reservation, half of it observed and half never. Settling past the
# quiet period must release exactly the half nobody ever saw land.
#
# Stated as a DELTA in both terms, because the absolute totals depend on what
# K28-K31 left behind and the property does not. Note there is no reset of
# ks1's state anywhere here: provider_observed_at is write-once and O14 proves
# it, so a check that needed to walk it back would be a check arguing with the
# ruling it is meant to protect.
expect_ok "K33 settlement releases the UNOBSERVED remainder and keeps the rest" "1|released 50|committed unchanged" <<SQL
SET ROLE computedriven_migrations;
UPDATE cd.entitlements SET byte_limit = 300 WHERE organization_id='$KS';
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$KS');
SELECT reservation_id FROM app.reserve_storage('$KSW','$KSP',100,'ks3');
SELECT intent_id FROM app.offer_upload(
  (SELECT id FROM cd.storage_reservations WHERE idempotency_key='ks3'),
  'org/$KS/world/$KSW/chunk/bbbb', 50, 'sha256:bbbb');
SELECT intent_id FROM app.offer_upload(
  (SELECT id FROM cd.storage_reservations WHERE idempotency_key='ks3'),
  'org/$KS/world/$KSW/chunk/cccc', 50, 'sha256:cccc');
COMMIT;
SET ROLE computedriven_jobs;
-- Only chunk bbbb ever lands.
SELECT observation_id FROM app.observe_storage_object(
  'cd-worlds','org/$KS/world/$KSW/chunk/bbbb','"etag-b"',50,'PutObject', now(), 'msg-ks-b','$Q');
SET ROLE computedriven_migrations;
UPDATE cd.storage_reservations SET expires_at = now() - interval '2 hours'
 WHERE idempotency_key='ks3';
SET ROLE computedriven_jobs;
-- Expiry first, and it is not a formality: settlement acts on a reservation
-- whose window has been CLOSED, never on a live one. reserve_storage() calls
-- the two in this order for the same reason.
SELECT app.expire_storage_reservations('$KS');
-- Created under the role that READS it. A temp table made as migrations and
-- selected as jobs is a permission denied, which K15/K16 avoid by accident by
-- never switching roles mid-check.
CREATE TEMP TABLE k33 AS
  SELECT committed_bytes AS c, outstanding_bytes AS o FROM app.storage_ledger_for('$KS');
-- THREE STATEMENTS, and it has to be three. app.storage_ledger() is STABLE, so
-- inside ONE statement every call to it sees that statement's snapshot -- the
-- pre-settle one -- and the delta reads zero however well settlement works.
-- Written as a single expression first, and it reported "released 0" against a
-- mechanism that a standalone reproduction showed releasing 50.
CREATE TEMP TABLE k33n AS SELECT app.settle_storage_reservations('$KS') AS n;
CREATE TEMP TABLE k33a AS
  SELECT committed_bytes AS c, outstanding_bytes AS o FROM app.storage_ledger_for('$KS');
SELECT (SELECT n FROM k33n)::text
  || '|released ' || ((SELECT o FROM k33) - (SELECT o FROM k33a))::text
  || '|' || CASE WHEN (SELECT c FROM k33a) = (SELECT c FROM k33)
                 THEN 'committed unchanged' ELSE 'committed MOVED' END;
SQL

# Settlement is a JOB. An API caller that could settle could release its own
# unobserved remainder on demand, which is finding 71 with extra steps.
expect_ok "K34 the API role cannot settle its own reservations" "f" <<'SQL'
SELECT has_function_privilege('computedriven_api',
  'app.settle_storage_reservations(uuid)','EXECUTE');
SQL

# R68 as a property of the SCHEMA rather than of the six functions that happen
# to be written correctly today. The migration asserts this at apply time; this
# asserts it against the installed catalog, which is the thing that will still
# be true after somebody hot-fixes a function in production.
expect_ok "K35 exactly one function writes the byte ledger, and it is the observer (R68)" "observe_storage_object" <<'SQL'
SELECT coalesce(string_agg(p.proname, ',' ORDER BY p.proname), 'nothing')
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
 WHERE n.nspname = 'app'
   AND p.prosrc ~ 'UPDATE cd\.storage_usage[^;]*SET[^;]*committed_bytes[[:space:]]*=';
SQL

# ---------------------------------------------------------------------------
# K36-K42 -- capability closure (0024). Findings 72, 73 and 75.
#
# A second tenant, because a cross-tenant read cannot be tested from one.
# ---------------------------------------------------------------------------
KX=bbbbbbbb-0000-4000-8000-0000000000f2
KXW=11111111-0000-4000-8000-0000000000f2
KXP=cccccccc-0000-4000-8000-0000000000f2

expect_ok "K36 a second tenant with something worth reading" "777" <<SQL
SET ROLE computedriven_migrations;
INSERT INTO cd.organizations (id, slug, display_name) VALUES ('$KX','org-x','X');
INSERT INTO cd.worlds (id, organization_id, name) VALUES ('$KXW','$KX','w');
INSERT INTO cd.principals (id) VALUES ('$KXP');
INSERT INTO cd.organization_principals (organization_id, principal_id, app_role)
VALUES ('$KX','$KXP','owner');
INSERT INTO cd.entitlements (organization_id, tier, byte_limit) VALUES ('$KX','driver',9999);
BEGIN; SET LOCAL ROLE computedriven_api; SELECT app.set_organization_context('$KX');
SELECT reservation_id FROM app.reserve_storage('$KXW','$KXP',777,'x-secret');
COMMIT;
SET ROLE computedriven_jobs;
SELECT outstanding_bytes FROM app.storage_ledger_for('$KX');
SQL

# FINDING 72. Org A's API connection naming org X. 0023 answered
# "committed=0 outstanding=777 used=777"; the function that let it is gone, so
# the refusal is a PARSE failure rather than a permission check -- which is the
# stronger shape, and the same one reserve_storage() has had since 0014.
expect_err "K37 the API role cannot name another tenant's ledger (finding 72)" "does not exist" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT used_bytes FROM app.storage_ledger('$KX');
COMMIT;
SQL

expect_err "K38 ...nor another tenant's divergence" "does not exist" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT count(*) FROM app.storage_divergence('$KX');
COMMIT;
SQL

# The one that mattered most: NULL meant EVERY tenant, and it was the most
# convenient call an API caller could write.
expect_err "K39 ...nor every tenant at once via a NULL argument" "does not exist" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT count(*) FROM app.storage_divergence(NULL);
COMMIT;
SQL

expect_err "K40 ...nor the raw outstanding helper" "permission denied" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT app.storage_outstanding('$KX');
COMMIT;
SQL

# The positive witness. Refusing everything is easy; the tenant-derived form has
# to still work, and has to return THIS tenant rather than the named one.
expect_ok "K41 ...and the no-argument form still answers, for THIS tenant only" "own" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$KX');
SELECT CASE WHEN (SELECT outstanding_bytes FROM app.storage_ledger()) = 777
            THEN 'own' ELSE 'wrong tenant' END;
COMMIT;
SQL

# FINDING 73. The quiet period is no longer a parameter, so there is no call to
# refuse -- the two-argument form does not exist.
expect_err "K42 a caller cannot choose the settlement law (finding 73)" "does not exist" <<SQL
SET ROLE computedriven_jobs;
SELECT app.settle_storage_reservations('$KX', interval '0');
SQL

expect_ok "K42b ...and settlement still refuses a reservation inside the quiet period" "0|500" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api; SELECT app.set_organization_context('$KX');
SELECT reservation_id FROM app.reserve_storage('$KXW','$KXP',500,'x-quiet');
COMMIT;
SET ROLE computedriven_migrations;
UPDATE cd.storage_reservations SET expires_at = now() - interval '1 second'
 WHERE idempotency_key='x-quiet';
SET ROLE computedriven_jobs;
SELECT app.expire_storage_reservations('$KX');
SELECT app.settle_storage_reservations('$KX')::text || '|' ||
       (SELECT outstanding_bytes - 777 FROM app.storage_ledger_for('$KX'))::text;
SQL

# FINDING 75, which the outside review CORRECTED US ON and which is now pinned.
# This tree's case E claimed an unstable queue message id would double-charge
# committed_bytes. It does not: the second observation gets past the message-id
# index, but the inventory row is locked and the charge is v_after - v_prior,
# which for the same write is ZERO. The duplicate is in the PROVENANCE log.
expect_ok "K43 a redelivery under a NEW message id duplicates the log, not the charge (finding 75)" "committed unchanged|2 observations|2 events" <<SQL
SET ROLE computedriven_jobs;
SELECT observation_id FROM app.observe_storage_object(
  'cd-worlds','org/$KX/world/$KXW/chunk/dup','"d"',40,'PutObject', now(), 'x-dup-1','$Q');
SET ROLE computedriven_migrations;
CREATE TEMP TABLE k43 AS SELECT committed_bytes AS c FROM cd.storage_usage WHERE organization_id='$KX';
SET ROLE computedriven_jobs;
SELECT observation_id FROM app.observe_storage_object(
  'cd-worlds','org/$KX/world/$KXW/chunk/dup','"d"',40,'PutObject', now(), 'x-dup-2-DIFFERENT-ID','$Q');
SET ROLE computedriven_migrations;
SELECT CASE WHEN (SELECT committed_bytes FROM cd.storage_usage WHERE organization_id='$KX') = (SELECT c FROM k43)
            THEN 'committed unchanged' ELSE 'DOUBLE CHARGED' END
  || '|' || (SELECT count(*) FROM cd.storage_observations WHERE object_key='org/$KX/world/$KXW/chunk/dup')::text || ' observations'
  || '|' || (SELECT event_count FROM cd.storage_objects WHERE object_key='org/$KX/world/$KXW/chunk/dup')::text || ' events';
SQL

expect_err "K27 a reservation cannot point at another tenant's world" "storage_reservations_world_fk" <<SQL
SET ROLE computedriven_migrations;
INSERT INTO cd.storage_reservations
  (organization_id, world_id, principal_id, bytes, idempotency_key, expires_at)
VALUES ('$A','22222222-0000-4000-8000-00000000000b','$KP',1,'k27', now() + interval '1 hour');
SQL

expect_ok "K28 the ledger tables carry ENABLE+FORCE row level security" "0" <<'SQL'
SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname='cd' AND c.relname IN ('entitlements','storage_usage','storage_reservations')
   AND NOT (c.relrowsecurity AND c.relforcerowsecurity);
SQL

expect_ok "K29 org B sees none of org A's reservations" "0" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$B');
SELECT count(*) FROM cd.storage_reservations;
COMMIT;
SQL

expect_ok "K30 org B sees no entitlement of org A's" "0" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$B');
SELECT count(*) FROM cd.entitlements;
COMMIT;
SQL

# ---------------------------------------------------------------------------
# L. the request path must survive HYPERDRIVE, not just PostgreSQL
#
# A NEW CATEGORY OF BLIND SPOT, and a more interesting one than the previous
# rounds'. Every earlier finding was something this battery COULD have tested and
# did not. This one it structurally cannot: it speaks to PostgreSQL directly over
# TCP, and production is
#
#     Worker -> Hyperdrive -> Workers VPC -> Tunnel -> Pigsty        (R7)
#
# 0013 fixed the concurrent-first-login race with pg_advisory_xact_lock. Correct
# PostgreSQL, proven green by concurrency.sh -- and Cloudflare's compatibility
# page lists advisory locks as UNSUPPORTED, verbatim:
#
#     "Advisory locks, LISTEN and NOTIFY, PREPARE and DEALLOCATE, any
#      modification to per-session state not explicitly documented as supported
#      elsewhere."
#
# So the battery went green on a fix the transport refuses.
#
#     A LOCAL BATTERY PROVES THE DATABASE'S BEHAVIOUR, NOT THE TRANSPORT'S.
#
# These checks are the substitute available without an account. They ask the
# DATABASE which functions the API role may execute and read those bodies, so the
# set under test is DERIVED -- a function added next year is covered the day it is
# granted, and nobody has to remember to list it. That is the D4 lesson: the
# hand-typed set is the one that goes stale.
#
# What they cannot do is prove Hyperdrive accepts what remains. That needs a real
# binding, and it is a named gap rather than a silent one -- see
# worker/test/live-falsifier.mjs.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# M. the object-key format has TWO parsers and they must not drift
#
# app.parse_object_key() decides which tenant an R2 event belongs to.
# reconcile.mjs's parseObjectKey() decides the same thing in the consumer. One
# format, two languages, and a disagreement between them is a tenancy bug --
# the SQL side accepting something the JS side rejects means an event is
# accounted to whoever the key claims.
#
# So neither is trusted to describe itself. Both read test/fixtures/object-keys.json
# and are asserted against the SAME cases. Adding a case here obliges both.
# ---------------------------------------------------------------------------
printf '\n%s== M. object-key parser parity (R32) ==%s\n' "$D" "$Z"

FIXTURE="$ROOT/worker/test/fixtures/object-keys.json"
if [ ! -f "$FIXTURE" ]; then
  bad "M0  the shared object-key fixture exists" "missing $FIXTURE"
else
  ok "M0  the shared object-key fixture exists"
  MCASES=$(node -e '
    const f=require("'"$FIXTURE"'");
    for (const c of f.cases) {
      process.stdout.write([c.key, c.valid?"1":"0", c.organizationId||"", c.worldId||"", c.why].join("\x1f")+"\n");
    }')
  MI=0
  while IFS=$'\x1f' read -r key valid org world why; do
    [ -z "${why:-}" ] && continue
    MI=$((MI+1))
    # A parse returns 0 or 1 rows. Compare the row itself, not just the count,
    # so a parser that returns the WRONG tenant fails rather than passes.
    got=$("${PSQL[@]}" -c "SELECT coalesce((SELECT organization_id::text || '|' || world_id::text
                            FROM app.parse_object_key(\$fx\$$key\$fx\$)), 'NONE');" 2>&1 | tail -1)
    if [ "$valid" = "1" ]; then want="$org|$world"; else want="NONE"; fi
    if [ "$got" = "$want" ]; then
      ok "M$MI SQL parser agrees: $why"
    else
      bad "M$MI SQL parser agrees: $why" "expected [$want] got [$got] for key [$key]"
    fi
  done <<< "$MCASES"
fi

# ---------------------------------------------------------------------------
# O. provider-observed object state (R32, still OPEN)
#
# 0017 stored provider evidence keyed (bucket, object_key, etag) -- correct for
# turning at-least-once delivery into exactly-once accounting -- and then read
# occupancy by SUMMING it. R2 fires an object-create event on OVERWRITE too, so
# the sum counts a replaced body twice:
#
#     chunk/x  PUT       10, etag A          sum of log        22
#     chunk/x  overwrite 12, etag B          actual occupancy  12
#
# The log and the inventory are now separate tables and these checks are what
# says so with numbers. O4 is the finding itself: it computes BOTH and requires
# them to differ, so if anyone ever repoints divergence back at the log, this
# check is the one that goes red.
# ---------------------------------------------------------------------------
printf '\n%s== O. provider-observed object state (R32) ==%s\n' "$D" "$Z"

# O0 -- the generalization of finding 59, and the check that would have caught it
# two rounds earlier than group O did.
#
# 0014 granted computedriven_ledger SELECT on cd.organizations and never wrote a
# policy admitting it, so every ledger-owned SECURITY DEFINER function that
# looked an organization up got zero rows and concluded the tenant did not
# exist. A GRANT is permission to ask; a POLICY is permission to be answered.
# Holding the first without the second is worse than holding neither, because it
# fails as ABSENCE rather than as denial.
#
# WIDENED, round 7.2. The first version named computedriven_ledger, so it proved
# a fact about the one role that had already been caught. The property is about
# the SHAPE, not the role: a SECURITY DEFINER function runs as its OWNER, and
# FORCE ROW LEVEL SECURITY subjects even a table's owner to its policies. So
# EVERY role that owns a SECURITY DEFINER function in app or cd is a role whose
# reads can silently return nothing.
#
# This enumerates those owners from pg_proc rather than from a list here -- a
# list would need updating by the same migration that introduces the gap.
#
#     NOT BY PARSING prosrc. Which tables a function touches is a static-analysis
#     problem, and solving it badly would produce a gate that is confident and
#     wrong. This asks the cheaper and stricter question: could this role read
#     this row-secured table AT ALL, and is it admitted by any policy? A named
#     exemption is available and there are currently none.
expect_ok "O0  every SECURITY DEFINER owner is admitted by policy on the row-secured tables it may read" "" <<'SQL'
WITH definer_owners AS (
  SELECT DISTINCT p.proowner AS roleoid
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname IN ('app', 'cd') AND p.prosecdef
)
SELECT string_agg(DISTINCT r.rolname || ' -> ' || c.relname, ', ')
FROM definer_owners d
JOIN pg_roles r ON r.oid = d.roleoid
JOIN pg_class c ON c.relrowsecurity
JOIN pg_namespace cn ON cn.oid = c.relnamespace AND cn.nspname IN ('cd', 'app')
WHERE has_table_privilege(r.oid, c.oid, 'SELECT')
  -- A superuser bypasses RLS entirely, so "no policy" is not a defect for one.
  -- It is also not a role this schema owns: the migration runner is a deployment
  -- detail, exactly as 0020's gate had to learn.
  AND NOT r.rolsuper
  AND NOT r.rolbypassrls
  AND NOT EXISTS (
    SELECT 1 FROM pg_policy p
     WHERE p.polrelid = c.oid
       AND (p.polroles = '{0}'::oid[] OR r.oid = ANY (p.polroles)));
SQL

OW=99999999-0000-4000-8000-000000000099
OP=abababab-0000-4000-8000-0000000000ab
OKEY="org/$A/world/$OW/chunk/o1"
OKEY2="org/$A/world/$OW/chunk/o2"

if ! oseed=$("${PSQL[@]}" 2>&1 <<SQL
SET ROLE computedriven_migrations;
INSERT INTO cd.worlds (id, organization_id, name, status) VALUES ('$OW','$A','o-world','active');
INSERT INTO cd.principals (id) VALUES ('$OP');
INSERT INTO cd.organization_principals (organization_id, principal_id, app_role)
  VALUES ('$A','$OP','member');
-- Headroom for this group only. Groups K and P own the quota-arithmetic
-- assertions; this one is about what the PROVIDER says, not about admission.
UPDATE cd.entitlements SET byte_limit = 100000 WHERE organization_id = '$A';
SQL
); then
  printf '\n%sO SEED FAILED%s\n%s\n' "$R" "$Z" "$oseed"
fi

ORES=$("${PSQL[@]}" 2>&1 <<SQL | grep -E '^[0-9a-f]{8}-' | tail -1
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT reservation_id FROM app.reserve_storage('$OW','$OP',500,'o-res');
COMMIT;
SQL
)

"${PSQL[@]}" >/dev/null 2>&1 <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT intent_id FROM app.offer_upload('$ORES','$OKEY',10,'sha256:o1');
COMMIT;
SQL

# FIXED timestamps and EXPLICIT message ids, both round 7.2.
#
# The first version of these checks used `now() - interval '10 min'` and no
# message id. Under 0017's (bucket,key,etag) constraint that deduped; under
# 0022's fallback index it does not, because `now()` is transaction start time
# and two psql invocations are two transactions. The checks were measuring the
# clock.
#
# More to the point: passing no message id exercises the FALLBACK path, and the
# fallback is the degraded one. A queue consumer always has an id, so the checks
# that stand in for a queue consumer must carry one.
# ...and they must also be AFTER the intents they attribute to, which nothing
# checked until 0024. These were three fixed 2026-08-22 timestamps: stable and
# correctly ordered relative to EACH OTHER, and unrelated to when the intent was
# created. R72 compares the two, so on any day after 2026-08-22 every one of
# these events predated its intent and was correctly recorded UNATTRIBUTED --
# O6 returned no rows at all.
#
#     A FIXTURE'S CONSTANTS ENCODE THE RELATIONSHIPS THE CODE HAPPENED TO CARE
#     ABOUT WHEN THEY WERE WRITTEN. A NEW RULE ABOUT A RELATIONSHIP THEY DO NOT
#     EXPRESS WILL FIND THEM.
#
# So the base is read from the database ONCE, after the intents exist, and the
# three offsets are computed from it in the shell. Fixed literals by the time
# any check runs -- so the ordering is still deterministic and still not the
# clock -- but now causally plausible: a provider cannot have written a chunk
# before we offered it.
OBASE=$("${PSQL[@]}" <<'SQL' | grep -v '^$' | tail -1
SET ROLE computedriven_migrations;
SELECT to_char(now() + interval '1 minute', 'YYYY-MM-DD"T"HH24:MI:SS.USOF');
SQL
)
otime() { "${PSQL[@]}" <<SQL | grep -v '^$' | tail -1
SET ROLE computedriven_migrations;
SELECT to_char('$OBASE'::timestamptz + interval '$1', 'YYYY-MM-DD"T"HH24:MI:SS.USOF');
SQL
}
OT0=$(otime "0 minutes")      # oldest
OT1=$(otime "60 minutes")
OT2=$(otime "90 minutes")     # newest

expect_ok "O1  a provider write lands in the inventory at its current size" "10|1|0" observe_storage_object <<SQL
SET ROLE computedriven_jobs;
SELECT observation_id IS NOT NULL FROM app.observe_storage_object(
  'cd-worlds','$OKEY','etag-A',10,'PutObject','$OT1'::timestamptz,'m-o1','$Q');
SET ROLE computedriven_migrations;
SELECT size_bytes || '|' || event_count || '|' || overwrite_count
  FROM cd.storage_objects WHERE object_key = '$OKEY';
SQL

# A redelivery is the SAME queue message arriving twice. That is what at-least-
# once delivery means, and it must not advance anything.
expect_ok "O2  a redelivery of the same MESSAGE does not advance the inventory" "10|1|0" <<SQL
SET ROLE computedriven_jobs;
SELECT duplicate FROM app.observe_storage_object(
  'cd-worlds','$OKEY','etag-A',10,'PutObject','$OT1'::timestamptz,'m-o1','$Q');
SET ROLE computedriven_migrations;
SELECT size_bytes || '|' || event_count || '|' || overwrite_count
  FROM cd.storage_objects WHERE object_key = '$OKEY';
SQL

# FINDING 62, as an assertion. Same bucket, same key, same etag, same size, same
# instant -- and a DIFFERENT queue message. That is a genuine second write of
# identical bytes, not a redelivery, and 0017's key called it a duplicate and
# dropped it. Occupancy is unchanged (the bytes really are the same) and the
# event log gains a row, which is the whole distinction.
expect_ok "O2b a DIFFERENT message for identical bytes is a second write, not a duplicate" "10|2|0" <<SQL
SET ROLE computedriven_jobs;
SELECT duplicate FROM app.observe_storage_object(
  'cd-worlds','$OKEY','etag-A',10,'PutObject','$OT1'::timestamptz,'m-o1b','$Q');
SET ROLE computedriven_migrations;
SELECT size_bytes || '|' || event_count || '|' || overwrite_count
  FROM cd.storage_objects WHERE object_key = '$OKEY';
SQL

# The overwrite. Same key, different body, later event: current size becomes 12
# and the fact that one name has held two bodies is COUNTED, because on a
# content-addressed key that is a defect and not a measurement.
expect_ok "O3  an overwrite replaces current size and is counted as an overwrite" "12|3|1" <<SQL
SET ROLE computedriven_jobs;
SELECT observation_id IS NOT NULL FROM app.observe_storage_object(
  'cd-worlds','$OKEY','etag-B',12,'PutObject','$OT2'::timestamptz,'m-o3','$Q');
SET ROLE computedriven_migrations;
SELECT size_bytes || '|' || event_count || '|' || overwrite_count
  FROM cd.storage_objects WHERE object_key = '$OKEY';
SQL

# THE FINDING, stated as an assertion. Summing the log is 32 -- 10 + 10 + 12 --
# while the object holds 12. Requiring them to DIFFER is what makes this check
# fail if divergence is ever repointed back at storage_observations.
expect_ok "O4  summing the event log is NOT occupancy (32 logged, 12 stored)" "32|12" <<SQL
SET ROLE computedriven_migrations;
SELECT (SELECT sum(size_bytes) FROM cd.storage_observations WHERE object_key = '$OKEY')
       || '|' ||
       (SELECT size_bytes      FROM cd.storage_objects      WHERE object_key = '$OKEY');
SQL

# Queues does not guarantee ORDER. An older event arriving after a newer one is
# a redelivery of history, not a rollback of the present.
expect_ok "O5  an out-of-order older event does not clobber newer current state" "12|4|2" <<SQL
SET ROLE computedriven_jobs;
SELECT observation_id IS NOT NULL FROM app.observe_storage_object(
  'cd-worlds','$OKEY','etag-OLD',7,'PutObject','$OT0'::timestamptz,'m-o5','$Q');
SET ROLE computedriven_migrations;
SELECT size_bytes || '|' || event_count || '|' || overwrite_count
  FROM cd.storage_objects WHERE object_key = '$OKEY';
SQL

# And the divergence report reads the inventory. finalize() was never called, so
# asserted is 0 and observed is 12 -- not 29, which is what the log now sums to.
expect_ok "O6  storage_divergence reports CURRENT occupancy, not the log total" "0|12|12|2" <<SQL
SET ROLE computedriven_jobs;
SELECT asserted_bytes || '|' || observed_bytes || '|' || delta || '|' || overwrites
  FROM app.storage_divergence_for('$A') WHERE reservation_id = '$ORES';
SQL

# An event for a key with no intent is still recorded -- it is the most
# interesting kind -- but it is not attributed to a reservation.
#
# TWO checks, not one statement pair. expect_ok compares the LAST non-empty line
# only, so a heredoc with two SELECTs silently asserts nothing about the first
# one; the draft of this check "expected [false|1]" and was handed [1].
expect_ok "O7a an unattributed write reports attributed = false" "false" <<SQL
SET ROLE computedriven_jobs;
SELECT attributed::text FROM app.observe_storage_object(
  'cd-worlds','$OKEY2','etag-C',33,'PutObject', now());
SQL

expect_ok "O7b ...and is still recorded in the inventory" "1" <<SQL
SET ROLE computedriven_migrations;
SELECT count(*) FROM cd.storage_objects WHERE object_key = '$OKEY2';
SQL

expect_err "O8  an event with no event_time is refused, not defaulted" CD-OBSERVE-TIME <<SQL
SET ROLE computedriven_jobs;
SELECT observation_id FROM app.observe_storage_object(
  'cd-worlds','$OKEY2','etag-D',33,'PutObject', NULL);
SQL

expect_err "O9  the API role still cannot assert a provider observation" "permission denied" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT observation_id FROM app.observe_storage_object(
  'cd-worlds','$OKEY2','etag-E',1,'PutObject', now());
COMMIT;
SQL

# ---------------------------------------------------------------------------
# O10-O15 -- causal attribution and orthogonal facts (0023).
# ---------------------------------------------------------------------------
OKEY3="org/$A/world/$OW/chunk/o3"
OKEY4="org/$A/world/$OW/chunk/o4"

# FINDING 68. An out-of-band write, then a LATER intent for the same key, and
# nothing new from R2. Before 0023 the second step retroactively attributed the
# first: the past changed because a row appeared in a different table.
expect_ok "O10 an out-of-band write is recorded and attributed to nobody" "false|0" <<SQL
SET ROLE computedriven_jobs;
SELECT attributed FROM app.observe_storage_object(
  'cd-worlds','$OKEY3','"etag-o3"',44,'PutObject', now() - interval '1 hour', 'msg-o3','$Q');
-- Read back as the owner: the recorded fact, not the return value. cd.* is
-- tenant-policied and the queue consumer deliberately carries no tenant context.
SET ROLE computedriven_migrations;
SELECT (intent_id IS NOT NULL)::text || '|' ||
       (SELECT count(*) FROM cd.storage_observations
         WHERE object_key='$OKEY3' AND intent_id IS NOT NULL)::text
  FROM cd.storage_observations WHERE message_id='msg-o3';
SQL

# FINDING 68, and stated as the DELTA it is: creating an intent for that key
# afterwards must not move one byte into the reservation's observed total. The
# old query joined storage_objects to upload_intents on object_key, so this
# step added 44 to a reservation that had never had anything to do with the
# write -- the past changed because a row appeared in a different table.
expect_ok "O10b a LATER intent does not claim an EARLIER write (finding 68)" "unchanged|44" <<SQL
SET ROLE computedriven_migrations;
CREATE TEMP TABLE o10 AS SELECT coalesce(
  (SELECT observed_bytes FROM app.storage_divergence_for('$A') d WHERE d.reservation_id='$ORES'), 0) AS b;
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT intent_id FROM app.offer_upload('$ORES','$OKEY3',44,'sha256:o3');
COMMIT;
SET ROLE computedriven_migrations;
SELECT CASE WHEN coalesce((SELECT observed_bytes FROM app.storage_divergence_for('$A') d
                            WHERE d.reservation_id='$ORES'), 0) = (SELECT b FROM o10)
            THEN 'unchanged' ELSE 'claimed ' ||
            (coalesce((SELECT observed_bytes FROM app.storage_divergence_for('$A') d
                        WHERE d.reservation_id='$ORES'), 0) - (SELECT b FROM o10))::text END
  || '|' || (SELECT size_bytes FROM cd.storage_objects WHERE object_key='$OKEY3')::text;
SQL

# FINDING 69. The same three provider events, delivered in two different
# orders. Before 0023 the second ordering scored 2 overwrites for a history
# containing 1, because the count was taken against the projection rather than
# against the append-only log.
expect_ok "O11 overwrite_count is independent of DELIVERY order (finding 69)" "1|1" <<SQL
SET ROLE computedriven_jobs;
SELECT observation_id FROM app.observe_storage_object('cd-worlds','$OKEY4','"A"',10,'PutObject', now() - interval '3 hours','o4-t1','$Q');
SELECT observation_id FROM app.observe_storage_object('cd-worlds','$OKEY4','"B"',10,'PutObject', now() - interval '1 hour','o4-t3','$Q');
SELECT observation_id FROM app.observe_storage_object('cd-worlds','$OKEY4','"A"',10,'PutObject', now() - interval '2 hours','o4-t2','$Q');
SET ROLE computedriven_migrations;
SELECT (SELECT overwrite_count FROM cd.storage_objects WHERE object_key='$OKEY4')
  || '|' || (SELECT greatest(count(DISTINCT etag) - 1, 0)
               FROM cd.storage_observations WHERE object_key='$OKEY4');
SQL

# FINDING 66 / R71. The client says it will not upload; the still-live presigned
# URL is used anyway. Both facts are true and 0022 kept only the second.
expect_ok "O12 an abandoned-then-observed intent carries BOTH facts (finding 66)" "true|true|observed" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT intent_id FROM app.offer_upload('$ORES','$OKEY2',12,'sha256:o2b');
SELECT app.abandon_upload((SELECT id FROM cd.upload_intents WHERE object_key='$OKEY2'));
COMMIT;
SET ROLE computedriven_jobs;
SELECT observation_id FROM app.observe_storage_object(
  'cd-worlds','$OKEY2','"etag-o2-late"',12,'PutObject', now(), 'msg-o2-late','$Q');
SET ROLE computedriven_migrations;
SELECT (client_abandoned_at IS NOT NULL)::text || '|' ||
       (provider_observed_at IS NOT NULL)::text || '|' || state
  FROM cd.upload_intents WHERE object_key='$OKEY2';
SQL

# R54, enforced by the column definition rather than by remembering a WHERE
# clause in three functions. A generated column cannot be assigned at all.
expect_err "O13 upload_intents.state cannot be written, by anyone (R71)" "generated column" <<SQL
SET ROLE computedriven_migrations;
UPDATE cd.upload_intents SET state = 'offered' WHERE object_key='$OKEY2';
SQL

expect_err "O14 provider_observed_at is write-once, even for the owner (R54)" "CD-INTENT-OBSERVED-FINAL" <<SQL
SET ROLE computedriven_migrations;
UPDATE cd.upload_intents SET provider_observed_at = NULL WHERE object_key='$OKEY2';
SQL

# The other direction: a re-offer withdraws the CLIENT's own declaration, which
# is the one party entitled to withdraw it. Uses a fresh key so O12's record is
# left intact for anyone reading the fixture afterwards.
# FINDING 74. O10/O10b vary the order rows are INSERTED. This varies the order
# the PROVIDER's events arrive, which is the seam that actually exists: a
# notification delayed in the queue lands long after the write, and by then a
# different intent may hold that key. MEASURED against 0023: an event three
# hours older than the intent was credited to it.
expect_ok "O16 a DELAYED event older than the intent is not credited to it (finding 74)" "false|3 hours predate" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT intent_id FROM app.offer_upload('$ORES','org/$A/world/$OW/chunk/late',9,'sha256:late');
COMMIT;
SET ROLE computedriven_jobs;
SELECT observation_id FROM app.observe_storage_object(
  'cd-worlds','org/$A/world/$OW/chunk/late','"late"',9,'PutObject',
  now() - interval '3 hours','o-late','$Q');
SET ROLE computedriven_migrations;
SELECT (intent_id IS NOT NULL)::text || '|3 hours predate'
  FROM cd.storage_observations WHERE message_id='o-late';
SQL

# The other direction, and it is the one that makes O16 a fix rather than a
# blunt refusal: a chunk uploaded moments after its offer must STILL attribute.
# Without the skew allowance, ordinary clock difference between R2 and us would
# strip attribution from every legitimate write.
expect_ok "O16b ...and a normally-timed event still attributes (the skew allowance)" "true" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT intent_id FROM app.offer_upload('$ORES','org/$A/world/$OW/chunk/prompt',8,'sha256:prompt');
COMMIT;
SET ROLE computedriven_jobs;
-- Two seconds EARLIER than our clock, which is what modest skew looks like.
SELECT observation_id FROM app.observe_storage_object(
  'cd-worlds','org/$A/world/$OW/chunk/prompt','"p"',8,'PutObject',
  now() - interval '2 seconds','o-prompt','$Q');
SET ROLE computedriven_migrations;
SELECT (intent_id IS NOT NULL)::text FROM cd.storage_observations WHERE message_id='o-prompt';
SQL

# FINDING 76. Before 0024 the column named provider_observed_at held now() --
# our consumption time -- while R2's own eventTime sat unused in the same
# function's arguments. On a delayed message the two were three hours apart, so
# the anomaly record R71 exists to preserve was storing the wrong one.
expect_ok "O17 the provider's clock and ours are separate columns (finding 76)" "differ|event is older" <<SQL
SET ROLE computedriven_migrations;
SELECT CASE WHEN provider_event_at IS DISTINCT FROM provider_observed_at
            THEN 'differ' ELSE 'SAME COLUMN TWICE' END
  || '|' || CASE WHEN provider_event_at < provider_observed_at
                 THEN 'event is older' ELSE 'ours is older' END
  FROM cd.upload_intents WHERE object_key='org/$A/world/$OW/chunk/prompt';
SQL

expect_err "O18 the provider's event time is write-once too (R54)" "CD-INTENT-EVENTAT-FINAL" <<SQL
SET ROLE computedriven_migrations;
UPDATE cd.upload_intents SET provider_event_at = now()
 WHERE object_key='org/$A/world/$OW/chunk/prompt';
SQL

# ---------------------------------------------------------------------------
# O19-O22 -- observation coherence (0025). Findings 78, 79 and 80.
# ---------------------------------------------------------------------------

# FINDING 79, exactly as the review specified it. The persisted row was right
# throughout; the FUNCTION told its caller otherwise, and observeBatch() uses
# that bit as an operational signal.
# Run as the OWNER, not as jobs: this check needs to call the observer AND read
# cd.storage_observations in one statement, and the queue-consumer role
# deliberately carries no tenant context so the policied read returns nothing.
expect_ok "O19 a redelivery returns the RECORDED decision, not today's (finding 79)" "true|NULL|false|NULL" <<SQL
SET ROLE computedriven_migrations;
SELECT observation_id FROM app.observe_storage_object(
  'cd-worlds','org/$A/world/$OW/chunk/replay','"r"',7,'PutObject', now(), 'o-replay','$Q');
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT intent_id FROM app.offer_upload('$ORES','org/$A/world/$OW/chunk/replay',7,'sha256:r');
COMMIT;
SET ROLE computedriven_migrations;
SELECT r.duplicate::text || '|' || coalesce(r.intent_id::text,'NULL')
       || '|' || r.attributed::text || '|' ||
       coalesce((SELECT intent_id::text FROM cd.storage_observations WHERE message_id='o-replay'),'NULL')
  FROM app.observe_storage_object(
    'cd-worlds','org/$A/world/$OW/chunk/replay','"r"',7,'PutObject', now(), 'o-replay','$Q') r;
SQL

# The sibling. The fallback unique index is (bucket, key, etag, event_time) and
# the duplicate lookup omitted event_time, so two genuine writes of identical
# bytes at different moments were indistinguishable to the reader that had just
# been told they differ.
expect_ok "O20 the no-message-id fallback looks up on its WHOLE key (finding 79)" "2|same row|2" <<SQL
SET ROLE computedriven_migrations;
SELECT observation_id FROM app.observe_storage_object(
  'cd-worlds','org/$A/world/$OW/chunk/fb','"f"',6,'PutObject','$OT0'::timestamptz);
SELECT observation_id FROM app.observe_storage_object(
  'cd-worlds','org/$A/world/$OW/chunk/fb','"f"',6,'PutObject','$OT2'::timestamptz);
CREATE TEMP TABLE o20 AS SELECT
  (SELECT count(*) FROM cd.storage_observations WHERE object_key='org/$A/world/$OW/chunk/fb') AS n,
  (SELECT id FROM cd.storage_observations
    WHERE object_key='org/$A/world/$OW/chunk/fb' AND event_time='$OT0'::timestamptz) AS older;
SELECT (SELECT n FROM o20)::text || '|' ||
       CASE WHEN (SELECT observation_id FROM app.observe_storage_object(
                    'cd-worlds','org/$A/world/$OW/chunk/fb','"f"',6,'PutObject','$OT0'::timestamptz))
                 = (SELECT older FROM o20)
            THEN 'same row' ELSE 'WRONG ROW' END
       || '|' || (SELECT count(*) FROM cd.storage_observations
                   WHERE object_key='org/$A/world/$OW/chunk/fb')::text;
SQL

# FINDING 78 / R74. The two clocks are a projection of ONE observation, and the
# schema now names it. 0024 backfilled them from two different rows because
# nothing said they shared a referent.
expect_ok "O21 both clocks come from the observation the intent names (R74)" "named|event matches|observed matches" <<SQL
SET ROLE computedriven_migrations;
SELECT CASE WHEN i.observing_observation_id IS NOT NULL THEN 'named' ELSE 'UNNAMED' END
  || '|' || CASE WHEN i.provider_event_at = o.event_time
                 THEN 'event matches' ELSE 'EVENT MISMATCH' END
  || '|' || CASE WHEN i.provider_observed_at >= o.observed_at
                 THEN 'observed matches' ELSE 'OBSERVED MISMATCH' END
  FROM cd.upload_intents i
  JOIN cd.storage_observations o ON o.id = i.observing_observation_id
 WHERE i.object_key = 'org/$A/world/$OW/chunk/prompt';
SQL

expect_err "O22 which observation settled an intent is not revisable either (R74)" "CD-INTENT-OBSERVER-FINAL" <<SQL
SET ROLE computedriven_migrations;
UPDATE cd.upload_intents SET observing_observation_id = NULL
 WHERE object_key='org/$A/world/$OW/chunk/prompt';
SQL

# ---------------------------------------------------------------------------
# O23-O28 -- provider order and the authority channel (0026). Findings 82-84.
# ---------------------------------------------------------------------------

# FINDING 82, exactly as the review specified it: same key state, two delivery
# orders, require the same semantic outcome. Two separate keys because one key
# cannot be un-observed, and the comparison is between the two runs.
#
# Note what is being asserted. NOT "the projection picks the right etag" -- at a
# tied eventTime there is no right etag to pick. The assertion is that both
# orders reach the SAME state and that the state says so.
expect_ok "O23 equal eventTime is order-independent, and says it does not know (R75)" \
          "same|(unknown)|20|ambiguous|(unknown)|20|ambiguous" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT intent_id FROM app.offer_upload('$ORES','org/$A/world/$OW/chunk/tie1',10,'sha256:tie1');
SELECT intent_id FROM app.offer_upload('$ORES','org/$A/world/$OW/chunk/tie2',10,'sha256:tie2');
COMMIT;
SET ROLE computedriven_jobs;
SELECT observation_id FROM app.observe_storage_object(
  'cd-worlds','org/$A/world/$OW/chunk/tie1','"tA"',10,'PutObject','$OT1'::timestamptz,'m-ab-1','$Q');
SELECT observation_id FROM app.observe_storage_object(
  'cd-worlds','org/$A/world/$OW/chunk/tie1','"tB"',20,'PutObject','$OT1'::timestamptz,'m-ab-2','$Q');
SELECT observation_id FROM app.observe_storage_object(
  'cd-worlds','org/$A/world/$OW/chunk/tie2','"tB"',20,'PutObject','$OT1'::timestamptz,'m-ba-1','$Q');
SELECT observation_id FROM app.observe_storage_object(
  'cd-worlds','org/$A/world/$OW/chunk/tie2','"tA"',10,'PutObject','$OT1'::timestamptz,'m-ba-2','$Q');
SET ROLE computedriven_migrations;
WITH s AS (
  SELECT object_key, coalesce(etag,'(unknown)') AS etag, size_bytes,
         CASE WHEN ambiguous_event_at IS NOT NULL THEN 'ambiguous' ELSE 'settled' END AS amb
    FROM cd.storage_objects
   WHERE object_key IN ('org/$A/world/$OW/chunk/tie1','org/$A/world/$OW/chunk/tie2')
   ORDER BY object_key
)
SELECT CASE WHEN count(DISTINCT (etag, size_bytes, amb)) = 1 THEN 'same' ELSE 'DIVERGED' END
       || '|' || string_agg(etag || '|' || size_bytes || '|' || amb, '|' ORDER BY object_key)
  FROM s;
SQL

# The ledger half of the same finding. Before 0026 these two keys charged 30 --
# neither of the two order-independent answers, because each key kept whichever
# size arrived last. Conservative means MAX: a quota must not be beatable by
# winning a delivery race.
#
# FINDING 86. This check used to sum cd.storage_objects while being named after
# the ledger -- it proved something its own name did not claim, so the quantity
# admission reads went unasserted and 0026 shipped an ambiguous object counted
# in BOTH committed and outstanding with group O green.
#
# FINDING 93, THE NEXT ROUND. The fix renamed the check and wrote a comment
# saying "It queries app.storage_ledger_for() now." IT DID NOT. The SQL below
# was untouched, so the description-versus-evidence mismatch that let 86 survive
# was reproduced in the sentence claiming to have fixed it -- by the same hand,
# one round later. The bug itself was closed (O29 measures the ledger), which is
# the only reason this was yellow rather than red.
#
#     A CORRECTION IS A CLAIM AND CLAIMS GET CHECKED. Renaming a check and
#     describing new behaviour is not implementing it.
#
# Split in two now, because there really are two facts and conflating them is
# what started this: O23b is the PROJECTION converging, O23c is the LEDGER
# agreeing with it.
expect_ok "O23b the projection converges conservatively either way (R68)" "40" <<SQL
SET ROLE computedriven_migrations;
SELECT sum(size_bytes) FROM cd.storage_objects
 WHERE object_key IN ('org/$A/world/$OW/chunk/tie1','org/$A/world/$OW/chunk/tie2');
SQL

expect_ok "O23c ...and the LEDGER agrees with the projection it is built from (R78)" \
          "ledger agrees" <<SQL
SET ROLE computedriven_migrations;
SELECT CASE WHEN (SELECT committed_bytes FROM app.storage_ledger_for('$A'))
               = (SELECT coalesce(sum(size_bytes),0) FROM cd.storage_objects
                   WHERE organization_id = '$A')
            THEN 'ledger agrees' ELSE 'LEDGER DISAGREES WITH ITS OWN OBJECTS' END;
SQL

# FINDING 86 / R78. committed + outstanding is a PARTITION of the quota
# position, so the two halves have to derive from one relation. They did not:
# storage_outstanding() joined through current_observation_id, which R75 sets to
# NULL on an ambiguous tip, so the reservation kept its entire hold for bytes
# the observer had already committed. MEASURED on 0026: 40 / 20 / 60.
#
# Both tie keys were offered under \$ORES (40 bytes of it observed and now
# ambiguous), so a correct partition puts zero of those 40 back in outstanding.
# FINDING 83. The FK's second column is the intent's own primary key, so an
# observation belonging to another intent is unnameable rather than merely
# wrong. Run as computedriven_ledger -- the role that DOES hold direct INSERT on
# both tables -- because a refusal from a role with no privilege would prove
# nothing about the constraint.
#
# An INSERT rather than an UPDATE, deliberately. The first draft updated an
# intent that group O creates LATER in the file, so it matched zero rows and
# "succeeded"; a zero-row UPDATE is a check with nothing to check, which is the
# failure mode this battery has now shipped twice. An INSERT cannot match
# nothing.
expect_err "O24 an intent cannot name another intent's observation (R76)" \
           "upload_intents_observation_projection_fk" <<SQL
SET ROLE computedriven_ledger;
INSERT INTO cd.upload_intents
  (reservation_id, organization_id, world_id, object_key, expected_bytes,
   content_digest, expires_at, observing_observation_id, provider_event_at, provider_observed_at)
SELECT i.reservation_id, i.organization_id, i.world_id,
       'org/$A/world/$OW/chunk/o24', 8, 'sha256:o24', now() + interval '15 minutes',
       o.id, o.event_time, o.observed_at
  FROM cd.upload_intents i
  JOIN cd.storage_observations o ON o.id = i.observing_observation_id
 WHERE i.object_key='org/$A/world/$OW/chunk/prompt';
SQL

expect_err "O25 ...nor copy clocks that disagree with the observation it names (R76)" \
           "upload_intents_observation_projection_fk" <<SQL
SET ROLE computedriven_ledger;
INSERT INTO cd.upload_intents
  (reservation_id, organization_id, world_id, object_key, expected_bytes,
   content_digest, expires_at, observing_observation_id, provider_event_at, provider_observed_at)
SELECT i.reservation_id, i.organization_id, i.world_id,
       'org/$A/world/$OW/chunk/o25', 8, 'sha256:o25', now() + interval '15 minutes',
       o.id, o.event_time + interval '1 second', o.observed_at
  FROM cd.upload_intents i
  JOIN cd.storage_observations o ON o.id = i.observing_observation_id
 WHERE i.object_key='org/$A/world/$OW/chunk/prompt';
SQL

# FINDING 84. Cloudflare documents Message.id as unique and documents no
# cross-queue scope for that uniqueness, so the row records the channel too.
# This does not claim ids ARE reused across queues -- it claims that if they
# ever are, a genuine second write does not silently become a duplicate.
# Everything is held identical except the channel: same key, same etag, same
# size, same eventTime, same message id. Under 0022's `(message_id)` index the
# second call was a duplicate; under 0026's `(queue_name, message_id)` it is a
# second delivery. If the only varying field were the event time this check
# would pass for the wrong reason.
expect_ok "O26 the same message id on another channel is another delivery (R77)" "false|2" <<SQL
SET ROLE computedriven_jobs;
SELECT observation_id FROM app.observe_storage_object(
  'cd-worlds','org/$A/world/$OW/chunk/chan','"c"',5,'PutObject','$OT1'::timestamptz,'m-shared','$Q');
SELECT duplicate FROM app.observe_storage_object(
  'cd-worlds','org/$A/world/$OW/chunk/chan','"c"',5,'PutObject','$OT1'::timestamptz,
  'm-shared','some-other-queue');
SET ROLE computedriven_migrations;
SELECT (SELECT duplicate::text FROM app.observe_storage_object(
          'cd-worlds','org/$A/world/$OW/chunk/chan','"c"',5,'PutObject','$OT1'::timestamptz,
          'm-shared','a-third-queue'))
       || '|' || (SELECT count(DISTINCT queue_name)::text FROM cd.storage_observations
                   WHERE message_id='m-shared' AND queue_name IN ('$Q','some-other-queue'));
SQL

expect_err "O27 a delivery identity with no channel is refused (R77)" "CD-OBSERVE-CHANNEL" <<SQL
SET ROLE computedriven_jobs;
SELECT observation_id FROM app.observe_storage_object(
  'cd-worlds','org/$A/world/$OW/chunk/nochan','"n"',5,'PutObject','$OT1'::timestamptz,'m-nochan');
SQL

# The divergence report has to SHOW an ambiguity, not lose the object to it.
# 0024 joined storage_objects through current_observation_id, which 0026 sets to
# NULL on an ambiguous tip -- so the un-fixed join would have dropped the
# ambiguous object out of observed_bytes and reported a clean, wrong number.
# Stated as "the report loses none", not as a literal count. A hardcoded number
# here drifts the moment another check makes another key ambiguous, and a
# drifting expected value gets corrected rather than read -- which is how O23b
# came to assert a quantity its own name did not name (finding 86).
expect_ok "O28 divergence surfaces every ambiguous object rather than dropping it" "none lost" <<SQL
SET ROLE computedriven_migrations;
SELECT CASE WHEN (SELECT coalesce(sum(ambiguous),0) FROM app.storage_divergence_for('$A'))
               = (SELECT count(*) FROM cd.storage_objects so
                    JOIN cd.upload_intents i ON i.object_key = so.object_key
                   WHERE so.ambiguous_event_at IS NOT NULL
                     AND so.organization_id = '$A'
                     AND i.reservation_id IS NOT NULL)
            THEN 'none lost' ELSE 'AMBIGUOUS OBJECTS DROPPED' END;
SQL

# THE MEASUREMENT FROM THE FINDING, as a ledger DELTA rather than an absolute:
# the absolute moves whenever an earlier group adds an observation, and a check
# whose expected value drifts gets "corrected" instead of read.
#
# 20-byte reservation, one key, observed at 10 -> the hold is 10 and used is 20.
# A SECOND observation at the SAME eventTime makes the tip ambiguous, so
# occupancy goes 10 -> 20 and the hold must go 10 -> 0. Net change to used: ZERO.
#
# On 0026 the hold went 10 -> 20 instead, because current_observation_id had
# gone NULL and storage_outstanding() read that as "nothing observed" -- so used
# jumped by 20 and the same bytes sat on both sides of the partition.
expect_ok "O29 an ambiguous tip discharges its hold instead of doubling it (R78)" "0|20|0|20" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT reservation_id FROM app.reserve_storage('$OW','$OP',20,'o29');
SELECT intent_id FROM app.offer_upload(
  (SELECT id FROM cd.storage_reservations WHERE idempotency_key='o29'),
  'org/$A/world/$OW/chunk/o29',20,'sha256:o29');
COMMIT;
SET ROLE computedriven_jobs;
SELECT observation_id FROM app.observe_storage_object(
  'cd-worlds','org/$A/world/$OW/chunk/o29','"x"',10,'PutObject','$OT2'::timestamptz,'m-o29-1','$Q');
SET ROLE computedriven_migrations;
CREATE TEMP TABLE o29 AS SELECT used_bytes AS before FROM app.storage_ledger_for('$A');
SET ROLE computedriven_jobs;
SELECT observation_id FROM app.observe_storage_object(
  'cd-worlds','org/$A/world/$OW/chunk/o29','"y"',20,'PutObject','$OT2'::timestamptz,'m-o29-2','$Q');
SET ROLE computedriven_migrations;
SELECT (l.used_bytes - (SELECT before FROM o29))::text
       || '|' || so.size_bytes
       || '|' || GREATEST(r.bytes - so.size_bytes, 0)
       || '|' || (so.size_bytes + GREATEST(r.bytes - so.size_bytes, 0))
  FROM app.storage_ledger_for('$A') l,
       cd.storage_reservations r
  JOIN cd.upload_intents i  ON i.reservation_id = r.id
  JOIN cd.storage_objects so ON so.object_key = i.object_key
 WHERE r.idempotency_key = 'o29';
SQL

# The general invariant, and the reason it is expressed as a COMPARISON: a check
# that recomputes storage_outstanding()'s body and asserts equality proves only
# that the battery copied the function. \`blind\` reproduces 0026's semantics --
# ambiguous objects dropped from the observed side -- so \`actual < blind\` is the
# claim that the fix changed the number, in the right direction, by a non-zero
# amount. On 0026 the two were EQUAL.
expect_ok "O29b outstanding no longer omits the ambiguous objects it once did (R78)" \
          "partition holds|ambiguous bytes discharge their hold" <<SQL
-- As the OWNER, not as jobs: this reads cd.storage_reservations directly, and
-- the queue-consumer role deliberately carries no tenant context, so the RLS
-- policy raises CD-TENANT-MISSING rather than returning nothing. Same reason
-- O19 gives.
SET ROLE computedriven_migrations;
WITH l AS (SELECT * FROM app.storage_ledger_for('$A')),
     blind AS (
  SELECT coalesce(sum(GREATEST(r.bytes - coalesce((
           SELECT sum(so.size_bytes)
             FROM (SELECT DISTINCT ob.bucket, ob.object_key
                     FROM cd.upload_intents i
                     JOIN cd.storage_observations ob ON ob.intent_id = i.id
                    WHERE i.reservation_id = r.id) k
             JOIN cd.storage_objects so
               ON so.bucket = k.bucket AND so.object_key = k.object_key
              AND so.ambiguous_event_at IS NULL), 0), 0)), 0) AS held
    FROM cd.storage_reservations r
   WHERE r.organization_id = '$A' AND r.state <> 'settled')
SELECT CASE WHEN l.used_bytes = l.committed_bytes + l.outstanding_bytes
            THEN 'partition holds' ELSE 'PARTITION BROKEN' END
    || '|' || CASE WHEN l.outstanding_bytes < blind.held
                   THEN 'ambiguous bytes discharge their hold'
                   ELSE 'AMBIGUOUS BYTES STILL HELD' END
  FROM l, blind;
SQL

expect_ok "O15 a re-offer clears the client's declaration and nothing else" "false|offered" <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT intent_id FROM app.offer_upload('$ORES','org/$A/world/$OW/chunk/o5',10,'sha256:o5');
SELECT app.abandon_upload(
  (SELECT id FROM cd.upload_intents WHERE object_key='org/$A/world/$OW/chunk/o5'));
SELECT intent_id FROM app.offer_upload('$ORES','org/$A/world/$OW/chunk/o5',10,'sha256:o5');
SELECT (client_abandoned_at IS NOT NULL)::text || '|' || state
  FROM cd.upload_intents WHERE object_key='org/$A/world/$OW/chunk/o5';
COMMIT;
SQL

printf '\n%s== L. Hyperdrive request-path compatibility (R7) ==%s\n' "$D" "$Z"

expect_ok "L1  no request-path function uses an advisory lock" "" <<'SQL'
SELECT string_agg(p.proname, ', ' ORDER BY p.proname)
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'app'
  AND has_function_privilege('computedriven_api', p.oid, 'EXECUTE')
  AND p.prosrc ~* 'pg_advisory';
SQL

expect_ok "L2  no request-path function uses LISTEN or NOTIFY" "" <<'SQL'
SELECT string_agg(p.proname, ', ' ORDER BY p.proname)
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'app'
  AND has_function_privilege('computedriven_api', p.oid, 'EXECUTE')
  AND p.prosrc ~* '\m(listen|notify|pg_notify)\M';
SQL

expect_ok "L3  no request-path function manages prepared statements or DISCARDs" "" <<'SQL'
SELECT string_agg(p.proname, ', ' ORDER BY p.proname)
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'app'
  AND has_function_privilege('computedriven_api', p.oid, 'EXECUTE')
  AND p.prosrc ~* '\m(prepare|deallocate|discard)\M';
SQL

# The one per-session mutation the design DOES rely on, asserted to be
# transaction-scoped. Hyperdrive is transaction-pooled, so a connection can serve
# another tenant on its very next transaction: a session-scoped SET here would be
# a cross-tenant leak, not a style preference. 0002's setter passes `true` as
# set_config's third argument, which is what makes it local.
expect_ok "L4  tenant context is set TRANSACTION-locally, never session-wide" "t" <<'SQL'
SELECT p.prosrc ~ 'set_config\s*\([^)]*,\s*true\s*\)'
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'app' AND p.proname = 'set_organization_context';
SQL

# Proof that L4 is measuring the thing it claims: a context set in one
# transaction must NOT survive into the next one on the same connection. This is
# the actual leak, exercised rather than inferred from the source text.
expect_err "L5  tenant context does not survive its transaction" CD-TENANT-MISSING <<SQL
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT app.set_organization_context('$A');
SELECT count(*) FROM cd.worlds;
COMMIT;
BEGIN; SET LOCAL ROLE computedriven_api;
SELECT count(*) FROM cd.worlds;
COMMIT;
SQL

# The version gate. Hyperdrive documents known support for PostgreSQL 9.0-17.x;
# this battery runs on whatever `postgres` is on PATH. That is not a failure --
# it is a fact the round has to state rather than discover later, and CD_PGBIN
# lets the same battery run against a 17.x build the moment one is installed.
expect_ok "L6  server major version is recorded, not assumed" "t" <<'SQL'
SELECT current_setting('server_version_num')::int >= 90000;
SQL

# L7 is the one check with a THIRD outcome, and the third outcome is honest.
#
# Running on a major Hyperdrive does not document is not a defect in the schema
# and it is not a pass either -- it means every green line above was measured on a
# server the production transport does not claim to speak. Scoring it FAIL would
# make `test:all` permanently red on this box for a reason unrelated to the code,
# and a red that is always expected is how a real red gets ignored. Scoring it
# PASS would bury it.
#
# So: WARN. Counted separately, printed in the summary, and recorded in
# status.json. The fix is one package install, and it is Travis's to run.
PGMAJ=$("${PSQL[@]}" -c "SELECT current_setting('server_version_num')::int / 10000" 2>/dev/null | tail -1)
if [ "${PGMAJ:-0}" -le 17 ]; then
  ok "L7  server major ${PGMAJ} is inside Hyperdrive's documented 9.0-17.x range"
else
  WARN=$((WARN+1))
  printf '  %sWARN%s  L7  server major %s is OUTSIDE Hyperdrive'\''s documented 9.0-17.x range\n' \
    "$Y" "$Z" "$PGMAJ"
  printf '        %sNot a schema defect: a gap between what is TESTED and what is DEPLOYABLE.\n' "$D"
  printf '        Everything above was measured on PostgreSQL %s; R7 puts the request path\n' "$PGMAJ"
  printf '        through Hyperdrive, which documents 9.0-17.x. Install a 17.x build and\n'
  printf '        re-run with CD_PGBIN=/opt/pgsql-17/bin, or make PG18-through-Hyperdrive a\n'
  printf '        live experiment (live-falsifier case H) BEFORE provisioning.%s\n' "$Z"
fi

# O0b -- the BEHAVIOURAL half, and the one that actually found finding 59.
#
# The structural check above is necessary and it is not sufficient: a policy can
# exist and still not admit the row a function's semantics require. What caught
# the bug was calling the function with an organization that EXISTS.
#
#     EVERY CROSS-TENANT SECURITY DEFINER CAPABILITY NEEDS AT LEAST ONE POSITIVE
#     ACCEPT WITNESS. A battery of refusals proves a function can say no.
#
# So this is a non-vacuity gate over the battery itself: for each named
# cross-tenant capability, at least one check in this file must have exercised
# its ACCEPT path. The witnesses are recorded as they run, and a capability with
# none fails here rather than shipping with an untested accept path.
CROSS_TENANT_CAPS="observe_storage_object resolve_principal resolve_organization"
missing_witness=""
for cap in $CROSS_TENANT_CAPS; do
  case " $ACCEPT_WITNESSES " in
    *" $cap "*) ;;
    *) missing_witness="$missing_witness $cap" ;;
  esac
done
if [ -z "$missing_witness" ]; then
  ok "O0b every cross-tenant SECURITY DEFINER capability has a positive accept witness"
else
  bad "O0b every cross-tenant SECURITY DEFINER capability has a positive accept witness" \
      "no accept path was exercised for:$missing_witness"
fi

# ---------------------------------------------------------------------------
# O0c -- the DERIVED form of the question O0b asks from a hand-maintained list.
#
# O0b passed on 0023 while 0023 was manufacturing three new cross-tenant read
# capabilities, and it could not have done otherwise: its list is written by
# hand, and nobody adds a capability to it that they did not realise they had
# created. Finding 72 is exactly that shape --
#
#     app.storage_ledger(B)         -> 777, from org A's connection
#     app.storage_divergence(NULL)  -> EVERY tenant's rows
#
# -- while the direct table read of the same data returned zero rows, because
# RLS worked. The definer was the only door and the migration built it.
#
#     A SECURITY DEFINER FUNCTION THAT TAKES A TENANT ID IS A CROSS-TENANT
#     CAPABILITY, WHATEVER ITS NAME SAYS. THE REQUEST SUPPLIES INTENT, NOT
#     AUTHORITY.
#
# So this asks the CATALOG instead: any storage-surface definer owned by the
# cross-tenant role, taking a uuid, and reachable by a request role, must carry
# the `_for` suffix that declares it jobs-only -- and if it carries that suffix
# it must not be granted to a request role at all.
# FINDING 80: there were TWO of these and they disagreed. 0024's apply-time copy,
# which the bundle called "the same assertion", checked only computedriven_api
# and EXEMPTED every name ending `_for` -- precisely the cross-tenant doors the
# round exists to keep shut, so a later `GRANT ... storage_ledger_for(uuid) TO
# computedriven_api` would have applied cleanly. 0025 uses this predicate
# verbatim.
#
#     A SUFFIX THAT MARKS A FUNCTION AS DANGEROUS IS NOT A REASON FOR THE GATE
#     TO SKIP IT. IT IS THE REASON TO CHECK IT.
expect_ok "O0c no request role can reach a tenant-naming definer on the ledger surface (finding 72)" "" <<'SQL'
SELECT string_agg(p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')', ', '
                  ORDER BY p.proname)
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
SQL

printf '\n%s== result ==%s\n' "$D" "$Z"
printf '  %s%d passed%s   %s%d failed%s   %s%d warned%s   (%d checks)\n' \
  "$G" "$PASS" "$Z" "$([ "$FAIL" -gt 0 ] && printf '%s' "$R")" "$FAIL" "$Z" \
  "$([ "$WARN" -gt 0 ] && printf '%s' "$Y")" "$WARN" "$Z" "$((PASS+FAIL+WARN))"

# In control mode the exit code INVERTS, so the run has to say so itself rather
# than leave a reader to remember. A sabotage run that reports "0 failed" looks
# like the best possible outcome and is in fact the worst one: it means the
# battery cannot tell the fail-closed function from the naive one, and every
# clean exit code it has ever printed was worthless.
if [ -n "${CD_SABOTAGE:-}" ]; then
  printf '\n%s== control verdict ==%s\n' "$D" "$Z"
  if [ "$FAIL" -gt 0 ]; then
    printf '  %sSABOTAGE CAUGHT%s  %d of %d checks detected the naive function.\n' \
      "$G" "$Z" "$FAIL" "$((PASS+FAIL))"
    printf '  The failures above are the point. The battery is not vacuous.\n\n'
    exit 0
  fi
  printf '  %sSABOTAGE MISSED%s  the naive function was installed and nothing failed.\n' "$R" "$Z"
  printf '  The battery is measuring nothing. Do not trust its clean runs.\n\n'
  exit 1
fi

printf '\n'
exit "$FAIL"
