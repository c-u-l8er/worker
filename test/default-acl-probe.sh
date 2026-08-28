#!/usr/bin/env bash
# The measurement R42 rests on. Runs standalone against a throwaway cluster.
#
#   ./worker/test/default-acl-probe.sh                  the R33 target build
#   CD_PGBIN=/usr/bin ./worker/test/default-acl-probe.sh   whatever is on PATH
#
# WHY THIS IS A FILE AND NOT A PARAGRAPH.
#
# 0009 asserted that ALTER DEFAULT PRIVILEGES would protect functions created by
# later migrations. 0018 measured that it did not, and generalized the result
# into "the REVOKE-from-PUBLIC form stores nothing" -- a claim about PostgreSQL
# rather than about the command that was actually run. Outside review pushed
# back, correctly: the `IN SCHEMA` clause is the defect.
#
# Both files were arguing about a fact. A fact this cheap to measure should never
# be argued about twice, and the second time it was argued about, the argument
# was settled by running exactly this.
#
#     A -- the IN SCHEMA form            stores nothing, protects nothing
#     B -- the GLOBAL form               stores {r=X/r}, protects
#     C -- ON ROUTINES                   covers functions AND procedures
#     D -- reach                         applies in a schema it never named
#     E -- SECURITY DEFINER + REPLACE    still protected
#     H -- privilege to install          a non-superuser may, FOR a role it is a member of
#     I -- privilege boundary            and may NOT, for a role it is not
#     J -- THE COVERAGE GAP              a role with no rule LEAKS
#
# J is why 0020 keeps 0018's event trigger instead of replacing it, and it is the
# case a canary created only as the migration role cannot see.
set -uo pipefail

DEFAULT_PGBIN=/opt/pgsql-17/bin
BIN="${CD_PGBIN-}"
if [ -z "${CD_PGBIN+set}" ] && [ -x "$DEFAULT_PGBIN/initdb" ]; then BIN="$DEFAULT_PGBIN"; fi
[ -n "$BIN" ] && BIN="$BIN/" || BIN=""
command -v "${BIN}initdb" >/dev/null 2>&1 || { echo "no initdb at '${BIN}initdb'"; exit 99; }

PORT="${CD_PGPORT:-55496}"
ROOT="${CD_PGROOT:-/tmp/cd-acl-$$}"
DATA="$ROOT/data"
PASS=0; FAIL=0
if [ -t 1 ]; then G=$'\033[32m'; R=$'\033[31m'; D=$'\033[2m'; Z=$'\033[0m'; else G=; R=; D=; Z=; fi
ok()  { PASS=$((PASS+1)); printf '  %sPASS%s  %s\n' "$G" "$Z" "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  %sFAIL%s  %s\n' "$R" "$Z" "$1"
        [ -n "${2:-}" ] && printf '        %s%s%s\n' "$D" "$2" "$Z"; return 0; }
trap '"${BIN}pg_ctl" -D "$DATA" -m immediate stop >/dev/null 2>&1; rm -rf "$ROOT"' EXIT

mkdir -p "$DATA"
"${BIN}initdb" -D "$DATA" -A trust -U cdtest --no-sync >/dev/null 2>&1 || { echo "initdb failed"; exit 99; }
"${BIN}pg_ctl" -D "$DATA" -l "$ROOT/pg.log" -w \
  -o "-p $PORT -c listen_addresses=127.0.0.1 -c unix_socket_directories='' -c fsync=off" \
  start >/dev/null 2>&1 || { echo "pg_ctl start failed"; tail -20 "$ROOT/pg.log"; exit 99; }
"${BIN}createdb" -h 127.0.0.1 -p "$PORT" -U cdtest acl || exit 99
Q() { "${BIN}psql" -h 127.0.0.1 -p "$PORT" -U cdtest -d acl -tAq "$@"; }

printf '\n%s== cluster ==%s\n  postgres %s\n' "$D" "$Z" "$(Q -c 'show server_version')"

Q <<'SQL' >/dev/null
CREATE ROLE mig       NOSUPERUSER;
CREATE ROLE r_schema  NOSUPERUSER;
CREATE ROLE r_global  NOSUPERUSER;
CREATE ROLE r_routine NOSUPERUSER;
CREATE ROLE r_norule  NOSUPERUSER;
CREATE ROLE stranger  NOSUPERUSER;
GRANT r_global, r_routine, r_norule TO mig WITH INHERIT TRUE;
CREATE SCHEMA s;
GRANT CREATE, USAGE ON SCHEMA s TO r_schema, r_global, r_routine, r_norule;
SQL

rules() { Q -c "SELECT count(*) FROM pg_default_acl d JOIN pg_roles r ON r.oid=d.defaclrole
                 WHERE r.rolname='$1' AND d.defaclnamespace=0"; }
pub()   { Q -c "SELECT has_function_privilege('public','$1','EXECUTE')"; }

printf '\n%s== A. the IN SCHEMA form — what 0009 wrote and 0018 measured ==%s\n' "$D" "$Z"
Q -c "ALTER DEFAULT PRIVILEGES FOR ROLE r_schema IN SCHEMA s REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;" >/dev/null
Q -c "SET ROLE r_schema; CREATE FUNCTION s.f_schema() RETURNS int LANGUAGE sql AS 'SELECT 1'" >/dev/null
N=$(Q -c "SELECT count(*) FROM pg_default_acl d JOIN pg_roles r ON r.oid=d.defaclrole WHERE r.rolname='r_schema'")
[ "$N" = 0 ] && ok "A1  stores NO rule  ${D}(pg_default_acl rows = 0)${Z}" \
             || bad "A1  stores NO rule" "rows=$N"
[ "$(pub 's.f_schema()')" = t ] && ok "A2  and a new function IS PUBLIC-executable — the schema-scoped form protects nothing" \
                                || bad "A2  and a new function IS PUBLIC-executable" "it was protected; the premise of R42 is wrong"

printf '\n%s== B/C. the GLOBAL form — what 0009 MEANT ==%s\n' "$D" "$Z"
Q -c "ALTER DEFAULT PRIVILEGES FOR ROLE r_global REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;" >/dev/null
Q -c "SET ROLE r_global; CREATE FUNCTION s.f_global() RETURNS int LANGUAGE sql AS 'SELECT 1'" >/dev/null
[ "$(rules r_global)" = 1 ] && ok "B1  stores a rule  ${D}$(Q -c "SELECT defaclacl FROM pg_default_acl d JOIN pg_roles r ON r.oid=d.defaclrole WHERE r.rolname='r_global'")${Z}" \
                            || bad "B1  stores a rule" "rows=$(rules r_global)"
[ "$(pub 's.f_global()')" = f ] && ok "B2  and a new function is NOT PUBLIC-executable" \
                                || bad "B2  and a new function is NOT PUBLIC-executable" "it leaked"

Q -c "ALTER DEFAULT PRIVILEGES FOR ROLE r_routine REVOKE EXECUTE ON ROUTINES FROM PUBLIC;" >/dev/null
Q -c "SET ROLE r_routine; CREATE FUNCTION  s.f_routine() RETURNS int LANGUAGE sql AS 'SELECT 1'" >/dev/null
Q -c "SET ROLE r_routine; CREATE PROCEDURE s.p_routine() LANGUAGE sql AS 'SELECT 1'" >/dev/null
[ "$(pub 's.f_routine()')" = f ] && [ "$(pub 's.p_routine()')" = f ] \
  && ok "C1  ON ROUTINES covers FUNCTION and PROCEDURE alike" \
  || bad "C1  ON ROUTINES covers FUNCTION and PROCEDURE alike" \
         "fn=$(pub 's.f_routine()') proc=$(pub 's.p_routine()')"

printf '\n%s== D/E. reach ==%s\n' "$D" "$Z"
Q -c "CREATE SCHEMA s2; GRANT CREATE, USAGE ON SCHEMA s2 TO r_routine;" >/dev/null
Q -c "SET ROLE r_routine; CREATE FUNCTION s2.f_other() RETURNS int LANGUAGE sql AS 'SELECT 1'" >/dev/null
[ "$(pub 's2.f_other()')" = f ] && ok "D1  the global rule applies in a schema it never named" \
                               || bad "D1  the global rule applies in a schema it never named" "leaked in s2"
Q -c "SET ROLE r_global; CREATE FUNCTION s.f_sd() RETURNS int LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'" >/dev/null
Q -c "SET ROLE r_global; CREATE OR REPLACE FUNCTION s.f_global() RETURNS int LANGUAGE sql AS 'SELECT 2'" >/dev/null
[ "$(pub 's.f_sd()')" = f ] && [ "$(pub 's.f_global()')" = f ] \
  && ok "E1  applies to SECURITY DEFINER, and survives CREATE OR REPLACE" \
  || bad "E1  applies to SECURITY DEFINER, and survives CREATE OR REPLACE" \
         "sd=$(pub 's.f_sd()') replaced=$(pub 's.f_global()')"

printf '\n%s== H/I. how much privilege it takes to install ==%s\n' "$D" "$Z"
OUT=$(Q -c "SET ROLE mig; ALTER DEFAULT PRIVILEGES FOR ROLE r_norule REVOKE EXECUTE ON ROUTINES FROM PUBLIC;" 2>&1)
case "$OUT" in
  *ERROR*) bad "H1  a NON-SUPERUSER may install a rule for a role it is a member of" "$OUT" ;;
  *)       ok  "H1  a NON-SUPERUSER may install a rule for a role it is a member of  ${D}(no superuser needed)${Z}" ;;
esac
OUT=$(Q -c "SET ROLE mig; ALTER DEFAULT PRIVILEGES FOR ROLE stranger REVOKE EXECUTE ON ROUTINES FROM PUBLIC;" 2>&1)
case "$OUT" in
  *"permission denied to change default privileges"*)
    ok "I1  and may NOT, for a role it is not a member of" ;;
  *) bad "I1  and may NOT, for a role it is not a member of" "${OUT:-it succeeded}" ;;
esac

printf '\n%s== J. THE COVERAGE GAP — why 0020 keeps the event trigger ==%s\n' "$D" "$Z"
# r_norule's rule was installed by H1 above, so a THIRD role is minted here with
# none. This is what a routine-owning role added by a future migration looks like
# on the day it is added.
Q -c "CREATE ROLE r_future NOSUPERUSER; GRANT CREATE, USAGE ON SCHEMA s TO r_future;" >/dev/null
Q -c "SET ROLE r_future; CREATE FUNCTION s.f_future() RETURNS int LANGUAGE sql AS 'SELECT 1'" >/dev/null
if [ "$(pub 's.f_future()')" = t ]; then
  ok "J1  a role with NO rule LEAKS — per-role defaults do not cover a role added later"
else
  bad "J1  a role with NO rule LEAKS" \
      "it was protected, which would mean 0020 can drop the event trigger — re-read this"
fi

printf '\n  %s%s passed%s   %s%s failed%s\n\n' "$G" "$PASS" "$Z" \
  "$([ "$FAIL" -gt 0 ] && echo "$R" || echo "$D")" "$FAIL" "$Z"
exit "$FAIL"
