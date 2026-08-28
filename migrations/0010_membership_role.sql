-- 0010 — the authorization answer carries a ROLE, not just a boolean
--
-- BUG, found by outside review 2026-08-22 and reproduced before fixing.
--
-- 0003 models four roles -- owner / admin / member / viewer -- and
-- authorize_membership() reduced all of them to `active = true`. The Worker then
-- took the requested R2 permission straight from the request body. So:
--
--     viewer  ->  active member = true
--             ->  POST { "permission": "object-write" }
--             ->  a write-scoped credential
--
-- Not exploitable today only because the R2 provider refuses (not deployed). It
-- would have gone live the moment the provider did, which is the worst kind of
-- latent hole: correct-looking code whose failure is scheduled.
--
-- Same shape as the 0008 defect, one layer up. 0008 made `suspended` mean
-- something; this makes `viewer` mean something. A schema that names a
-- distinction the code never reads is a control that is not there.
--
-- authorize_membership() keeps its boolean contract -- group G depends on it and
-- "may this principal act here at all" is still a real question. This ADDS the
-- finer answer rather than overloading the coarse one.

BEGIN;

SET LOCAL ROLE computedriven_migrations;

GRANT CREATE ON SCHEMA app TO computedriven_bootstrap;
SET LOCAL ROLE computedriven_bootstrap;

-- Returns the app_role for an ACTIVE membership of an ACTIVE principal in an
-- ACTIVE organization, or NULL. NULL means "no authority here" and is the same
-- answer authorize_membership() gives as false -- the two cannot disagree,
-- because both apply the identical three-status predicate.
CREATE OR REPLACE FUNCTION app.membership_role(
  p_principal_id    uuid,
  p_organization_id uuid
)
RETURNS text
LANGUAGE sql
SECURITY DEFINER
SET search_path = cd, pg_temp
STABLE
AS $$
  SELECT op.app_role
  FROM cd.organization_principals op
  JOIN cd.principals    p ON p.id = op.principal_id
  JOIN cd.organizations o ON o.id = op.organization_id
  WHERE op.principal_id    = p_principal_id
    AND op.organization_id = p_organization_id
    AND op.status          = 'active'
    AND p.status           = 'active'
    AND o.status           = 'active';
$$;

COMMENT ON FUNCTION app.membership_role(uuid, uuid) IS
  'The role a principal actually holds, or NULL. The client may request an '
  'operation; this is what decides whether it may have it.';

RESET ROLE;
SET LOCAL ROLE computedriven_migrations;
REVOKE CREATE ON SCHEMA app FROM computedriven_bootstrap;

-- Same ACL discipline as 0009: PUBLIC gets nothing, and only the request path
-- may call it. A new function created after 0009 is covered by the DEFAULT
-- PRIVILEGES it set, but asserting it here means a future reordering cannot
-- quietly reopen the hole.
REVOKE EXECUTE ON FUNCTION app.membership_role(uuid, uuid) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION app.membership_role(uuid, uuid) TO computedriven_api;

DO $$
BEGIN
  IF has_function_privilege('public', 'app.membership_role(uuid,uuid)', 'EXECUTE') THEN
    RAISE EXCEPTION 'CD-ACL-PUBLIC: PUBLIC holds EXECUTE on app.membership_role';
  END IF;
  IF has_function_privilege('computedriven_readonly', 'app.membership_role(uuid,uuid)', 'EXECUTE') THEN
    RAISE EXCEPTION 'CD-ACL-WIDE: computedriven_readonly can execute app.membership_role';
  END IF;
END
$$;

COMMIT;
