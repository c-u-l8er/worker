-- 0011 — what may happen to a row, as distinct from whose row it is
--
-- BUG, found by outside review 2026-08-22 and reproduced before fixing.
--
-- 0004 documents world_versions as "Immutable by convention: a new state is a
-- new version, never an UPDATE, so history cannot be rewritten." 0007 then
-- granted the API role SELECT, INSERT, **UPDATE** and **DELETE** on every tenant
-- table, world_versions and audit_events included. So "cannot be rewritten" was
-- convention in the strictest sense: nothing enforced it.
--
--     UPDATE cd.world_versions SET manifest_root = 'hash-B' WHERE ...
--
-- is a legal statement for the request-plane role, inside its own tenant. RLS
-- had nothing to say about it, because RLS answers a different question:
--
--     TENANT ISOLATION answers WHOSE row.
--     TABLE AUTHORITY answers WHAT MAY HAPPEN to that row.
--
-- The database was excellent at the first and silently permissive at the second.
-- The same blanket grant made audit_events erasable by the very role whose
-- actions it records, which is the one property an audit table cannot have.
--
-- The verb matrix below is the whole fix. Group I of the battery proves each
-- refusal by attempting it and then witnessing that the row did not change --
-- a privilege bit alone is not proof that the data survived.

BEGIN;

SET LOCAL ROLE computedriven_migrations;

-- ---------------------------------------------------------------------------
-- Start from nothing. Re-granting is explicit below, so the matrix is readable
-- in one place rather than inferred from a history of ALTERs.
-- ---------------------------------------------------------------------------
REVOKE ALL ON cd.organizations, cd.organization_principals, cd.worlds,
              cd.world_versions, cd.wrl_heads, cd.audit_events
  FROM computedriven_api, computedriven_jobs, computedriven_readonly;

-- APPEND-ONLY. No UPDATE, no DELETE, for any request-plane role.
--
-- A world version is a claim about what a machine looked like at an instant.
-- Editing one does not correct history; it forges it. Superseding is what
-- inserting the next version is for.
GRANT SELECT, INSERT ON cd.world_versions TO computedriven_api, computedriven_jobs;
GRANT SELECT           ON cd.world_versions TO computedriven_readonly;

-- Likewise, and more so. An audit row exists to survive the actor.
GRANT SELECT, INSERT ON cd.audit_events TO computedriven_api, computedriven_jobs;
GRANT SELECT           ON cd.audit_events TO computedriven_readonly;

-- Genuinely mutable: a head is a pointer, and moving it is the operation.
GRANT SELECT, INSERT, UPDATE ON cd.wrl_heads TO computedriven_api, computedriven_jobs;
GRANT SELECT                 ON cd.wrl_heads TO computedriven_readonly;

-- Worlds may be created and amended, and ARCHIVED rather than deleted -- so the
-- versions and receipts that reference a world can never be orphaned by an
-- ordinary request. `status = 'archived'` is the retirement path.
GRANT SELECT, INSERT, UPDATE ON cd.worlds TO computedriven_api, computedriven_jobs;
GRANT SELECT                 ON cd.worlds TO computedriven_readonly;

-- The organization row itself: readable and amendable, never created or removed
-- from the request path. Provisioning and closure are deliberate acts elsewhere.
GRANT SELECT, UPDATE ON cd.organizations TO computedriven_api, computedriven_jobs;
GRANT SELECT         ON cd.organizations TO computedriven_readonly;

-- Membership changes are a management operation, not a side effect of a request.
-- The API may read membership and record last-seen; it may not enrol or remove.
GRANT SELECT, UPDATE ON cd.organization_principals TO computedriven_api;
GRANT SELECT, INSERT, UPDATE ON cd.organization_principals TO computedriven_jobs;
GRANT SELECT         ON cd.organization_principals TO computedriven_readonly;

-- ---------------------------------------------------------------------------
-- Assert the matrix, so a later blanket GRANT fails here rather than in
-- production. This is the check that would have caught the original defect.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  bad text;
BEGIN
  SELECT string_agg(format('%s:%s:%s', r, t, v), ', ') INTO bad
  FROM (
    SELECT r, t, v
    FROM unnest(ARRAY['computedriven_api','computedriven_jobs','computedriven_readonly']) r,
         unnest(ARRAY['world_versions','audit_events']) t,
         unnest(ARRAY['UPDATE','DELETE']) v
    WHERE has_table_privilege(r, 'cd.' || t, v)
  ) q;
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'CD-VERB-APPEND-ONLY: % holds a mutating verb on an append-only table', bad;
  END IF;
END
$$;

DO $$
DECLARE
  bad text;
BEGIN
  -- No request-plane role may DELETE anything in cd. Retirement is a status
  -- change; removal is a migration.
  SELECT string_agg(format('%s:%s', r, c.relname), ', ') INTO bad
  FROM unnest(ARRAY['computedriven_api','computedriven_jobs','computedriven_readonly']) r,
       pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'cd' AND c.relkind = 'r'
    AND has_table_privilege(r, c.oid, 'DELETE');
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'CD-VERB-DELETE: % holds DELETE in cd', bad;
  END IF;
END
$$;

COMMIT;
