-- 0012 — which FACTS an operation may change
--
-- BUG, found by outside review 2026-08-22 and reproduced before fixing. This is
-- the most serious defect found so far, because it composes.
--
-- 0011 wrote, in its own comment: "The API may read membership and record
-- last-seen; it may not enrol or remove." It then granted:
--
--     GRANT SELECT, UPDATE ON cd.organization_principals TO computedriven_api;
--
-- Table-level UPDATE reaches every column. Measured on a throwaway cluster:
--
--     role before:  viewer
--     UPDATE cd.organization_principals SET app_role='owner'   -> SUCCEEDED
--     role after:   owner
--     UPDATE ... SET status='active' (from 'revoked')           -> SUCCEEDED
--     final:        role=owner status=active
--
-- And it composes with 0010: permissionFor() derives R2 write authority from the
-- role membership_role() returns. So a viewer could promote itself and obtain a
-- write credential -- the exact escalation 0010 was written to prevent, reached
-- by a different door.
--
-- THE PATTERN, NOW NAMED. This is the third round where a comment described a
-- restriction the grant beside it did not implement:
--
--     0003  "provider_alias ... Never matched against."   the Worker matched on it
--     0004  "Immutable by convention"                     0007 granted UPDATE/DELETE
--     0011  "may only record last-seen"                   granted table-wide UPDATE
--
-- A comment is not an enforcement mechanism, and prose next to a GRANT reads as
-- though it were. Every restriction a comment claims must be expressed as a
-- privilege, a policy or a constraint -- or the comment must say "by convention,
-- not enforced" in those words.
--
-- THE LADDER, COMPLETE:
--
--     RLS               answers WHOSE row.
--     verb matrix       answers WHAT operation.
--     column authority  answers WHICH FACTS that operation may change.   <- 0012

BEGIN;

SET LOCAL ROLE computedriven_migrations;

-- Table-level UPDATE must go first. A column grant is meaningless while a
-- table-level grant reaches every column anyway.
REVOKE UPDATE ON cd.organization_principals, cd.organizations, cd.worlds, cd.wrl_heads
  FROM computedriven_api, computedriven_jobs;

-- ---------------------------------------------------------------------------
-- membership: the API records a fact about a session, and nothing else.
--
-- app_role and status are AUTHORITY. They move through a management path, which
-- is the jobs role today and will be an explicit administrative surface later.
-- organization_id and principal_id are the identity of the row itself: changing
-- either is not an update, it is a forgery.
-- ---------------------------------------------------------------------------
GRANT UPDATE (last_seen_at) ON cd.organization_principals TO computedriven_api;
GRANT UPDATE (app_role, status, last_seen_at)
  ON cd.organization_principals TO computedriven_jobs;

-- ---------------------------------------------------------------------------
-- organizations: a display name is cosmetic. `slug` is routing identity and
-- `status` is suspension -- neither belongs on the request path.
-- ---------------------------------------------------------------------------
GRANT UPDATE (display_name) ON cd.organizations TO computedriven_api;
GRANT UPDATE (display_name, status) ON cd.organizations TO computedriven_jobs;

-- ---------------------------------------------------------------------------
-- worlds: renaming and archiving are ordinary product operations. `id`,
-- `organization_id` and `created_at` are not facts a request may revise --
-- moving a world between tenants by UPDATE would defeat every layer above.
-- ---------------------------------------------------------------------------
GRANT UPDATE (name, status) ON cd.worlds TO computedriven_api, computedriven_jobs;

-- ---------------------------------------------------------------------------
-- wrl_heads: genuinely a pointer. Moving it is the whole operation -- but the
-- world it points AT is fixed.
-- ---------------------------------------------------------------------------
GRANT UPDATE (wrl_head, semantic_head, updated_at)
  ON cd.wrl_heads TO computedriven_api, computedriven_jobs;

-- ---------------------------------------------------------------------------
-- Assertions. Each names a column whose mutability would undo a layer above.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  bad text;
  forbidden text[][] := ARRAY[
    ['computedriven_api','organization_principals','app_role'],
    ['computedriven_api','organization_principals','status'],
    ['computedriven_api','organization_principals','principal_id'],
    ['computedriven_api','organization_principals','organization_id'],
    ['computedriven_api','organizations','slug'],
    ['computedriven_api','organizations','status'],
    ['computedriven_api','worlds','id'],
    ['computedriven_api','worlds','organization_id'],
    ['computedriven_api','worlds','created_at'],
    ['computedriven_api','wrl_heads','world_id'],
    ['computedriven_api','wrl_heads','organization_id'],
    ['computedriven_jobs','organization_principals','principal_id'],
    ['computedriven_jobs','worlds','organization_id']
  ];
  i int;
BEGIN
  FOR i IN 1 .. array_length(forbidden, 1) LOOP
    IF has_column_privilege(forbidden[i][1], 'cd.' || forbidden[i][2],
                            forbidden[i][3], 'UPDATE') THEN
      bad := coalesce(bad || ', ', '') ||
             format('%s may UPDATE %s.%s', forbidden[i][1], forbidden[i][2], forbidden[i][3]);
    END IF;
  END LOOP;
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'CD-COLUMN-AUTHORITY: %', bad;
  END IF;
END
$$;

-- ...and the intended updates must still work, or this is not a matrix, it is a
-- wall. A restriction that also breaks the product is not a win.
DO $$
BEGIN
  IF NOT has_column_privilege('computedriven_api', 'cd.organization_principals',
                              'last_seen_at', 'UPDATE') THEN
    RAISE EXCEPTION 'CD-COLUMN-AUTHORITY: the API can no longer record last_seen_at';
  END IF;
  IF NOT has_column_privilege('computedriven_api', 'cd.worlds', 'status', 'UPDATE') THEN
    RAISE EXCEPTION 'CD-COLUMN-AUTHORITY: the API can no longer archive a world';
  END IF;
  IF NOT has_column_privilege('computedriven_api', 'cd.wrl_heads', 'wrl_head', 'UPDATE') THEN
    RAISE EXCEPTION 'CD-COLUMN-AUTHORITY: the API can no longer move a WRL head';
  END IF;
END
$$;

COMMIT;
