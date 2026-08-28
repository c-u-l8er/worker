-- 0006 — audit events
--
-- Enough to make the M1 lifecycle visible: who did what, in which organization.
-- Not a receipt. A receipt names authority, placement and an executing node, and
-- none of those exist until M3/M4 -- calling this one would be an overclaim.

BEGIN;

SET LOCAL ROLE computedriven_migrations;

CREATE TABLE cd.audit_events (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES cd.organizations(id) ON DELETE RESTRICT,
  principal_id    uuid REFERENCES cd.principals(id) ON DELETE RESTRICT,
  action          text NOT NULL,
  subject_kind    text,
  subject_id      text,
  outcome         text NOT NULL DEFAULT 'ok'
                  CHECK (outcome IN ('ok', 'refused', 'failed')),
  detail          jsonb NOT NULL DEFAULT '{}'::jsonb,
  occurred_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_events_org_time_idx
  ON cd.audit_events (organization_id, occurred_at DESC);

COMMENT ON COLUMN cd.audit_events.outcome IS
  'refused and failed are DIFFERENT. A refusal is the system working.';

COMMIT;
