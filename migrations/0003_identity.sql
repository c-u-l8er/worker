-- 0003 — identity: provider-independent roots, external bindings beside them
--
-- R10. `principals` and `organizations` are ComputeDriven's own id space.
-- Keycloak's `sub` and its organization id are BINDINGS to that space, held in
-- `principal_identities` / `organization_identities` with status and history.
--
-- The failure this shape defends against is NOT backup/restore -- a faithful
-- restore of the same Keycloak database preserves its ids. It is:
--
--     a clean realm rebuild · a realm migration · an IdP change ·
--     leaving Keycloak entirely
--
-- any of which reissues subjects. With bindings, that is a rebind. With
-- `principals.keycloak_sub`, it is a data-loss event with no recovery path --
-- and CLOUD_V1.md's own release gate rehearses exactly those operations.

BEGIN;

SET LOCAL ROLE computedriven_migrations;

CREATE TABLE cd.principals (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  status     text NOT NULL DEFAULT 'active'
             CHECK (status IN ('active', 'suspended', 'closed')),
  created_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE cd.principals IS
  'A ComputeDriven application identity. Holds no credential and no IdP id (R10).';

CREATE TABLE cd.principal_identities (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  principal_id uuid NOT NULL REFERENCES cd.principals(id) ON DELETE RESTRICT,
  provider     text NOT NULL,                       -- 'keycloak'
  issuer       text NOT NULL,                       -- OIDC iss
  subject      text NOT NULL,                       -- OIDC sub
  status       text NOT NULL DEFAULT 'active'
               CHECK (status IN ('active', 'unbound')),
  bound_at     timestamptz NOT NULL DEFAULT now(),
  unbound_at   timestamptz,
  CONSTRAINT principal_identity_unbind_consistent CHECK (
    (status = 'active'  AND unbound_at IS NULL) OR
    (status = 'unbound' AND unbound_at IS NOT NULL)
  )
);

-- Partial-unique on ACTIVE only. Two consequences, both wanted:
--   * the same subject can never have two live bindings (idempotent login);
--   * an unbound row stays as history, and the subject can be rebound later.
CREATE UNIQUE INDEX principal_identities_active_uq
  ON cd.principal_identities (provider, issuer, subject)
  WHERE status = 'active';

CREATE INDEX principal_identities_principal_idx
  ON cd.principal_identities (principal_id);

COMMENT ON TABLE cd.principal_identities IS
  'External IdP bindings. Never store a password or a token here.';

CREATE TABLE cd.organizations (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug         text NOT NULL UNIQUE,
  display_name text NOT NULL,
  status       text NOT NULL DEFAULT 'active'
               CHECK (status IN ('active', 'suspended', 'closed')),
  created_at   timestamptz NOT NULL DEFAULT now()
);

COMMENT ON COLUMN cd.organizations.slug IS
  'Human-readable, for routing. NEVER the security boundary -- id is.';

CREATE TABLE cd.organization_identities (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES cd.organizations(id) ON DELETE RESTRICT,
  provider        text NOT NULL,
  issuer          text NOT NULL,
  provider_org_id text NOT NULL,
  provider_alias  text,
  status          text NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active', 'unbound')),
  bound_at        timestamptz NOT NULL DEFAULT now(),
  unbound_at      timestamptz,
  CONSTRAINT organization_identity_unbind_consistent CHECK (
    (status = 'active'  AND unbound_at IS NULL) OR
    (status = 'unbound' AND unbound_at IS NOT NULL)
  )
);

CREATE UNIQUE INDEX organization_identities_active_uq
  ON cd.organization_identities (provider, issuer, provider_org_id)
  WHERE status = 'active';

COMMENT ON COLUMN cd.organization_identities.provider_alias IS
  'The IdP-side human name. Recorded for debugging. Never matched against.';

-- The application shadow. Keycloak stays authoritative for authentication and
-- for who is in an organization; this table is what the product knows about that
-- membership -- app role, first/last seen, local status.
CREATE TABLE cd.organization_principals (
  organization_id uuid NOT NULL REFERENCES cd.organizations(id) ON DELETE RESTRICT,
  principal_id    uuid NOT NULL REFERENCES cd.principals(id)    ON DELETE RESTRICT,
  app_role        text NOT NULL DEFAULT 'member'
                  CHECK (app_role IN ('owner', 'admin', 'member', 'viewer')),
  status          text NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active', 'revoked')),
  first_seen_at   timestamptz NOT NULL DEFAULT now(),
  last_seen_at    timestamptz,
  PRIMARY KEY (organization_id, principal_id)
);

COMMENT ON TABLE cd.organization_principals IS
  'Application membership shadow. NOT the auth source -- Keycloak is (R10).';

COMMIT;
