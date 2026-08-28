-- 0005 — the resolvers: the only code allowed to run without tenant context
--
-- Split out of 0002 because these reference tables created in 0003/0004, and a
-- LANGUAGE sql function is validated at CREATE time.

BEGIN;

SET LOCAL ROLE computedriven_migrations;

-- ---------------------------------------------------------------------------
-- The resolvers.
--
-- These are the ONLY functions permitted to run without tenant context, for a
-- reason that is easy to miss: the code that DERIVES tenant context cannot
-- itself require it. Login order is
--
--     verified OIDC token -> principal -> organization -> context -> queries
--
-- and the first three steps happen before there is a context to set.
--
-- They are SECURITY DEFINER and owned by computedriven_migrations, so they run
-- outside RLS. That is a deliberate, narrow escape hatch: three functions with
-- one job each, rather than granting the API role direct DML on the identity
-- tables. 0006 grants the API role EXECUTE on these and NO table privileges on
-- cd.principals / cd.principal_identities / cd.organization_identities.
--
-- search_path is pinned on each, because a SECURITY DEFINER function with a
-- caller-controlled search_path is a privilege-escalation primitive.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.resolve_principal(
  p_provider text,
  p_issuer   text,
  p_subject  text
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cd, pg_temp
AS $$
DECLARE
  found uuid;
  fresh uuid;
BEGIN
  IF p_provider IS NULL OR p_issuer IS NULL OR p_subject IS NULL
     OR btrim(p_provider) = '' OR btrim(p_issuer) = '' OR btrim(p_subject) = '' THEN
    RAISE EXCEPTION
      USING ERRCODE = '22023',
            MESSAGE = 'CD-IDENTITY-INCOMPLETE: provider, issuer and subject are all required';
  END IF;

  SELECT pi.principal_id INTO found
  FROM cd.principal_identities pi
  WHERE pi.provider = p_provider
    AND pi.issuer   = p_issuer
    AND pi.subject  = p_subject
    AND pi.status   = 'active';

  IF found IS NOT NULL THEN
    RETURN found;                       -- idempotent: same subject, same principal
  END IF;

  INSERT INTO cd.principals DEFAULT VALUES RETURNING id INTO fresh;

  INSERT INTO cd.principal_identities (principal_id, provider, issuer, subject)
  VALUES (fresh, p_provider, p_issuer, p_subject);

  RETURN fresh;
END;
$$;

COMMENT ON FUNCTION app.resolve_principal(text, text, text) IS
  'Idempotently maps an external OIDC identity to a ComputeDriven principal. '
  'The IdP subject is a BINDING, not the identity (R10).';

-- Organizations are NOT auto-created. Provisioning one is a deliberate act with
-- billing consequences; a login that names an unknown organization is a refusal,
-- not an invitation to create it.
CREATE OR REPLACE FUNCTION app.resolve_organization(
  p_provider        text,
  p_issuer          text,
  p_provider_org_id text
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = cd, pg_temp
AS $$
DECLARE
  found uuid;
BEGIN
  SELECT oi.organization_id INTO found
  FROM cd.organization_identities oi
  JOIN cd.organizations o ON o.id = oi.organization_id
  WHERE oi.provider        = p_provider
    AND oi.issuer          = p_issuer
    AND oi.provider_org_id = p_provider_org_id
    AND oi.status          = 'active'
    AND o.status           = 'active';

  IF found IS NULL THEN
    RAISE EXCEPTION
      USING ERRCODE = '42501',
            MESSAGE = format('CD-ORG-UNBOUND: no active organization bound to %L/%L',
                             p_provider, p_provider_org_id);
  END IF;

  RETURN found;
END;
$$;

COMMENT ON FUNCTION app.resolve_organization(text, text, text) IS
  'Maps an external IdP organization id to an internal organization id. Refuses '
  'unknown organizations; does not create them.';

-- Membership. Holding a token that names an organization is not authority over
-- it -- CLOUD_V1.md, the core law. This is the check that turns identity into
-- permission, and it is the last gate before context is established.
CREATE OR REPLACE FUNCTION app.authorize_membership(
  p_principal_id    uuid,
  p_organization_id uuid
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = cd, pg_temp
STABLE
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM cd.organization_principals op
    WHERE op.principal_id    = p_principal_id
      AND op.organization_id = p_organization_id
      AND op.status          = 'active'
  );
$$;

COMMENT ON FUNCTION app.authorize_membership(uuid, uuid) IS
  'A valid token saying you belong to org A does not itself grant authority. This does.';

-- Ownership: these three run as computedriven_bootstrap, which holds exactly the
-- narrow policies in 0007 and nothing else. See 0001 for why this role exists.
--
-- Transferring ownership of a function requires the incoming owner to hold
-- CREATE on its schema. Granted for the transfer and revoked immediately, so at
-- rest the bootstrap role has USAGE and cannot create anything in app.
GRANT USAGE, CREATE ON SCHEMA app TO computedriven_bootstrap;

ALTER FUNCTION app.resolve_principal(text, text, text)    OWNER TO computedriven_bootstrap;
ALTER FUNCTION app.resolve_organization(text, text, text) OWNER TO computedriven_bootstrap;
ALTER FUNCTION app.authorize_membership(uuid, uuid)       OWNER TO computedriven_bootstrap;

REVOKE CREATE ON SCHEMA app FROM computedriven_bootstrap;

-- cd.principals and cd.principal_identities carry no RLS (a principal is not
-- tenant-owned -- one human can be in several organizations), so the bootstrap
-- role reaches them by grant rather than by policy.
GRANT USAGE ON SCHEMA cd TO computedriven_bootstrap;
GRANT SELECT, INSERT ON cd.principals, cd.principal_identities TO computedriven_bootstrap;
GRANT SELECT ON cd.organization_identities TO computedriven_bootstrap;

-- A policy admits; a GRANT is still required. The two are independent gates and
-- needing both is the point: 0007 gives this role a SELECT policy on these two
-- tables, and without the grant below the policy alone reaches nothing. Read-only
-- on purpose -- the bootstrap path resolves identity and never mutates a tenant.
GRANT SELECT ON cd.organizations, cd.organization_principals TO computedriven_bootstrap;

COMMIT;
