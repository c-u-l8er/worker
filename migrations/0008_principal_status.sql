-- 0008 — make principal.status mean something
--
-- BUG, found by outside review 2026-08-21 and reproduced before fixing.
--
-- 0003 gives a principal three states -- active / suspended / closed -- and
-- nothing anywhere enforced them. Measured on a throwaway cluster:
--
--     principal.status            = suspended
--     principal_identity.status   = active
--     organization_principals     = active
--         -> resolve_principal()    SUCCEEDS
--         -> authorize_membership() TRUE
--
-- So `suspended` was decorative: a schema advertising a state with no semantic
-- consequence. The asymmetry made it easy to miss -- resolve_organization()
-- already checked o.status = 'active', so organizations were enforced and
-- principals were not.
--
-- Fixed in BOTH places on purpose:
--   * resolve_principal() refuses by name, so an operator debugging "why can
--     this person not log in" gets CD-PRINCIPAL-SUSPENDED rather than a silent
--     authorization false;
--   * authorize_membership() re-checks all three, so the authorization answer
--     does not depend on the caller having gone through the resolver first.

BEGIN;

SET LOCAL ROLE computedriven_migrations;

-- CREATE OR REPLACE requires ownership, and 0005 handed these to the bootstrap
-- role. Same borrow-and-return dance as 0005: CREATE on the schema is granted
-- for the replacement and revoked immediately after.
GRANT CREATE ON SCHEMA app TO computedriven_bootstrap;
SET LOCAL ROLE computedriven_bootstrap;

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
  found  uuid;
  st     text;
  fresh  uuid;
BEGIN
  IF p_provider IS NULL OR p_issuer IS NULL OR p_subject IS NULL
     OR btrim(p_provider) = '' OR btrim(p_issuer) = '' OR btrim(p_subject) = '' THEN
    RAISE EXCEPTION
      USING ERRCODE = '22023',
            MESSAGE = 'CD-IDENTITY-INCOMPLETE: provider, issuer and subject are all required';
  END IF;

  SELECT pi.principal_id, p.status
    INTO found, st
  FROM cd.principal_identities pi
  JOIN cd.principals p ON p.id = pi.principal_id
  WHERE pi.provider = p_provider
    AND pi.issuer   = p_issuer
    AND pi.subject  = p_subject
    AND pi.status   = 'active';

  IF found IS NOT NULL THEN
    IF st <> 'active' THEN
      -- A live IdP binding onto a principal that is not active. The binding is
      -- fine; the principal is not. Refuse by name.
      RAISE EXCEPTION
        USING ERRCODE = '42501',
              MESSAGE = format('CD-PRINCIPAL-%s: principal %s is %s, not active',
                               upper(st), found, st);
    END IF;
    RETURN found;                       -- idempotent: same subject, same principal
  END IF;

  INSERT INTO cd.principals DEFAULT VALUES RETURNING id INTO fresh;

  INSERT INTO cd.principal_identities (principal_id, provider, issuer, subject)
  VALUES (fresh, p_provider, p_issuer, p_subject);

  RETURN fresh;
END;
$$;

-- All three statuses, not just the membership row. A token is not authority;
-- neither is a membership whose principal has been suspended underneath it.
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
    JOIN cd.principals    p ON p.id = op.principal_id
    JOIN cd.organizations o ON o.id = op.organization_id
    WHERE op.principal_id    = p_principal_id
      AND op.organization_id = p_organization_id
      AND op.status          = 'active'
      AND p.status           = 'active'
      AND o.status           = 'active'
  );
$$;

RESET ROLE;
SET LOCAL ROLE computedriven_migrations;
REVOKE CREATE ON SCHEMA app FROM computedriven_bootstrap;

COMMIT;
