// The authenticated path: token -> principal -> organization -> membership ->
// role -> tenant. The ONLY module that calls withoutTenant().
//
// The core law, in the order it actually executes:
//
//   Keycloak identifies the subject.   verifyToken()
//   Pigsty owns ComputeDriven truth.   resolve_principal / resolve_organization
//   Membership is a separate answer.   membership_role
//   Only then is there a tenant.       deriveTenant()
//
// A valid token that says you belong to org A does not itself grant authority
// over org A. The database grants it, and it answers with a ROLE -- because
// "is a member" and "may write" are different questions.

import { verifyToken, assertVerified, JwtRefusal } from "./jwt.mjs";
import { withoutTenant, deriveTenant, TenantRefusal } from "./tenant.mjs";

export class AuthzRefusal extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.name = "AuthzRefusal";
    this.code = code;
  }
}

/**
 * Pull {alias, providerOrgId} pairs out of the organization claim.
 *
 * R10, AND THE PLACE THE WORKER PREVIOUSLY UNDID IT.
 *
 * `cd.organization_identities` separates `provider_org_id` (stable, in the
 * active-unique index) from `provider_alias` (which 0003 documents as
 * "Recorded for debugging. Never matched against."). An earlier version of this
 * function returned `Object.keys(raw)` -- the ALIASES -- and the authenticated
 * path fed one of them into resolve_organization()'s `p_provider_org_id`. The
 * Worker was matching on exactly the column the schema says never to match on.
 *
 * Two ways that bites, neither hypothetical:
 *   * rename an organization in Keycloak and its ComputeDriven binding is
 *     orphaned, though nothing about the organization actually changed;
 *   * a freed alias reused by a DIFFERENT organization silently resolves to the
 *     old one -- a cross-tenant bind produced by an administrator doing
 *     something ordinary.
 *
 * Keycloak does not include the organization id by default: the Organization
 * Membership mapper has an explicit "Add organization id" setting. So the
 * absence of an id is a REALM MISCONFIGURATION and is refused by name. Falling
 * back to the alias would reintroduce the bug precisely when the realm is set up
 * wrong, which is the worst moment to be lenient.
 */
export function organizationEntries(claims, claimName = "organization") {
  const raw = claims?.[claimName];
  if (raw === undefined || raw === null) return [];

  if (!Array.isArray(raw) && typeof raw === "object") {
    return Object.entries(raw).map(([alias, meta]) => {
      const id = meta?.id;
      if (typeof id !== "string" || id === "") {
        throw new AuthzRefusal(
          "CD-AUTHZ-ORGID-MISSING",
          `organization ${JSON.stringify(alias)} carries no id; enable ` +
          `"Add organization id" on the Organization Membership mapper`
        );
      }
      return { alias, providerOrgId: id };
    });
  }

  // Alias-only shapes. They parse, they look fine, and they carry no stable
  // identity at all -- so they are refused rather than accepted as aliases.
  if (Array.isArray(raw) || typeof raw === "string") {
    throw new AuthzRefusal(
      "CD-AUTHZ-ORGID-MISSING",
      "the organization claim carries aliases but no ids"
    );
  }
  throw new AuthzRefusal("CD-AUTHZ-ORGCLAIM", `${claimName} has an unusable shape`);
}

/**
 * Which organization is this request for?
 *
 * Selection is BY ALIAS, because that is what a human picks in a UI and what a
 * URL can carry. Resolution is BY ID. The alias never leaves this function.
 */
export function chooseOrganization(entries, requestedAlias) {
  if (entries.length === 0) {
    throw new AuthzRefusal("CD-AUTHZ-NOORG", "token asserts no organization");
  }
  if (requestedAlias !== undefined && requestedAlias !== null && requestedAlias !== "") {
    const hit = entries.find((e) => e.alias === requestedAlias);
    if (!hit) {
      // Note what is NOT said: we do not reveal which organizations the token
      // does assert.
      throw new AuthzRefusal("CD-AUTHZ-ORGMISMATCH",
        "token does not assert the requested organization");
    }
    return hit;
  }
  if (entries.length > 1) {
    throw new AuthzRefusal("CD-AUTHZ-ORGAMBIGUOUS",
      `token asserts ${entries.length} organizations; the request must name one`);
  }
  return entries[0];
}

/**
 * The maximum object permission a role may hold.
 *
 * THE LAW: the client may request an operation. The client never chooses its
 * authority. An earlier version passed `body.permission` straight into
 * scopeForWorld(), so an active `viewer` could ask for -- and be scoped for --
 * writes. Valid is not authorized.
 *
 * An over-reach is REFUSED, not silently downgraded. A client that asked to
 * upload and quietly received a read credential fails later, somewhere else,
 * with a message about R2 rather than about permission.
 */
const MAX_PERMISSION = Object.freeze({
  owner: "object-write",
  admin: "object-write",
  member: "object-write",
  viewer: "object-read",
});

export function permissionFor({ role, requested = "object-read", worldStatus = "active" }) {
  const max = MAX_PERMISSION[role];
  if (!max) {
    throw new AuthzRefusal("CD-AUTHZ-NOROLE", "the principal holds no role in that organization");
  }
  if (requested !== "object-read" && requested !== "object-write") {
    throw new AuthzRefusal("CD-AUTHZ-PERM", `unknown permission ${JSON.stringify(requested)}`);
  }
  if (requested === "object-write") {
    if (max !== "object-write") {
      throw new AuthzRefusal("CD-AUTHZ-WRITEDENIED",
        `role ${role} may not obtain write authority`);
    }
    if (worldStatus !== "active") {
      throw new AuthzRefusal("CD-AUTHZ-WORLDARCHIVED",
        `world is ${worldStatus}; writes are refused`);
    }
  }
  return requested;
}

function one(result, column, code, what) {
  const rows = result?.rows ?? result;
  const row = Array.isArray(rows) ? rows[0] : undefined;
  const val = row?.[column];
  if (val === undefined) {
    throw new AuthzRefusal(code, `${what} returned no value`);
  }
  return val;
}

export async function authenticate({ token, jwks, expected, ...rest }) {
  // 1. Keycloak identifies the subject. Throws JwtRefusal by name on failure.
  const claims = await verifyToken(token, jwks, expected);
  // 2-4. Everything downstream operates on VERIFIED claims and nothing else.
  return authorizeClaims({ claims, ...rest });
}

/**
 * Steps 2-4, split out so they are testable without a token.
 *
 * The split is not a testing convenience -- it is the boundary that matters.
 * Above this line a token is an untrusted string; below it, `claims` are
 * verified facts. Keeping the two callable separately makes that boundary
 * something a reader can see rather than something they have to trace, and means
 * the authorization battery exercises the real function instead of needing a
 * test-only bypass inside authenticate().
 */
export async function authorizeClaims({
  claims,
  conn,
  requestedOrganization,
  provider = "keycloak",
  organizationClaim = "organization",
}) {
  if (!conn) throw new AuthzRefusal("CD-AUTHZ-CONFIG", "a connection is required");
  // PROVENANCE, not shape. The previous check tested that `sub` and `iss` were
  // strings -- which a fabricated object satisfies trivially, so the test named
  // "claims that were never verified are refused" was passing because `iss` was
  // missing, not because anything proved verification happened. This throws
  // CD-JWT-UNVERIFIED for any object verifyToken() did not itself return.
  assertVerified(claims);

  // 2. Which organization, decided before touching the database. Chosen by
  //    alias; resolved by stable id.
  const chosen = chooseOrganization(
    organizationEntries(claims, organizationClaim),
    requestedOrganization
  );

  // 3. Pigsty owns the truth. This is the one place without tenant context,
  //    because these are the calls that produce it.
  const resolved = await withoutTenant(conn, async (tx) => {
    const principalId = one(
      await tx.query("SELECT app.resolve_principal($1,$2,$3) AS id",
        [provider, claims.iss, claims.sub]),
      "id", "CD-AUTHZ-PRINCIPAL", "resolve_principal"
    );
    const organizationId = one(
      await tx.query("SELECT app.resolve_organization($1,$2,$3) AS id",
        [provider, claims.iss, chosen.providerOrgId]),
      "id", "CD-AUTHZ-ORG", "resolve_organization"
    );
    // The finer answer. NULL means no authority, identical to authorize_membership
    // returning false -- both apply the same three-status predicate.
    const role = one(
      await tx.query("SELECT app.membership_role($1,$2) AS role",
        [principalId, organizationId]),
      "role", "CD-AUTHZ-MEMBERSHIP", "membership_role"
    );
    return { principalId, organizationId, role };
  });

  // 4. Membership is its own answer, and it is the one that grants authority.
  //    resolve_* succeeding is not the same as being allowed in.
  if (typeof resolved.role !== "string" || !Object.hasOwn(MAX_PERMISSION, resolved.role)) {
    throw new AuthzRefusal("CD-AUTHZ-DENIED",
      "the principal is not an active member of that organization");
  }

  return {
    claims,
    principalId: resolved.principalId,
    organizationId: resolved.organizationId,
    organizationAlias: chosen.alias,
    role: resolved.role,
    tenant: deriveTenant(
      resolved.organizationId,
      `${provider}:${claims.iss}#${claims.sub}`
    ),
  };
}

/** Every refusal this path can produce, so a handler can map them uniformly. */
export function refusalCode(err) {
  if (err instanceof AuthzRefusal || err instanceof JwtRefusal || err instanceof TenantRefusal) {
    return err.code;
  }
  return null;
}
