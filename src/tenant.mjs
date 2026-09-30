// Tenant context, established at transaction entry.
//
// This closes the gap R19 named. The database's guarantee is "no ROW may pass
// without a valid tenant context" -- not "every statement raises", because a
// statement the planner proves scans nothing never reaches the policy. So the
// raise is a loud backstop and THIS FILE is the primary control: context is set
// on entering the transaction, before any application query runs, or the
// transaction does not happen.
//
// DRIVER-AGNOSTIC ON PURPOSE
//
// Takes anything with `query(sql, params)`. The real binding is Hyperdrive ->
// Workers VPC -> Cloudflare Tunnel -> Pigsty (R7) and does not exist yet; the
// adapter is one file at the edge and is declared NOT DEPLOYED. Everything in
// here is provable today against a local PostgreSQL, which is the whole reason
// it is shaped this way.
//
// THE CONNECTION MUST BE A SINGLE CONNECTION
//
// BEGIN, set_config and COMMIT must reach the same backend. Under a transaction
// pooler that is guaranteed only within a transaction -- which is exactly what
// this helper opens. Do not hand it a pool that round-robins per statement.

export class TenantRefusal extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.name = "TenantRefusal";
    this.code = code;
  }
}

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * A tenant id that the SERVER derived from a verified token.
 *
 * This exists so "never trust an organization id the client sent" is a property
 * of the type system rather than a comment someone has to remember. The
 * constructor is guarded: the only way to obtain one is deriveTenant(), which
 * lives on the authenticated path. An organization id parsed out of a request
 * body is a plain string, and withTenant() refuses plain strings -- so the
 * dangerous version does not typecheck its way into production, it throws on
 * the first test that tries it.
 */
const GUARD = Symbol("server-derived");

export class ServerDerivedOrg {
  constructor(guard, organizationId, provenance) {
    if (guard !== GUARD) {
      throw new TenantRefusal(
        "CD-TENANT-FORGED",
        "ServerDerivedOrg cannot be constructed directly; use deriveTenant()"
      );
    }
    if (!UUID_RE.test(organizationId ?? "")) {
      throw new TenantRefusal("CD-TENANT-MALFORMED", "organization id is not a uuid");
    }
    this.organizationId = organizationId;
    this.provenance = provenance; // e.g. "workos:<iss>#<sub>"
    Object.freeze(this);
  }
  toString() {
    return this.organizationId;
  }
}

/**
 * The only factory. Call it from the authenticated path, after a token has been
 * verified AND membership has been authorized -- never before.
 */
export function deriveTenant(organizationId, provenance) {
  if (!provenance) {
    throw new TenantRefusal("CD-TENANT-UNPROVENANCED",
      "a derived tenant must record where it came from");
  }
  return new ServerDerivedOrg(GUARD, organizationId, provenance);
}

/**
 * Run `fn` inside a transaction whose tenant context is already established.
 *
 * @param conn  { query(sql, params) } -- a single connection
 * @param org   a ServerDerivedOrg. A string is refused.
 * @param fn    async (tx) => result, where tx has the same query() shape
 */
export async function withTenant(conn, org, fn) {
  if (!(org instanceof ServerDerivedOrg)) {
    throw new TenantRefusal(
      "CD-TENANT-UNVERIFIED",
      `refusing a tenant context that is not server-derived (got ${typeof org})`
    );
  }
  if (typeof fn !== "function") {
    throw new TenantRefusal("CD-TENANT-USAGE", "withTenant needs a callback");
  }

  await conn.query("BEGIN");
  try {
    // Transaction-local. Hyperdrive and PgBouncer both reset transaction state
    // when the connection goes back to the pool, which is what makes this the
    // correct primitive and a bare SET the wrong one.
    await conn.query("SELECT app.set_organization_context($1)", [org.organizationId]);
    const out = await fn(conn);
    await conn.query("COMMIT");
    return out;
  } catch (e) {
    // Rollback failure must not mask the original error -- that is how a useful
    // stack trace becomes "connection already closed".
    try {
      await conn.query("ROLLBACK");
    } catch { /* the original error is the interesting one */ }
    throw e;
  }
}

/**
 * The bootstrap path: a transaction with NO tenant context, for the three
 * resolvers that derive the context in the first place.
 *
 * Named this way so it is conspicuous in review. Every call site is a place
 * where tenant isolation is not in force, and there should only ever be one
 * (authz.mjs). If this appears anywhere else, that is the thing to question.
 */
export async function withoutTenant(conn, fn) {
  await conn.query("BEGIN");
  try {
    const out = await fn(conn);
    await conn.query("COMMIT");
    return out;
  } catch (e) {
    try {
      await conn.query("ROLLBACK");
    } catch { /* as above */ }
    throw e;
  }
}
