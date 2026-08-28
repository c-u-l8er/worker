// The Worker entry point. Deliberately thin: every decision worth testing lives
// in a module this file calls, so the handler is routing and error mapping and
// nothing else.
//
// NOT DEPLOYED. There is no account, no Hyperdrive binding, no R2 bucket and no
// Keycloak realm. `env.DB` is expected to be a Hyperdrive binding whose adapter
// does not exist yet -- see the note on connect() below. This file is here so
// the shape is reviewable and so the modules beneath it have a real caller;
// running it against production would fail at the first query, by design.

import { JwksCache, verifyToken, JwtRefusal } from "./jwt.mjs";
import { authorizeClaims, permissionFor, AuthzRefusal } from "./authz.mjs";
import { withTenant, TenantRefusal } from "./tenant.mjs";
import { scopeForWorld, WRITE_PERMISSIONS, R2Provider, CredentialRefusal } from "./r2creds.mjs";
import { admitStorage, AdmissionRefusal } from "./admission.mjs";
import { observeBatch } from "./reconcile.mjs";

// Refusal -> HTTP. A refusal is the system working, so these are 4xx and carry
// their code; only an unrecognised error is a 500. REFUSED and FAILED stay
// distinguishable all the way out to the wire.
const STATUS = {
  "CD-JWT-CONFIG": 500, "CD-JWKS-CONFIG": 500, "CD-AUTHZ-CONFIG": 500,
  "CD-JWKS-FETCH": 503, "CD-JWKS-PARSE": 503,
  "CD-AUTHZ-DENIED": 403, "CD-AUTHZ-ORGMISMATCH": 403,
  "CD-AUTHZ-WRITEDENIED": 403, "CD-AUTHZ-NOROLE": 403,
  "CD-AUTHZ-WORLDARCHIVED": 409, "CD-AUTHZ-ORGAMBIGUOUS": 409,
  "CD-AUTHZ-PERM": 400,
  // A realm misconfiguration, not a caller error -- the operator has to fix the
  // Organization Membership mapper, and a 401 would send them hunting the token.
  "CD-AUTHZ-ORGID-MISSING": 503,
  "CD-CRED-NOTDEPLOYED": 501,
  // R24 / M1.5. A quota refusal is 507 rather than 403 because nothing about
  // the caller's authority is wrong -- it has run out of room, and a client
  // that reads 403 will go looking for a permissions problem it does not have.
  "CD-QUOTA-EXCEEDED": 507,
  "CD-RESERVE-NOENTITLEMENT": 402,
  "CD-RESERVE-ROLE": 403, "CD-RESERVE-NOTMEMBER": 403,
  "CD-RESERVE-WORLD": 404, "CD-RESERVE-WORLDSTATUS": 409,
  "CD-RESERVE-SETTLED": 409, "CD-RESERVE-TTL": 400,
  "CD-RESERVE-BYTES": 400, "CD-RESERVE-IDEMPOTENCY": 400,
  "CD-ADMISSION-BYTES": 400, "CD-ADMISSION-IDEMPOTENCY": 400,
  "CD-CRED-ADMISSION": 400,
  "CD-FINALIZE-CONFLICT": 409, "CD-FINALIZE-STATE": 409,
  "CD-FINALIZE-OVERRUN": 507, "CD-FINALIZE-NOTFOUND": 404,
};

function refuse(err) {
  const known =
    err instanceof JwtRefusal ||
    err instanceof AuthzRefusal ||
    err instanceof TenantRefusal ||
    err instanceof CredentialRefusal ||
    err instanceof AdmissionRefusal;
  if (!known) {
    // Do not leak an unexpected stack to the caller. This is the only 500.
    return Response.json({ error: "internal", code: null }, { status: 500 });
  }
  const status = STATUS[err.code] ?? 401;
  // The code is safe to return: it names WHICH rule refused, never what the
  // caller would have needed to satisfy it.
  return Response.json({ error: "refused", code: err.code }, { status });
}

/**
 * JWKS caches live at MODULE scope, not per request.
 *
 * THE BUG THIS FIXES, and it is the most interesting one found so far: the
 * handler used to do `new JwksCache(...)` inside fetch(). Every request got a
 * fresh object with `keys = null` and `forcedAt = 0`, so R22's forced-refresh
 * cooldown -- proven correct by its own module test -- did not exist at the
 * entrypoint. 1000 requests with 1000 invented kids meant 1000 issuer fetches.
 *
 *     the module law passed; composition falsified it.
 *
 * WHAT THIS DOES AND DOES NOT BUY. Workers reuse isolates, so in practice this
 * shares the cache and the cooldown across most requests. It is NOT a durable
 * global limit: an isolate can be evicted at any time and requests are not
 * guaranteed to land on the same one. So this is best-effort in-isolate
 * protection. The cross-request mechanism -- Cache API for the JWKS document,
 * a Rate Limiting binding for refresh admission -- is named in status.json as
 * `spec` and is NOT claimed here.
 */
const JWKS_CACHES = new Map();

function jwksFor(env) {
  const uri = env?.KEYCLOAK_JWKS_URI;
  if (!uri) throw new JwtRefusal("CD-JWKS-CONFIG", "KEYCLOAK_JWKS_URI is not configured");
  let cache = JWKS_CACHES.get(uri);
  if (!cache) {
    cache = new JwksCache({ jwksUri: uri });
    JWKS_CACHES.set(uri, cache);
  }
  return cache;
}

function bearer(request) {
  const h = request.headers.get("authorization") ?? "";
  const m = /^Bearer (.+)$/.exec(h);
  if (!m) throw new JwtRefusal("CD-JWT-SHAPE", "no bearer token");
  return m[1];
}

/**
 * The Hyperdrive adapter.
 *
 * R17: the control-plane binding must have caching DISABLED. Everything this
 * Worker reads is authorization, tenancy, membership or billing state, and the
 * cache cannot see the RLS predicate PostgreSQL adds -- two tenants issue
 * byte-identical SQL and the correct answers differ.
 *
 * NOT IMPLEMENTED. A driver has to be chosen and neither the binding nor a
 * bucket exists. Throwing here rather than shipping a stub means this cannot be
 * mistaken for a working integration.
 */
async function connect(env) {
  if (!env?.HYPERDRIVE_CONTROL) {
    throw new CredentialRefusal(
      "CD-CRED-NOTDEPLOYED",
      "no HYPERDRIVE_CONTROL binding; the control-plane database is not connected"
    );
  }
  throw new CredentialRefusal(
    "CD-CRED-NOTDEPLOYED",
    "the Hyperdrive driver adapter is not implemented (M1, still spec)"
  );
}

/**
 * The QUEUE CONSUMER's connection, and it is a different one on purpose.
 *
 * The observer runs as `computedriven_jobs`: cross-tenant by nature, no tenant
 * context, and the only role granted EXECUTE on app.observe_storage_object().
 * The request role is deliberately NOT -- telling the ledger that bytes landed
 * is exactly the client-asserted path R68 replaced. Two named functions rather
 * than one with a flag, so the separation is visible at the call site.
 *
 * NOT IMPLEMENTED, for the same reason as connect().
 */
async function connectJobs(env) {
  // A DIFFERENT BINDING, not the same one (finding 94, R80). A Hyperdrive
  // configuration carries its own origin user and password, so one binding is
  // one database credential -- and these two helpers reading HYPERDRIVE_CONTROL
  // between them would have made `computedriven_api` and `computedriven_jobs`
  // one authority wearing two function names, at the moment the driver was
  // written and without any test noticing. Each binding's origin user is a
  // LOGIN principal inheriting exactly one of the two NOLOGIN roles.
  //
  // The alternative -- one login holding both roles with SET ROLE at runtime --
  // is refused: the credential then possesses the union, and the boundary is
  // enforced by convention rather than by the database.
  if (!env?.HYPERDRIVE_JOBS) {
    throw new CredentialRefusal(
      "CD-CRED-NOTDEPLOYED",
      "no HYPERDRIVE_JOBS binding; the queue consumer has no jobs-role credential"
    );
  }
  throw new CredentialRefusal(
    "CD-CRED-NOTDEPLOYED",
    "the Hyperdrive driver adapter is not implemented (M1, still spec)"
  );
}

/**
 * CHANNEL ADMISSION — finding 89, R77's second half.
 *
 * R77 gave delivery identity its channel: the row records WHICH queue delivered
 * a message. That answers *identity*. It does not answer *authority*:
 *
 *     identity    which queue delivered this message?
 *     authority   is THIS one of the queues permitted to assert provider truth?
 *
 * `observeBatch()` answered only the first -- it read whatever `batch.queue`
 * contained and recorded it. Cloudflare explicitly supports attaching one
 * consumer Worker to several queues and tells applications to switch on
 * `MessageBatch.queue`, so "the batch names a channel" and "the channel had
 * authority" come apart the moment a second consumer binding is added. Today
 * wrangler.toml declares one; that makes this provisioning drift rather than a
 * present exploit, and provisioning drift is what a deployment survives
 * silently.
 *
 * Exported so the refusal is testable without a queue, a database or an
 * account -- the admission decision is made BEFORE anything is connected,
 * which is also why an unauthorized batch cannot cost a database connection.
 *
 * @returns null when admitted, or a refusal reason
 */
export function channelRefusal(batchQueue, expected) {
  if (typeof expected !== "string" || expected.trim() === "") {
    // NOT a pass. A consumer with no attested channel has no way to tell an
    // authority from a stranger, and defaulting to "trust whatever arrived" is
    // the exact shape of the thing R77 exists to refuse.
    return "CD-QUEUE-UNATTESTED: no PROVIDER_QUEUE is configured, so no channel can be admitted";
  }
  if (typeof batchQueue !== "string" || batchQueue.trim() === "") {
    return "CD-QUEUE-UNNAMED: the batch does not name the queue it came from";
  }
  if (batchQueue !== expected) {
    return `CD-QUEUE-FOREIGN: ${JSON.stringify(batchQueue)} is not the attested provider ` +
           `channel ${JSON.stringify(expected)}; it may not assert provider truth`;
  }
  return null;
}

export default {
  /**
   * The R2 notification consumer.
   *
   * IT THROWS on a foreign channel rather than acking or retrying by hand, and
   * the choice matters. Not calling retryAll() ACKS the batch, so a delivery
   * that should have alarmed would disappear; calling retryAll() by hand
   * retries something that can never become authorized. Throwing gives both
   * halves of what an unauthorized delivery deserves: no ledger movement, and
   * the batch preserved through the retries into the dead-letter queue, where
   * it is evidence instead of a log line.
   */
  async queue(batch, env, _ctx) {
    const refusal = channelRefusal(batch?.queue, env?.PROVIDER_QUEUE);
    if (refusal) throw new Error(refusal);

    // Only now. An unauthorized batch must not cost a database connection --
    // the same rule the fetch path applies to an unverified token.
    const conn = await connectJobs(env);
    const report = await observeBatch(conn, batch, { expectedQueue: env.PROVIDER_QUEUE });

    // THE COUNTERS ARE THE POINT, AND RETURNING THEM IS NOT EMITTING THEM.
    // Cloudflare's queue contract is acknowledgement and retry; nothing reads a
    // consumer's return value. `observeBatch()` carefully computes `refused`,
    // `unattributed` and `unidentified` -- each of which is an anomaly this
    // system has spent rounds learning to name -- and until this line they went
    // nowhere. A number computed and discarded is worse than one not computed:
    // it reads, in the source, as though somebody is watching it.
    //
    // One structured line so a log query can select on it. `unidentified > 0`
    // in production means deliveries are being deduplicated by object state
    // rather than by delivery identity, which is the condition under which a
    // genuine identical re-PUT disappears.
    console.log(JSON.stringify({
      at: "queue.observeBatch",
      queue: batch.queue,
      messages: batch.messages?.length ?? 0,
      observed: report.observed,
      duplicates: report.duplicates,
      unattributed: report.unattributed,
      unidentified: report.unidentified,
      refused: report.refused.length,
      // Codes only. A refusal message can carry an object key, and an object
      // key carries an organization id -- logs are not the place to spread
      // tenant identifiers around.
      refusedCodes: [...new Set(report.refused.map((r) => r.code))],
    }));
    return report;
  },

  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/healthz") {
      // Says what is true, not "ok". A health endpoint that reports healthy
      // while nothing is connected is the first lie a system tells.
      return Response.json({
        service: "computedriven-cloud-api",
        deployed: false,
        database: env?.HYPERDRIVE_CONTROL ? "bound" : "not bound",
        note: "M1 in progress. See cloud.computedriven.com/status",
      });
    }

    let conn;
    try {
      // VERIFY BEFORE CONNECTING. An unauthenticated request must not cost a
      // database connection -- otherwise anyone with a malformed bearer token can
      // exhaust the pool without ever presenting a credential. It also means the
      // JWKS abuse path above is reachable and therefore testable without a
      // database at all, which is what the entrypoint falsifier exercises.
      const claims = await verifyToken(
        bearer(request),
        jwksFor(env),
        { issuer: env.KEYCLOAK_ISSUER, audience: env.OIDC_AUDIENCE }
      );

      conn = await connect(env);

      const { tenant, principalId, role } = await authorizeClaims({
        claims,
        conn,
        requestedOrganization: url.searchParams.get("org") ?? undefined,
      });

      // GET /v1/worlds
      if (url.pathname === "/v1/worlds" && request.method === "GET") {
        const worlds = await withTenant(conn, tenant, async (tx) => {
          const r = await tx.query(
            "SELECT id, name, created_at FROM cd.worlds ORDER BY created_at DESC"
          );
          return r.rows ?? r;
        });
        return Response.json({ organization: tenant.organizationId, worlds });
      }

      // POST /v1/worlds/:id/credential
      const m = /^\/v1\/worlds\/([^/]+)\/credential$/.exec(url.pathname);
      if (m && request.method === "POST") {
        const worldId = m[1];
        const body = await request.json().catch(() => ({}));
        // The world must belong to the tenant, and RLS is what proves it -- the
        // lookup runs inside withTenant, so a world in another organization is
        // simply not there. Status comes back too, because an archived world
        // must not accept writes.
        // ONE transaction for the world lookup AND the reservation. Two would
        // mean the world could be archived, or the entitlement suspended,
        // between the check and the admission -- and the credential would be
        // minted against a decision that was true a moment ago.
        const { world, admission, permission } = await withTenant(conn, tenant, async (tx) => {
          const r = await tx.query(
            "SELECT id, status FROM cd.worlds WHERE id = $1", [worldId]);
          const w = (r.rows ?? r)[0] ?? null;
          if (!w) return { world: null, admission: null, permission: null };

          // THE LAW: the client may request an operation; the client never
          // chooses its authority. `body.permission` is a REQUEST. What it is
          // allowed to become is decided here, from the role the database
          // returned and the world's own state -- and an over-reach is refused
          // rather than quietly downgraded, so a client that asked to upload
          // learns why now instead of failing against R2 later.
          const p = permissionFor({
            role,
            requested: body.permission ?? "object-read",
            worldStatus: w.status,
          });

          // R24 / M1.5. A write credential is the artifact that lets a client
          // put bytes into a bucket we pay for, so the bytes are reserved
          // BEFORE it exists. A read costs nothing and reserves nothing.
          let a = null;
          if (WRITE_PERMISSIONS.includes(p)) {
            a = await admitStorage(tx, {
              worldId,
              principalId,
              bytes: body.bytes,
              idempotencyKey: body.idempotencyKey,
              // The reservation must outlive the credential it justifies;
              // scopeForWorld() refuses the pair if it does not.
              ttlSeconds: 3600,
            });
          }
          return { world: w, admission: a, permission: p };
        });

        if (!world) {
          return Response.json({ error: "refused", code: "CD-WORLD-NOTFOUND" }, { status: 404 });
        }

        const scope = scopeForWorld({
          bucket: env.R2_BUCKET,
          organizationId: tenant.organizationId,
          worldId,
          permission,
          admission,
        });
        const cred = await new R2Provider().mint(scope);  // refuses: not deployed
        return Response.json({
          principalId, role, permission,
          reservation: admission && {
            id: admission.reservationId,
            bytes: admission.bytes,
            expiresAt: admission.expiresAt,
            usage: {
              tier: admission.tier,
              limit: admission.byteLimit,
              committed: admission.committedBytes,
              reserved: admission.reservedBytes,
            },
          },
          ...cred,
        });
      }

      return Response.json({ error: "not found" }, { status: 404 });
    } catch (err) {
      return refuse(err);
    } finally {
      await conn?.close?.().catch?.(() => {});
    }
  },
};
