// M1.5 — storage admission. R24.
//
// THE SENTENCE THIS FILE EXISTS TO MAKE TRUE:
//
//     NO WRITE CREDENTIAL IS ISSUED WITHOUT AN ACTIVE ENTITLEMENT AND
//     RESERVED BYTES.
//
// Round 5 shipped a credential minter whose scope was narrow in bucket, prefix,
// actions and expiry -- and said nothing about how many bytes the holder could
// push. R8 sends bulk bytes client -> R2 directly, so the Worker never sees the
// upload. By the time an over-quota world is visible it is an R2 invoice.
//
// The admission is where it gets refused, and the ORDER is the design:
//
//     VerifiedClaims  ->  tenant + membership + world
//                     ->  StorageAdmission   entitlement, reservation, expiry
//                     ->  AuthorizedScope    (r2creds.mjs, requires the above)
//                     ->  ProviderNativeGrant
//                     ->  signed credential
//
// Read downward, that says: CREDENTIAL AUTHORITY IS THE OUTPUT OF ADMISSION,
// NOT AN INPUT TO MINTING. A provider can never mint because somebody handed it
// an organization uuid and a prefix.
//
// WHERE THE REAL WORK IS. Almost none of it is here. The atomicity that makes
// two simultaneous 8 GB requests against 10 GB of headroom impossible is ONE
// PostgreSQL statement in 0014_storage_admission.sql, and this file is the
// typed, branded wrapper around calling it. That is deliberate: an admission
// decided in JavaScript would be a read-then-write across a network, and two
// Workers would both read the same number.
//
// STATUS: local. The functions this calls exist and are proven by the battery
// against a real cluster. Nothing here has ever run against Pigsty, because
// there is no Hyperdrive binding -- see cloud.computedriven.com/status.json.

import { registerAdmissionGuard } from "./r2creds.mjs";

export class AdmissionRefusal extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.name = "AdmissionRefusal";
    this.code = code;
  }
}

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// ---------------------------------------------------------------------------
// PROVENANCE, third time in this codebase and the reason is the same each time.
//
// verifyToken() brands verified claims; scopeForWorld() brands authorized
// scopes; this brands admissions. In all three cases the defect being prevented
// is a downstream function checking SHAPE and concluding AUTHORITY -- an object
// with the right fields is not an object that came from the right place, and a
// structural clone is the cheapest forgery there is.
//
// A module-private WeakSet, and nothing exported can add to it.
// ---------------------------------------------------------------------------
const ADMITTED = new WeakSet();

export function isAdmitted(a) {
  return typeof a === "object" && a !== null && ADMITTED.has(a);
}

export function assertAdmitted(admission) {
  if (!isAdmitted(admission)) {
    throw new AdmissionRefusal(
      "CD-ADMISSION-FORGED",
      "this is not a storage admission; one comes from admitStorage() and " +
      "nothing else can produce one"
    );
  }
  return admission;
}

// r2creds.mjs asks for this rather than importing it, so a write scope cannot be
// built at all in a program that never loaded this module. Failing closed when
// the admission layer is absent is the correct direction.
registerAdmissionGuard(assertAdmitted);

function rowsOf(result) {
  return result?.rows ?? result ?? [];
}

// PostgreSQL's SQLSTATE and the RAISE prefixes in 0014 both carry meaning; the
// prefix is the one that survives a driver, so that is what is parsed. A message
// this does not recognise is re-thrown untouched rather than flattened into a
// generic refusal -- an unrecognised database error is not an admission
// decision and must not be reported as one.
const KNOWN_CODES = [
  "CD-RESERVE-BYTES", "CD-RESERVE-IDEMPOTENCY", "CD-RESERVE-TTL",
  "CD-RESERVE-SETTLED", "CD-RESERVE-NOTMEMBER", "CD-RESERVE-ROLE",
  "CD-RESERVE-WORLD", "CD-RESERVE-WORLDSTATUS", "CD-RESERVE-NOENTITLEMENT",
  "CD-QUOTA-EXCEEDED",
  "CD-FINALIZE-BYTES", "CD-FINALIZE-NOTFOUND", "CD-FINALIZE-CONFLICT",
  "CD-FINALIZE-STATE", "CD-FINALIZE-OVERRUN",
  "CD-ABORT-NOTFOUND", "CD-ABORT-FINALIZED",
  "CD-TENANT-MISSING", "CD-TENANT-MALFORMED",
];

function refusalFrom(err) {
  const msg = String(err?.message ?? err);
  const hit = KNOWN_CODES.find((c) => msg.includes(c));
  return hit ? new AdmissionRefusal(hit, msg) : err;
}

function brand(row) {
  const admission = Object.freeze({
    reservationId:   row.reservation_id,
    organizationId:  row.organization_id,
    worldId:         row.world_id,
    bytes:           Number(row.bytes),
    expiresAt:       row.expires_at instanceof Date
                       ? row.expires_at.toISOString()
                       : String(row.expires_at),
    tier:            row.tier,
    byteLimit:       Number(row.byte_limit),
    committedBytes:  Number(row.committed_bytes),
    reservedBytes:   Number(row.reserved_bytes),
    // True when this call did not change anything -- a replayed reserve or a
    // repeated finalize. Surfaced rather than hidden because a client that
    // cannot tell a fresh reservation from a replay will double-count its own
    // uploads.
    replayed:        row.replayed === true || row.replayed === "t",
  });
  ADMITTED.add(admission);
  return admission;
}

/**
 * Admit a storage write, or refuse it.
 *
 * MUST run inside withTenant() -- reserve_storage() takes no organization
 * argument and reads app.current_organization_id(), which raises without
 * context. That is not an oversight to work around; it is why a caller cannot
 * reserve against a tenant it does not hold.
 *
 * @param tx                a connection already inside a tenant transaction
 * @param worldId           the world the bytes are for
 * @param principalId       who is asking; membership and role are re-checked
 *                          server-side, not trusted from here
 * @param bytes             how many bytes to hold
 * @param idempotencyKey    a retry of the same request must return the same
 *                          reservation, not a second one
 * @param ttlSeconds        how long the hold lasts. Held bytes are unavailable
 *                          bytes, so this is short by default.
 */
export async function admitStorage(tx, {
  worldId, principalId, bytes, idempotencyKey, ttlSeconds = 3600,
} = {}) {
  if (!UUID_RE.test(worldId ?? "")) {
    throw new AdmissionRefusal("CD-ADMISSION-WORLD", "world id is not a uuid");
  }
  if (!UUID_RE.test(principalId ?? "")) {
    throw new AdmissionRefusal("CD-ADMISSION-PRINCIPAL", "principal id is not a uuid");
  }
  if (!Number.isInteger(bytes) || bytes <= 0) {
    throw new AdmissionRefusal("CD-ADMISSION-BYTES",
      "bytes must be a positive integer count");
  }
  if (typeof idempotencyKey !== "string" || idempotencyKey.trim() === "") {
    // Not defaulted to a random value. A generated key would make every retry a
    // new reservation, which is the exact bug idempotency keys exist to prevent,
    // and it would do it silently.
    throw new AdmissionRefusal("CD-ADMISSION-IDEMPOTENCY",
      "an idempotency key is required; a generated one would make every retry a new reservation");
  }
  if (!Number.isInteger(ttlSeconds) || ttlSeconds <= 0) {
    throw new AdmissionRefusal("CD-ADMISSION-TTL", "ttlSeconds must be a positive integer");
  }

  let result;
  try {
    result = await tx.query(
      "SELECT * FROM app.reserve_storage($1, $2, $3, $4, make_interval(secs => $5))",
      [worldId, principalId, bytes, idempotencyKey, ttlSeconds]
    );
  } catch (e) {
    throw refusalFrom(e);
  }
  const row = rowsOf(result)[0];
  if (!row) {
    throw new AdmissionRefusal("CD-ADMISSION-EMPTY",
      "reserve_storage returned no row; treat this as a refusal, not a success");
  }
  return brand(row);
}

/**
 * The bytes landed. reserved -> finalized, exactly once.
 *
 * Idempotent on retry with the SAME byte count, and a refusal on retry with a
 * different one -- the database cannot know which number is true, so it commits
 * neither.
 */
export async function finalizeStorage(tx, admission, { actualBytes } = {}) {
  assertAdmitted(admission);
  if (!Number.isInteger(actualBytes) || actualBytes < 0) {
    throw new AdmissionRefusal("CD-ADMISSION-BYTES",
      "actualBytes must be zero or more");
  }
  if (actualBytes > admission.bytes) {
    // Refused here as well as in the database. Not redundant: this one names
    // the reservation the client actually holds, so the message says "you
    // reserved 5, you wrote 9" instead of surfacing a constraint name.
    throw new AdmissionRefusal("CD-FINALIZE-OVERRUN",
      `${actualBytes} bytes written against a ${admission.bytes} byte reservation`);
  }
  let result;
  try {
    result = await tx.query("SELECT * FROM app.finalize_storage($1, $2)",
      [admission.reservationId, actualBytes]);
  } catch (e) {
    throw refusalFrom(e);
  }
  const row = rowsOf(result)[0];
  if (!row) {
    throw new AdmissionRefusal("CD-ADMISSION-EMPTY", "finalize_storage returned no row");
  }
  return brand(row);
}

/** The client gave up and said so. Releasing twice is a no-op, by design. */
export async function abortStorage(tx, admission) {
  assertAdmitted(admission);
  let result;
  try {
    result = await tx.query("SELECT * FROM app.abort_storage($1)",
      [admission.reservationId]);
  } catch (e) {
    throw refusalFrom(e);
  }
  const row = rowsOf(result)[0];
  if (!row) {
    throw new AdmissionRefusal("CD-ADMISSION-EMPTY", "abort_storage returned no row");
  }
  return brand(row);
}

/**
 * The sweep. Releases quota held by reservations whose time is up.
 *
 * Runs WITHOUT tenant context -- it is a maintenance job across every tenant,
 * and the jobs role is the only one that holds EXECUTE on it. reserve_storage()
 * also calls it for its own tenant first, so a crashed client's hold does not
 * outlive its usefulness just because no cron has run yet.
 */
export async function expireReservations(conn, { organizationId = null } = {}) {
  const r = await conn.query("SELECT app.expire_storage_reservations($1) AS released",
    [organizationId]);
  return Number(rowsOf(r)[0]?.released ?? 0);
}
