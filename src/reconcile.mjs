// R32 (PROPOSED) — committed storage is provider-observed, never client-asserted.
//
// THE PROBLEM THIS EXISTS FOR. `finalize(actualBytes)` trusts the uploader,
// bounded above by its reservation. R8 puts the bytes on a wire the Worker never
// sees, so the control plane's committed-byte number is a client's word about
// something only R2 can know. Round 6 named that as an open question and said the
// honest reconciliation "would require an R2-side usage read, which does not
// exist."
//
// There is a better primitive and it does exist: R2 Event Notifications. On
// object-create -- PutObject, CopyObject, CompleteMultipartUpload -- R2 emits a
// message carrying `object.size` and `object.eTag`, delivered over Cloudflare
// Queues.
//
//     https://developers.cloudflare.com/r2/buckets/event-notifications/
//
// So:
//
//     CLIENT  "I finished uploading"   ->  a completion HINT, useful for UX
//     R2      key + size + etag        ->  what is actually being paid for
//
// AT-LEAST-ONCE IS THE DESIGN CONSTRAINT, NOT A CAVEAT. Cloudflare Queues
// delivers at least once, so a duplicate notification is normal operation. Every
// exactly-once property here comes from the unique constraint on
// (bucket, object_key, etag) in 0017 -- never from believing a message arrives
// once. Cloudflare's own guidance is to key on a unique id for this reason.
//
//     https://developers.cloudflare.com/queues/reference/delivery-guarantees/
//
// R32 IS NOT RULED. This module is built so the ruling can be made against
// measured divergence instead of an argument: `finalize` still records what the
// client said, `observe()` records what R2 said, and app.storage_divergence()
// reports the gap. Replacing a measured mechanism with an unmeasured one before
// a single real event has ever arrived would be the same overclaim this tree
// keeps retracting.
//
// STATUS: local, with fixture events. No bucket, no queue, no notification rule.

export class ReconcileRefusal extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.name = "ReconcileRefusal";
    this.code = code;
  }
}

// The actions R2 documents as producing an object-create notification. A closed
// set, for the same reason r2native.mjs keeps a closed action vocabulary: an
// action we do not recognise is a refusal, not a shrug.
export const CREATE_ACTIONS = Object.freeze([
  "PutObject", "CopyObject", "CompleteMultipartUpload",
]);
export const DELETE_ACTIONS = Object.freeze(["DeleteObject", "LifecycleDeletion"]);

// The prefix format minted by scopeForWorld(). MOVED to ./objectkey.mjs 2026-08-23
// (finding 98) and re-exported here so existing importers are unaffected: the
// grammar had been written a third time in inventory.mjs, weaker, and the two
// already disagreed. It is duplicated in SQL as app.parse_object_key() because
// the parse that decides tenancy has to be where the constraint is, and battery
// check M4 pins those two together — that duplicate the substrate forces, and it
// is the only one allowed.
// A re-export alone would not bind the name locally, and observeEvent() below
// calls it.
import { parseObjectKey } from "./objectkey.mjs";
export { KEY_RE, parseObjectKey } from "./objectkey.mjs";

// parseObjectKey() and its trust-boundary rationale now live in ./objectkey.mjs.

/**
 * The DELIVERY identity of a queue message: Cloudflare's system-generated
 * `message.id`.
 *
 * NOT "event identity", which is what this said until 2026-08-23 and what R57
 * was narrowed away from a day earlier. R2's notification body carries
 * `account`, `action`, `bucket`, `object{key,size,eTag}` and `eventTime` and NO
 * event id, so provider-event identity is a thing we do not have rather than a
 * thing we hold under another name. The pull-consumer docs go further and call
 * `id` an ephemeral identifier.
 *
 * THIS IS THE THING WE DID NOT HAVE, and the reason dedupeKeyFor() below was
 * being asked a question it cannot answer. Four different notions of "same" had
 * been sharing one key, and only three of them are answerable:
 *
 *     delivery identity   the queue message id     is this the same DELIVERY?
 *     object identity     bucket + key             is this the same OBJECT?
 *     object state        etag, eventTime          is this the same CONTENTS?
 *     provider event id   NOT EXPOSED              -- unanswerable
 *
 * A genuine second PUT of identical bytes to the same key produces the same
 * bucket, key and etag. Keying delivery on those three called that a redelivery
 * and dropped it -- lossless for occupancy, lossy for the append-only provenance
 * log, and outright wrong once deletes exist:
 *
 *     PUT hash X       etag E
 *     DELETE hash X
 *     PUT identical X  etag E     <- dismissed because an ancient row matched
 *
 * The same lesson as user identity vs binding, WORLD vs VERSION vs GRAPH, and
 * request idempotence vs content dedup. Fourth time.
 *
 * Returns null when there is no message id. That is not a failure: a backfill,
 * a battery or an operator replaying a capture legitimately has none, and the
 * database has a narrower fallback index for exactly those. It IS a failure for
 * a queue consumer, which is why observeBatch() below reads it from the message
 * rather than letting a caller forget.
 */
export function messageIdOf(message) {
  const id = message?.id;
  return typeof id === "string" && id !== "" ? id : null;
}

/**
 * The OBJECT-STATE key for a notification.
 *
 * `(bucket, key, etag)` identifies a stored object state. It is NOT a delivery
 * identity -- see messageIdOf() -- and it is kept because it is still the right
 * answer to "does the provider now hold different bytes under this name?", which
 * is what storage_objects.overwrite_count counts.
 */
export function dedupeKeyFor(event) {
  // Separated, not concatenated: without a separator, bucket "a" + key "bc"
  // and bucket "ab" + key "c" produce the same dedupe key and one write
  // silently absorbs the other. Same reasoning as the record separator in the
  // identity lock key.
  //
  // Written as an ESCAPE. It was a raw U+001F byte inside the template literal --
  // invisible in every editor and in every diff, and it made the mutation vector
  // for this function unmatchable, which the parse gate reported as NO-ANCHOR
  // rather than crediting. A control character you cannot see is a control
  // character you cannot review.
  const SEP = "\u001f";
  return [event.bucket, event.object?.key, event.object?.eTag].join(SEP);
}

/**
 * Validate the shape of a notification before it reaches the database.
 *
 * Deliberately strict and deliberately NOT trusting: this is the one place in
 * the control plane that consumes a message produced somewhere else, so
 * everything it will act on is checked here rather than assumed downstream.
 */
export function normalizeEvent(event) {
  if (!event || typeof event !== "object") {
    throw new ReconcileRefusal("CD-OBSERVE-SHAPE", "the event is not an object");
  }
  const { bucket, action, eventTime, object } = event;
  if (typeof bucket !== "string" || bucket.trim() === "") {
    throw new ReconcileRefusal("CD-OBSERVE-SHAPE", "the event has no bucket");
  }
  if (!object || typeof object !== "object") {
    throw new ReconcileRefusal("CD-OBSERVE-SHAPE", "the event has no object");
  }
  if (DELETE_ACTIONS.includes(action)) {
    // Deletions are a real thing that a later round has to account for. Refusing
    // by name beats silently ignoring them, which would look identical to a
    // notification rule that was never configured.
    throw new ReconcileRefusal("CD-OBSERVE-DELETE",
      `${action} is an object-delete event; deletion accounting is not built (M2+)`);
  }
  if (!CREATE_ACTIONS.includes(action)) {
    throw new ReconcileRefusal("CD-OBSERVE-ACTION",
      `${JSON.stringify(action)} is not an object-create action`);
  }
  if (typeof object.key !== "string" || object.key === "") {
    throw new ReconcileRefusal("CD-OBSERVE-SHAPE", "the object has no key");
  }
  if (typeof object.eTag !== "string" || object.eTag === "") {
    throw new ReconcileRefusal("CD-OBSERVE-SHAPE", "the object has no eTag");
  }
  // Integer bytes, same lesson as the expiry work: a size that is a string, a
  // float or NaN must refuse rather than compare falsely.
  if (!Number.isInteger(object.size) || object.size < 0) {
    throw new ReconcileRefusal("CD-OBSERVE-SIZE",
      `object.size must be a non-negative integer, got ${JSON.stringify(object.size)}`);
  }
  const when = Date.parse(eventTime);
  if (!Number.isFinite(when)) {
    throw new ReconcileRefusal("CD-OBSERVE-TIME",
      `eventTime ${JSON.stringify(eventTime)} is not a parseable timestamp`);
  }
  const tenant = parseObjectKey(object.key);
  if (!tenant) {
    // An object in our bucket under a key we did not mint. Refused rather than
    // accounted to nobody -- if this ever fires in production it means either a
    // key format change or something writing to the bucket out of band, and both
    // deserve an alarm rather than a silently skipped message.
    throw new ReconcileRefusal("CD-OBSERVE-KEY",
      `${JSON.stringify(object.key)} is not a key this control plane minted`);
  }
  return Object.freeze({
    bucket,
    action,
    eventTime: new Date(when).toISOString(),
    key: object.key,
    eTag: object.eTag,
    size: object.size,
    organizationId: tenant.organizationId,
    worldId: tenant.worldId,
    dedupeKey: dedupeKeyFor(event),
  });
}

function rowsOf(result) {
  return result?.rows ?? result ?? [];
}

/**
 * Record one notification. Idempotent by CONSTRAINT, not by delivery guarantee.
 *
 * Runs WITHOUT tenant context on purpose: a queue consumer is cross-tenant by
 * nature and derives each message's tenant from the key. That is the third named
 * cross-tenant path in the system, after the bootstrap resolvers and the ledger
 * functions, and it is named here so it stays countable.
 */
export async function observeEvent(conn, event, { messageId = null, queue = null } = {}) {
  const e = normalizeEvent(event);
  // R77. A message id whose channel is unnamed is a string that was unique
  // somewhere. Refused here as well as in the database because this is the
  // layer that knows the two came from one envelope, and a caller that has the
  // id must have had the batch it arrived in.
  if (messageId !== null && (typeof queue !== "string" || queue.trim() === "")) {
    throw new ReconcileRefusal("CD-OBSERVE-CHANNEL",
      "a delivery identity must name the queue that delivered it (MessageBatch.queue)");
  }
  let result;
  try {
    result = await conn.query(
      "SELECT * FROM app.observe_storage_object($1, $2, $3, $4, $5, $6, $7, $8)",
      // messageId and queue are DELIVERY identity and are passed separately from
      // the event body on purpose: they are envelope facts, not something the
      // producer put in the notification. Reading either out of `event` would
      // invite a producer to choose its own delivery identity -- and under R77
      // the channel is the half that says who was allowed to speak at all.
      [e.bucket, e.key, e.eTag, e.size, e.action, e.eventTime, messageId, queue]
    );
  } catch (err) {
    const msg = String(err?.message ?? err);
    const hit = ["CD-OBSERVE-KEY", "CD-OBSERVE-ORG", "CD-OBSERVE-SIZE",
                 "CD-OBSERVE-ACTION", "CD-OBSERVE-SHAPE", "CD-OBSERVE-CHANNEL"].find((c) => msg.includes(c));
    // An unrecognised database error is not an observation decision and must not
    // be reported as one; the queue should retry it, not discard it.
    throw hit ? new ReconcileRefusal(hit, msg) : err;
  }
  const row = rowsOf(result)[0];
  if (!row) {
    throw new ReconcileRefusal("CD-OBSERVE-EMPTY",
      "observe_storage_object returned no row; treat as a retryable failure, not a success");
  }
  return Object.freeze({
    observationId: row.observation_id,
    intentId: row.intent_id ?? null,
    sizeBytes: Number(row.size_bytes),
    // True when this message had already been recorded. Surfaced rather than
    // hidden: a consumer that cannot tell a redelivery from a new write has no
    // way to report queue health.
    duplicate: row.duplicate === true || row.duplicate === "t",
    // False when the object landed under a key with no upload intent -- a write
    // the control plane did not offer authority for. Not an error here; it is a
    // number a later round has to explain.
    attributed: row.attributed === true || row.attributed === "t",
  });
}

/**
 * Drain a batch of queue messages. Returns a per-message outcome rather than
 * throwing on the first bad one, because one malformed message must not stop a
 * batch -- and because the counts are the operational signal.
 *
 * `unidentified` counts messages that arrived with no queue message id. In
 * production that should always be zero; a non-zero value means deliveries are
 * being deduplicated by object state rather than by delivery identity, which is the
 * exact condition under which a genuine identical re-PUT disappears. It is
 * COUNTED rather than refused, because refusing would also lock out backfills.
 *
 * TAKES THE BATCH, NOT THE MESSAGE ARRAY (R77, 0026). `MessageBatch.queue` is
 * the authority channel, and a signature that accepted only `messages` made the
 * channel something a caller could forget. An array is still accepted for the
 * backfill/battery case that genuinely has no envelope -- and then every message
 * in it must be id-less, because an id without its channel is not an identity.
 */
export async function observeBatch(conn, batch, { expectedQueue = null } = {}) {
  const isBatch = batch !== null && typeof batch === "object" && Array.isArray(batch.messages);
  const messages = isBatch ? batch.messages : batch;
  const queue = isBatch && typeof batch.queue === "string" ? batch.queue : null;

  // CHANNEL ADMISSION (finding 89 / R77). The entrypoint refuses a foreign
  // channel before it connects, and this is the same refusal one layer down --
  // because this function is exported, is what every test and backfill calls,
  // and would otherwise happily record a channel nobody attested. `identity`
  // and `authority` are different questions and R77 owes both.
  //
  // OPT-IN, not defaulted on: a backfill genuinely has no channel and must stay
  // able to run. But once a caller states an expectation, a mismatch is a
  // whole-batch refusal, not a per-message one -- the batch came from one
  // channel, so either all of it is admissible or none of it is.
  if (expectedQueue !== null && queue !== expectedQueue) {
    throw new ReconcileRefusal("CD-QUEUE-FOREIGN",
      `batch arrived on ${JSON.stringify(queue)}, not the attested provider channel ` +
      `${JSON.stringify(expectedQueue)}; it may not assert provider truth`);
  }

  const out = { observed: 0, duplicates: 0, unattributed: 0, unidentified: 0, refused: [], queue };
  for (const [i, m] of messages.entries()) {
    // A Cloudflare queue message is an ENVELOPE -- {id, timestamp, attempts,
    // body} -- and the notification is its body. Accepting a bare notification
    // too, because every battery and every backfill has one and refusing them
    // would make the fallback index unreachable from the only code that could
    // exercise it.
    const messageId = messageIdOf(m);
    const event = messageId !== null && m.body !== undefined ? m.body : m;
    if (messageId === null) out.unidentified++;
    try {
      const r = await observeEvent(conn, event, { messageId, queue });
      if (r.duplicate) out.duplicates++; else out.observed++;
      if (!r.attributed) out.unattributed++;
    } catch (err) {
      if (err instanceof ReconcileRefusal) {
        out.refused.push({ index: i, code: err.code, message: err.message });
      } else {
        throw err;      // infrastructure failure: let the queue retry the batch
      }
    }
  }
  return out;
}

/**
 * Where the client and the provider disagree. The reason R32 is built before it
 * is ruled: rule with a number, not with an argument.
 */
export async function divergence(conn, { organizationId = null } = {}) {
  // `_for`, and the suffix is the whole point (0024). This module is the QUEUE
  // CONSUMER -- cross-tenant by nature, running as computedriven_jobs -- so it
  // is entitled to name a tenant and to pass null for all of them. A REQUEST
  // path is not, and until 0024 the same function was granted to both: an API
  // connection scoped to org A could read org B by naming it, or every tenant
  // by naming none (finding 72). The tenant-derived form is app.storage_divergence().
  const r = await conn.query("SELECT * FROM app.storage_divergence_for($1)", [organizationId]);
  return rowsOf(r).map((row) => Object.freeze({
    reservationId: row.reservation_id,
    organizationId: row.organization_id,
    assertedBytes: Number(row.asserted_bytes),
    observedBytes: Number(row.observed_bytes),
    delta: Number(row.delta),
    // 0021. observedBytes is now CURRENT occupancy read from cd.storage_objects,
    // not the sum of the event log -- summing the log double counts an
    // overwritten key. `overwrites` is how many times a key under this
    // reservation has held a second body, which on a content-addressed key is a
    // defect and not a measurement, so it travels beside the number it explains.
    overwrites: Number(row.overwrites ?? 0),
    // 0026 / R75, ADDED IN 4.1 AS FINDING 87. How many of this reservation's
    // objects the provider has left AMBIGUOUS -- two or more observations at the
    // same eventTime disagreeing about the key's state, so `observedBytes`
    // counts max(size) and nobody knows which body is there. The database
    // learned to raise this alarm and this adapter dropped it on the floor:
    // each layer correct in isolation, the property destroyed between them.
    // A non-zero value means observedBytes is an upper bound, not a fact.
    ambiguous: Number(row.ambiguous ?? 0),
  }));
}
