// R32 (PROPOSED) — provider-observed storage, and the at-least-once problem.
//
// Cloudflare Queues delivers AT LEAST ONCE, so a duplicate object-create
// notification is normal operation rather than an edge case. Every exactly-once
// property tested here comes from the unique constraint in 0017, never from
// believing a message arrives once.
//
// The object-key cases come from a SHARED fixture that battery group M also
// reads, because the format is parsed in two languages -- here and in
// app.parse_object_key() -- and two parsers for one format is how a tenancy bug
// gets written. Pinning them to one file is the mechanism; saying "keep them in
// sync" would be the comment.

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  parseObjectKey, dedupeKeyFor, messageIdOf, normalizeEvent, observeEvent, observeBatch,
  divergence, CREATE_ACTIONS, DELETE_ACTIONS, ReconcileRefusal,
} from "../src/reconcile.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE = JSON.parse(readFileSync(join(HERE, "fixtures/object-keys.json"), "utf8"));

const ORG = "aaaaaaaa-0000-4000-8000-000000000001";
const WORLD = "11111111-0000-4000-8000-00000000000a";
const KEY = `org/${ORG}/world/${WORLD}/chunk/abc123`;

const event = (over = {}) => ({
  account: "acct",
  action: "PutObject",
  bucket: "cd",
  object: { key: KEY, size: 4096, eTag: "d41d8cd98f00b204e9800998ecf8427e", ...(over.object ?? {}) },
  eventTime: "2026-08-22T20:00:00.000Z",
  ...Object.fromEntries(Object.entries(over).filter(([k]) => k !== "object")),
});

// A conn that answers observe_storage_object the way 0017 does.
const observingConn = (over = {}) => ({
  calls: [],
  async query(sql, params) {
    this.calls.push({ sql, params });
    return { rows: [{
      observation_id: "cccccccc-0000-4000-8000-00000000000c",
      intent_id: "dddddddd-0000-4000-8000-00000000000d",
      size_bytes: 4096, duplicate: false, attributed: true, ...over,
    }] };
  },
});

describe("the object key is the tenancy boundary, and both parsers agree on it", () => {
  for (const c of FIXTURE.cases) {
    test(`${c.valid ? "parses" : "refuses"}: ${c.why}`, () => {
      const got = parseObjectKey(c.key);
      if (!c.valid) {
        assert.equal(got, null, `${JSON.stringify(c.key)} must not parse`);
        return;
      }
      assert.ok(got, `${JSON.stringify(c.key)} must parse`);
      assert.equal(got.organizationId, c.organizationId);
      assert.equal(got.worldId, c.worldId);
    });
  }

  test("the fixture is not vacuous -- it carries both outcomes", () => {
    assert.ok(FIXTURE.cases.some((c) => c.valid), "no positive cases");
    assert.ok(FIXTURE.cases.some((c) => !c.valid), "no negative cases");
  });

  test("the organization is DERIVED from the key, never read from the message", () => {
    // The only reason consuming these events is safe: R2 is authoritative for
    // what was written, the prefix is authoritative for whose it is, and we
    // minted the prefix.
    const e = normalizeEvent(event({ organization: "some-other-org", account: "attacker" }));
    assert.equal(e.organizationId, ORG);
  });
});

describe("a notification is validated before it reaches the ledger", () => {
  test("a well-formed create event normalizes", () => {
    const e = normalizeEvent(event());
    assert.equal(e.size, 4096);
    assert.equal(e.worldId, WORLD);
    assert.equal(e.eventTime, "2026-08-22T20:00:00.000Z");
  });

  test("every documented create action is accepted", () => {
    for (const action of CREATE_ACTIONS) {
      assert.ok(normalizeEvent(event({ action })), action);
    }
  });

  test("a DELETE event is refused BY NAME, not ignored", () => {
    // Silently skipping deletions would look identical to a notification rule
    // that was never configured, which is the failure mode that takes months to
    // notice.
    for (const action of DELETE_ACTIONS) {
      assert.throws(() => normalizeEvent(event({ action })), /CD-OBSERVE-DELETE/, action);
    }
  });

  test("an unknown action is refused", () => {
    assert.throws(() => normalizeEvent(event({ action: "PutObjectMaybe" })),
      /CD-OBSERVE-ACTION/);
  });

  test("a non-integer size is refused rather than coerced", () => {
    // Same lesson as the expiry work: a size that is a string or a float must
    // refuse, not compare falsely.
    for (const size of ["4096", 40.5, NaN, Infinity, -1, null, undefined]) {
      assert.throws(() => normalizeEvent(event({ object: { size } })),
        /CD-OBSERVE-SIZE|CD-OBSERVE-SHAPE/, String(size));
    }
  });

  test("a zero-byte object is legitimate and is NOT refused", () => {
    assert.equal(normalizeEvent(event({ object: { size: 0 } })).size, 0);
  });

  test("an unparseable eventTime is refused", () => {
    assert.throws(() => normalizeEvent(event({ eventTime: "whenever" })), /CD-OBSERVE-TIME/);
  });

  test("a key we did not mint is refused, not accounted to nobody", () => {
    assert.throws(() => normalizeEvent(event({ object: { key: "loose/object" } })),
      /CD-OBSERVE-KEY/);
  });

  test("the PREFIX is not an object", () => {
    assert.throws(() => normalizeEvent(event({ object: { key: `org/${ORG}/world/${WORLD}/` } })),
      /CD-OBSERVE-KEY/);
  });
});

describe("at-least-once delivery is absorbed by a key, not by hope", () => {
  test("the SAME stored object state has one key even at a different eventTime", () => {
    // The first version of this compared two identical events, which the
    // mutation battery survived: adding eventTime to the key breaks nothing when
    // both copies carry the same one.
    //
    // RE-AIMED, round 7.2. This test used to be titled "one observation" and its
    // comment said a re-PUT of identical bytes "must not be charged twice". Half
    // right, and the half it got wrong is finding 62: identical bytes must not be
    // charged twice for OCCUPANCY, and they are still a second WRITE EVENT. This
    // key answers the first question. messageIdOf() answers the second, and until
    // round 7.2 nothing did.
    assert.equal(
      dedupeKeyFor(event()),
      dedupeKeyFor(event({ eventTime: "2026-08-23T09:15:00.000Z" })));
  });

  test("the separator prevents field-boundary collisions", () => {
    // Without one, bucket "a" + key "bc" and bucket "ab" + key "c" produce the
    // same key and one write silently absorbs the other.
    assert.notEqual(
      dedupeKeyFor({ bucket: "a", object: { key: "bc", eTag: "e" } }),
      dedupeKeyFor({ bucket: "ab", object: { key: "c", eTag: "e" } }));
  });

  test("a genuine overwrite of the same key has a DIFFERENT one", () => {
    // Which is why eTag is in the key and eventTime is not: including eventTime
    // would make every redelivery look new, and that is the bug at-least-once
    // sets for you.
    assert.notEqual(dedupeKeyFor(event()), dedupeKeyFor(event({ object: { eTag: "other" } })));
  });

  test("DELIVERY identity comes from the queue envelope, not from the notification", () => {
    // Finding 62. A producer must not get to choose its own delivery identity,
    // so the message id is read from the envelope Cloudflare wraps the
    // notification in -- never from a field inside the body.
    assert.equal(messageIdOf({ id: "m-1", body: event() }), "m-1");
    assert.equal(messageIdOf(event()), null,
      "a bare notification has no delivery identity and must say so");
    assert.equal(messageIdOf({ id: "" }), null, "an empty id is not an identity");
    assert.equal(messageIdOf(null), null);
  });

  test("two deliveries of ONE write share a message id; two writes do not", () => {
    // The distinction the old key could not draw. Same body, same etag, and the
    // only thing separating a redelivery from a genuine identical re-PUT is
    // which envelope it arrived in.
    const body = event();
    assert.equal(messageIdOf({ id: "m-1", body }), messageIdOf({ id: "m-1", body }));
    assert.notEqual(messageIdOf({ id: "m-1", body }), messageIdOf({ id: "m-2", body }));
    assert.equal(dedupeKeyFor(body), dedupeKeyFor(body),
      "...while the OBJECT-STATE key is identical for both, which is correct");
  });

  test("observeBatch unwraps envelopes and passes the id AND its channel", async () => {
    const seen = [];
    const conn = { async query(_sql, params) {
      seen.push([params[6], params[7]]);
      return { rows: [{ observation_id: "o", intent_id: "i", size_bytes: "1",
                        duplicate: false, attributed: true }] };
    } };
    const r = await observeBatch(conn,
      { queue: "computedriven-r2-notifications", messages: [{ id: "m-7", body: event() }] });
    assert.deepEqual(seen, [["m-7", "computedriven-r2-notifications"]],
      "delivery identity is (queue, message id) and both must reach the database (R77)");
    assert.equal(r.unidentified, 0);
    assert.equal(r.queue, "computedriven-r2-notifications");
  });

  test("an identified message with no channel is REFUSED, not accounted (R77)", async () => {
    // The whole of finding 84 in one assertion. `Message.id` is documented as
    // unique with no stated cross-queue scope, so an id whose channel is unknown
    // is a string that was unique somewhere. Passing the bare array is exactly
    // what a caller who forgot `MessageBatch.queue` would write.
    const conn = { async query() { throw new Error("must not reach the database"); } };
    const r = await observeBatch(conn, [{ id: "m-8", body: event() }]);
    assert.equal(r.observed, 0);
    assert.equal(r.refused.length, 1);
    assert.equal(r.refused[0].code, "CD-OBSERVE-CHANNEL");
  });

  test("the SAME message id from two channels is two deliveries, not one", async () => {
    // The reason the tuple exists rather than the id alone. Nothing here proves
    // Cloudflare reuses ids across queues -- it proves that if it ever does, the
    // consumer hands the database two distinguishable deliveries rather than
    // silently collapsing a genuine second write into a duplicate.
    const seen = [];
    const conn = { async query(_sql, params) {
      seen.push(`${params[7]}/${params[6]}`);
      return { rows: [{ observation_id: "o", intent_id: null, size_bytes: "1",
                        duplicate: false, attributed: false }] };
    } };
    await observeBatch(conn, { queue: "q-one", messages: [{ id: "m-9", body: event() }] });
    await observeBatch(conn, { queue: "q-two", messages: [{ id: "m-9", body: event() }] });
    assert.deepEqual(seen, ["q-one/m-9", "q-two/m-9"]);
  });

  test("a batch of bare notifications is COUNTED as unidentified, not refused", async () => {
    // Refusing would lock out every backfill and every battery -- the only code
    // that can exercise the database's fallback index. A non-zero count in
    // production means deliveries are being deduplicated by object state, which
    // is the exact condition under which an identical re-PUT disappears.
    const conn = { async query() {
      return { rows: [{ observation_id: "o", intent_id: null, size_bytes: "1",
                        duplicate: false, attributed: false }] };
    } };
    const r = await observeBatch(conn, [event(), event()]);
    assert.equal(r.unidentified, 2);
    assert.equal(r.refused.length, 0);
    assert.equal(r.observed, 2);
  });

  test("a redelivery is reported as a duplicate, not as a second write", async () => {
    const r = await observeEvent(observingConn({ duplicate: true }), event());
    assert.equal(r.duplicate, true);
  });

  test("an object with no upload intent is surfaced as unattributed", async () => {
    const r = await observeEvent(observingConn({ intent_id: null, attributed: false }), event());
    assert.equal(r.attributed, false);
    assert.equal(r.intentId, null);
  });

  test("the size that is recorded is R2's, not the client's", async () => {
    const r = await observeEvent(observingConn({ size_bytes: 999 }), event({ object: { size: 999 } }));
    assert.equal(r.sizeBytes, 999);
  });

  test("an empty result is a retryable failure, never a success", async () => {
    const empty = { async query() { return { rows: [] }; } };
    await assert.rejects(() => observeEvent(empty, event()), /CD-OBSERVE-EMPTY/);
  });

  test("an UNRECOGNISED database error propagates so the queue retries it", async () => {
    // Flattening it into a refusal would make the consumer ack a message it
    // never processed.
    const broken = { async query() { throw new Error("connection reset by peer"); } };
    await assert.rejects(() => observeEvent(broken, event()), (e) => {
      assert.ok(!(e instanceof ReconcileRefusal), "must not be reported as a decision");
      assert.match(e.message, /connection reset/);
      return true;
    });
  });
});

describe("a batch survives one bad message", () => {
  test("counts are per message, and a refusal does not stop the batch", async () => {
    const conn = observingConn();
    const out = await observeBatch(conn, [
      event(),
      event({ action: "DeleteObject" }),                       // refused by name
      event({ object: { key: "not/ours" } }),                  // refused by key
      event({ object: { eTag: "second-write" } }),
    ]);
    assert.equal(out.observed, 2);
    assert.equal(out.refused.length, 2);
    assert.deepEqual(out.refused.map((r) => r.index), [1, 2]);
    assert.match(out.refused[0].code, /CD-OBSERVE-DELETE/);
  });

  test("an infrastructure failure aborts the batch instead of acking it", async () => {
    const broken = { async query() { throw new Error("pool exhausted"); } };
    await assert.rejects(() => observeBatch(broken, [event()]), /pool exhausted/);
  });
});

describe("divergence is measured, because R32 is not ruled yet", () => {
  test("client-asserted and provider-observed are reported side by side", async () => {
    const conn = { async query() { return { rows: [
      { reservation_id: "r1", organization_id: ORG,
        asserted_bytes: "100", observed_bytes: "4096", delta: "3996" },
    ] }; } };
    const rows = await divergence(conn);
    assert.equal(rows[0].assertedBytes, 100);
    assert.equal(rows[0].observedBytes, 4096);
    assert.equal(rows[0].delta, 3996);
    // The point of building R32 before ruling it: rule with a number rather than
    // an argument about whose number to trust.
  });

  test("the overwrite count travels beside the bytes it explains", async () => {
    // 0021. observed_bytes is CURRENT occupancy from cd.storage_objects, not the
    // sum of the event log -- R2 fires an object-create event on overwrite, so
    // summing the log charges a replaced body twice. `overwrites` is what says
    // a key under this reservation has held more than one body, which on a
    // content-addressed key is a defect rather than a measurement.
    const conn = { async query() { return { rows: [
      { reservation_id: "r1", organization_id: ORG,
        asserted_bytes: "10", observed_bytes: "12", delta: "2", overwrites: "1" },
    ] }; } };
    const rows = await divergence(conn);
    assert.equal(rows[0].observedBytes, 12);
    assert.equal(rows[0].overwrites, 1,
      "an overwritten key must be reported, not absorbed into the byte delta");
  });

  test("a database that does not report overwrites reads as zero, not NaN", async () => {
    // Number(undefined) is NaN, and a NaN silently propagates into every
    // comparison downstream as false -- so an older storage_divergence() would
    // make 'no overwrites' and 'unknown' indistinguishable in the direction that
    // looks safe.
    const conn = { async query() { return { rows: [
      { reservation_id: "r1", organization_id: ORG,
        asserted_bytes: "10", observed_bytes: "10", delta: "0" },
    ] }; } };
    const rows = await divergence(conn);
    assert.equal(rows[0].overwrites, 0);
  });

  test("the ambiguity alarm reaches the consumer with a NON-ZERO value", async () => {
    // FINDING 87. 0026 taught storage_divergence_for() to return `ambiguous` --
    // objects whose newest eventTime carries two disagreeing states, so
    // observedBytes is max(size) and an upper bound rather than a fact. This
    // adapter mapped six columns and not that one, so:
    //
    //     PostgreSQL: "provider state is ambiguous"
    //     Worker:     [information discarded]
    //
    // The overwrite tests above are the reason it survived: they cover the
    // PROPAGATION shape for the previous alarm and nobody added the new one.
    //
    // Asserted at a NON-ZERO value on purpose. A test that only checks the
    // default-zero path passes against a mapper that never reads the column.
    const conn = { async query() { return { rows: [
      { reservation_id: "r1", organization_id: ORG,
        asserted_bytes: "20", observed_bytes: "20", delta: "0",
        overwrites: "0", ambiguous: "1" },
    ] }; } };
    const rows = await divergence(conn);
    assert.equal(rows[0].ambiguous, 1,
      "an ambiguous object must reach the consumer; observedBytes is an upper bound when it does");
  });

  test("a database that does not report ambiguity reads as zero, not NaN", async () => {
    const conn = { async query() { return { rows: [
      { reservation_id: "r1", organization_id: ORG,
        asserted_bytes: "10", observed_bytes: "10", delta: "0", overwrites: "0" },
    ] }; } };
    const rows = await divergence(conn);
    assert.equal(rows[0].ambiguous, 0);
  });
});

describe("channel admission at the reconcile layer too (finding 89)", () => {
  const evt = () => ({
    account: "acct", action: "PutObject", bucket: "cd-worlds",
    object: { key: "org/aaaaaaaa-0000-4000-8000-000000000001/world/11111111-0000-4000-8000-00000000000a/chunk/x",
              size: 10, eTag: "e" },
    eventTime: "2026-08-23T10:00:00.000Z",
  });
  const conn = { async query() { return { rows: [{ observation_id: "o", intent_id: null,
    size_bytes: "10", duplicate: false, attributed: false }] }; } };

  test("a stated expectation makes a foreign channel a WHOLE-BATCH refusal", async () => {
    // Whole batch, not per message: a batch came from one channel, so either
    // all of it is admissible or none of it is. Throwing rather than collecting
    // into `refused` for the same reason -- a partial success count on an
    // unauthorized channel is a number nobody should be able to read.
    await assert.rejects(
      () => observeBatch(conn, { queue: "not-ours", messages: [{ id: "m", body: evt() }] },
                         { expectedQueue: "computedriven-r2-notifications" }),
      /CD-QUEUE-FOREIGN/);
  });

  test("the attested channel is admitted", async () => {
    const r = await observeBatch(conn,
      { queue: "computedriven-r2-notifications", messages: [{ id: "m", body: evt() }] },
      { expectedQueue: "computedriven-r2-notifications" });
    assert.equal(r.observed, 1);
  });

  test("with NO expectation stated a backfill still runs — admission is opt-in here", async () => {
    // Deliberate. The entrypoint always states one; this function is also what
    // every battery and backfill calls, and those genuinely have no channel.
    // The gate that makes the production path safe is queue(), not this.
    const r = await observeBatch(conn, [evt(), evt()]);
    assert.equal(r.observed, 2);
    assert.equal(r.unidentified, 2);
  });
});
