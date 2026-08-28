// CASE P2's predicate (R77, R79, finding 99).
//
// Case P asks whether the thing speaking on the authority channel is really R2.
// This asks the other half — whether R2 is speaking about EVERY write we admit —
// and neither implies the other. Both configurations can be independently right
// or wrong, because the queue's producer list and the bucket's notification
// rules are two different objects in the account.
//
// THE FIXTURES ARE PROVIDER-SHAPED. `{ bucketName, queues[{queueId, queueName,
// rules[{actions, prefix, suffix}]}] }` is Cloudflare's own schema for
// GET .../event_notifications/r2/{bucket}/configuration, and the action strings
// are its closed five-value enum. Finding 96 next door was a battery passing
// against a shape the provider does not return; this one pastes the shape.

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  notificationCoverageVerdict, PROVIDER_ACTIONS, NAMESPACE_PREFIX,
} from "../../scripts/check-notification-coverage.mjs";
import { CREATE_ACTIONS, DELETE_ACTIONS } from "../src/reconcile.mjs";

const BUCKET = "cd-worlds";
const QUEUE = "computedriven-r2-notifications";

const config = (over = {}) => ({
  bucketName: BUCKET,
  queues: [{
    queueId: "q1",
    queueName: QUEUE,
    rules: [{ actions: [...CREATE_ACTIONS], description: "object-create -> observer" }],
  }],
  ...over,
});
const withRule = (rule) => config({
  queues: [{ queueId: "q1", queueName: QUEUE, rules: [rule] }],
});
const verdict = (c) => notificationCoverageVerdict(c, { bucket: BUCKET, queue: QUEUE });
const refusedBy = (v, re) => {
  assert.equal(v.ok, false, "expected a refusal, got ok");
  assert.ok(v.refusals.some((r) => re.test(r)),
    `no refusal matched ${re}\n  got: ${v.refusals.join("\n       ")}`);
};

describe("our action vocabulary and the provider's are the same five", () => {
  test("CREATE_ACTIONS + DELETE_ACTIONS is exactly Cloudflare's enum", () => {
    // Worth asserting rather than assuming: Cloudflare's schema enum is
    // PutObject, CopyObject, DeleteObject, CompleteMultipartUpload,
    // LifecycleDeletion, and reconcile.mjs declares 3 + 2 of exactly those. This
    // is one of the few places in five rounds where the tree's vocabulary and
    // the provider's already agreed, and a test is how it stays that way.
    assert.deepEqual([...PROVIDER_ACTIONS].sort(),
      ["CompleteMultipartUpload", "CopyObject", "DeleteObject", "LifecycleDeletion", "PutObject"]);
    assert.equal(CREATE_ACTIONS.length, 3);
    assert.equal(DELETE_ACTIONS.length, 2);
  });

  test("finding 112 — the rule is broader than what M2.0 AUTHORIZES, deliberately", () => {
    // The credential minter is PutObject-shaped today and multipart is
    // unearned, so a CopyObject notification is not "an admitted write arriving
    // normally" — it is an object created by an operation we never authorized.
    // Requiring the rule to cover it is what makes that visible AS AN ALARM
    // instead of silently absent. Occupancy is a property of the bucket, not of
    // our intentions.
    const v = verdict(config());
    assert.equal(v.ok, true);
    assert.ok(CREATE_ACTIONS.includes("CopyObject"));
    assert.ok(CREATE_ACTIONS.includes("CompleteMultipartUpload"));
    const gap = verdict(withRule({ actions: ["PutObject"] }));
    assert.ok(gap.refusals.some((r) => /whether or not M2\.0 authorized it/.test(r)),
      "the refusal must not call these 'admitted writes' — that claims more than the system does");
  });

  test("the requirement is DERIVED from reconcile.mjs, not retyped here", () => {
    // If a fourth create action is ever admitted by the consumer, this predicate
    // must start requiring the rule to carry it — without an edit.
    const v = verdict(withRule({ actions: CREATE_ACTIONS.slice(0, 2) }));
    refusedBy(v, new RegExp(`does not cover ${CREATE_ACTIONS[2]}`));
  });
});

describe("finding 99 — the configuration that passes case P and loses writes", () => {
  test("the control case passes", () => {
    const v = verdict(config());
    assert.equal(v.ok, true, v.refusals.join(" | "));
  });

  test("THE REPRODUCTION: actions=[PutObject], prefix=wrong-prefix/", () => {
    // This is the exact shape from the finding. Case P sees a genuine r2_bucket
    // producer and one consumer, and exits 0. Every CopyObject, every
    // CompleteMultipartUpload — which is how a large world chunk arrives — and
    // every key outside the prefix is never produced at all.
    const v = verdict(withRule({ actions: ["PutObject"], prefix: "wrong-prefix/" }));
    refusedBy(v, /does not cover CopyObject, CompleteMultipartUpload/);
    refusedBy(v, /prefix "wrong-prefix\/", which does not cover/);
    assert.equal(v.refusals.length, 2, "both halves of the gap, separately named");
  });

  test("a missing CompleteMultipartUpload is named as occupancy that never arrives", () => {
    // The worst single omission: multipart is how the big objects land, so this
    // gap loses exactly the writes that matter most for occupancy.
    const v = verdict(withRule({ actions: ["PutObject", "CopyObject"] }));
    refusedBy(v, /CompleteMultipartUpload/);
    refusedBy(v, /no retry budget to exhaust because no message was ever produced/);
  });

  test("an EMPTY action list is refused", () => {
    refusedBy(verdict(withRule({ actions: [] })), /does not cover/);
  });

  test("a rule with no action array at all is refused", () => {
    refusedBy(verdict(withRule({ prefix: "org/" })), /declares no action array/);
  });

  test("an action outside the provider's enum is refused, not ignored", () => {
    // Finding 88's law. A vocabulary this gate does not positively recognise is
    // a refusal — a future API version adding a sixth action must stop it.
    refusedBy(verdict(withRule({ actions: [...CREATE_ACTIONS, "RestoreObject"] })),
              /outside Cloudflare's documented enum/);
  });
});

describe("the key namespace", () => {
  test("no prefix covers everything, and passes", () => {
    assert.equal(verdict(withRule({ actions: [...CREATE_ACTIONS] })).ok, true);
  });

  test(`prefix ${JSON.stringify(NAMESPACE_PREFIX)} covers everything, and passes`, () => {
    assert.equal(verdict(withRule({ actions: [...CREATE_ACTIONS], prefix: "org/" })).ok, true);
  });

  test("a PREFIX OF the namespace prefix also covers it", () => {
    // `o`, `or`, `org` all match every key. Refusing them would be a gate going
    // red for a reason unrelated to the property, which is how gates get ignored.
    for (const prefix of ["", "o", "or", "org"]) {
      assert.equal(verdict(withRule({ actions: [...CREATE_ACTIONS], prefix })).ok, true, prefix);
    }
  });

  test("a NARROWER prefix is a gap, even though it looks like ours", () => {
    // `org/a` is the dangerous case: it is our namespace, it will match many
    // real keys, and it silently drops every organization whose uuid starts with
    // anything else. A gate that only caught obviously-foreign prefixes would
    // pass it.
    for (const prefix of ["org/a", "org/aaaaaaaa-0000-4000-8000-000000000001/", "chunks/"]) {
      refusedBy(verdict(withRule({ actions: [...CREATE_ACTIONS], prefix })), /does not cover every key/);
    }
  });

  test("ANY suffix is a gap", () => {
    // Keys end in a content hash or a manifest path. No suffix covers them, and
    // one that appears to is a coincidence waiting to end.
    refusedBy(verdict(withRule({ actions: [...CREATE_ACTIONS], suffix: ".json" })),
              /filters on suffix/);
    assert.equal(verdict(withRule({ actions: [...CREATE_ACTIONS], suffix: "" })).ok, true,
      "an empty suffix is absence, not a filter");
  });
});

describe("M2.0 is append-only, so a delete rule is a REFUSAL", () => {
  for (const a of DELETE_ACTIONS) {
    test(`${a} routed to the observer is refused`, () => {
      // The observer has no delete path — reconcile.mjs names these actions in
      // order to refuse them. A delete rule also contradicts the premise the
      // `extra` refusal in inventory.mjs rests on: that an object in the ledger
      // and not in R2 cannot happen legitimately.
      refusedBy(verdict(withRule({ actions: [...CREATE_ACTIONS, a] })), /append-only/);
    });
  }
});

describe("exactly one rule, so drift is a visible edit", () => {
  test("two rules to our queue is refused even when they jointly cover", () => {
    // Cloudflare permits 100 rules per bucket and prohibits overlaps that fire
    // twice. Proving an arbitrary set equivalent to the intended one is a harder
    // claim than provisioning one rule that plainly is it.
    const v = verdict(config({ queues: [{ queueId: "q1", queueName: QUEUE, rules: [
      { actions: ["PutObject"] }, { actions: ["CopyObject", "CompleteMultipartUpload"] }] }] }));
    refusedBy(v, /2 rules route to this queue/);
  });

  test("two queue ENTRIES for our queue is refused", () => {
    const v = verdict(config({ queues: [
      { queueId: "q1", queueName: QUEUE, rules: [{ actions: [...CREATE_ACTIONS] }] },
      { queueId: "q1", queueName: QUEUE, rules: [{ actions: [...CREATE_ACTIONS] }] }] }));
    refusedBy(v, /2 separate queue entries/);
  });

  test("a queue attached with NO rules routes nothing, and is refused", () => {
    refusedBy(verdict(config({ queues: [{ queueId: "q1", queueName: QUEUE, rules: [] }] })),
              /no rules, so nothing is actually routed/);
  });
});

describe("the case-P-passes-and-this-fails case, stated directly", () => {
  test("a bucket with rules to OTHER queues but none to ours is refused", () => {
    // The channel can be authentic, dedicated, correctly consumed — and empty.
    const v = verdict(config({ queues: [
      { queueId: "q9", queueName: "someone-elses", rules: [{ actions: [...CREATE_ACTIONS] }] }] }));
    refusedBy(v, /can be authentic, dedicated and empty/);
  });

  test("another queue on the same bucket is a NOTE, not a refusal", () => {
    // A second listener takes no authority away from ours. It is reported
    // because a reader should know the bucket has other consumers.
    const v = verdict(config({ queues: [
      { queueId: "q1", queueName: QUEUE, rules: [{ actions: [...CREATE_ACTIONS] }] },
      { queueId: "q9", queueName: "analytics", rules: [{ actions: ["PutObject"] }] }] }));
    assert.equal(v.ok, true, v.refusals.join(" | "));
    assert.ok(v.notes.some((n) => /also routes to 1 other queue/.test(n)));
  });
});

describe("it refuses rather than passes when it cannot see", () => {
  test("the subject must be named", () => {
    refusedBy(notificationCoverageVerdict(config(), { bucket: BUCKET }), /which queue to expect/);
    refusedBy(notificationCoverageVerdict(config(), { queue: QUEUE }), /which bucket to expect/);
  });

  test("a configuration about the WRONG bucket is refused", () => {
    refusedBy(verdict(config({ bucketName: "someone-elses-bucket" })), /not "cd-worlds"/);
  });

  test("no enumerable queue list learns nothing, and says so", () => {
    refusedBy(verdict({ bucketName: BUCKET }), /no enumerable queue list/);
    refusedBy(verdict(null), /was not an object/);
  });

  test("a queue entry with a non-array rules field is refused", () => {
    refusedBy(verdict(config({ queues: [{ queueId: "q1", queueName: QUEUE, rules: null }] })),
              /no enumerable rule list|nothing is actually routed/);
  });
});
