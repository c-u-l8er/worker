// Case P's predicate, exercised without a Cloudflare account.
//
// FINDING 88. The first version of scripts/check-queue-authority.mjs exited 0
// on a queue it had not proved clean, in two ways, and neither was reachable
// from any test -- the whole file only ran when someone had credentials, which
// nobody does. A GATE THAT CAN ONLY BE EXERCISED IN PRODUCTION IS A GATE NOBODY
// EXERCISES, so the judgement is now a pure function and this file is the
// falsifier for it.
//
// The two reproducers the reviewer sent are the first two tests below,
// verbatim in shape.

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { queueAuthorityVerdict } from "../../scripts/check-queue-authority.mjs";

const BUCKET = "cd-worlds";
const QUEUE = "computedriven-r2-notifications";
const OBS = "computedriven-cloud-api";
const OK_PRODUCER = { type: "r2_bucket", bucket_name: BUCKET };

// Cloudflare's documented consumer object. A VALID one is supplied to every
// producer-side test below, because the consumer half is mandatory since
// finding 90 -- and a producer test that fails for want of a consumer is
// measuring the wrong thing.
const OK_CONSUMER = {
  consumer_id: "023e105f4ecef8ad9ca31a8372d0c353",
  created_on: "2019-12-27T18:11:19.117Z",
  dead_letter_queue: "computedriven-r2-notifications-dlq",
  queue_name: QUEUE,
  script_name: OBS,
  settings: { batch_size: 50, max_concurrency: 10, max_retries: 5,
              max_wait_time_ms: 5000, retry_delay: 10 },
  type: "worker",
};
const EXPECT = { bucket: BUCKET, consumerScript: OBS, queue: QUEUE };

// The provider's own total has to agree with the list, so every fixture states
// it. A helper rather than a literal, because forgetting it is itself a refusal
// and the tests that are ABOUT something else should not trip on that.
const queue = (producers, extra = {}) => ({
  queue_id: "q-1",
  queue_name: QUEUE,
  producers,
  producers_total_count: producers.length,
  consumers: [OK_CONSUMER],
  consumers_total_count: 1,
  ...extra,
});

describe("case P refuses anything it has not positively recognised (finding 88)", () => {
  test("an unclassified producer type REFUSES, it does not merely warn", () => {
    // REPRODUCER 1. Shipped behaviour: `NOTE 1 producer(s) of a type this
    // script does not classify` followed by `OK`, exit 0.
    const v = queueAuthorityVerdict(
      queue([OK_PRODUCER, { type: "future_external_authority" }]), EXPECT);
    assert.equal(v.ok, false);
    assert.match(v.refusals.join(" "), /does not recognise/);
  });

  test("an r2_bucket producer with NO bucket_name REFUSES", () => {
    // REPRODUCER 2. Shipped behaviour: exit 0, because the bucket was judged
    // wrong only when bucket_name was truthy AND different.
    const v = queueAuthorityVerdict(queue([{ type: "r2_bucket" }]), EXPECT);
    assert.equal(v.ok, false);
    assert.match(v.refusals.join(" "), /names null/);
  });

  test("the clean case is the ONLY thing that passes", () => {
    const v = queueAuthorityVerdict(queue([OK_PRODUCER]), EXPECT);
    assert.deepEqual(v.refusals, []);
    assert.equal(v.ok, true);
  });

  test("a Worker producer REFUSES — that is the whole of R77", () => {
    const v = queueAuthorityVerdict(
      queue([OK_PRODUCER, { type: "worker", script: "some-other-worker" }]), EXPECT);
    assert.equal(v.ok, false);
    assert.match(v.refusals.join(" "), /some-other-worker/);
  });

  test("a producer naming ANOTHER bucket REFUSES", () => {
    const v = queueAuthorityVerdict(
      queue([{ type: "r2_bucket", bucket_name: "someone-elses-bucket" }]), EXPECT);
    assert.equal(v.ok, false);
  });

  test("zero producers REFUSES — an empty list is not a clean list", () => {
    assert.equal(queueAuthorityVerdict(queue([]), EXPECT).ok, false);
  });
});

describe("case P refuses when it cannot see (finding 88)", () => {
  test("no producers array at all REFUSES and says what it saw", () => {
    const v = queueAuthorityVerdict({ queue_id: "q-1", consumers: [] }, EXPECT);
    assert.equal(v.ok, false);
    assert.match(v.refusals.join(" "), /learned nothing/);
  });

  test("a total that disagrees with the list REFUSES — the missing ones are unexamined", () => {
    const v = queueAuthorityVerdict(
      { producers: [OK_PRODUCER], producers_total_count: 4 }, EXPECT);
    assert.equal(v.ok, false);
    assert.match(v.refusals.join(" "), /incomplete/);
  });

  test("a MISSING total REFUSES — there is then nothing to cross-check against", () => {
    const v = queueAuthorityVerdict({ producers: [OK_PRODUCER] }, EXPECT);
    assert.equal(v.ok, false);
    assert.match(v.refusals.join(" "), /producers_total_count is absent/);
  });

  test("a non-object response REFUSES", () => {
    assert.equal(queueAuthorityVerdict(null, EXPECT).ok, false);
    assert.equal(queueAuthorityVerdict("q", EXPECT).ok, false);
  });
});

describe("the consumer half of R77 (findings 89, 90, 91, 92)", () => {
  const consumer = (over = {}) => ({ ...OK_CONSUMER, ...over });
  const expect = EXPECT;
  const withConsumers = (cs) => queue([OK_PRODUCER], { consumers: cs, consumers_total_count: cs.length });

  test("FINDING 90: Cloudflare's LITERAL documented consumer object passes", () => {
    // THE TEST THAT WAS MISSING, and its absence is the whole of finding 90.
    // The predicate read `c?.script ?? c?.service` -- two field names nobody at
    // Cloudflare uses -- and the tests below it were written against the same
    // invention, so the gate passed every test it had while REFUSING a
    // correctly provisioned live queue. Pasted from the API reference, not
    // paraphrased.
    //
    //     A FIXTURE INVENTED BY THE HAND THAT WROTE THE PREDICATE TESTS THE
    //     INVENTION, NOT THE PROVIDER.
    const v = queueAuthorityVerdict(withConsumers([consumer()]), expect);
    assert.deepEqual(v.refusals, [],
      "a correctly provisioned queue must PASS; this is the reproducer for finding 90");
    assert.equal(v.ok, true);
  });

  test("a consumer with no recognisable name REFUSES rather than reading as unnamed", () => {
    const v = queueAuthorityVerdict(
      withConsumers([consumer({ script_name: undefined })]), expect);
    assert.equal(v.ok, false);
    assert.match(v.refusals.join(" "), /names null/);
  });

  test("a foreign consumer on the authority channel REFUSES", () => {
    const v = queueAuthorityVerdict(
      withConsumers([consumer(), consumer({ script_name: "someone-else" })]), expect);
    assert.equal(v.ok, false);
    assert.match(v.refusals.join(" "), /someone-else/);
  });

  test("no consumer at all REFUSES — the channel is not being received", () => {
    const v = queueAuthorityVerdict(withConsumers([]), expect);
    assert.equal(v.ok, false);
    assert.match(v.refusals.join(" "), /nothing is receiving/);
  });

  test("a consumer type other than \"worker\" REFUSES", () => {
    const v = queueAuthorityVerdict(withConsumers([consumer({ type: "http_pull" })]), expect);
    assert.equal(v.ok, false);
    assert.match(v.refusals.join(" "), /only "worker" is recognised/);
  });

  test("FINDING 91: a consumer attached to a DIFFERENT queue REFUSES", () => {
    // The attestation would otherwise be true and irrelevant: case P proves
    // queue A is clean while the runtime trusts queue B.
    const v = queueAuthorityVerdict(
      withConsumers([consumer({ queue_name: "some-other-queue" })]), expect);
    assert.equal(v.ok, false);
    assert.match(v.refusals.join(" "), /about a different channel/);
  });

  test("FINDING 92: a consumer with NO dead_letter_queue REFUSES", () => {
    // Cloudflare: "Without a DLQ configured, messages that reach the retry
    // limit are deleted permanently." A deleted notification is an occupancy
    // number that silently never arrives.
    for (const dlq of ["", "   ", undefined, null]) {
      const v = queueAuthorityVerdict(withConsumers([consumer({ dead_letter_queue: dlq })]), expect);
      assert.equal(v.ok, false, `dlq=${JSON.stringify(dlq)} must refuse`);
      assert.match(v.refusals.join(" "), /deleted permanently/);
    }
  });

  test("a consumers_total_count that disagrees with the list REFUSES", () => {
    const v = queueAuthorityVerdict(
      queue([OK_PRODUCER], { consumers: [consumer()], consumers_total_count: 3 }), expect);
    assert.equal(v.ok, false);
  });

  test("an ABSENT consumer expectation REFUSES — case P asserts both sides or neither", () => {
    // It used to be optional, so "case P PASS" could mean "the producer side is
    // clean and nobody looked at the consumer side". Absence is not permission,
    // one layer up from finding 89.
    const v = queueAuthorityVerdict(withConsumers([consumer()]), { bucket: BUCKET, queue: QUEUE });
    assert.equal(v.ok, false);
    assert.match(v.refusals.join(" "), /BOTH sides or it asserts nothing/);
  });
});
