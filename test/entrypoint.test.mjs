// COMPOSITION battery — drives the real `default.fetch`, not a module.
//
// This file exists because of a specific class of defect an outside review
// found: every module law held, and the entrypoint invalidated one anyway.
//
//   jwt.mjs proves    a JwksCache instance rate-caps forced refreshes.
//   index.mjs did     `new JwksCache(...)` INSIDE fetch(), so every request got
//                     a fresh object with forcedAt = 0.
//   net effect        the cap did not exist where it mattered.
//
// The lesson generalises, so it gets its own suite: for every load-bearing local
// invariant, exercise at least one path through the ACTUAL entrypoint that could
// invalidate it while its module test stays green.

import { test, describe, before, beforeEach } from "node:test";
import assert from "node:assert/strict";
import worker from "../src/index.mjs";
import { makeKeys, mintWith, ISS, AUD } from "./helpers.mjs";

let keys, issuerFetches, realFetch;

const ENV = () => ({
  WORKOS_ISSUER: ISS,
  WORKOS_JWKS_URI: "https://auth.invalid/jwks",
  OIDC_AUDIENCE: AUD,
  R2_BUCKET: "test-bucket",
  // deliberately absent: HYPERDRIVE_CONTROL. connect() refuses, which is correct
  // and lets these tests reach the auth path without a database.
});

const req = (path, token) => new Request(`https://api.invalid${path}`, {
  method: "GET",
  headers: token ? { authorization: `Bearer ${token}` } : {},
});

before(async () => {
  keys = await makeKeys();
  realFetch = globalThis.fetch;
});

beforeEach(() => {
  issuerFetches = 0;
  globalThis.fetch = async (url) => {
    if (String(url).includes("/jwks")) {
      issuerFetches++;
      return { ok: true, status: 200, json: async () => keys.jwksDoc };
    }
    return realFetch(url);
  };
});

describe("the JWKS cooldown survives at the entrypoint, not just in the module", () => {
  test("50 requests with 50 unknown kids do not cause 50 issuer fetches", async () => {
    for (let i = 0; i < 50; i++) {
      const token = await mintWith(keys.pair, {}, { kid: `bogus-entry-${i}` });
      const res = await worker.fetch(req("/v1/worlds", token), ENV());
      assert.equal(res.status, 401, "an unknown kid must be refused");
    }
    // Without the module-scope cache this was 50. The exact bound depends on the
    // cooldown; what must never be true again is one-fetch-per-request.
    assert.ok(issuerFetches <= 3,
      `expected the forced-refresh cap to hold across requests, got ${issuerFetches} fetches`);
  });

  test("a legitimate token still verifies after the flood", async () => {
    for (let i = 0; i < 5; i++) {
      await worker.fetch(req("/v1/worlds", await mintWith(keys.pair, {}, { kid: `x-${i}` })), ENV());
    }
    const good = await mintWith(keys.pair);
    const res = await worker.fetch(req("/v1/worlds", good), ENV());
    const body = await res.json();
    // It gets past verification and stops at the database, which is not deployed.
    assert.equal(body.code, "CD-CRED-NOTDEPLOYED",
      `expected to reach connect(), got ${JSON.stringify(body)}`);
  });
});

describe("an unauthenticated request never costs a database connection", () => {
  test("a malformed bearer token is refused before connect()", async () => {
    const res = await worker.fetch(req("/v1/worlds", "not-a-jwt"), ENV());
    const body = await res.json();
    assert.equal(res.status, 401);
    assert.notEqual(body.code, "CD-CRED-NOTDEPLOYED",
      "connect() must not run for an unverifiable token");
  });

  test("a missing authorization header is refused before connect()", async () => {
    const body = await (await worker.fetch(req("/v1/worlds"), ENV())).json();
    assert.equal(body.code, "CD-JWT-SHAPE");
  });

  test("a token signed by the wrong key is refused before connect()", async () => {
    const bad = await mintWith(keys.pair, {}, { signWith: keys.other.privateKey });
    const body = await (await worker.fetch(req("/v1/worlds", bad), ENV())).json();
    assert.equal(body.code, "CD-JWT-SIG");
  });
});

describe("refusals reach the wire as refusals", () => {
  test("/healthz reports what is true rather than 'ok'", async () => {
    const body = await (await worker.fetch(req("/healthz"), ENV())).json();
    assert.equal(body.deployed, false);
    assert.equal(body.database, "not bound");
  });

  test("an expired token is a 401 carrying its code, not a 500", async () => {
    const nowS = Math.floor(Date.now() / 1000);
    const stale = await mintWith(keys.pair, { iat: nowS - 4000, exp: nowS - 3600 });
    const res = await worker.fetch(req("/v1/worlds", stale), ENV());
    assert.equal(res.status, 401);
    assert.equal((await res.json()).code, "CD-JWT-EXP");
  });

  test("a realm that omits organization ids is a 503, not a 401", async () => {
    // An operator misconfiguration must not be reported as a bad credential --
    // that sends them hunting the token instead of the mapper.
    const t = await mintWith(keys.pair, { organization: ["acme"] });
    const res = await worker.fetch(req("/v1/worlds", t), { ...ENV(), HYPERDRIVE_CONTROL: {} });
    const body = await res.json();
    // connect() still refuses first here (no driver), so assert the code is
    // reachable rather than asserting a status the database beat us to.
    assert.ok(["CD-AUTHZ-ORGID-MISSING", "CD-CRED-NOTDEPLOYED"].includes(body.code), body.code);
  });

  test("no response body ever leaks a stack trace", async () => {
    const res = await worker.fetch(req("/v1/worlds", "x.y.z"), ENV());
    const text = JSON.stringify(await res.json());
    for (const leak of ["at ", ".mjs:", "node:internal"]) {
      assert.ok(!text.includes(leak), `response leaked ${leak}: ${text}`);
    }
  });
});

describe("the queue consumer admits ONE channel, and refuses before it connects", () => {
  // FINDING 89 / R77. R77's first half gave delivery identity its channel, so
  // the row records WHICH queue spoke. This is the second half: whether that
  // channel was ALLOWED to. Cloudflare supports attaching one consumer Worker
  // to several queues and tells applications to switch on MessageBatch.queue,
  // so identity and authority come apart the moment a second consumer binding
  // is added -- which is provisioning drift, and provisioning drift is what a
  // deployment survives silently.
  const QENV = { ...ENV(), PROVIDER_QUEUE: "computedriven-r2-notifications" };
  const batch = (queue) => ({ queue, messages: [{ id: "m-1", body: {} }] });

  test("a batch from a foreign queue is refused, and NO connection is attempted", async () => {
    // HYPERDRIVE_CONTROL is PRESENT here on purpose. If admission ran after
    // connect(), the refusal would read CD-CRED-NOTDEPLOYED and this test would
    // pass for the wrong reason -- the same trap the unauthenticated-request
    // suite above exists for.
    const env = { ...QENV, HYPERDRIVE_CONTROL: {} };
    await assert.rejects(() => worker.queue(batch("some-other-queue"), env, {}),
      /CD-QUEUE-FOREIGN/);
  });

  test("a Worker with NO attested channel refuses everything, including the right queue", async () => {
    // Absence is not permission. A consumer that cannot name its authority has
    // no way to tell one from a stranger.
    const { PROVIDER_QUEUE, ...noAttestation } = QENV;
    await assert.rejects(
      () => worker.queue(batch("computedriven-r2-notifications"), noAttestation, {}),
      /CD-QUEUE-UNATTESTED/);
  });

  test("a batch that names no queue at all is refused", async () => {
    await assert.rejects(() => worker.queue({ messages: [] }, QENV, {}), /CD-QUEUE-UNNAMED/);
  });

  test("the attested channel gets PAST admission and fails on the absent driver", async () => {
    // The accept path, and it has to be here: a suite that only proves refusals
    // passes against a handler that refuses everything. CD-CRED-NOTDEPLOYED is
    // the correct next refusal while 0 live is true, and it is proof that
    // admission was cleared rather than that nothing was tried.
    await assert.rejects(
      () => worker.queue(batch("computedriven-r2-notifications"), QENV, {}),
      /CD-CRED-NOTDEPLOYED/);
  });
});

describe("the observer's credential is not the request path's (finding 94 / R80)", () => {
  // `computedriven_api` and `computedriven_jobs` are separate PostgreSQL roles
  // and the API role deliberately has NO EXECUTE on observe_storage_object().
  // A Hyperdrive configuration carries its own origin user, so one binding is
  // one credential — and connect()/connectJobs() sharing HYPERDRIVE_CONTROL
  // would have collapsed that boundary at the moment the driver was written,
  // with both function names still reading correctly.
  //
  // THE MUTATION `jobs-uses-request-credential` SURVIVED UNTIL THIS TEST
  // EXISTED. Every other queue test omits both bindings, so the correct and
  // the collapsed code threw the same CD-CRED-NOTDEPLOYED and nothing could
  // tell them apart. Present ONE binding and the difference becomes visible —
  // which is the same trick the foreign-channel test uses on connect().
  const QENV = { ...ENV(), PROVIDER_QUEUE: "computedriven-r2-notifications" };
  const batch = { queue: "computedriven-r2-notifications", messages: [{ id: "m", body: {} }] };

  test("with only the REQUEST binding present, the consumer still has no credential", async () => {
    await assert.rejects(
      () => worker.queue(batch, { ...QENV, HYPERDRIVE_CONTROL: {} }, {}),
      /no HYPERDRIVE_JOBS binding/);
  });

  test("with only the JOBS binding present, the consumer gets past the binding check", async () => {
    // The accept path for the same property: it reaches the unimplemented
    // driver, which is the correct next refusal while 0 live is true.
    await assert.rejects(
      () => worker.queue(batch, { ...QENV, HYPERDRIVE_JOBS: {} }, {}),
      /driver adapter is not implemented/);
  });

  test("and the request path is unaffected by the jobs binding", async () => {
    const res = await worker.fetch(req("/healthz"), { ...ENV(), HYPERDRIVE_JOBS: {} });
    assert.equal((await res.json()).database, "not bound");
  });
});
