// The provider-native R2 seam. Round 6, finding 1.
//
// THE DEFECT, reproduced before it was fixed:
//
//     r2creds.mjs said, in capitals, "THESE ARE COMPUTEDRIVEN CAPABILITY NAMES,
//     NOT PROVIDER ACTION STRINGS ... a provider adapter MAPS these".
//     assertProviderConformance() then compared provider actions to those same
//     ComputeDriven words literally, so a CORRECT R2 adapter --
//
//         ListObjects  ->  ListObjectsV1, ListObjectsV2
//
//     -- failed the very law it was written to satisfy, with CD-CRED-WIDENED.
//
// The module was simultaneously demanding a translation and forbidding one. The
// first test below is that reproduction, kept as a test so the contradiction
// cannot come back quietly.

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  scopeForWorld, assertProviderConformance, grantForScope, epochSeconds,
} from "../src/r2creds.mjs";
import {
  r2GrantForScope, assertR2Conformance, assertPayloadMatchesGrant,
  refuseCoarsePreset, R2_TRANSLATION, R2_NATIVE_ACTIONS, R2_FORBIDDEN, R2,
  r2UploadIntentGrant, R31_BYTE_BINDING,
} from "../src/r2native.mjs";

const ORG_A = "aaaaaaaa-0000-4000-8000-000000000001";
const ORG_B = "bbbbbbbb-0000-4000-8000-000000000002";
const WORLD = "11111111-0000-4000-8000-00000000000a";

const scope = () => scopeForWorld({
  bucket: "cd", organizationId: ORG_A, worldId: WORLD, permission: "object-read" });
const bend = (s, over = {}) => Object.freeze({ ...r2GrantForScope(s), ...over });

describe("the two vocabularies are different, and the difference is declared", () => {
  test("REPRODUCTION: a correct R2 grant used to fail; it now conforms", () => {
    const s = scope();
    const native = {
      provider: "r2",
      bucket: "cd",
      prefixPaths: [s.prefix],
      objectPaths: [],
      // R2's own words, from its documentation -- not ours.
      actions: ["GetObject", "HeadObject", "ListObjectsV1", "ListObjectsV2"],
      expiresAtEpochSeconds: s.expiresAtEpochSeconds,
    };
    assert.ok(assertR2Conformance(s, native), "the correct R2 grant must conform");

    // And the other half of the same fact: those native names are NOT
    // ComputeDriven capability names, so the provider-independent law still
    // refuses them. Both laws are right; they are about different vocabularies.
    assert.throws(() => assertProviderConformance(s, native),
      /CD-CRED-UNKNOWNACTION|CD-CRED-WIDENED/);
  });

  test("ComputeDriven says ListObjects; R2 does not have that action at all", () => {
    assert.ok(!R2_NATIVE_ACTIONS.includes("ListObjects"));
    assert.ok(!R2_NATIVE_ACTIONS.includes("ListBucket"), "that is AWS IAM's name, not R2's");
    assert.deepEqual(R2_TRANSLATION.ListObjects, ["ListObjectsV1", "ListObjectsV2"]);
  });

  test("one capability becomes TWO actions -- which is why a table, not a rename", () => {
    const g = r2GrantForScope(scope());
    assert.deepEqual(g.actions, ["GetObject", "HeadObject", "ListObjectsV1", "ListObjectsV2"]);
    assert.equal(scope().operations.length, 3);
    assert.equal(g.actions.length, 4);
  });

  test("the translation table only maps into R2's real vocabulary", () => {
    // makeVocabulary() refuses a table that maps to an action R2 does not
    // define, so a typo in the table is a load error rather than a credential
    // that fails at 3am against a real bucket.
    for (const natives of Object.values(R2_TRANSLATION)) {
      for (const n of natives) assert.ok(R2_NATIVE_ACTIONS.includes(n), n);
    }
  });

  test("a capability with no declared translation is a refusal, never a pass-through", () => {
    // Pass-through is exactly how `ListObjects` would reach R2 as a literal
    // action name that R2 does not define.
    const s = scope();
    const invented = Object.create(Object.getPrototypeOf(s), {
      ...Object.getOwnPropertyDescriptors(s),
      operations: { value: Object.freeze(["ListObjects", "SomeFutureCapability"]) },
    });
    // (An invented scope is unbranded, so this refuses on provenance first --
    // which is itself the right answer. The vocabulary refusal is checked
    // directly below, where the scope is real.)
    assert.throws(() => r2GrantForScope(invented), /CD-CRED-SCOPE/);
    assert.throws(() => R2.expand(["SomeFutureCapability"]), /CD-CRED-UNTRANSLATED/);
  });
});

describe("R2 conformance is checked against the NATIVE grant", () => {
  test("the derived native grant conforms to the scope it came from", () => {
    const s = scope();
    assert.ok(assertR2Conformance(s, r2GrantForScope(s)));
  });

  test("the native grant is frozen, so what was checked is what gets signed", () => {
    const g = r2GrantForScope(scope());
    assert.ok(Object.isFrozen(g) && Object.isFrozen(g.actions) && Object.isFrozen(g.prefixPaths));
    assert.throws(() => { g.bucket = "elsewhere"; }, TypeError);
  });

  test("it uses R2's own field names, so the adapter serialises rather than translates twice", () => {
    const g = r2GrantForScope(scope());
    assert.ok("prefixPaths" in g && "objectPaths" in g,
      "local signing spells these paths.prefixPaths / paths.objectPaths");
    assert.equal(typeof g.expiresAtEpochSeconds, "number",
      "the signed exp claim is epoch seconds, so that is what we carry");
  });

  test("HALF the list capability is an UNDER-grant, not a narrowing", () => {
    // A credential that can list one way and not the other is a support ticket
    // in three months.
    assert.throws(() => assertR2Conformance(scope(), bend(scope(), {
      actions: ["GetObject", "HeadObject", "ListObjectsV2"] })), /CD-CRED-UNDERGRANT/);
  });

  test("an action R2 does not define is refused as UNKNOWN, not merely unforbidden", () => {
    // A closed vocabulary. This is stronger than a deny-list: it catches the
    // action nobody thought to forbid, including a typo.
    assert.throws(() => assertR2Conformance(scope(), bend(scope(), {
      actions: [...r2GrantForScope(scope()).actions, "GetObjectt"] })),
      /CD-CRED-UNKNOWNACTION/);
  });

  test("every destructive R2 action is refused even though R2 defines it", () => {
    for (const op of R2_FORBIDDEN) {
      assert.ok(R2_NATIVE_ACTIONS.includes(op), `${op} must be a real R2 action`);
      assert.throws(() => assertR2Conformance(scope(), bend(scope(), {
        actions: [...r2GrantForScope(scope()).actions, op] })),
        /CD-CRED-FORBIDDEN|CD-CRED-WIDENED/, op);
    }
  });

  test("multipart is NOT authorized today, and adding it silently would widen", () => {
    // M2 chunking will need CreateMultipartUpload/UploadPart. When it arrives it
    // gets its own ComputeDriven capability and its own table row, so the
    // widening shows up in a diff instead of in a credential.
    for (const op of ["CreateMultipartUpload", "UploadPart", "CompleteMultipartUpload"]) {
      assert.ok(R2_NATIVE_ACTIONS.includes(op));
      assert.throws(() => assertR2Conformance(scope(), bend(scope(), {
        actions: [...r2GrantForScope(scope()).actions, op] })), /CD-CRED-WIDENED/, op);
    }
  });

  test("a whole-bucket native grant with identical actions is refused", () => {
    assert.throws(() => assertR2Conformance(scope(), bend(scope(), { prefixPaths: [""] })),
      /CD-CRED-WIDENED/);
  });

  test("a native grant reaching another tenant's prefix is refused", () => {
    assert.throws(() => assertR2Conformance(scope(), bend(scope(), {
      prefixPaths: [`org/${ORG_B}/`] })), /CD-CRED-WIDENED/);
  });

  test("a native grant that outlives the scope is refused", () => {
    const s = scope();
    assert.throws(() => assertR2Conformance(s, bend(s, {
      // R2's REST ttlSeconds ceiling is 604800 -- seven days, and this is what
      // asking for it would look like.
      expiresAtEpochSeconds: s.expiresAtEpochSeconds + 604800,
    })), /CD-CRED-WIDENED/);
  });
});

describe("the coarse preset shortcut is refused by name", () => {
  test("object-read-write cannot express object-write, because it deletes", () => {
    assert.throws(() => refuseCoarsePreset("object-read-write"), /CD-CRED-COARSE/);
    assert.throws(() => refuseCoarsePreset("object-read-write"), /DeleteObject/);
  });

  test("the refusal says what to do instead", () => {
    assert.throws(() => refuseCoarsePreset("object-read-only"), /locally-signed/);
  });
});

describe("what is signed is what was checked", () => {
  // Round 4's lesson, one layer further down: checking a grant object buys
  // nothing if a separately-built payload is what reaches the signer.
  const payloadFor = (g, over = {}) => ({
    bucket: g.bucket,
    paths: { prefixPaths: [...g.prefixPaths], objectPaths: [...g.objectPaths] },
    actions: [...g.actions],
    exp: g.expiresAtEpochSeconds,
    ...over,
  });

  test("the faithful payload is accepted", () => {
    const g = r2GrantForScope(scope());
    assert.ok(assertPayloadMatchesGrant(g, payloadFor(g)));
  });

  test("a payload that widens the paths after the check is caught", () => {
    const g = r2GrantForScope(scope());
    assert.throws(() => assertPayloadMatchesGrant(g,
      payloadFor(g, { paths: { prefixPaths: [""], objectPaths: [] } })),
      /CD-CRED-PAYLOAD/);
  });

  test("a payload that adds an action after the check is caught", () => {
    const g = r2GrantForScope(scope());
    assert.throws(() => assertPayloadMatchesGrant(g,
      payloadFor(g, { actions: [...g.actions, "DeleteObject"] })), /CD-CRED-PAYLOAD/);
  });

  test("a payload that extends exp after the check is caught", () => {
    const g = r2GrantForScope(scope());
    assert.throws(() => assertPayloadMatchesGrant(g,
      payloadFor(g, { exp: g.expiresAtEpochSeconds + 86400 })), /CD-CRED-PAYLOAD/);
  });

  test("a malformed exp in the payload is refused rather than compared as NaN", () => {
    const g = r2GrantForScope(scope());
    assert.throws(() => assertPayloadMatchesGrant(g, payloadFor(g, { exp: "soon" })),
      /CD-CRED-EXPIRY/);
  });
});

// ---------------------------------------------------------------------------
// ROUND 7. The M2 write shape — and this whole block exists because the MUTATION
// BATTERY found it missing, not because anyone reviewed for it. Four vectors
// survived against object-scoped authority and the upload artifact:
//
//     object-scope-accepts-prefix · object-scope-any-object
//     upload-intent-any-permission · upload-intent-needs-no-digest
//
// Code written and never tested, in the same round that added it. A surviving
// mutation is an untested decision, and these were four.
// ---------------------------------------------------------------------------
describe("object-scoped authority is narrower than the prefix it lives in", () => {
  const KEY = `org/${ORG_A}/world/${WORLD}/chunk/abc123`;
  const OTHER = `org/${ORG_A}/world/${WORLD}/chunk/def456`;
  const objScope = (over = {}) => scopeForWorld({
    bucket: "cd", organizationId: ORG_A, worldId: WORLD, objectKey: KEY, ...over });

  test("the grant carries ONE object key and no prefix at all", () => {
    const g = r2GrantForScope(objScope());
    assert.deepEqual([...g.objectPaths], [KEY]);
    assert.deepEqual([...g.prefixPaths], []);
  });

  test("a PREFIX grant against an object scope is a widening, not a formatting choice", () => {
    // Same bucket, same actions, same expiry — and reach over every chunk in the
    // world instead of the one that was paid for.
    const s = objScope();
    assert.throws(() => assertR2Conformance(s, {
      ...r2GrantForScope(s), prefixPaths: [s.prefix], objectPaths: [],
    }), /CD-CRED-WIDENED/);
  });

  test("a grant for a DIFFERENT object in the same world is refused", () => {
    const s = objScope();
    assert.throws(() => assertR2Conformance(s, { ...r2GrantForScope(s), objectPaths: [OTHER] }),
      /CD-CRED-WIDENED/);
  });

  test("a grant for TWO objects is refused even if one of them is right", () => {
    const s = objScope();
    assert.throws(() => assertR2Conformance(s, { ...r2GrantForScope(s), objectPaths: [KEY, OTHER] }),
      /CD-CRED-WIDENED/);
  });

  test("a grant for NO object cannot satisfy an object scope", () => {
    const s = objScope();
    assert.throws(() => assertR2Conformance(s, { ...r2GrantForScope(s), objectPaths: [] }),
      /CD-CRED-UNDERGRANT/);
  });

  test("an object key outside the world prefix is refused at construction", () => {
    for (const bad of [
      `org/${ORG_B}/world/${WORLD}/chunk/abc`,
      `org/${ORG_A}/world/${WORLD}/../../escape`,
      `/org/${ORG_A}/world/${WORLD}/chunk/abc`,
      "chunk/abc",
      "",
    ]) {
      assert.throws(() => objScope({ objectKey: bad }), /CD-CRED-OBJECT/, bad);
    }
  });

  test("the PREFIX itself is not an object key", () => {
    const prefix = `org/${ORG_A}/world/${WORLD}/`;
    assert.throws(() => objScope({ objectKey: prefix }), /CD-CRED-OBJECT/);
  });
});

describe("the upload artifact bounds what it can, and says what it cannot", () => {
  const KEY = `org/${ORG_A}/world/${WORLD}/chunk/abc123`;
  const readScope = () => scopeForWorld({
    bucket: "cd", organizationId: ORG_A, worldId: WORLD, objectKey: KEY });

  // A write scope needs a real admission, so this fakes the one thing the
  // provider layer legitimately does not own.
  const writeScope = async () => {
    const { admitStorage } = await import("../src/admission.mjs");
    const conn = { async query() { return { rows: [{
      reservation_id: "dddddddd-0000-4000-8000-00000000000d",
      organization_id: ORG_A, world_id: WORLD, bytes: 4096,
      expires_at: new Date(Date.now() + 3600_000), tier: "driver",
      byte_limit: 107374182400, committed_bytes: 0, reserved_bytes: 4096, replayed: false,
    }] }; } };
    const admission = await admitStorage(conn, {
      worldId: WORLD, principalId: ORG_B, bytes: 4096, idempotencyKey: "k" });
    return scopeForWorld({
      bucket: "cd", organizationId: ORG_A, worldId: WORLD,
      objectKey: KEY, permission: "object-write", admission, ttlSeconds: 900 });
  };

  test("a well-formed intent authorizes exactly one PutObject on one key", async () => {
    const g = r2UploadIntentGrant(await writeScope(), {
      expectedBytes: 4096, contentDigest: "blake3:abc" });
    assert.deepEqual([...g.actions], ["PutObject"]);
    assert.deepEqual([...g.objectPaths], [KEY]);
    assert.deepEqual([...g.prefixPaths], []);
    assert.equal(g.form, "presigned");
  });

  test("a READ scope cannot become an upload artifact", () => {
    assert.throws(() => r2UploadIntentGrant(readScope(), {
      expectedBytes: 1, contentDigest: "blake3:abc" }), /CD-CRED-PERM/);
  });

  test("a prefix-scoped write cannot become an upload artifact", async () => {
    const { admitStorage } = await import("../src/admission.mjs");
    const conn = { async query() { return { rows: [{
      reservation_id: "dddddddd-0000-4000-8000-00000000000d",
      organization_id: ORG_A, world_id: WORLD, bytes: 4096,
      expires_at: new Date(Date.now() + 3600_000), tier: "driver",
      byte_limit: 1, committed_bytes: 0, reserved_bytes: 0, replayed: false,
    }] }; } };
    const admission = await admitStorage(conn, {
      worldId: WORLD, principalId: ORG_B, bytes: 4096, idempotencyKey: "k" });
    const prefixWrite = scopeForWorld({
      bucket: "cd", organizationId: ORG_A, worldId: WORLD,
      permission: "object-write", admission, ttlSeconds: 900 });
    assert.throws(() => r2UploadIntentGrant(prefixWrite, {
      expectedBytes: 1, contentDigest: "blake3:abc" }), /CD-CRED-OBJECT/);
  });

  test("a digest is required — without one there is nothing to check an arrival against", async () => {
    const s = await writeScope();
    for (const bad of [undefined, "", "   ", 42, null]) {
      assert.throws(() => r2UploadIntentGrant(s, { expectedBytes: 1, contentDigest: bad }),
        /CD-CRED-OBJECT/, String(bad));
    }
  });

  test("expectedBytes must be a positive integer", async () => {
    const s = await writeScope();
    for (const bad of [0, -1, 1.5, "4096", NaN, undefined]) {
      assert.throws(() => r2UploadIntentGrant(s, {
        expectedBytes: bad, contentDigest: "blake3:abc" }), /CD-CRED-OBJECT/, String(bad));
    }
  });

  test("the artifact says byte-binding is UNPROVEN rather than implying enforcement", async () => {
    // The whole point of R31 being OPEN: a consumer must not read expectedBytes
    // off this object and conclude R2 is enforcing it. Cloudflare documents
    // Content-Type as signed and enforced and says nothing about Content-Length.
    const g = r2UploadIntentGrant(await writeScope(), {
      expectedBytes: 4096, contentDigest: "blake3:abc" });
    assert.equal(g.byteBinding, "unproven");
    assert.equal(R31_BYTE_BINDING.status, "unproven");
    assert.match(R31_BYTE_BINDING.falsifier, /live-falsifier/);
  });

  test("the artifact carries the reservation that paid for it", async () => {
    const g = r2UploadIntentGrant(await writeScope(), {
      expectedBytes: 4096, contentDigest: "blake3:abc" });
    assert.equal(g.reservationId, "dddddddd-0000-4000-8000-00000000000d");
  });

  test("a forged scope cannot produce an upload artifact", () => {
    assert.throws(() => r2UploadIntentGrant({
      bucket: "cd", prefix: "", objectKey: KEY, permission: "object-write",
      operations: ["PutObject"], expiresAtEpochSeconds: 4102444799,
    }, { expectedBytes: 1, contentDigest: "d" }), /CD-CRED-SCOPE/);
  });
});

describe("provenance holds at the provider boundary too", () => {
  test("a hand-built scope cannot produce a native grant", () => {
    assert.throws(() => r2GrantForScope({
      bucket: "cd", prefix: "", operations: ["GetObject"],
      expiresAtEpochSeconds: 4102444799,
    }), /CD-CRED-SCOPE/);
  });

  test("the provider-independent grant and the native one describe the same authority", () => {
    const s = scope();
    const generic = grantForScope(s);
    const native = r2GrantForScope(s);
    assert.equal(generic.bucket, native.bucket);
    assert.deepEqual([...generic.prefixPaths], [...native.prefixPaths]);
    assert.equal(epochSeconds(generic.expiresAtEpochSeconds),
                 epochSeconds(native.expiresAtEpochSeconds));
    // ...and differ in exactly one place, which is the point of the file.
    assert.notDeepEqual([...generic.actions], [...native.actions]);
  });
});
