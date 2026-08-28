// The provider-native R2 seam.
//
// WHY THIS FILE EXISTS. r2creds.mjs said, correctly and in capitals, that its
// permission names are ComputeDriven capability names and that "a provider
// adapter MAPS these; it does not assume they are already R2's words." And then
// its conformance checker compared provider actions against those same
// ComputeDriven words literally. Both halves cannot be true. Reproduced before
// fixing:
//
//     scope.operations       GetObject HeadObject ListObjects
//     correct R2 grant       GetObject HeadObject ListObjectsV1 ListObjectsV2
//     assertProviderConformance()  ->  CD-CRED-WIDENED
//
// A correct adapter failed the law it was written to satisfy. The module was
// simultaneously demanding a translation and forbidding one.
//
//     REFINEMENT BETWEEN CAPABILITY VOCABULARIES MUST ITSELF BE EXPLICIT AND
//     TESTABLE.
//
// So the translation is a declared table, not an assumption, and the thing
// conformance checks is the NATIVE grant -- the exact object that gets signed --
// against the ComputeDriven scope, through that table.
//
// STATUS: this is the translator and its law. There is still no account, no
// bucket, no parent key and no signing. See cloud.computedriven.com/status.json.

import {
  CredentialRefusal, assertAuthorizedScope, makeVocabulary, assertRefines,
  epochSeconds,
} from "./r2creds.mjs";

// ---------------------------------------------------------------------------
// R2's OWN vocabulary. Verified first-party against Cloudflare's documentation
// on 2026-08-22, not recalled:
//
//   https://developers.cloudflare.com/r2/api/s3/temporary-credentials/
//
//   read       HeadObject GetObject GetBucketLocation
//              ListObjectsV1 ListObjectsV2 ListMultipartUploads ListParts
//   write      PutObject DeleteObject DeleteObjects CopyObject
//   multipart  CreateMultipartUpload UploadPart UploadPartCopy
//              AbortMultipartUpload CompleteMultipartUpload
//
// Two facts from that page that decide the shape of this module:
//
//   1. `actions` -- the explicit per-operation list -- is "currently supported
//      via local signing only". The REST temporary-credentials API takes only
//      the four COARSE presets (object-read-only, object-read-write,
//      admin-read-only, admin-read-write). object-read-write BUNDLES DeleteObject.
//      Our object-write must not delete, so the REST API cannot express our
//      scope and the adapter must locally sign. That is a conclusion, not a
//      preference, and REFUSE_COARSE_PRESETS below is it.
//
//   2. Local signing scopes paths under `paths.prefixPaths` / `paths.objectPaths`
//      (the REST API calls the same things `prefixes` / `objects`). A prefix
//      matches keys STARTING WITH it -- there is no wildcard suffix, so
//      `org/A/world/W/` is the literal correct form and `org/A/world/W/*` would
//      be wrong.
// ---------------------------------------------------------------------------

export const R2_NATIVE_ACTIONS = Object.freeze([
  // read
  "HeadObject", "GetObject", "GetBucketLocation",
  "ListObjectsV1", "ListObjectsV2", "ListMultipartUploads", "ListParts",
  // write
  "PutObject", "DeleteObject", "DeleteObjects", "CopyObject",
  // multipart
  "CreateMultipartUpload", "UploadPart", "UploadPartCopy",
  "AbortMultipartUpload", "CompleteMultipartUpload",
]);

// The coarse presets, named so the refusal can name what it refused.
export const R2_COARSE_PRESETS = Object.freeze([
  "object-read-only", "object-read-write", "admin-read-only", "admin-read-write",
]);

/**
 * THE TRANSLATION TABLE. ComputeDriven capability -> R2 native actions.
 *
 * Read the ListObjects row twice: ONE ComputeDriven capability becomes TWO
 * native actions, because R2 versions its list operation and a credential that
 * can only do V1 fails against any modern S3 client. That one-to-many row is
 * the entire reason a translation table exists rather than a rename -- a
 * bijection would not have needed one, and a bijection is what the old code
 * assumed by comparing the two vocabularies directly.
 *
 * Not present, deliberately:
 *
 *   GetBucketLocation      not needed to read an object under a known prefix
 *
 *   multipart              CLAIM RETRACTED. This used to say "M2 chunking will
 *                          need it", which was an assumption wearing the clothes
 *                          of a plan. A 2 TB WORLD IS NOT A 2 TB OBJECT.
 *
 *                          R2 recommends ordinary PutObject below ~100 MB and
 *                          supports single PUT up to 5 GiB; multipart is aimed at
 *                          larger or resumable INDIVIDUAL objects. A world that
 *                          chunks into bounded content-addressed objects syncs
 *                          over tens of thousands of ordinary puts, and the
 *                          session may last days while each authorization lasts
 *                          minutes.
 *
 *                          Granting CreateMultipartUpload, UploadPart, ListParts,
 *                          CompleteMultipartUpload and AbortMultipartUpload is
 *                          five capabilities we have not measured a need for. If
 *                          a single chunk ever exceeds 5 GiB, multipart arrives
 *                          as its own ComputeDriven capability with its own row
 *                          in this table, and the widening is visible in a diff.
 */
export const R2_TRANSLATION = Object.freeze({
  GetObject:   Object.freeze(["GetObject"]),
  HeadObject:  Object.freeze(["HeadObject"]),
  ListObjects: Object.freeze(["ListObjectsV1", "ListObjectsV2"]),
  PutObject:   Object.freeze(["PutObject"]),
});

/**
 * Native actions that must never appear in an effective R2 authority, whatever
 * a preset bundles or an adapter believes it asked for.
 *
 * The closed vocabulary above is the primary control -- an action R2 does not
 * define is refused as unknown, so this list is not load-bearing for typos. It
 * is load-bearing for the actions R2 DOES define and we never want: everything
 * that destroys or duplicates an object.
 */
export const R2_FORBIDDEN = Object.freeze([
  "DeleteObject", "DeleteObjects", "CopyObject", "UploadPartCopy",
]);

export const R2 = makeVocabulary({
  provider: "r2",
  actions: R2_NATIVE_ACTIONS,
  translation: R2_TRANSLATION,
  forbidden: R2_FORBIDDEN,
});

/**
 * The exact artifact an R2 adapter must sign. THE ONLY constructor for one.
 *
 * Takes an AUTHORIZED scope -- one that carries scopeForWorld()'s provenance
 * brand -- not an object that merely looks like a scope. Frozen, so the value
 * that conformance checked cannot become a different value before it is signed.
 *
 * Field names are R2's own, so the adapter's job is a serialisation and not a
 * second translation:
 *
 *   bucket                  the bucket name
 *   prefixPaths             local-signing spelling of `prefixes`
 *   actions                 explicit list; local signing only
 *   expiresAtEpochSeconds   integer, feeds the signed `exp` claim directly
 *   ttlSeconds              for the REST form, if it ever grows action support
 */
export function r2GrantForScope(scope) {
  assertAuthorizedScope(scope);

  const actions = [];
  for (const capability of scope.operations) {
    const native = R2_TRANSLATION[capability];
    if (!native) {
      // A capability with no declared translation is a refusal, never a
      // pass-through. Pass-through is exactly how `ListObjects` would have
      // reached R2 as a literal action name that R2 does not define.
      throw new CredentialRefusal(
        "CD-CRED-UNTRANSLATED",
        `no R2 translation is declared for the capability ${JSON.stringify(capability)}`
      );
    }
    for (const a of native) if (!actions.includes(a)) actions.push(a);
  }

  return Object.freeze({
    provider: "r2",
    bucket: scope.bucket,
    // An object-scoped authorization produces an object-scoped grant. Emitting
    // the prefix here as well would be the widening assertRefines() refuses --
    // and the mutation battery is what noticed this function had not been
    // updated alongside grantForScope().
    prefixPaths: Object.freeze(scope.objectKey ? [] : [scope.prefix]),
    objectPaths: Object.freeze(scope.objectKey ? [scope.objectKey] : []),
    actions: Object.freeze(actions),
    expiresAtEpochSeconds: scope.expiresAtEpochSeconds,
    ttlSeconds: scope.ttlSeconds,
  });
}

/**
 * CONFORMANCE, run against the NATIVE grant.
 *
 * `scope` is what the control plane authorized, in ComputeDriven words.
 * `grant` is what R2 will really honour, in R2's words. The translation table
 * is how the two are compared, and it is checked in BOTH directions:
 *
 *   no widening    every native action must map back to an authorized capability
 *   no undergrant  every native action the authorized capabilities expand to
 *                  must be present
 *
 * so `ListObjectsV2` alone is a REFUSAL, not a pass -- a credential that can
 * list one way and not the other is a support ticket in three months.
 */
export function assertR2Conformance(scope, grant, { now = Date.now() } = {}) {
  return assertRefines(scope, grant, R2, { now });
}

// ---------------------------------------------------------------------------
// R31 (PROPOSED, NOT RULED) — storage authority may never authorize more bytes
// than the reservation that produced it.
//
// WHAT IS ACTUALLY KNOWN, verified first-party 2026-08-22:
//
//   temporary credentials   constrain bucket, operations, prefixes/objects, TTL.
//                           No maximum byte count is documented.
//   presigned URLs          authorize ONE operation on ONE object. Content-Type
//                           is signed and ENFORCED -- "uploads will fail with a
//                           403/SignatureDoesNotMatch error if the client sends a
//                           different Content-Type". Content-Length is NOT
//                           documented as signable or enforced. Max TTL 7 days.
//
// So the hole is real and it is not closed here:
//
//     reserve 1 MB -> receive PutObject authority -> upload 500 MB
//         -> R2 HAS ALREADY ACCEPTED IT -> finalize(500 MB) refused, too late
//
// BYTE-EXACTNESS IS AN EXPERIMENT, NOT AN ASSUMPTION. It is case B of
// worker/test/live-falsifier.mjs. If a signed Content-Length turns out to be
// enforced, R31 becomes provable and this constant changes to "proven". If it
// does not, we have learned something architectural rather than shipped
// something untrue:
//
//     hard pre-write quota and fully direct client->R2 uploads cannot BOTH be
//     claimed with the current grant primitive
//
// and the choice between a small controlled data plane and softer asynchronous
// quota (R32) becomes a decision instead of an accident.
// ---------------------------------------------------------------------------
export const R31_BYTE_BINDING = Object.freeze({
  status: "unproven",
  reason: "Cloudflare documents Content-Type as a signed, enforced header for presigned " +
          "PUTs and says nothing about Content-Length. Until the live falsifier measures it, " +
          "an upload artifact bounds bytes on OUR side only.",
  falsifier: "worker/test/live-falsifier.mjs case B",
});

/**
 * The M2 write artifact: authority for ONE object, of a stated size, briefly.
 *
 *     one bounded content-addressed chunk
 *       -> one reservation
 *       -> one EXACT object key
 *       -> one short-lived write artifact
 *
 * This is what dissolves round 6's unanswerable question about whether a
 * reservation should last an hour or a week: it was unanswerable because it was
 * asking one object to be both the session and the grant.
 *
 *     THE SESSION CAN LIVE FOR DAYS; A CHUNK GRANT DOES NOT.
 *
 * `expectedBytes` is carried and is NOT claimed to be enforced by R2 -- see
 * R31_BYTE_BINDING. It is what the control plane offered authority for, which is
 * the half we can guarantee, and what an arriving object-create event is checked
 * against (reconcile.mjs).
 */
export function r2UploadIntentGrant(scope, { expectedBytes, contentDigest } = {}) {
  assertAuthorizedScope(scope);
  if (!scope.objectKey) {
    throw new CredentialRefusal("CD-CRED-OBJECT",
      "an upload intent needs an object-scoped authorization; pass objectKey to scopeForWorld()");
  }
  if (scope.permission !== "object-write") {
    throw new CredentialRefusal("CD-CRED-PERM",
      `an upload intent needs object-write, not ${JSON.stringify(scope.permission)}`);
  }
  if (!Number.isInteger(expectedBytes) || expectedBytes <= 0) {
    throw new CredentialRefusal("CD-CRED-OBJECT",
      "expectedBytes must be a positive integer");
  }
  if (typeof contentDigest !== "string" || contentDigest.trim() === "") {
    // Content addressing is the point of a chunk. Without a digest there is
    // nothing to check an arriving object against, and the intent becomes a
    // permission slip rather than a description.
    throw new CredentialRefusal("CD-CRED-OBJECT", "a content digest is required");
  }

  return Object.freeze({
    provider: "r2",
    form: "presigned",
    operation: "PutObject",
    bucket: scope.bucket,
    // ONE key. Not a prefix -- a credential for .../chunk/abc must not reach
    // .../chunk/def, and that is the whole reason M2 writes are object-scoped.
    objectPaths: Object.freeze([scope.objectKey]),
    prefixPaths: Object.freeze([]),
    actions: Object.freeze(["PutObject"]),
    expiresAtEpochSeconds: scope.expiresAtEpochSeconds,
    ttlSeconds: scope.ttlSeconds,
    reservationId: scope.reservationId,
    expectedBytes,
    contentDigest,
    // Carried on the artifact itself so a consumer cannot read the byte count and
    // conclude the provider is enforcing it.
    byteBinding: R31_BYTE_BINDING.status,
  });
}

/**
 * A named refusal for the shortcut this whole file exists to prevent.
 *
 * An adapter reaching for the REST temporary-credentials API will find it takes
 * `permission: "object-read-write"` and nothing finer, and that preset includes
 * DeleteObject. Calling that "close enough to object-write" is the silent
 * widening from round 4, and it will look like it works.
 */
export function refuseCoarsePreset(preset) {
  throw new CredentialRefusal(
    "CD-CRED-COARSE",
    `R2 preset ${JSON.stringify(preset)} cannot express a ComputeDriven scope exactly; ` +
    `object-read-write bundles DeleteObject. Use locally-signed credentials with an explicit action list.`
  );
}

/**
 * Local signing produces a JWT whose payload carries the grant. This checks the
 * payload an adapter is ABOUT TO SIGN still says what the checked grant said.
 *
 * The round-4 lesson one layer further down: it is not enough to check a grant
 * object if what reaches the signer is a separately-built payload. Two
 * constructions is one too many.
 */
export function assertPayloadMatchesGrant(grant, payload) {
  if (!payload || typeof payload !== "object") {
    throw new CredentialRefusal("CD-CRED-PAYLOAD", "the signing payload is not an object");
  }
  const wantExp = grant.expiresAtEpochSeconds;
  if (epochSeconds(payload.exp, "the signing payload exp") !== wantExp) {
    throw new CredentialRefusal("CD-CRED-PAYLOAD",
      `payload exp ${payload.exp} is not the checked grant's ${wantExp}`);
  }
  const paths = payload.paths ?? {};
  const same = (a, b) =>
    Array.isArray(a) && Array.isArray(b) && a.length === b.length &&
    [...a].sort().every((v, i) => v === [...b].sort()[i]);
  if (!same(paths.prefixPaths ?? [], grant.prefixPaths)) {
    throw new CredentialRefusal("CD-CRED-PAYLOAD",
      `payload prefixPaths ${JSON.stringify(paths.prefixPaths)} is not the checked grant's ${JSON.stringify(grant.prefixPaths)}`);
  }
  if (!same(paths.objectPaths ?? [], grant.objectPaths)) {
    throw new CredentialRefusal("CD-CRED-PAYLOAD",
      `payload objectPaths ${JSON.stringify(paths.objectPaths)} is not the checked grant's ${JSON.stringify(grant.objectPaths)}`);
  }
  if (!same(payload.actions ?? [], grant.actions)) {
    throw new CredentialRefusal("CD-CRED-PAYLOAD",
      `payload actions ${JSON.stringify(payload.actions)} is not the checked grant's ${JSON.stringify(grant.actions)}`);
  }
  if (payload.bucket !== undefined && payload.bucket !== grant.bucket) {
    throw new CredentialRefusal("CD-CRED-PAYLOAD",
      `payload bucket ${JSON.stringify(payload.bucket)} is not the checked grant's ${JSON.stringify(grant.bucket)}`);
  }
  return payload;
}
