// The reconciliation planner (R79; findings 92, 96–98, 100, 103, 107–110).
//
// Written as falsifiers around PURE functions for the reason finding 88 taught
// the hard way: a repair path that can only be exercised against a real bucket
// is a repair path nobody exercises, and this one is the thing standing between
// a lost notification and occupancy the ledger never learns about.
//
// THE PROVIDER FIXTURES ARE PASTED, NOT INVENTED (finding 96). Every response
// shape below is Cloudflare's or AWS's documented one, with the citation on it.
// The previous two versions of this file each tested a shape its own author had
// made up, and each passed.

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  normalizeR2ListingPage, beginSweep, sweepFromPages, sweepBucket, reconciliationPlan,
  observeArgsFor, InventoryRefusal, LISTING_SOURCES, PROVENANCE_BASES, EVENT_TIME_BASES,
  isCompletedSweep, repairCandidate, isAuthoritativeSweep, isCompleteLedger,
  isAuthoritativeLedger, ledgerInventoryAdapter, ledgerAuthorityFor,
  jobsConnection, isLedgerConnection, parseListObjectsV2Xml, r2Endpoint,
  beginLedgerInventory, ledgerFromRows, r2ListingAdapter, LEDGER_AUTHORITIES,
  CAUSATION_BASES,
} from "../src/inventory.mjs";
import { parseObjectKey } from "../src/objectkey.mjs";
import { CREATE_ACTIONS } from "../src/reconcile.mjs";

const ORG = "aaaaaaaa-0000-4000-8000-000000000001";
const WORLD = "11111111-0000-4000-8000-00000000000a";
const k = (n) => `org/${ORG}/world/${WORLD}/chunk/${n}`;
const BUCKET = "cd-worlds";
const T = "2026-08-24T10:00:00.000Z";
const HEX = "c846ff7a18f28c2e262116d6e8719ef0";   // CF's own event-notification example
const HEX2 = "d41d8cd98f00b204e9800998ecf8427e";  // CF's own r2_r2_object example

/** One S3 `Contents` entry, RFC 7232-quoted ETag as R2's S3 surface returns it. */
const s3Obj = (name, over = {}) => ({
  Key: k(name), ETag: `"${HEX}"`, Size: 100, LastModified: new Date(T),
  StorageClass: "STANDARD", ...over,
});
/** A whole S3 ListObjectsV2 response. */
const s3Page = (objs, over = {}) => ({
  Name: BUCKET, IsTruncated: false, KeyCount: objs.length, Contents: objs, ...over,
});
/** Workers R2 binding .list(). developers.cloudflare.com/r2/api/workers/workers-api-reference/ */
const wkPage = (over = {}) => ({
  objects: [{
    key: k("a"), version: "v", size: 100,
    etag: HEX,             // raw
    httpEtag: `"${HEX}"`,  // "in quotes so as to be returned as a header"
    uploaded: new Date(T), // a Date, not a string
    httpMetadata: {}, customMetadata: {}, checksums: {}, storageClass: "Standard",
  }],
  truncated: false, delimitedPrefixes: [], ...over,
});
/** Cloudflare REST List Objects. Normalized by NOBODY — refused by name. */
const restPage = () => ({
  result: [{ key: k("a"), etag: HEX, size: 100, last_modified: T }],
  success: true, errors: [], messages: [],
});

const page = (r, source = "s3") => normalizeR2ListingPage(r, { source });
const sweep1 = (r) => sweepFromPages([[r, null]], { bucket: BUCKET, source: "s3" });
const known = (over = {}) => ({ objectKey: k("a"), sizeBytes: 100, etag: HEX,
                                ambiguous: false, ...over });
// FINDING 122. The ledger is an operand of a set difference and now has to prove
// its own completeness, exactly like the sweep. `jobs` is the authority that can
// see every tenant's rows; a `tenant` read is RLS-filtered and cannot support
// absence.
const ledger = (rows = [], authority = "jobs") =>
  ledgerFromRows(rows, { bucket: BUCKET, authority, snapshot: "snap-test-1" });

// FINDING 123/128. A sweep whose pages came through the SIGNING adapter. The
// network is injected below the signer, so this exercises signing and parsing —
// and deliberately does NOT earn provider authority, because an injected network
// cannot certify that R2 answered. That is the crisp gate:
//
//     NO R2 AND NO POSTGRES  =>  absenceEstablished can never be true.
const xmlFor = (objs, over = {}) => {
  const c = objs.map((o) => `<Contents><Key>${o.Key}</Key><Size>${o.Size}</Size>` +
    `<ETag>&quot;${String(o.ETag).replace(/"/g, "")}&quot;</ETag>` +
    `<LastModified>${o.LastModified instanceof Date ? o.LastModified.toISOString() : o.LastModified}` +
    `</LastModified></Contents>`).join("");
  return `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>${over.name ?? BUCKET}</Name>` +
    `<KeyCount>${objs.length}</KeyCount>` +
    `<IsTruncated>${over.truncated ? "true" : "false"}</IsTruncated>` +
    (over.next ? `<NextContinuationToken>${over.next}</NextContinuationToken>` : "") +
    (over.echo ? `<ContinuationToken>${over.echo}</ContinuationToken>` : "") + c +
    `</ListBucketResult>`;
};
// FINDING 132. The endpoint is DERIVED from the account id and is not a
// parameter; a caller-chosen endpoint is a caller-controlled counterparty.
const ACCOUNT = "0123456789abcdef0123456789abcdef";
const signingAdapter = (...xmls) => {
  let i = 0;
  return r2ListingAdapter({
    accountId: ACCOUNT, bucket: BUCKET, accessKeyId: "AKIAEXAMPLE", secretAccessKey: "s3cr3t",
    fetchImpl: async () => ({ ok: true, status: 200, text: async () => xmls[i++] }),
  });
};
// FINDING 137. `sweep()` is the interface; there is no `listPage` to rebind.
const authSweep = (...responses) =>
  signingAdapter(...responses.map((r) => xmlFor(r.Contents ?? [], {}))).sweep();

const PROV = { action: "PutObject", basis: "upload_intent", intentId: "i-1" };
// FINDING 117. There is no licensed event-time basis yet, so observeArgsFor()
// refuses every call. Kept as a name so the day one is earned is a one-line diff.
const PROV_FULL = { ...PROV, eventTimeBasis: "none-exists-yet" };

// ===========================================================================

describe("finding 96 — the normalizer meets the provider, and only it does", () => {
  test("the S3 ListObjectsV2 shape normalizes", () => {
    const p = page(s3Page([s3Obj("a")]));
    assert.deepEqual(p.entries, [{ key: k("a"), size: 100, etag: HEX, providerStateTime: T }]);
    assert.equal(p.truncated, false);
  });

  test("the Workers binding shape normalizes — `uploaded` is a Date and that is fine here", () => {
    assert.deepEqual(page(wkPage(), "workers").entries,
                     [{ key: k("a"), size: 100, etag: HEX, providerStateTime: T }]);
  });

  test("BOTH surfaces produce the SAME entry — that is the whole point of the layer", () => {
    assert.deepEqual(page(s3Page([s3Obj("a")])).entries, page(wkPage(), "workers").entries,
      "if these diverge, the planner's semantics silently depend on which API was called");
  });

  test("the REST surface is REFUSED BY NAME, with the credential reason", () => {
    // Cloudflare: object-scoped tokens "fail to authenticate" against
    // api.cloudflare.com and are "only supported by the S3-compatible API";
    // REST needs an Admin token granting "account-wide access rather than
    // bucket-scoped access". Reading one bucket must not cost the account.
    assert.throws(() => page(restPage(), "rest"),
      (e) => e instanceof InventoryRefusal && e.code === "CD-INV-REST"
             && /account-wide Admin token/.test(e.message));
  });

  test("the source must be NAMED — the shape is never sniffed", () => {
    assert.throws(() => normalizeR2ListingPage(s3Page([]), {}), /unknown listing source/);
    assert.throws(() => page(s3Page([]), "S3"), /unknown listing source/);
    assert.equal(Object.keys(LISTING_SOURCES).length, 3);
  });

  test("a non-object response refuses", () => {
    assert.throws(() => page(null), (e) => e.code === "CD-INV-RESPONSE");
  });
});

describe("finding 100 — the etag spelling is not the same on every surface", () => {
  test("S3's RFC 7232 quotes are stripped, so a correct ledger does not read as divergent", () => {
    // The ledger's etags come from the notification body, whose documented
    // example is a bare hex digest. The S3 listing carries the same digest in
    // quotes. Compared unnormalized, EVERY object reports `divergent` and the
    // pass rewrites every etag to a quoted one.
    const p = reconciliationPlan(sweep1(s3Page([s3Obj("a")])), ledger([known()]));
    assert.deepEqual(p.repairs, []);
  });

  test("a multipart etag keeps its part-count suffix", () => {
    // CompleteMultipartUpload is one of the three admitted create actions and
    // its etag is <hex>-<parts>. A rule assuming 32 hex characters would refuse
    // every large upload — the object class this product exists to store.
    assert.equal(page(s3Page([s3Obj("a", { ETag: `"${HEX}-12"` })])).entries[0].etag, `${HEX}-12`);
  });

  test("a WEAK validator is malformed, not an etag", () => {
    const p = page(s3Page([s3Obj("a", { ETag: `W/"${HEX}"` })]));
    assert.deepEqual(p.entries, []);
    assert.equal(p.malformed.length, 1);
  });

  test("anything that is not a hex digest is malformed", () => {
    for (const ETag of ['"aaa"', '""', "not-hex", `"${HEX}-0"`, 7, null]) {
      const p = page(s3Page([s3Obj("a", { ETag })]));
      assert.deepEqual(p.entries, [], JSON.stringify(ETag));
      assert.equal(p.malformed.length, 1, JSON.stringify(ETag));
    }
  });
});

// ===========================================================================

describe("finding 107 — absence is a property of a complete enumeration, not its last page", () => {
  test("THE REPRODUCTION: a two-page scan must not call page one's object deleted", () => {
    // Against the shipped tree: bucket holds A and B, ledger holds A and B,
    //   page 1  [A]  IsTruncated=true   -> 0 refusals   (finding 103's fix, correct)
    //   page 2  [B]  IsTruncated=false  -> 1 refusal:  "the ledger holds A and the
    //                                                   complete listing does not"
    // The first-page bug had been MOVED to the last page, where it alleges an
    // out-of-band delete of an object page 1 had just reported present.
    const both = [known({ objectKey: k("A") }), known({ objectKey: k("B") })];
    const scan = sweepFromPages([
      [s3Page([s3Obj("A")], { IsTruncated: true, NextContinuationToken: "tok1" }), null],
      [s3Page([s3Obj("B")]), "tok1"],
    ], { bucket: BUCKET, source: "s3" });
    const p = reconciliationPlan(scan, ledger(both));
    assert.deepEqual(p.refusals, [], "neither object is absent; both were enumerated");
    assert.equal(p.summary.pages, 2);
    assert.equal(p.summary.present, 2);
  });

  test("a page cannot be handed to the planner at all", () => {
    // The type is the fix. `IsTruncated: false` on a single page is exactly the
    // value that used to mean "complete", so the old calling convention has to
    // be unrepresentable rather than discouraged.
    assert.throws(() => reconciliationPlan(page(s3Page([s3Obj("a")])), ledger([])),
      /not a completed sweep/);
    assert.throws(() => reconciliationPlan({ entries: [], complete: true }, ledger()),
      /not a completed sweep/);
    assert.throws(() => reconciliationPlan([], ledger()), /not a completed sweep/);
  });

  test("an unfinished scan REFUSES to become one", () => {
    const s = beginSweep({ bucket: BUCKET, source: "s3" });
    s.addPage(page(s3Page([s3Obj("A")], { IsTruncated: true, NextContinuationToken: "t" })),
              { requestedWith: null });
    assert.equal(s.done, false);
    assert.equal(s.nextToken, "t");
    assert.throws(() => s.finish(), (e) => e.code === "CD-INV-INCOMPLETE"
      && /still outstanding/.test(e.message));
  });

  test("STARTED AT THE BEGINNING: a first page fetched with a token is refused", () => {
    // Resuming from a saved cursor after a crash yields pages that are each
    // individually valid and a union missing everything before the token.
    const s = beginSweep({ bucket: BUCKET, source: "s3" });
    assert.throws(() => s.addPage(page(s3Page([s3Obj("A")])), { requestedWith: "saved-token" }),
      (e) => e.code === "CD-INV-CHAIN" && /did not start at the beginning/.test(e.message));
  });

  test("CHAIN VERIFIED: a spliced cursor is refused", () => {
    // Re-listing from a DIFFERENT token halfway through is the subtle one: both
    // pages are real, both are from this bucket, and the range between them was
    // never enumerated.
    const s = beginSweep({ bucket: BUCKET, source: "s3" });
    s.addPage(page(s3Page([s3Obj("A")], { IsTruncated: true, NextContinuationToken: "tok1" })),
              { requestedWith: null });
    assert.throws(() => s.addPage(page(s3Page([s3Obj("B")])), { requestedWith: "tok-other" }),
      (e) => e.code === "CD-INV-CHAIN" && /spliced/.test(e.message));
  });

  test("the cursor a page was fetched with is REQUIRED, not optional", () => {
    // An optional argument defaulting to null would make every unverified loop
    // look like a verified one — the same defect as `CD_CONSUMER_SCRIPT` being
    // optional in finding 90.
    const s = beginSweep({ bucket: BUCKET, source: "s3" });
    assert.throws(() => s.addPage(page(s3Page([s3Obj("A")]))),
      (e) => e.code === "CD-INV-NO-CURSOR");
  });

  test("TERMINATED NORMALLY: a page after the terminating page is refused", () => {
    const s = beginSweep({ bucket: BUCKET, source: "s3" });
    s.addPage(page(s3Page([s3Obj("A")])), { requestedWith: null });
    assert.throws(() => s.addPage(page(s3Page([s3Obj("B")])), { requestedWith: null }),
      (e) => e.code === "CD-INV-SCAN-CLOSED");
  });

  test("truncated with NO continuation token is refused — the scan cannot be continued", () => {
    const s = beginSweep({ bucket: BUCKET, source: "s3" });
    assert.throws(() => s.addPage(page(s3Page([s3Obj("A")], { IsTruncated: true })),
                                  { requestedWith: null }),
      (e) => e.code === "CD-INV-NO-NEXT");
  });

  test("a page with no truncation flag cannot take its place in a chain", () => {
    assert.throws(() => page({ Contents: [], KeyCount: 0 }), (e) => e.code === "CD-INV-TRUNCATION");
    assert.throws(() => page({ objects: [], truncated: "no" }, "workers"),
      (e) => e.code === "CD-INV-TRUNCATION");
  });

  test("two sources cannot be mixed in one scan", () => {
    const s = beginSweep({ bucket: BUCKET, source: "s3" });
    assert.throws(() => s.addPage(page(wkPage(), "workers"), { requestedWith: null }),
      (e) => e.code === "CD-INV-SOURCE-MIX");
  });

  test("a scan must name its bucket", () => {
    assert.throws(() => beginSweep({ source: "s3" }), (e) => e.code === "CD-INV-BUCKET");
    assert.throws(() => beginSweep({ bucket: "  ", source: "s3" }), (e) => e.code === "CD-INV-BUCKET");
  });

  test("a COMPLETE scan does read absence, and refuses rather than crediting", async () => {
    // FINDING 123. `authSweep` rather than `sweep1`: absence needs pages that
    // actually came from R2 through the credentialed adapter, not merely a
    // well-formed protocol run over a caller-supplied closure.
    // FINDINGS 128/129. Absence-as-refusal now requires LIVE provider I/O on both
    // operands, so offline it is `absenceUnknown` — the same SELECTION, a
    // different label. The set difference is what this test is about and it is
    // asserted exactly as before.
    const p = reconciliationPlan(await authSweep(s3Page([s3Obj("a")])),
                                 ledger([known(), known({ objectKey: k("gone") })]));
    assert.equal(p.summary.absenceEstablished, false, "no real R2 and no real database");
    assert.equal(p.absenceUnknown.length, 1);
    assert.equal(p.absenceUnknown[0].key, k("gone"));
    assert.equal(p.refusals.length, 0);
  });
});

describe("finding 108 — presence and usable state are independent facts", () => {
  test("THE REPRODUCTION: a present key with a bad etag is not a deletion", async () => {
    // Against the shipped tree this reported "the ledger holds this object and
    // the complete listing does not — an out-of-band delete" about an object R2
    // had just named.
    //
    // AUTHORITATIVE deliberately (finding 123): on a merely protocol-complete
    // sweep absence is blocked for a DIFFERENT reason, and the test would pass
    // without exercising finding 108 at all. The mutation battery caught exactly
    // that — `malformed-entry-becomes-absent` went CAUGHT -> MISSED when 123
    // landed, because the assertion could no longer distinguish the two causes.
    const scan = await authSweep(s3Page([s3Obj("a", { ETag: '"zz"' }), s3Obj("b")]));
    const p = reconciliationPlan(scan, ledger([known(), known({ objectKey: k("b") })]));
    // The point of finding 108: the key is NOT SELECTED as absent at all. That is
    // independent of whether absence could be concluded, so it is asserted on the
    // selection rather than on the label.
    assert.deepEqual(p.refusals, [], "R2 named this key; it is not absent");
    assert.deepEqual(p.absenceUnknown, [], "and it is not even a candidate for absence");
    assert.equal(p.unreadable.length, 1);
    assert.equal(p.unreadable[0].key, k("a"));
    assert.match(p.unreadable[0].why, /PRESENCE is established and its STATE is not/);
  });

  test("presence is recorded before any metadata check can fail", () => {
    for (const bad of [{ ETag: '"zz"' }, { Size: -1 }, { LastModified: "not a date" }]) {
      const p = page(s3Page([s3Obj("a", bad)]));
      assert.deepEqual(p.presentKeys, [k("a")], JSON.stringify(bad));
      assert.deepEqual(p.entries, [], JSON.stringify(bad));
    }
  });

  test("an unreadable key produces NO repair — there is nothing to write", () => {
    const p = reconciliationPlan(sweep1(s3Page([s3Obj("new", { ETag: '"zz"' })])), ledger([]));
    assert.deepEqual(p.repairs, []);
    assert.equal(p.unreadable.length, 1);
    assert.equal(p.summary.unreadable, 1);
  });

  test("a row with no key at all is malformed and contributes NO presence", () => {
    // Absence of a key is the one case where nothing can be asserted about
    // presence, because there is no key to assert it about.
    const p = page(s3Page([{ ETag: `"${HEX}"`, Size: 1, LastModified: T }]));
    assert.deepEqual(p.presentKeys, []);
    assert.equal(p.malformed.length, 1);
  });

  test("an unowned key contributes no presence either", () => {
    const p = page(s3Page([{ Key: "loose/object", ETag: `"${HEX}"`, Size: 1, LastModified: T }]));
    assert.deepEqual(p.presentKeys, []);
    assert.deepEqual(p.unowned, ["loose/object"]);
  });
});

describe("finding 110 — an empty bucket is a legal answer, positively proven", () => {
  test("Contents omitted with KeyCount 0 is an empty bucket, not an unreadable response", () => {
    // AWS's ListObjectsV2 output marks Contents optional; a bucket with no
    // objects omits it. Refusing that would make case N — which deliberately
    // empties the normal path — read its own success as a provider fault.
    const p = page({ Name: BUCKET, KeyCount: 0, IsTruncated: false });
    assert.deepEqual(p.entries, []);
    assert.deepEqual(p.presentKeys, []);
  });

  test("Contents omitted WITHOUT a positive zero is still refused", () => {
    // Fails closed. A response missing both the list and the count is a response
    // we could not read, and reporting it as a clean bucket is the false green
    // this whole pass exists to avoid.
    assert.throws(() => page({ Name: BUCKET, IsTruncated: false }), (e) => e.code === "CD-INV-ENUM");
    assert.throws(() => page({ Name: BUCKET, KeyCount: 3, IsTruncated: false }),
      (e) => e.code === "CD-INV-ENUM");
  });

  test("KeyCount disagreeing with Contents is refused", () => {
    // Same law as case P comparing producers_total_count against the producer
    // array: when a count and a list disagree, the missing entries are the
    // interesting ones.
    assert.throws(() => page(s3Page([s3Obj("a")], { KeyCount: 5 })),
      (e) => e.code === "CD-INV-KEYCOUNT");
  });

  test("an empty bucket against a non-empty ledger refuses every key, and says so once each", async () => {
    const p = reconciliationPlan(await authSweep({ Name: BUCKET, KeyCount: 0, IsTruncated: false }),
                                 ledger([known(), known({ objectKey: k("b") })]));
    assert.equal(p.absenceUnknown.length, 2);
    assert.equal(p.summary.present, 0);
  });
});

// ===========================================================================

describe("the lost notification is the case this exists for (R79)", () => {
  test("an object in R2 the ledger has never seen is a repairable MISSING", () => {
    const p = reconciliationPlan(sweep1(s3Page([s3Obj("a")])), ledger([]));
    assert.equal(p.summary.missing, 1);
    assert.equal(p.repairs[0].kind, "missing");
    assert.equal(p.repairs[0].size, 100);
    assert.equal(p.repairs[0].providerStateTime, T,
      "the repair carries R2's own state time, not ours — R68 all the way down");
    assert.equal(p.repairs[0].eventTime, undefined,
      "FINDING 117: a listing's LastModified is NOT a queue eventTime, and the field " +
      "name must not let a reader assume it is");
  });

  test("a disagreeing object is DIVERGENT and the provider's number wins", () => {
    const p = reconciliationPlan(sweep1(s3Page([s3Obj("a", { Size: 250, ETag: `"${HEX2}"` })])), ledger([known()]));
    assert.equal(p.repairs[0].kind, "divergent");
    assert.equal(p.repairs[0].size, 250);
    assert.deepEqual(p.repairs[0].from, { etag: HEX, size: 100 });
  });

  test("a SMALLER listed size is still a legitimate repair, not a floor violation", () => {
    // An overwrite to a smaller body is ordinary. Refusing to move occupancy
    // downward would make the ledger permanently overstate a tenant — the same
    // class of error as finding 86, in the other direction.
    const p = reconciliationPlan(sweep1(s3Page([s3Obj("a", { Size: 10, ETag: `"${HEX2}"` })])), ledger([known()]));
    assert.equal(p.repairs[0].size, 10);
  });
});

describe("finding 109 — the listing does not say which API call produced the state", () => {
  test("NO repair carries a provider action", () => {
    // `observeArgsFor()` refused to synthesize a queue message id, with a
    // paragraph explaining why — and then passed "PutObject".
    const p = reconciliationPlan(sweep1(s3Page([s3Obj("a")])), ledger([]));
    assert.equal(p.repairs[0].providerAction, null);
  });

  test("observeArgsFor REFUSES without provenance", () => {
    const p = reconciliationPlan(sweep1(s3Page([s3Obj("a")])), ledger([]));
    assert.throws(() => observeArgsFor(p.repairs[0]),
      (e) => e instanceof InventoryRefusal && e.code === "CD-INV-NO-PROVENANCE"
             && /do not default to PutObject/.test(e.message));
    assert.throws(() => observeArgsFor(p.repairs[0], null), (e) => e.code === "CD-INV-NO-PROVENANCE");
  });

  test("all three create actions are accepted, because all three change occupancy", () => {
    // FINDING 117 moved the terminal refusal one step later: a create action is
    // ACCEPTED (it gets past CD-INV-ACTION) and the call still refuses, on the
    // clock. Asserting the CODE rather than the throw is what keeps these two
    // separate — otherwise "it threw" would hide the action check regressing.
    const p = reconciliationPlan(sweep1(s3Page([s3Obj("a")])), ledger([]));
    for (const action of CREATE_ACTIONS) {
      assert.throws(() => observeArgsFor(p.repairs[0], { ...PROV, action }),
        (e) => e.code === "CD-INV-BLOCKED", String(action));
    }
    assert.equal(CREATE_ACTIONS.length, 3);
  });

  test("a delete action is refused as provenance", () => {
    const p = reconciliationPlan(sweep1(s3Page([s3Obj("a")])), ledger([]));
    for (const action of ["DeleteObject", "LifecycleDeletion", "PutObjectAcl", null]) {
      assert.throws(() => observeArgsFor(p.repairs[0], { ...PROV, action }),
        (e) => e.code === "CD-INV-ACTION", String(action));
    }
  });

  test("the BASIS is a closed vocabulary and must reference the intent", () => {
    const p = reconciliationPlan(sweep1(s3Page([s3Obj("a")])), ledger([]));
    assert.deepEqual(Object.keys(PROVENANCE_BASES), ["upload_intent"]);
    // FINDING 118. The basis states what it proves, because round 8.2 justified
    // it with "we minted the credential that performed it" — which assumes the
    // conclusion. Authority is not causation.
    assert.equal(PROVENANCE_BASES.upload_intent.proves, "authority");
    assert.equal(PROVENANCE_BASES.upload_intent.doesNotProve, "causation");
    assert.throws(() => observeArgsFor(p.repairs[0], { ...PROV, basis: "operator_says_so" }),
      (e) => e.code === "CD-INV-BASIS");
    // R76: a basis that names no intent is a word, not a reference.
    assert.throws(() => observeArgsFor(p.repairs[0], { ...PROV, intentId: "" }),
      (e) => e.code === "CD-INV-INTENT");
    assert.throws(() => observeArgsFor(p.repairs[0], { action: "PutObject", basis: "upload_intent" }),
      (e) => e.code === "CD-INV-INTENT");
  });

  test("the multipart etag shape is RECORDED, never promoted to a derived action", () => {
    // <hex>-<parts> is suggestive and not conclusive: a copy can carry one too.
    // Recording the observation while refusing the inference is the whole
    // distinction finding 109 is about.
    const p = reconciliationPlan(sweep1(s3Page([s3Obj("a", { ETag: `"${HEX}-12"` })])), ledger([]));
    assert.equal(p.repairs[0].etagIsMultipartShaped, true);
    assert.equal(p.repairs[0].providerAction, null);
    assert.throws(() => observeArgsFor(p.repairs[0]), (e) => e.code === "CD-INV-NO-PROVENANCE");
  });

  test("with provenance, no delivery identity is still claimed (R77)", () => {
    // A reconciliation did not arrive on the authority channel, so it has none
    // to claim. Synthesizing one would make a repair indistinguishable from a
    // notification in the provenance log — the one place the difference matters.
    // FINDING 117. This used to assert the returned argument vector. It cannot
    // any more, because there is no licensed event-time basis and the call
    // refuses before returning one. The R77 property is asserted where it is now
    // provable — on the SHAPE of the return, exercised the day a basis exists —
    // and the refusal itself is asserted here.
    const p = reconciliationPlan(sweep1(s3Page([s3Obj("a")])), ledger([]));
    assert.throws(() => observeArgsFor(p.repairs[0], PROV),
      (e) => e.code === "CD-INV-BLOCKED" && /CANDIDATE/.test(e.message));
    assert.deepEqual(EVENT_TIME_BASES, [],
      "no measurement has licensed typing LastModified as p_event_time; case N earns the first");
  });
});

describe("finding 97 — the listing REPORTS an ambiguity, it does not settle one", () => {
  test("a tied tip produces a CANDIDATE, in its own list, marked unapplied", () => {
    const p = reconciliationPlan(sweep1(s3Page([s3Obj("a")])), ledger([known({ etag: null, ambiguous: true })]));
    assert.deepEqual(p.repairs, []);
    assert.equal(p.ambiguityCandidates.length, 1);
    assert.equal(p.ambiguityCandidates[0].applied, false);
    assert.equal(p.summary.ambiguous, 1);
  });

  test("THE ARITHMETIC THAT SAYS WHY, reproduced here so it cannot be forgotten", () => {
    // app.project_object_state() (0026) calls a tip ambiguous when
    //     count(DISTINCT (etag, size_bytes)) > 1  over  event_time = max(event_time)
    // and a repair enters at the provider's own instant. R2 reports the
    // surviving object's upload time, which in a tie IS that instant.
    const tip = [{ etag: "a", size: 10 }, { etag: "b", size: 20 }];
    const distinct = (rows) => new Set(rows.map((r) => `${r.etag}/${r.size}`)).size;
    assert.equal(distinct(tip) > 1, true, "ambiguous before");
    const applied = [...tip, { etag: "b", size: 20 }];   // the listing's answer, same instant
    assert.equal(distinct(applied) > 1, true,
      "STILL ambiguous after — only event_count moved");
    assert.equal(Math.max(...applied.map((r) => r.size)), Math.max(...tip.map((r) => r.size)),
      "size_bytes = max() over the tip does not move either, so occupancy is unchanged too");
  });

  test("observeArgsFor REFUSES a candidate, provenance or not", () => {
    const p = reconciliationPlan(sweep1(s3Page([s3Obj("a")])), ledger([known({ etag: null, ambiguous: true })]));
    assert.throws(() => observeArgsFor(p.ambiguityCandidates[0], PROV),
      (e) => e.code === "CD-INV-AMBIGUOUS");
  });

  test("ambiguity is checked BEFORE divergence — a NULL etag is not a mismatch", () => {
    const p = reconciliationPlan(sweep1(s3Page([s3Obj("a", { Size: 999, ETag: `"${HEX2}"` })])), ledger([known({ etag: null, ambiguous: true })]));
    assert.deepEqual(p.repairs, []);
    assert.equal(p.ambiguityCandidates.length, 1);
  });

  test("NOTHING in the plan claims the tie was resolved", () => {
    const p = reconciliationPlan(sweep1(s3Page([s3Obj("a")])), ledger([known({ etag: null, ambiguous: true })]));
    assert.match(p.ambiguityCandidates[0].why, /NOT A RESOLUTION/);
    assert.doesNotMatch(JSON.stringify(p.summary), /settl/i);
  });
});

describe("finding 98 — ONE object-key grammar, and this file reads the shared fixture", () => {
  const FIX = JSON.parse(readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), "fixtures/object-keys.json"), "utf8"));

  test("every fixture case classifies the same way here as in the canonical parser", () => {
    // This file used to carry its own regex, /^org\/[0-9a-f-]{36}\/world\/…/,
    // which accepted a nil uuid and thirty-six dashes — the planner claiming
    // ownership of keys this control plane never mints.
    let owned = 0, notOwned = 0;
    for (const c of FIX.cases) {
      const p = page(s3Page([s3Obj("x", { Key: c.key })]));
      // PRESENCE, not `unowned.length === 0`. The first draft of this assertion
      // used the latter and FAILED on the fixture's empty-key case, which lands
      // in `malformed` (no key to own) rather than `unowned` — so "not unowned"
      // read as "ours". Presence is the property that actually matters: a key
      // this control plane will account for is one it recorded as present.
      const isOwned = p.presentKeys.includes(c.key);
      assert.equal(isOwned, c.valid === true, `${JSON.stringify(c.key)} — ${c.why}`);
      assert.equal(isOwned, parseObjectKey(c.key) !== null,
        "the planner and the canonical parser must agree, case by case");
      if (isOwned) owned++; else notOwned++;
    }
    assert.ok(owned >= 2 && notOwned >= 6,
      `the fixture must exercise both sides (${owned} owned / ${notOwned} not)`);
  });
});

describe("the summary is the operational signal", () => {
  test("every category is counted, including the ones that produce no repair", () => {
    const scan = sweepFromPages([[s3Page([
      s3Obj("new"),
      s3Obj("bad", { ETag: '"zz"' }),
      { Key: "loose", ETag: `"${HEX}"`, Size: 1, LastModified: T },
    ]), null]], { bucket: BUCKET, source: "s3" });
    const p = reconciliationPlan(scan, ledger([known({ objectKey: k("gone") })]));
    // FINDINGS 122/123. `refused: 0` and `absenceUnknown: 1` because this sweep
    // is protocol-complete and NOT provider-authoritative: the one ledger key R2
    // did not name cannot be called deleted by a pass that cannot show its pages
    // came from R2. The whole summary is asserted so a new field cannot arrive
    // unnoticed.
    assert.deepEqual(p.summary, {
      bucket: BUCKET, source: "s3", pages: 1, sweepComplete: true,
      sweepAuthoritative: false, ledgerAuthority: "jobs",
      ledgerSnapshot: "snap-test-1", ledgerPages: 1, absenceEstablished: false,
      listed: 1, present: 2, known: 1, missing: 1, divergent: 0, ambiguous: 0,
      unreadable: 1, refused: 0, absenceUnknown: 1, unowned: 1, malformed: 1,
    });
  });

  test("a plan cannot be built from a bare array, or from nothing (finding 122)", () => {
    assert.throws(() => reconciliationPlan(sweep1(s3Page([])), null),
      (e) => e.code === "CD-INV-LEDGER");
    // The defect itself: an ordinary array was accepted for two whole rounds.
    assert.throws(() => reconciliationPlan(sweep1(s3Page([])), [known()]),
      (e) => e.code === "CD-INV-LEDGER" && /both directions/.test(e.message));
  });
});

// ===========================================================================

describe("finding 113 — a proof object is not proved by containing the field that says so", () => {
  const KNOWN = [known()];

  test("a hand-built object carrying every field of a completed sweep is REFUSED", () => {
    // THE REPRODUCTION. This literal was accepted by the shipped tree and the
    // planner then concluded that a known ledger object was absent from R2 —
    // an alleged out-of-band delete, from an enumeration that never ran.
    const forged = {
      __completeScan: true, bucket: BUCKET, source: "s3", pages: 1,
      entries: [], presentKeys: new Set(), malformed: [], unowned: [],
      startedAtBeginning: true, chainVerified: true, terminatedNormally: true,
    };
    assert.throws(() => reconciliationPlan(forged, ledger(KNOWN)),
      (e) => e instanceof InventoryRefusal && e.code === "CD-INV-NOT-SWEPT");
    assert.equal(isCompletedSweep(forged), false);
  });

  test("even a structural CLONE of a real sweep is refused", () => {
    // The same assertion jwt.mjs makes about verified claims. A spread copies
    // the fields and cannot copy membership.
    const real = sweep1(s3Page([s3Obj("a")]));
    assert.equal(isCompletedSweep(real), true);
    assert.equal(isCompletedSweep({ ...real }), false);
    assert.throws(() => reconciliationPlan({ ...real }, ledger(KNOWN)), (e) => e.code === "CD-INV-NOT-SWEPT");
  });

  test("the field that used to grant admission does not exist any more", () => {
    // Demoting it would leave a reader something to make load-bearing again.
    const real = sweep1(s3Page([s3Obj("a")]));
    assert.equal("__completeScan" in real, false);
  });

  test("presentKeys cannot be mutated on a frozen sweep — the negative-evidence half", () => {
    // THE SECOND REPRODUCTION, and the sharper one. Object.freeze froze the
    // POINTER; presentKeys was a live Set. MEASURED against the shipped tree:
    // 0 refusals, then delete(key), then 1 refusal claiming that very key was
    // deleted out of band.
    const real = sweep1(s3Page([s3Obj("a")]));
    assert.equal(reconciliationPlan(real, ledger(KNOWN)).refusals.length, 0);

    for (const method of ["delete", "add", "clear"]) {
      assert.throws(() => real.presentKeys[method](k("a")), TypeError, method);
    }
    assert.throws(() => { real.presentKeys.has = () => false; }, TypeError);

    assert.equal(real.presentKeys.has(k("a")), true);
    assert.equal(reconciliationPlan(real, ledger(KNOWN)).refusals.length, 0,
      "EVIDENCE USED FOR A NEGATIVE CONCLUSION MUST BE BOTH UNFORGEABLE AND IMMUTABLE");
  });

  test("entries and malformed are frozen all the way down, not just at the top", () => {
    const real = sweep1(s3Page([s3Obj("a"), s3Obj("b", { Size: "x" })]));
    assert.equal(Object.isFrozen(real.entries), true);
    assert.equal(Object.isFrozen(real.entries[0]), true);
    assert.equal(Object.isFrozen(real.malformed), true);
    assert.equal(Object.isFrozen(real.malformed[0]), true);
  });
});

describe("finding 115 — provenance supplied by the claimant is not provenance", () => {
  test("the PROVIDER's echoed ContinuationToken overrules the caller's claim", () => {
    // THE REPRODUCTION. Provider says this page answers "WRONG-TOKEN"; caller
    // says it fetched with "tok1"; the shipped tree returned chainVerified.
    const p1 = s3Page([s3Obj("A")], { IsTruncated: true, NextContinuationToken: "tok1" });
    const p2 = s3Page([s3Obj("B")], { ContinuationToken: "WRONG-TOKEN" });
    assert.throws(() => sweepFromPages([[p1, null], [p2, "tok1"]], { bucket: BUCKET, source: "s3" }),
      (e) => e.code === "CD-INV-ECHO" && /answers a different request/.test(e.message));
  });

  test("an agreeing echo is counted, so the sweep states what it actually checked", () => {
    const p1 = s3Page([s3Obj("A")], { IsTruncated: true, NextContinuationToken: "tok1" });
    const p2 = s3Page([s3Obj("B")], { ContinuationToken: "tok1" });
    const sw = sweepFromPages([[p1, null], [p2, "tok1"]], { bucket: BUCKET, source: "s3" });
    assert.equal(sw.pages, 2);
    // Page 1 carries no echo by construction; only page 2 corroborates.
    assert.equal(sw.echoVerifiedPages, 1);
  });

  test("a surface that does not echo still sweeps, and says so by counting zero", () => {
    // R2's S3 compatibility layer may or may not echo; requiring it would refuse
    // a correct bucket over an undocumented guarantee. Case N measures it.
    const p1 = s3Page([s3Obj("A")], { IsTruncated: true, NextContinuationToken: "tok1" });
    const p2 = s3Page([s3Obj("B")]);
    const sw = sweepFromPages([[p1, null], [p2, "tok1"]], { bucket: BUCKET, source: "s3" });
    assert.equal(sw.echoVerifiedPages, 0);
  });

  test("sweepBucket OWNS the cursor: the caller never states which token it used", async () => {
    // The structural half. `requestedWith` is no longer a caller's report about
    // its own work — it is what this function threaded from the previous page.
    const asked = [];
    const sw = await sweepBucket({
      bucket: BUCKET, source: "s3",
      listPage: async (token) => {
        asked.push(token);
        return token === null
          ? s3Page([s3Obj("A")], { IsTruncated: true, NextContinuationToken: "tok1" })
          : s3Page([s3Obj("B")], { ContinuationToken: token });
      },
    });
    assert.deepEqual(asked, [null, "tok1"]);
    assert.equal(sw.pages, 2);
    assert.equal(sw.echoVerifiedPages, 1);
    assert.equal(isCompletedSweep(sw), true);
  });

  test("sweepBucket refuses a lister that ignores the token it was handed", async () => {
    // A caller that re-lists from the start halfway through yields pages that
    // are each individually valid and a union missing a range.
    await assert.rejects(
      sweepBucket({
        bucket: BUCKET, source: "s3",
        listPage: async () => s3Page([s3Obj("A")], { IsTruncated: true, NextContinuationToken: "t" }),
        maxPages: 3,
      }),
      (e) => e.code === "CD-INV-PAGE-CAP");
  });

  test("sweepBucket needs the I/O function; it will not invent one", async () => {
    await assert.rejects(sweepBucket({ bucket: BUCKET, source: "s3" }),
      (e) => e.code === "CD-INV-NO-LISTER");
  });
});

describe("finding 116 — a finished sweep is not a point-in-time snapshot", () => {
  test("the sweep states what it asserts, and what it does NOT", () => {
    const sw = sweep1(s3Page([s3Obj("a")]));
    assert.match(sw.asserts, /verified cursor chain/);
    assert.match(sw.doesNotAssert, /point-in-time image/);
    // Cloudflare documents point-in-time consistency for ONE list operation. A
    // multi-page sweep is many, and nothing first-party joins them.
    assert.match(sw.doesNotAssert, /one list operation/);
  });
});

describe("finding 118 — authority to cause an event is not evidence it caused it", () => {
  test("upload_intent is recorded as proving authority, and explicitly not causation", () => {
    assert.equal(PROVENANCE_BASES.upload_intent.proves, "authority");
    assert.equal(PROVENANCE_BASES.upload_intent.doesNotProve, "causation");
    assert.match(PROVENANCE_BASES.upload_intent.why, /not that the object currently there/);
  });

  test("the refusal names BOTH reasons a repair stays a candidate", () => {
    const p = reconciliationPlan(sweep1(s3Page([s3Obj("a")])), ledger([]));
    assert.throws(() => observeArgsFor(p.repairs[0], PROV_FULL), (e) =>
      e.code === "CD-INV-BLOCKED"
      && /LastModified/.test(e.message)                 // finding 117, the clock
      && /proves authority and not causation/.test(e.message));  // finding 118
  });
});

describe("the candidate is reachable, because a protection behind a refusal is not one", () => {
  // THE MUTATION BATTERY FOUND THIS, in the round that introduced it. Finding
  // 117's fix made observeArgsFor() refuse unconditionally, which made its
  // argument vector unreachable — and `inventory-fabricates-action`, the vector
  // guarding finding 109, flipped from CAUGHT to MISSED. Nothing about the
  // source looked wrong; the line was simply no longer reachable by any test.
  const repair = () => reconciliationPlan(sweep1(s3Page([s3Obj("a")])), ledger([])).repairs[0];

  test("the candidate carries the caller's DERIVED action, never a default", () => {
    for (const action of CREATE_ACTIONS) {
      assert.equal(repairCandidate(repair(), { ...PROV, action }).action, action);
    }
    assert.equal(CREATE_ACTIONS.length, 3);
  });

  test("R77: the candidate claims NO delivery identity", () => {
    const c = repairCandidate(repair(), PROV);
    assert.equal(c.messageId, null, "a repair did not arrive on the authority channel");
    assert.equal(c.queue, null);
    assert.equal(c.providerStateTime, T);
    assert.equal(c.eventTime, undefined, "finding 117: not this clock, not this name");
  });

  test("the candidate names what BLOCKS it, so 'candidate' is a fact and not a comment", () => {
    const c = repairCandidate(repair(), PROV);
    // THREE now: finding 130 added provider authority for POSITIVE facts, and it
    // is enforced through the same one computation rather than beside it.
    // FOUR now: finding 136 added the LEDGER side, because a `missing` repair
    // rests on what the ledger does NOT say.
    assert.equal(c.blocked.length, 4);
    assert.match(c.blocked.join(" "), /proves authority and not causation/);      // 118
    assert.match(c.blocked.join(" "), /LastModified/);                            // 117
    assert.match(c.blocked.join(" "), /not provider-authoritative/);              // 130
    assert.match(c.blocked.join(" "), /rests on what the LEDGER does not say/);   // 136
    assert.equal(Object.isFrozen(c), true);
  });

  test("every provenance rule still applies to the candidate, not only to application", () => {
    assert.throws(() => repairCandidate(repair(), undefined), (e) => e.code === "CD-INV-NO-PROVENANCE");
    assert.throws(() => repairCandidate(repair(), { ...PROV, basis: "operator_says_so" }),
      (e) => e.code === "CD-INV-BASIS");
    assert.throws(() => repairCandidate(repair(), { ...PROV, action: "DeleteObject" }),
      (e) => e.code === "CD-INV-ACTION");
    assert.throws(() => repairCandidate(repair(), { ...PROV, intentId: "" }),
      (e) => e.code === "CD-INV-INTENT");
  });
});

// ===========================================================================

describe("finding 122 — a set difference needs completeness on BOTH operands", () => {
  test("THE REPRODUCTION, direction 1: a partial ledger FABRICATES a missing repair", () => {
    // R2 holds A and B; the ledger really holds A and B; the caller passes [A].
    // Two rounds of work earned the sweep's completeness and the other operand
    // was an ordinary array, so this reported a repair for an object the ledger
    // already had.
    const short = ledger([known()]);                       // ...and B is not read
    const p = reconciliationPlan(sweep1(s3Page([s3Obj("a"), s3Obj("b")])), short);
    assert.equal(p.summary.missing, 1, "B looks unknown to the ledger because it was not read");
    // The protocol is what makes that unrepresentable: a read that never declared
    // itself final cannot become a ledger at all.
    const partial = beginLedgerInventory({ bucket: BUCKET, authority: "jobs", snapshot: "s" });
    partial.addPage([known()], { after: null });           // NOT final
    assert.throws(() => partial.finish(),
      (e) => e.code === "CD-LED-INCOMPLETE" && /hides the out-of-band deletes/.test(e.message));
  });

  test("THE REPRODUCTION, direction 2: a partial ledger HIDES an out-of-band delete", async () => {
    // R2 holds only A; the ledger really holds A and B. B is the exact
    // R56-impossible state this pass exists to catch, and a short read erases it.
    const full = ledger([known(), known({ objectKey: k("b") })]);
    const p = reconciliationPlan(await authSweep(s3Page([s3Obj("a")])), full);
    assert.equal(p.summary.absenceUnknown, 1, "the complete ledger SELECTS it");
    const short = ledger([known()]);
    const q = reconciliationPlan(await authSweep(s3Page([s3Obj("a")])), short);
    assert.equal(q.summary.absenceUnknown, 0,
      "and a short one would not have — which is why it is a type");
  });

  test("a bare array is refused where a ledger inventory is required", () => {
    assert.throws(() => reconciliationPlan(sweep1(s3Page([s3Obj("a")])), [known()]),
      (e) => e.code === "CD-INV-LEDGER");
  });

  test("the ledger must be about the SAME bucket as the sweep", async () => {
    const elsewhere = ledgerFromRows([known()],
      { bucket: "some-other-bucket", authority: "jobs", snapshot: "s" });
    await assert.rejects(async () => reconciliationPlan(await authSweep(s3Page([])), elsewhere),
      (e) => e.code === "CD-INV-LEDGER-BUCKET");
  });

  test("an RLS-policied read cannot support absence, because it returns a SUBSET", async () => {
    // The likeliest way direction 2 actually happens: computedriven_jobs carries
    // no tenant context on purpose, and a tenant session's read is filtered.
    const p = reconciliationPlan(await authSweep(s3Page([s3Obj("a")])),
                                 ledger([known(), known({ objectKey: k("b") })], "tenant"));
    assert.equal(p.summary.absenceEstablished, false);
    assert.equal(p.summary.refused, 0);
    assert.equal(p.summary.absenceUnknown, 1);
    assert.match(p.absenceUnknown[0].blocked.join(" "), /absence from a POLICY/);
    assert.equal(LEDGER_AUTHORITIES.tenant.seesAllTenants, false);
  });

  test("the ledger chain is verified the same way the sweep's is", () => {
    const inv = () => beginLedgerInventory({ bucket: BUCKET, authority: "jobs", snapshot: "s" });
    // A first page resuming FROM a cursor means everything before it is unseen.
    assert.throws(() => inv().addPage([known()], { after: k("a") }),
      (e) => e.code === "CD-LED-CHAIN" && /did not start at the beginning/.test(e.message));
    // A spliced chain.
    const a = inv(); a.addPage([known()], { after: null });
    assert.throws(() => a.addPage([known({ objectKey: k("z") })], { after: k("q") }),
      (e) => e.code === "CD-LED-CHAIN");
    // The cursor is REQUIRED, exactly as in beginSweep().
    assert.throws(() => inv().addPage([known()]), (e) => e.code === "CD-LED-NO-CURSOR");
    // Unsorted rows make a keyset cursor meaningless.
    assert.throws(() => inv().addPage([known({ objectKey: k("z") }), known({ objectKey: k("a") })],
                                      { after: null, final: true }),
      (e) => e.code === "CD-LED-ORDER");
    // A page after the final one splices two reads.
    const b = inv(); b.addPage([known()], { after: null, final: true });
    assert.throws(() => b.addPage([], { after: null }), (e) => e.code === "CD-LED-CLOSED");
  });

  test("a ledger must name its bucket, its reader and its snapshot", () => {
    assert.throws(() => beginLedgerInventory({ authority: "jobs", snapshot: "s" }),
      (e) => e.code === "CD-LED-BUCKET");
    assert.throws(() => beginLedgerInventory({ bucket: BUCKET, snapshot: "s" }),
      (e) => e.code === "CD-LED-AUTHORITY");
    assert.throws(() => beginLedgerInventory({ bucket: BUCKET, authority: "root", snapshot: "s" }),
      (e) => e.code === "CD-LED-AUTHORITY");
    // Two snapshots are two ledgers and their union is neither.
    assert.throws(() => beginLedgerInventory({ bucket: BUCKET, authority: "jobs" }),
      (e) => e.code === "CD-LED-SNAPSHOT");
  });

  test("a structural clone of a ledger inventory is refused, like every other proof here", () => {
    const real = ledger([known()]);
    assert.equal(isCompleteLedger(real), true);
    assert.equal(isCompleteLedger({ ...real }), false);
  });
});

describe("finding 123 — a brand cannot mean two things", () => {
  test("THE REPRODUCTION: a synthetic lister with no R2 anywhere minted a usable sweep", async () => {
    const fake = await sweepBucket({
      bucket: BUCKET, source: "s3",
      listPage: async () => ({ Contents: [], KeyCount: 0, IsTruncated: false }),
    });
    // Still protocol-complete — that fact is true and worth having.
    assert.equal(isCompletedSweep(fake), true);
    // But no longer authoritative, so it cannot conclude absence.
    assert.equal(isAuthoritativeSweep(fake), false);
    const p = reconciliationPlan(fake, ledger([known()]));
    assert.equal(p.summary.refused, 0);
    assert.equal(p.summary.absenceUnknown, 1);
    assert.match(p.absenceUnknown[0].blocked.join(" "), /came from R2 at all/);
  });

  test("a sweep through the SIGNING adapter is protocol-complete and still not authoritative",
       async () => {
    // FINDING 128. Round 8.4 branded this authoritative. It signs correctly and
    // the bytes still came from an injected function, so it cannot certify R2.
    const sw = await authSweep(s3Page([s3Obj("a")]));
    assert.equal(isCompletedSweep(sw), true);
    assert.equal(isAuthoritativeSweep(sw), false);
  });

  test("sweepFromPages is protocol-complete and NEVER authoritative", () => {
    assert.equal(isAuthoritativeSweep(sweep1(s3Page([s3Obj("a")]))), false);
  });

  test("the adapter refuses an incomplete credential", () => {
    const ok = { accountId: ACCOUNT, bucket: BUCKET, accessKeyId: "AK", secretAccessKey: "SK",
                 fetchImpl: async () => ({}) };
    for (const f of ["bucket", "accessKeyId", "secretAccessKey"]) {
      const { [f]: _drop, ...rest } = ok;
      assert.throws(() => r2ListingAdapter(rest), (e) => e.code === "CD-INV-ADAPTER", f);
    }
    // FINDING 132. The account id is what derives the endpoint, so a bad one is
    // a refusal rather than a base URL nobody checked.
    assert.throws(() => r2ListingAdapter({ ...ok, accountId: "not-an-account-id" }),
      (e) => e.code === "CD-INV-ACCOUNT");
  });

  test("positive evidence survives without authority; only absence needs it", async () => {
    // R2 naming a key is true the moment it is read. The asymmetry is the point.
    const p = reconciliationPlan(sweep1(s3Page([s3Obj("a")])), ledger([]));
    assert.equal(p.summary.missing, 1, "a repair is positive evidence and still computed");
    assert.equal(p.summary.absenceEstablished, false);
  });
});

describe("finding 124 — a blocked reason that is only printed is not a gate", () => {
  const repair = () => reconciliationPlan(sweep1(s3Page([s3Obj("a")])), ledger()).repairs[0];

  test("THE REPRODUCTION: earning the clock must NOT unlock causation", () => {
    // Round 8.3 checked EVENT_TIME_BASES and nothing else, so with that list
    // non-empty an upload_intent provenance returned a valid argument vector —
    // silently satisfying finding 118's blocker, which nothing had resolved.
    // Both lists are empty today, and they are SEPARATE lists on purpose.
    // The two lists are SEPARATE and both empty. Separateness is the fix:
    // round 8.3 had one check, so a member appearing in the clock list would
    // have satisfied the causation blocker too.
    assert.deepEqual(EVENT_TIME_BASES, []);
    assert.deepEqual(CAUSATION_BASES, []);

    // The reachable form of the reproduction: the causation blocker is present
    // for EVERY value of eventTimeBasis, so no clock measurement can ever remove
    // it. (The module-edit form — EVENT_TIME_BASES = ["measured_equal"] — is the
    // `event-time-basis-bypasses-causation` mutation vector.)
    for (const basis of ["measured_equal", "", null, undefined, "anything-at-all"]) {
      const c = repairCandidate(repair(), { ...PROV, eventTimeBasis: basis });
      const causation = c.blocked.filter((b) => /proves authority and not causation/.test(b));
      assert.equal(causation.length, 1, `causation blocker must survive eventTimeBasis=${basis}`);
    }
  });

  test("the printed blockers and the enforced ones are ONE computation", () => {
    const c = repairCandidate(repair(), PROV);
    assert.equal(c.blocked.length, 4);
    try {
      observeArgsFor(repair(), PROV);
      assert.fail("must refuse");
    } catch (e) {
      assert.equal(e.code, "CD-INV-BLOCKED");
      // Every printed reason appears in the refusal, because they are the same array.
      for (const b of c.blocked) assert.ok(e.message.includes(b), b.slice(0, 40));
      assert.match(e.message, /4 blocker\(s\) stand/);
    }
  });

  test("upload_intent can never become a causation basis", () => {
    assert.equal(CAUSATION_BASES.includes("upload_intent"), false);
    assert.equal(PROVENANCE_BASES.upload_intent.doesNotProve, "causation");
  });
});

// ===========================================================================

describe("finding 128 — if the adapter does not perform the authenticated act", () => {
  test("THE REPRODUCTION: round 8.4's transport callback minted authority with no R2", async () => {
    // The old signature took `transport`, checked four strings were non-empty,
    // and branded the closure. With a fake key, a fake secret and a transport
    // returning an object literal, isAuthoritativeSweep() was TRUE. The parameter
    // is gone; a caller passing it gets the runtime's own fetch, not a bypass.
    const a = r2ListingAdapter({
      accountId: ACCOUNT, bucket: BUCKET, accessKeyId: "FAKE", secretAccessKey: "FAKE",
      transport: async () => ({ Contents: [], KeyCount: 0, IsTruncated: false }),
      endpoint: "http://127.0.0.1:9/anything",
      fetchImpl: async () => ({ ok: true, text: async () => xmlFor([]) }),
    });
    // Both stray parameters are simply not read any more.
    assert.equal(a.endpoint, r2Endpoint(ACCOUNT));
    assert.equal(a.networkVerified, false);
    assert.equal(isAuthoritativeSweep(await a.sweep()), false);
  });

  test("the adapter actually SIGNS, with SigV4, and the test can inspect the request", async () => {
    const a = signingAdapter(xmlFor([]));
    await a.sweep();
    assert.equal(a.signedRequests.length, 1);
    const h = a.signedRequests[0].headers;
    assert.match(h.Authorization, /^AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE\/\d{8}\/auto\/s3\/aws4_request, /);
    assert.match(h.Authorization, /SignedHeaders=host;x-amz-content-sha256;x-amz-date/);
    assert.match(h.Authorization, /Signature=[0-9a-f]{64}$/);
    // S3 requires the payload hash be present AND signed.
    assert.equal(h["x-amz-content-sha256"],
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert.match(a.signedRequests[0].canonical, /^GET\n\/cd-worlds\nlist-type=2\n/);
    assert.equal(a.signedRequests[0].headers.host, ACCOUNT + ".r2.cloudflarestorage.com",
      "the SIGNED host is the derived R2 identity, not one a caller chose (finding 132)");
  });

  test("the continuation token is SIGNED, so a resumed page is authenticated too", async () => {
    const a = signingAdapter(xmlFor([s3Obj("A")], { truncated: true, next: "tok1" }),
                             xmlFor([s3Obj("B")], { echo: "tok1" }));
    await a.sweep();
    assert.equal(a.signedRequests.length, 2);
    assert.match(a.signedRequests[1].canonical, /continuation-token=tok1/);
    // AWS sorts the canonical query by ENCODED name: continuation-token < list-type.
    assert.match(a.signedRequests[1].canonical, /continuation-token=tok1&list-type=2/);
  });

  test("the SIGNED headers are what reaches the network", async () => {
    // A signer whose output never leaves the function is decoration. This is the
    // assertion that the Authorization header is actually on the wire.
    let seen = null;
    const a = r2ListingAdapter({
      accountId: ACCOUNT, bucket: BUCKET, accessKeyId: "AK", secretAccessKey: "SK",
      fetchImpl: async (url, init) => { seen = { url, init };
                                        return { ok: true, text: async () => xmlFor([]) }; },
    });
    await a.sweep();
    assert.match(seen.init.headers.Authorization, /^AWS4-HMAC-SHA256 Credential=AK\//);
    assert.equal(seen.init.headers["x-amz-content-sha256"],
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert.match(seen.init.headers["x-amz-date"], /^\d{8}T\d{6}Z$/);
    assert.match(seen.url,
      new RegExp("^https://" + ACCOUNT + "\\.r2\\.cloudflarestorage\\.com/cd-worlds\\?"));
    assert.match(seen.url, /list-type=2/);
  });

  test("a provider error is a refusal, never an empty bucket", async () => {
    const a = r2ListingAdapter({
      accountId: ACCOUNT, bucket: BUCKET, accessKeyId: "AK", secretAccessKey: "SK",
      fetchImpl: async () => ({ ok: false, status: 403, text: async () => "" }),
    });
    await assert.rejects(a.sweep(), (e) => e.code === "CD-INV-HTTP");
  });

  test("the XML reader keeps finding 110: an omitted Contents is not an empty array", () => {
    const empty = parseListObjectsV2Xml(xmlFor([]));
    assert.equal(empty.Contents, undefined, "absent, so the normalizer can demand KeyCount === 0");
    assert.equal(empty.KeyCount, 0);
    assert.equal(empty.IsTruncated, false);
    // And an unreadable document is a refusal rather than a clean bucket.
    assert.throws(() => parseListObjectsV2Xml("<html>502</html>"), (e) => e.code === "CD-INV-XML");
    // The quoted etag survives, so finding 100's unquoting still has something to do.
    const one = parseListObjectsV2Xml(xmlFor([s3Obj("a")]));
    assert.equal(one.Contents[0].ETag, `"${HEX}"`);
  });
});

describe("finding 129 — the ledger adapter derives what the caller used to declare", () => {
  const rows = [{ object_key: k("a"), size_bytes: 100, etag: HEX, ambiguous: false }];
  // FINDING 133. The statements execute ON the connection being attested; there
  // is no separate `query` argument that could answer them from somewhere else.
  // FINDING 134. The identity read asks for the ISOLATION LEVEL and
  // pg_current_snapshot(), because a transaction id is not a snapshot.
  const ID = { current_user: "computedriven_jobs_login", isolation: "repeatable read",
               read_only: "on", snapshot: "8891:8891:" };
  const db = (idRow, pages) => {
    let i = 0;
    return jobsConnection({
      query: async (sql) => {
        if (/^BEGIN|^COMMIT/.test(sql)) return [];
        if (/current_user/.test(sql) && !/storage_objects/.test(sql)) return [idRow];
        return pages[i++];
      },
    }, { hyperdriveBinding: "HYPERDRIVE_JOBS" });
  };

  test("THE REPRODUCTION: hand-written rows plus two strings minted a complete ledger", () => {
    // `ledgerFromRows(..., { authority: "jobs", snapshot: "I-made-this-up" })`
    // was branded complete with no PostgreSQL anywhere. It still is
    // protocol-complete — that is a real and useful fact — and it is no longer
    // AUTHORITATIVE, which is the fact absence depends on.
    const fake = ledger([known()]);
    assert.equal(isCompleteLedger(fake), true);
    assert.equal(isAuthoritativeLedger(fake), false);
  });

  test("authority and snapshot come from the DATABASE, not from an argument", async () => {
    const led = await ledgerInventoryAdapter({
      bucket: BUCKET, pageSize: 1000,
      connection: db({ ...ID, current_user: "computedriven_jobs_login" }, [rows]),
    });
    assert.equal(led.authority, "jobs");
    assert.equal(led.snapshot, ID.snapshot, "pg_current_snapshot(), not a transaction id (134)");
    assert.equal(led.rows.length, 1);
    // A bound jobs connection IS the authority now — there is no separate
    // registrar, and no way to answer its statements from elsewhere (133).
    assert.equal(isAuthoritativeLedger(led), true);
  });

  test("the request credential's login maps to `tenant`, which cannot support absence", async () => {
    const led = await ledgerInventoryAdapter({
      bucket: BUCKET,
      connection: db({ ...ID, current_user: "computedriven_api_login" }, [[]]),
    });
    assert.equal(led.authority, "tenant");
    assert.equal(led.seesAllTenants, false);
  });

  test("an unclassified login is a refusal — unknown reader, unknown visibility", async () => {
    await assert.rejects(ledgerInventoryAdapter({
      bucket: BUCKET, connection: db({ ...ID, current_user: "postgres" }, [[]]),
    }), (e) => e.code === "CD-LED-LOGIN");
    assert.throws(() => ledgerAuthorityFor(undefined), (e) => e.code === "CD-LED-LOGIN");
    assert.equal(ledgerAuthorityFor("computedriven_jobs_login"), "jobs");
  });

  test("FINALITY IS MEASURED: a short page ends the keyset, a full one continues it", async () => {
    const page1 = Array.from({ length: 2 }, (_, i) => ({
      object_key: k(`p${i}`), size_bytes: 1, etag: HEX, ambiguous: false }));
    const led = await ledgerInventoryAdapter({
      bucket: BUCKET, pageSize: 2,
      connection: db({ ...ID, current_user: "computedriven_jobs_login" }, [page1, []]),
    });
    assert.equal(led.pages, 2, "a full page cannot be final, so it asked again");
    assert.equal(led.rows.length, 2);
  });

  test("pages from two snapshots are two ledgers, and refused as such", async () => {
    await assert.rejects(ledgerInventoryAdapter({
      bucket: BUCKET, pageSize: 1000,
      connection: db(ID, [[{ ...rows[0], snapshot: "A-DIFFERENT-ONE" }]]),
    }), (e) => e.code === "CD-LED-SNAPSHOT-DRIFT");
  });

  test("a database that names no transaction cannot name its snapshot", async () => {
    await assert.rejects(ledgerInventoryAdapter({
      bucket: BUCKET, connection: db({ ...ID, snapshot: undefined }, [[]]),
    }), (e) => e.code === "CD-LED-NO-SNAPSHOT");
  });

  test("FINDING 133: an unbranded connection cannot reach the adapter at all", async () => {
    await assert.rejects(ledgerInventoryAdapter({ connection: {}, bucket: BUCKET }),
      (e) => e.code === "CD-LED-CONN");
    await assert.rejects(ledgerInventoryAdapter({ bucket: BUCKET }),
      (e) => e.code === "CD-LED-CONN");
  });
});

describe("THE CRISP GATE: no R2 and no PostgreSQL means no absence, ever", () => {
  test("both operands manufactured offline still cannot conclude absence", async () => {
    // Round 8.4's answer to this was `absenceEstablished: true, refused: 1`.
    const sweep = await authSweep(s3Page([]));
    const led = ledger([known({ objectKey: k("victim") })]);
    const p = reconciliationPlan(sweep, led);
    assert.equal(p.summary.absenceEstablished, false);
    assert.equal(p.summary.refused, 0);
    assert.equal(p.absenceUnknown.length, 1);
    // BOTH sides say why, independently.
    const why = p.absenceUnknown[0].blocked.join(" ");
    assert.match(why, /the sweep is protocol-complete but not provider-authoritative/);
    assert.match(why, /the ledger inventory is protocol-complete but not provider-authoritative/);
  });

  test("a real jobs transaction is still not enough while R2 is injected", async () => {
    const led = await ledgerInventoryAdapter({
      bucket: BUCKET, pageSize: 1000,
      connection: jobsConnection({
        query: async (sql) => {
          if (/^BEGIN|^COMMIT/.test(sql)) return [];
          if (/current_user/.test(sql) && !/storage_objects/.test(sql)) {
            return [{ current_user: "computedriven_jobs_login", isolation: "repeatable read",
                      read_only: "on", snapshot: "8891:8891:" }];
          }
          return [{ object_key: k("victim"), size_bytes: 1, etag: HEX, ambiguous: false }];
        },
      }, { hyperdriveBinding: "HYPERDRIVE_JOBS" }),
    });
    assert.equal(isAuthoritativeLedger(led), true);
    const p = reconciliationPlan(await authSweep(s3Page([])), led);
    assert.equal(p.summary.absenceEstablished, false, "one authority is not two");
    assert.equal(p.absenceUnknown[0].blocked.length, 1, "and it says which one is missing");
  });
});

describe("finding 130 — a provider fact needs provider provenance, presence included", () => {
  test("THE REPRODUCTION: a synthetic page manufactured a 10 TB repair candidate", () => {
    const huge = sweep1(s3Page([s3Obj("victim", { Size: 10_000_000_000_000 })]));
    const p = reconciliationPlan(huge, ledger([]));
    // The diff still computes — that keeps the algorithm testable with no account.
    assert.equal(p.summary.missing, 1);
    // But the repair is marked for what it is, and cannot be applied.
    assert.equal(p.repairs[0].providerAuthoritative, false);
    const c = repairCandidate(p.repairs[0], PROV);
    assert.match(c.blocked.join(" "), /not evidence about R2 at all/);
    assert.throws(() => observeArgsFor(p.repairs[0], PROV), (e) => e.code === "CD-INV-BLOCKED");
  });

  test("authority has two dimensions: presence needs it, absence needs it AND completeness", () => {
    const p = reconciliationPlan(sweep1(s3Page([s3Obj("a")])), ledger([known({ objectKey: k("z") })]));
    // Presence: computed, and marked non-authoritative.
    assert.equal(p.summary.missing, 1);
    assert.equal(p.repairs[0].providerAuthoritative, false);
    // Absence: selected, and not concluded.
    assert.equal(p.summary.sweepAuthoritative, false);
    assert.equal(p.summary.absenceEstablished, false);
    assert.equal(p.absenceUnknown.length, 1);
  });
});

// ===========================================================================

describe("THE ACCEPTANCE BATTERY — each authority, refused at its own boundary", () => {
  // Round 8.5 published this as a theorem and it was FALSE in the tree that
  // published it: an ordinary local HTTP server reached by the real global fetch
  // minted an authoritative sweep, and a registered empty object plus an
  // unrelated query function minted an authoritative ledger. The verification
  // that missed it tested ONE attack and asserted the general case. Each clause
  // is now a separate test with its own reproduction.

  test("NO CLOUDFLARE R2 => impossible to mint an AuthoritativeR2Sweep", async () => {
    // FINDING 132's reproduction, in the form it can still be attempted: the
    // endpoint is derived from the account id, so there is no argument through
    // which any other host can be named — including one a real fetch can reach.
    const a = r2ListingAdapter({
      accountId: ACCOUNT, bucket: BUCKET, accessKeyId: "F", secretAccessKey: "F",
      endpoint: "http://127.0.0.1:9/anything",     // ignored
      fetchImpl: async () => ({ ok: true, text: async () => xmlFor([]) }),
    });
    assert.equal(a.endpoint, r2Endpoint(ACCOUNT));
    assert.equal(a.endpointVerified, true, "the host is Cloudflare's, derived");
    assert.equal(a.networkVerified, false, "and the transport is not the runtime's own");
    assert.equal(isAuthoritativeSweep(await a.sweep()), false, "so authority is refused");
  });

  test("NO REAL JOBS CONNECTION => impossible to mint an authoritative ledger", async () => {
    await assert.rejects(ledgerInventoryAdapter({ connection: {}, bucket: BUCKET }),
      (e) => e.code === "CD-LED-CONN");
    // And the registrar that made round 8.5's version forgeable is gone.
    assert.equal(typeof globalThis.registerLedgerConnection, "undefined");
    assert.throws(() => jobsConnection({}, { hyperdriveBinding: "HYPERDRIVE_JOBS" }),
      (e) => e.code === "CD-LED-CLIENT", "an empty object is not a client");
    assert.throws(() => jobsConnection({ query: async () => [] },
                                       { hyperdriveBinding: "HYPERDRIVE_CONTROL" }),
      (e) => e.code === "CD-LED-BINDING", "the request credential is not the observer credential");
  });

  test("NO REPEATABLE READ => impossible to mint complete ledger evidence", async () => {
    // FINDING 134. PostgreSQL's DEFAULT is READ COMMITTED, under which "two
    // successive SELECT commands can see different data ... within a single
    // transaction". A transaction id is stable across exactly that, so round
    // 8.5's txid equality check proved nothing it claimed.
    const readCommitted = jobsConnection({
      query: async (sql) => {
        if (/^BEGIN|^COMMIT/.test(sql)) return [];
        if (/current_user/.test(sql) && !/storage_objects/.test(sql)) {
          return [{ current_user: "computedriven_jobs_login", isolation: "read committed",
                    read_only: "on", snapshot: "8891:8891:" }];
        }
        return [];
      },
    }, { hyperdriveBinding: "HYPERDRIVE_JOBS" });
    await assert.rejects(ledgerInventoryAdapter({ connection: readCommitted, bucket: BUCKET }),
      (e) => e.code === "CD-LED-ISOLATION" && /own snapshot/.test(e.message));
  });

  test("a ledger scan that can WRITE is refused", async () => {
    const writable = jobsConnection({
      query: async (sql) => {
        if (/^BEGIN|^COMMIT/.test(sql)) return [];
        if (/current_user/.test(sql) && !/storage_objects/.test(sql)) {
          return [{ current_user: "computedriven_jobs_login", isolation: "repeatable read",
                    read_only: "off", snapshot: "8891:8891:" }];
        }
        return [];
      },
    }, { hyperdriveBinding: "HYPERDRIVE_JOBS" });
    await assert.rejects(ledgerInventoryAdapter({ connection: writable, bucket: BUCKET }),
      (e) => e.code === "CD-LED-READ-ONLY");
  });

  test("the adapter OWNS the transaction — it does not expect the caller to have opened one",
       async () => {
    // Round 8.5's comment said "the caller is expected to have opened a
    // REPEATABLE READ transaction", which is the kind of external convention
    // this system has spent rounds deleting.
    const seen = [];
    const conn = jobsConnection({
      query: async (sql) => {
        seen.push(sql.split("\n")[0].slice(0, 60));
        if (/^BEGIN|^COMMIT/.test(sql)) return [];
        if (/current_user/.test(sql) && !/storage_objects/.test(sql)) {
          return [{ current_user: "computedriven_jobs_login", isolation: "repeatable read",
                    read_only: "on", snapshot: "8891:8891:" }];
        }
        return [];
      },
    }, { hyperdriveBinding: "HYPERDRIVE_JOBS" });
    await ledgerInventoryAdapter({ connection: conn, bucket: BUCKET });
    assert.match(seen[0], /^BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY/);
    assert.equal(seen[seen.length - 1], "COMMIT",
      "and it closes the transaction, so a pooled connection does not inherit the snapshot");
  });

  test("ANY NEGATIVE FACT => authority on the side whose absence is asserted", async () => {
    // Both directions of finding 136's symmetry, on one plan.
    const sweep = await authSweep(s3Page([s3Obj("present")]));
    const led = ledger([known({ objectKey: k("gone") })]);
    const p = reconciliationPlan(sweep, led);

    // "missing" rests on the LEDGER's silence.
    const missing = p.repairs.find((r) => r.kind === "missing");
    assert.equal(missing.ledgerAuthoritative, false);
    assert.match(repairCandidate(missing, PROV).blocked.join(" "),
      /rests on what the LEDGER does not say/);

    // absence rests on R2's silence.
    assert.equal(p.summary.absenceEstablished, false);
    assert.equal(p.absenceUnknown.length, 1);
  });

  test("THE WHOLE THEOREM: no R2 and no PostgreSQL, both operands refused", async () => {
    const p = reconciliationPlan(await authSweep(s3Page([])), ledger([known({ objectKey: k("v") })]));
    assert.equal(p.summary.absenceEstablished, false);
    assert.equal(p.summary.refused, 0);
    const why = p.absenceUnknown[0].blocked.join(" ");
    assert.match(why, /the sweep is protocol-complete but not provider-authoritative/);
    assert.match(why, /the ledger inventory is protocol-complete but not provider-authoritative/);
  });
});

// ===========================================================================

describe("round 8.6 — the properties the battery could not previously see", () => {
  const ID = { current_user: "computedriven_jobs_login", isolation: "repeatable read",
               read_only: "on", snapshot: "8891:8891:" };
  const db = (idRow, pages) => {
    let i = 0;
    return jobsConnection({
      query: async (sql) => {
        if (/^BEGIN|^COMMIT/.test(sql)) return [];
        if (/current_user/.test(sql) && !/storage_objects/.test(sql)) return [idRow];
        return pages[i++];
      },
    }, { hyperdriveBinding: "HYPERDRIVE_JOBS" });
  };

  test("the derived endpoint is HTTPS and Cloudflare's, and that fact is asserted", () => {
    const a = signingAdapter(xmlFor([]));
    assert.equal(a.endpoint, `https://${ACCOUNT}.r2.cloudflarestorage.com`);
    assert.equal(a.endpointVerified, true,
      "endpointVerified is the finding-132 half of authority and must be observable");
  });

  test("the capability does NOT expose a rebindable lister (finding 137)", () => {
    const a = signingAdapter(xmlFor([]));
    assert.equal(a.listPage, undefined,
      "round 8.5 returned one, and an adapter for bucket A could sweep bucket B with it");
    assert.deepEqual(Object.keys(a).sort(),
      ["accountId", "bucket", "endpoint", "endpointVerified", "networkVerified",
       "signedRequests", "sweep"]);
    assert.equal(Object.isFrozen(a), true);
  });

  test("a listing about ANOTHER bucket is refused however correctly it was signed", async () => {
    const a = r2ListingAdapter({
      accountId: ACCOUNT, bucket: BUCKET, accessKeyId: "AK", secretAccessKey: "SK",
      fetchImpl: async () => ({ ok: true, text: async () => xmlFor([], { name: "somewhere-else" }) }),
    });
    await assert.rejects(a.sweep(),
      (e) => e.code === "CD-INV-BUCKET-NAME" && /wrong subject/.test(e.message));
  });

  test("the ledger adapter IGNORES a caller-supplied query (finding 133)", async () => {
    // The defect was that `query` and `connection` were separate arguments, so
    // the brand and the observations were never connected. Passing one now has
    // no effect: the statements run on the connection being attested.
    let calledTheImposter = false;
    const led = await ledgerInventoryAdapter({
      bucket: BUCKET,
      connection: db(ID, [[{ object_key: k("a"), size_bytes: 1, etag: HEX, ambiguous: false }]]),
      query: async () => { calledTheImposter = true; return []; },
    });
    assert.equal(calledTheImposter, false, "a passed query must never be executed");
    assert.equal(led.rows.length, 1, "and the connection's own answers are what was read");
  });

  test("a TENANT ledger cannot mint a missing repair either (finding 136)", async () => {
    // The RLS case, on the positive side: a tenant read's silence about a key is
    // silence from a POLICY, so it cannot support "the ledger has never seen it".
    const tenant = await ledgerInventoryAdapter({
      bucket: BUCKET,
      connection: db({ ...ID, current_user: "computedriven_api_login" }, [[]]),
    });
    assert.equal(tenant.authority, "tenant");
    const p = reconciliationPlan(await authSweep(s3Page([s3Obj("a")])), tenant);
    const c = repairCandidate(p.repairs[0], PROV);
    assert.match(c.blocked.join(" "), /cannot see every tenant's rows/);
  });
});
