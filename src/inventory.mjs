// R2 INVENTORY RECONCILIATION — the repair path under the notification path.
//
// FINDING 92, 2026-08-23. `max_retries = 5` and, until R79, no dead letter
// queue. Cloudflare documents the consequence exactly: "Without a DLQ
// configured, messages that reach the retry limit are deleted permanently."
// So if Pigsty is unreachable long enough, the reachable state is
//
//     R2                object exists, 100 MB
//     Queue             notification retried five times, then deleted
//     storage_objects   no row
//     committed_bytes   unmoved
//
// which is finding 65 -- occupancy the ledger does not know about -- arriving
// from BELOW the database instead of above it.
//
//     R79 -- QUEUE NOTIFICATIONS MINIMIZE CONVERGENCE LATENCY. R2 INVENTORY
//     ESTABLISHES RECOVERABILITY.
//
// ===========================================================================
// FINDING 107 — AND "ESTABLISHES" TURNED OUT TO BE THE WHOLE PROBLEM.
//
// Finding 103 fixed a planner that read absence out of one page of a listing.
// The fix asked the provider whether the response was truncated and refused to
// read absence when it was. That was still wrong, and the round shipped it:
//
//     IsTruncated = false  means  THERE IS NO NEXT PAGE.
//     It does NOT mean    THIS PAGE IS THE WHOLE BUCKET.
//
// Reproduced against the shipped tree. Bucket holds A and B; ledger holds A
// and B; the listing paginates:
//
//     page 1   Contents=[A]  IsTruncated=true    -> 0 refusals   correct
//     page 2   Contents=[B]  IsTruncated=false   -> 1 refusal:
//                                                   "the ledger holds A and the
//                                                    complete listing does not"
//
// **The first-page bug was not fixed. It was moved to the last page**, where it
// is worse: page 2 alleges an out-of-band delete of an object PAGE 1 HAD JUST
// REPORTED PRESENT. A gate that reads its own earlier evidence as a deletion.
//
//     ABSENCE IS A PROPERTY OF A COMPLETE ENUMERATION, NOT OF ITS FINAL PAGE.
//
// So the abstraction changes rather than the predicate. A page cannot carry a
// `complete` flag, because completeness is not a property a single provider
// response has. It is earned by a PROTOCOL over a sequence of them:
//
//     normalizeR2ListingPage()   one response -> entries, presence, nextToken
//              |
//              v
//     InventorySweep.addPage()   accumulates, and VERIFIES THE CURSOR CHAIN
//              |
//              v
//     .finish()  -> CompletedSweep  startedAtBeginning + chainVerified +
//              |                     terminatedNormally, or it REFUSES
//              v
//     reconciliationPlan()       the only thing allowed to read absence
//
// Positive evidence is safe page by page: *R2 says K exists* is true the moment
// it is read. Negative evidence is not: *I did not see K on this page* proves
// nothing at all. The types now say so — `reconciliationPlan()` will not accept
// a page, and a sweep that did not terminate normally cannot become one.
//
// ---------------------------------------------------------------------------
// FINDING 108 — AND MALFORMED IS NOT ABSENT.
//
// Reproduced: R2 returns key A with an unusable etag, and B. The normalizer put
// A in `malformed` and out of `entries`; the planner then looked for A among the
// valid entries, did not find it, and reported
//
//     "the ledger holds this object and the complete listing does not —
//      an out-of-band delete, the wrong bucket, or a lifecycle rule"
//
// about an object **R2 had just told us exists.** Two independent facts had been
// collapsed into one array:
//
//     presence          KNOWN     — R2 named the key
//     usable metadata   UNKNOWN   — we cannot compare its state
//
//     PRESENCE AND USABLE STATE ARE INDEPENDENT FACTS.
//
// A sweep therefore accumulates `presentKeys` (every key the provider named,
// however garbled) alongside `entries` (those with metadata we can compare).
// Absence is checked against presence; state repair is computed from entries.
//
// ---------------------------------------------------------------------------
// FINDING 109 — WE STOPPED INVENTING A MESSAGE ID AND INVENTED AN ACTION.
//
// `observeArgsFor()` correctly refuses to synthesize a queue message id, with a
// paragraph explaining that a reconciliation did not arrive on the authority
// channel and has no delivery identity to claim. It then passed `"PutObject"`.
//
//     A LISTING REPORTS CURRENT STATE. IT DOES NOT REPORT WHICH HISTORICAL API
//     CALL PRODUCED THAT STATE.
//
// The lost notification could have been PutObject, CopyObject or
// CompleteMultipartUpload — case P2 requires the rule to cover all three
// precisely because all three can change occupancy. So the two observation
// kinds are not the same epistemic type:
//
//     QUEUE       "R2 says action X occurred at T"
//     INVENTORY   "R2 currently says key K has state S"
//
// `observeArgsFor()` now REQUIRES a provenance argument naming where the action
// came from, and refuses without one. Nothing in the pure layer can supply it:
// deriving `PutObject` from a matching upload intent is a database read, which
// is the caller's job, and if the caller has no such evidence the honest output
// is a surfaced candidate rather than a fabricated action.
//
// **This does NOT open `0028`.** The schema change that would make this natural
// — `observation_source = queue_event | inventory_state` with `provider_action`
// meaningful only for the first — is earned by case N showing that general
// direct-state reconciliation is actually needed, not by this argument.
//
// ===========================================================================
// FINDING 113 — AND THE PROOF OBJECT WAS A CLAIM ANYBODY COULD MINT.
//
// Finding 107's type was the right abstraction and its ADMISSION CHECK was a
// field read:
//
//     if (scan?.__completeScan !== true) refuse
//
// REPRODUCED against the shipped tree. An object literal typed by hand —
// `{ __completeScan: true, bucket, source, pages: 1, entries: [],
//    presentKeys: new Set(), malformed: [], unowned: [] }` — was accepted as a
// completed enumeration, and the planner concluded that a known ledger object
// was absent from R2. No protocol ran. No page was ever read.
//
//     A PROOF OBJECT IS NOT PROVED BECAUSE IT CONTAINS THE FIELD THAT SAYS IT
//     IS PROVED.
//
// This module was the only one in the tree that had not learned it. Three
// siblings already had:
//
//     jwt.mjs        VERIFIED           = new WeakSet()
//     admission.mjs  ADMITTED           = new WeakSet()
//     r2creds.mjs    AUTHORIZED_SCOPES  = new WeakSet()
//
// and jwt.mjs even ships the test — "even a structural CLONE of verified claims
// is refused". So this is R76's shape again, for the fourth time in four rounds:
// a law learned in one file is not learned. `COMPLETED_SWEEPS` is module-private,
// nothing exported adds to it, and `__completeScan` is GONE rather than demoted —
// a field that no longer decides anything is a field a future reader will make
// decide something again.
//
// There is a second half, and it is the sharper one. `Object.freeze(scan)` does
// not freeze what `scan.presentKeys` REFERS to, and it was a live `Set`.
// REPRODUCED on a genuinely protocol-built scan:
//
//     Object.isFrozen(scan) === true
//     scan.presentKeys.delete(realKey)   ->  planner reports realKey ABSENT
//
// A frozen object holding a mutable collection is a frozen pointer to mutable
// evidence. Absence is this pass's strongest and least reversible conclusion, so:
//
//     EVIDENCE USED FOR A NEGATIVE CONCLUSION MUST BE BOTH UNFORGEABLE AND
//     IMMUTABLE.
//
// `presentKeys` is now a frozen facade over a closure-private Set: `has`, `size`
// and iteration, and no way to add or remove.
//
// ---------------------------------------------------------------------------
// FINDING 115 — THE CURSOR CHAIN WAS VERIFIED AGAINST THE CALLER.
//
// `addPage(page, { requestedWith })` compared `requestedWith` to the previous
// page's `NextContinuationToken` — but `requestedWith` came from the caller, so
// the chain check asked the claimant to attest its own provenance. REPRODUCED:
//
//     page 1 provider   NextContinuationToken = "tok1"
//     page 2 provider   ContinuationToken     = "WRONG-TOKEN"
//     caller says       requestedWith         = "tok1"
//     -> chainVerified: true
//
// The provider and the caller disagreed and the caller won. That is finding
// 105's shape one level down:
//
//     PROVENANCE SUPPLIED BY THE CLAIMANT IS NOT PROVENANCE.
//
// Fixed in both directions. First, `sweepBucket()` OWNS the pagination loop: it
// threads the token from each page's own `nextToken` into the next request, so
// `requestedWith` is never a caller's word about what it did. Second, S3 echoes
// the token back — AWS, first-party: "If ContinuationToken was sent with the
// request, it is included in the response" — so `echoedToken` is normalized and
// a page whose echo disagrees with the token used is a REFUSAL.
//
// The echo is checked WHEN PRESENT and never required, because that guarantee is
// documented for Amazon S3 and R2's compatibility layer is a separate question
// this pass has not measured. The sweep records `echoVerifiedPages` so it states
// what it actually checked rather than what the S3 specification promises — case
// N measures whether R2 echoes at all.
//
// ---------------------------------------------------------------------------
// FINDING 116 — "COMPLETE SCAN" CLAIMED A SNAPSHOT NOBODY DOCUMENTED.
//
// Cloudflare's consistency page is strong but narrow: an object-list operation
// "will list all objects at that point in time." That is a guarantee about ONE
// list operation. A million-key enumeration is a thousand of them, and nothing
// first-party says page 1 at T₁ and page 500 at T₅₀₀ share a snapshot. So under
// concurrent writes:
//
//     page 1  ->  object X created behind the cursor  ->  pages 2..N
//
// the documentation does not establish that this enumeration must include X.
// `CompletedScan` implied it did. The name is the overclaim, so the name goes:
//
//     CompletedSweep — every provider page was traversed through a verified
//     cursor chain from the beginning to normal termination.
//
// and NOT "this is a point-in-time image of the bucket". R79 is narrowed to
// match: recoverability is **eventual, through repeated authoritative sweeps**,
// not one-pass reconstruction under concurrent mutation. Case N either makes the
// test bucket quiescent or repeats the sweep until the delta converges to zero.
//
// ---------------------------------------------------------------------------
// FINDING 117 — TWO R2 CLOCKS WERE BECOMING ONE CLOCK AGAIN.
//
// The normalizer mapped `LastModified -> providerTime`, and the repair then
// offered it as `eventTime`, bound for `p_event_time`. But Cloudflare defines a
// notification's `eventTime` as when the TRIGGERING ACTION occurred, and
// `LastModified` is a listing's statement about the object. Nothing first-party
// says they are the same instant. They may well be; that is something case N and
// case D can MEASURE, and until then typing one as the other is R74 exactly —
//
//     two timestamps that look related -> one variable name -> the semantic
//     distinction disappears.
//
// The field is `providerStateTime` throughout, and `observeArgsFor()` refuses to
// hand it to the observer as an event time: `EVENT_TIME_BASES` is deliberately
// EMPTY, so every call refuses until a live case earns the first member.
//
// ---------------------------------------------------------------------------
// FINDING 118 — MINTED AUTHORITY IS NOT CAUSAL PROVENANCE.
//
// Finding 109 stopped inventing `"PutObject"` and required a provenance basis;
// the only basis is an upload intent, justified because "we minted the
// credential that performed it". That justifies the wrong proposition. An
// upload intent establishes
//
//     we authorized capability X for key K
//
// and not
//
//     the current R2 state of K was caused by X.
//
//     AUTHORITY TO CAUSE AN EVENT IS NOT EVIDENCE THAT THE EVENT WAS CAUSED BY
//     THAT AUTHORITY.
//
// An out-of-band provider write is a case this architecture already knows how to
// represent, and the inventory path exists precisely because the event carrying
// the causal history may have been lost — so the one place we most want causation
// is the one place we least have it. `upload_intent` is therefore recorded as
// proving AUTHORITY ONLY, repairs stay candidates, and the `0028` that would
// make this natural — `observation_source = queue_event | inventory_state` with
// source-specific provenance — is still earned by case N and not by this
// argument.
//
// ===========================================================================
// FINDING 122 — COMPLETENESS WAS PROVED ON ONE SIDE OF A SET DIFFERENCE.
//
// Rounds 8.2 and 8.3 spent themselves earning one operand:
//
//     page -> page -> page -> CompletedSweep      unforgeable, immutable,
//                                                 cursor-chain verified
// and then handed it to
//
//     reconciliationPlan(sweep, known)            known: any ordinary Array
//
// Nothing said `known` held every ledger object, was read under an authority
// that can see every tenant, was not truncated, belonged to THIS bucket, or came
// from one snapshot. REPRODUCED in both directions:
//
//     R2 {A,B}  ledger really {A,B}  caller passes [A]
//         -> missing=1     a repair fabricated out of a short read
//
//     R2 {A}    ledger really {A,B}  caller passes [A]
//         -> refused=0     THE OUT-OF-BAND DELETE VANISHES
//
// The second is the bad one: B is the exact R56-impossible state this whole pass
// exists to catch, and a partial ledger view erases it silently. And the most
// likely cause is not a careless slice — it is **RLS**. The jobs role carries no
// tenant context on purpose; a policied read from a tenant session returns a
// SUBSET and looks exactly like a clean bucket.
//
//     A SET-DIFFERENCE THEOREM REQUIRES COMPLETENESS OF BOTH OPERANDS.
//
// The types were saying so out loud — `CompletedSweep` on one side and `Array`
// on the other — and nobody read them. So the ledger gets the same discipline:
// `beginLedgerInventory()` earns a `CompleteLedgerInventory` by protocol, brands
// it in a module-private WeakSet, and carries its bucket, authority and snapshot.
// `reconciliationPlan()` takes two proofs or it takes nothing.
//
// ---------------------------------------------------------------------------
// FINDING 123 — AND A BRAND CANNOT MEAN TWO THINGS.
//
// Finding 113's WeakSet proves a value went through the sweep state machine. It
// does not prove the pages came from R2, because `sweepBucket()` takes its I/O
// from the caller. REPRODUCED with no R2 anywhere:
//
//     sweepBucket({ listPage: async () => ({Contents:[], KeyCount:0,
//                                           IsTruncated:false}) })
//     -> isCompletedSweep(...) === true, and absence conclusions follow
//
//     AN I/O CALLBACK SUPPLIED BY THE CLAIMANT IS STILL CLAIMANT-SUPPLIED
//     PROVENANCE.
//
// The register already holds this boundary (R27): a WeakSet attestation is
// unforgeable by DATA and still forgeable by CODE. So the two facts get two
// brands rather than one brand carrying both:
//
//     CompletedSweep         protocol-complete. Pure, testable, and it may
//                            compute repairs — every one of which is POSITIVE
//                            evidence, true the moment R2 names the key.
//     AuthoritativeR2Sweep   protocol-complete AND every page arrived through
//                            the bucket-scoped credentialed adapter. ONLY this
//                            supports absence.
//
// A plan built from a merely protocol-complete sweep reports `absenceUnknown`
// instead of `refusals`, and says why. There is no option to override it: a flag
// that lets the caller weaken the evidence is the caller attesting again.
//
// ---------------------------------------------------------------------------
// FINDING 124 — A BLOCKED REASON THAT IS ONLY PRINTED IS NOT A GATE.
//
// Round 8.3 recorded two independent blockers on every repair candidate — 117's
// clock and 118's authority-vs-causation — and enforced ONE. `observeArgsFor()`
// checked `EVENT_TIME_BASES` and nothing else, which was safe only because that
// list was empty. Changing that single line to model a successful case N:
//
//     EVENT_TIME_BASES = ["measured_equal"]
//     basis            = upload_intent      (proves authority, NOT causation)
//     -> observeArgsFor RETURNED a valid observer argument vector
//
// So the first clock measurement would have silently unlocked the causation
// blocker too. `blocked` was documentation sitting next to an enforcement point
// that ignored it — the same shape as finding 86's check named after a quantity
// it did not query.
//
// Now `blocked` IS the gate: it is computed by predicates, and application
// refuses while it is non-empty. Adding a reason adds enforcement; there is no
// way to record one without it counting.
//
// ---------------------------------------------------------------------------
// FINDING 96 (round 8.1) — the layer that made all of the above expressible.
//
// The planner's declared input was `{ key, size, etag, uploaded }` with
// `uploaded` a string, which no documented R2 listing interface returns; all
// three real surfaces were refused by it and thirteen tests passed anyway. The
// normalizer is the only thing here that knows what a provider looks like, and
// the planner cannot be handed a provider object at all.
//
// FINDING 100 — the etag spelling differs by surface. Cloudflare's schema: JSON
// list/get responses carry the raw hex digest; the HTTP `ETag` header follows
// RFC 7232 and IS quoted. The notification body — where the ledger's etags come
// from — is raw. S3 `ListObjectsV2`, the surface with the right credential
// story, carries the quoted form. Unnormalized, the first pass would report
// every object divergent and rewrite every etag.
//
// FINDING 110 — an empty bucket is a legal answer. `Contents` is optional in the
// S3 response and a bucket with no objects omits it entirely. Refusing that
// shape as unenumerable would make case N — which deliberately empties the
// normal path — read its own success as a provider fault. It is accepted, but
// ONLY when the response positively proves zero objects (`KeyCount === 0`), so
// that a genuinely unreadable response is still a refusal.
//
// ---------------------------------------------------------------------------
// WHY S3 ListObjectsV2 IS THE CHOSEN SURFACE, AND WHY REST IS REFUSED.
//
// Cloudflare's token page: "Object Read only — allows the ability to read and
// list objects in specific buckets", scoped to a set of buckets. That is the
// least authority a reconciler can hold. The REST Object API cannot use it:
// object-level tokens "fail to authenticate" against api.cloudflare.com and are
// "only supported by the S3-compatible API"; REST means an Admin token granting
// "account-wide access rather than bucket-scoped access", and the same page adds
// that "the REST API is rate limited". REST is refused BY NAME so a future
// caller is told why. The Workers binding is a second named source — but note an
// r2_bucket binding carries write, so it is not the least-authority option.
//
// ---------------------------------------------------------------------------
// WHAT IT WILL AND WILL NOT REPAIR
//
//   missing     in R2, absent from the ledger.  REPAIRABLE -- the lost
//               notification. This is the whole reason the pass exists.
//   divergent   in both, disagreeing about etag or size. REPAIRABLE; R68 says
//               the provider's number wins.
//   ambiguous   the ledger holds a tied tip (R75). **REPORTED, NOT SETTLED** --
//               see the finding 97 note on ambiguityCandidates.
//   unreadable  present in R2 with metadata we cannot use (finding 108). Not a
//               repair and NOT an absence.
//   extra       in the ledger, absent from a COMPLETED SWEEP. **REFUSED**, and not
//               claimed at all from anything less (findings 103, 107).

import { parseObjectKey } from "./objectkey.mjs";
import { CREATE_ACTIONS } from "./reconcile.mjs";
import { signS3Get, uriEncode } from "./s3sig.mjs";

export class InventoryRefusal extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.name = "InventoryRefusal";
    this.code = code;
  }
}

// FINDING 113. A module-private WeakSet, and NOTHING EXPORTED FROM THIS MODULE
// CAN ADD TO IT — only `finish()`, at the end of the protocol that earns it.
// `assertCompletedSweep()` only reads. Same construction as jwt.mjs's VERIFIED,
// admission.mjs's ADMITTED and r2creds.mjs's AUTHORIZED_SCOPES, for the same
// reason: membership is granted by having gone through the protocol, and cannot
// be claimed by looking like something that did.
const COMPLETED_SWEEPS = new WeakSet();

/** Did this value come out of beginSweep(...).finish()? Shape cannot fake it. */
export function isCompletedSweep(v) {
  return typeof v === "object" && v !== null && COMPLETED_SWEEPS.has(v);
}

export function assertCompletedSweep(v) {
  if (!isCompletedSweep(v)) {
    throw new InventoryRefusal("CD-INV-NOT-SWEPT",
      "this is not a completed sweep. It may be a page, a provider response, or an object " +
      "carrying every field a completed sweep carries — none of which is the same thing as " +
      "having enumerated the bucket. Completeness is granted by beginSweep()/addPage()/finish() " +
      "and is not a property any value can declare about itself (finding 113)");
  }
  return v;
}

/**
 * FINDING 113, second half. `Object.freeze` freezes the POINTER, not the Set it
 * points at, and a frozen scan's `presentKeys.delete(k)` turned a present object
 * into an alleged out-of-band deletion.
 *
 * A frozen facade over a closure-private Set: readable, iterable, and with no
 * reachable path to `add` or `delete`.
 */
function sealedPresence(keys) {
  const inner = new Set(keys);
  return Object.freeze({
    has: (k) => inner.has(k),
    size: inner.size,
    keys: () => inner.values(),
    values: () => inner.values(),
    toArray: () => Object.freeze([...inner]),
    [Symbol.iterator]: () => inner.values(),
  });
}

/** Frozen all the way down, for the same reason. */
function deepFreezeList(items) {
  return Object.freeze(items.map((i) => (i && typeof i === "object" ? Object.freeze(i) : i)));
}

// FINDING 123. The second brand. Protocol-completeness and provider-authority
// are two facts, and one WeakSet carrying both is a brand that lies about half
// of what it asserts.
const AUTHORITATIVE_SWEEPS = new WeakSet();
/** Page-fetchers minted by the credentialed adapter, and only those. */
const CREDENTIALED_LISTERS = new WeakSet();
/** Listers whose network is the runtime's own fetch, not an injected one (128). */
const NETWORK_VERIFIED_LISTERS = new WeakSet();
/** FINDING 137. What each credentialed lister is a capability FOR. */
const LISTER_SUBJECT = new WeakMap();

export function isAuthoritativeSweep(v) {
  return typeof v === "object" && v !== null && AUTHORITATIVE_SWEEPS.has(v);
}

// FINDING 122. The ledger side's brand.
const COMPLETE_LEDGERS = new WeakSet();

// FINDING 129. The ledger side needs the SAME two-brand split as R2 (finding
// 128), for the same reason. Round 8.4's `beginLedgerInventory()` took
// `authority: "jobs"` and `snapshot: "..."` as ARGUMENTS and branded whatever
// came back. REPRODUCED with no PostgreSQL anywhere:
//
//     ledgerFromRows([handWrittenRow],
//       { bucket: "b", authority: "jobs", snapshot: "I-made-this-up" })
//     -> isCompleteLedger() === true, authority "jobs", seesAllTenants true
//
// and combined with the fake R2 sweep, `absenceEstablished: true, refused: 1`.
// **Both authoritative operands manufactured, with neither provider present.**
//
// A WeakSet proved those CLAIMS went through the protocol. It cannot prove the
// claims are true, because the claimant supplied them.
const AUTHORITATIVE_LEDGERS = new WeakSet();
export function isAuthoritativeLedger(v) {
  return typeof v === "object" && v !== null && AUTHORITATIVE_LEDGERS.has(v);
}

/**
 * FINDING 133. THE REGISTRAR IS GONE.
 *
 * Round 8.5 exported `registerLedgerConnection(conn)`, which added ANY object to
 * the trusted set — and its own tests called `registerLedgerConnection({})`. A
 * capability anyone can mint is not a capability. Worse, the registered object
 * and the object that answered the queries were different arguments, so the
 * brand and the observations were never connected at all.
 *
 * A jobs connection is now minted by ONE function, which requires a live
 * PostgreSQL client — something with a `query` method that this module did not
 * write. That function is what the Hyperdrive jobs driver will call. The driver
 * does not exist, so **no authoritative ledger is reachable today**, and that is
 * the honest state at 0 live rather than a testing convenience.
 *
 * The connection is a CLOSED capability: the returned object's `query` is bound
 * to the client it was made from and cannot be replaced, so an attacker holding
 * the connection cannot redirect its statements.
 */
const LEDGER_CONNECTIONS = new WeakSet();

export function isLedgerConnection(v) {
  return typeof v === "object" && v !== null && LEDGER_CONNECTIONS.has(v);
}

/**
 * @param client   a live PostgreSQL client with `query(sql, params)`
 * @param attest   proof this client is the JOBS credential — supplied by the
 *                 driver, which is the only thing that knows how it connected.
 *                 REQUIRED and checked, so a bare object cannot stand in.
 */
export function jobsConnection(client, { hyperdriveBinding } = {}) {
  if (client === null || typeof client !== "object" || typeof client.query !== "function") {
    throw new InventoryRefusal("CD-LED-CLIENT",
      "a jobs connection needs a live PostgreSQL client with a query method. An empty object is " +
      "what round 8.5's tests registered, and it earned the authoritative brand (finding 133)");
  }
  if (hyperdriveBinding !== "HYPERDRIVE_JOBS") {
    throw new InventoryRefusal("CD-LED-BINDING",
      `a jobs connection must come from the HYPERDRIVE_JOBS binding, not ` +
      `${JSON.stringify(hyperdriveBinding ?? null)}. R80 splits the request credential from the ` +
      "observer credential, and a ledger read through the request credential is RLS-policied " +
      "(finding 129)");
  }
  const conn = Object.freeze({
    hyperdriveBinding,
    // BOUND. The statements execute on the client this was minted from, and
    // nothing can substitute another (finding 133).
    query: (sql, params) => client.query(sql, params),
  });
  LEDGER_CONNECTIONS.add(conn);
  return conn;
}

/**
 * Which LEDGER_AUTHORITIES key a PostgreSQL login corresponds to.
 *
 * PURE, and the whole point of finding 129: this is derived from what the
 * DATABASE answered to `SELECT current_user`, never from a string the caller
 * chose. A login this does not recognise is a refusal — an unclassified reader
 * is one whose row visibility is unknown, which is finding 88's law.
 */
export const LEDGER_LOGINS = Object.freeze({
  computedriven_jobs_login: "jobs",
  computedriven_jobs: "jobs",
  computedriven_api_login: "tenant",
  computedriven_api: "tenant",
});

export function ledgerAuthorityFor(currentUser) {
  const a = LEDGER_LOGINS[currentUser];
  if (a === undefined) {
    throw new InventoryRefusal("CD-LED-LOGIN",
      `the database answered current_user = ${JSON.stringify(currentUser ?? null)}, which this ` +
      `system does not classify (${Object.keys(LEDGER_LOGINS).join(", ")}). An unclassified ` +
      "reader is one whose row visibility is unknown, and absence read through it would be " +
      "absence from an unknown policy (finding 129)");
  }
  return a;
}

export function isCompleteLedger(v) {
  return typeof v === "object" && v !== null && COMPLETE_LEDGERS.has(v);
}

/**
 * Who read the ledger, and whether that reader could see all of it.
 *
 * CLOSED, and the distinction is the finding. `computedriven_jobs` deliberately
 * carries no tenant context, so it sees every row. A tenant session's policied
 * read returns a SUBSET — which is indistinguishable from a clean bucket, and is
 * the most likely way finding 122's false-clean actually happens in production.
 */
export const LEDGER_AUTHORITIES = Object.freeze({
  jobs: Object.freeze({
    seesAllTenants: true,
    why: "computedriven_jobs carries no tenant context and no RLS predicate elides rows",
  }),
  tenant: Object.freeze({
    seesAllTenants: false,
    why: "an RLS-policied read returns only this tenant's rows, so absence from it is " +
         "absence from a POLICY, not from the ledger (finding 122)",
  }),
});

/**
 * THE PROTOCOL THAT EARNS LEDGER COMPLETENESS (finding 122).
 *
 * Deliberately the same shape as `beginSweep()`, because it is the same theorem
 * on the other operand: a keyset chain from the beginning to a declared final
 * page, over one snapshot, naming its bucket and its reader.
 *
 * @param bucket    the bucket these rows are about. Compared against the sweep's.
 * @param authority a LEDGER_AUTHORITIES key. REQUIRED — see above.
 * @param snapshot  an identifier for the single database snapshot every page was
 *                  read in (a txid, `pg_export_snapshot()`, whatever the caller
 *                  actually pinned). REQUIRED: pages from two snapshots are two
 *                  ledgers, and their union is neither.
 */
export function beginLedgerInventory({ bucket, authority, snapshot } = {}) {
  if (typeof bucket !== "string" || bucket.trim() === "") {
    throw new InventoryRefusal("CD-LED-BUCKET",
      "a ledger inventory must name the bucket it enumerates, or it cannot be compared with a " +
      "sweep of one (finding 122)");
  }
  if (!Object.hasOwn(LEDGER_AUTHORITIES, authority ?? "")) {
    throw new InventoryRefusal("CD-LED-AUTHORITY",
      `unknown ledger authority ${JSON.stringify(authority ?? null)}; expected one of ` +
      `${Object.keys(LEDGER_AUTHORITIES).join(", ")}. An unstated reader is one whose row ` +
      "visibility is unstated");
  }
  if (typeof snapshot !== "string" || snapshot.trim() === "") {
    throw new InventoryRefusal("CD-LED-SNAPSHOT",
      "a ledger inventory must name the database snapshot its pages were read in; pages from " +
      "two snapshots are two ledgers and their union is neither");
  }

  const rows = [];
  let pages = 0;
  let expectAfter = null;    // the keyset cursor the NEXT page must resume from
  let sealed = false;

  return {
    /**
     * @param page   ledger rows { objectKey, sizeBytes, etag, ambiguous },
     *               ASCENDING by objectKey — the chain is meaningless unsorted.
     * @param after  the cursor this page resumed from; null for the first.
     * @param final  true iff the query reported no further rows.
     */
    addPage(page, { after = undefined, final = false } = {}) {
      if (sealed) throw new InventoryRefusal("CD-LED-CLOSED",
        "this ledger inventory already took its final page; a page after it means two reads " +
        "were spliced together");
      if (after === undefined) throw new InventoryRefusal("CD-LED-NO-CURSOR",
        "addPage needs the keyset cursor this page resumed from (null for the first). Without " +
        "it the chain is unverifiable, and an unverified chain cannot support completeness");
      if (!Array.isArray(page)) throw new InventoryRefusal("CD-LED-ROWS",
        "a ledger page is an array of rows; a missing page is not an empty one");
      if ((expectAfter ?? null) !== (after ?? null)) {
        throw new InventoryRefusal("CD-LED-CHAIN",
          pages === 0
            ? "the first ledger page resumed FROM a cursor, so the read did not start at the " +
              "beginning and every row before it is unseen"
            : `ledger page ${pages + 1} resumed from ${JSON.stringify(after)} but page ${pages} ` +
              `ended at ${JSON.stringify(expectAfter)} — the range between them was never read`);
      }
      let prev = null;
      for (const r of page) {
        if (typeof r?.objectKey !== "string" || r.objectKey === "") {
          throw new InventoryRefusal("CD-LED-ROW", "a ledger row must name its object key");
        }
        if (prev !== null && r.objectKey <= prev) {
          throw new InventoryRefusal("CD-LED-ORDER",
            `ledger rows must ascend by objectKey for the keyset chain to mean anything; ` +
            `${JSON.stringify(r.objectKey)} follows ${JSON.stringify(prev)}`);
        }
        prev = r.objectKey;
        rows.push(Object.freeze({ ...r }));
      }
      pages++;
      if (final) { sealed = true; }
      else if (prev === null) {
        throw new InventoryRefusal("CD-LED-EMPTY-NONFINAL",
          "a non-final ledger page returned no rows, so there is no cursor to resume from and " +
          "the read cannot be continued or completed");
      } else { expectAfter = prev; }
      return this;
    },

    finish() {
      if (!sealed) {
        throw new InventoryRefusal("CD-LED-INCOMPLETE",
          `the ledger read stopped after ${pages} page(s) at cursor ` +
          `${JSON.stringify(expectAfter)} without a final page. A partial ledger cannot support ` +
          "either direction of the comparison: it fabricates repairs for rows it did not read, " +
          "and it hides the out-of-band deletes it was run to find (finding 122)");
      }
      const ledger = Object.freeze({
        bucket, authority, snapshot, pages,
        rows: deepFreezeList(rows.slice()),
        seesAllTenants: LEDGER_AUTHORITIES[authority].seesAllTenants,
      });
      COMPLETE_LEDGERS.add(ledger);
      return ledger;
    },
  };
}

/**
 * THE ONLY THING THAT MINTS LEDGER AUTHORITY (finding 129).
 *
 * The symmetric counterpart of `r2ListingAdapter()`, and it exists for the same
 * reason: round 8.4 let the CALLER state which authority performed the read,
 * which snapshot it came from, and whether a page was final. Those are the three
 * facts the proof is about, so the claimant was attesting its own claim.
 *
 * Here the adapter derives every one of them from what the DATABASE returned:
 *
 *     SELECT current_user, txid_current()   ->  authority AND snapshot
 *     rows.length < pageSize                ->  final
 *     last row's object_key                 ->  the next keyset cursor
 *
 * and the caller supplies only the connection and the bucket it wants read.
 *
 * AUTHORITY REQUIRES A REAL CONNECTION, minted by `jobsConnection()` from a live
 * PostgreSQL client on the HYPERDRIVE_JOBS binding. That driver does not exist
 * yet, so **no authoritative ledger is reachable today** — which is exactly right
 * while the bundle says 0 live, and which keeps the acceptance theorem true by
 * construction rather than by advertisement:
 *
 *     NO R2 AND NO POSTGRES  =>  absenceEstablished can never be true.
 *
 * The DERIVATIONS above are pure and tested; the connection is not testable and
 * so is not something a test may certify.
 *
 * ONE SNAPSHOT. The caller is expected to have opened a REPEATABLE READ
 * transaction; `txid_current()` is recorded so the evidence names it, and every
 * page is required to report the same one. Pages from two snapshots are two
 * ledgers and their union is neither — checked here rather than assumed, because
 * that is precisely the kind of thing a caller would otherwise assert.
 *
 * @param connection  the jobs connection, registered by the driver
 * @param query       async (sql, params) -> rows. The DB seam, below the identity
 *                    read — so an injected query cannot skip it.
 */
export async function ledgerInventoryAdapter(opts = {}) {
  const { connection, bucket, pageSize = 1000 } = opts;
  // FINDING 133. THERE IS NO `query` PARAMETER ANY MORE.
  //
  // Round 8.5 took `connection` AND `query` as separate arguments, branded on the
  // first, and read every fact through the second. REPRODUCED: a registered empty
  // object plus an unrelated async function returning hand-written rows produced
  // `isAuthoritativeLedger() === true` with no PostgreSQL anywhere.
  //
  //     AN AUTHORITY TOKEN AND AN OBSERVATION ARE NOT CONNECTED MERELY BECAUSE
  //     THE SAME FUNCTION RECEIVED BOTH ARGUMENTS.
  //
  // The statements now execute ON the object being attested.
  if (!isLedgerConnection(connection)) {
    throw new InventoryRefusal("CD-LED-CONN",
      "an authoritative ledger inventory needs a jobs connection minted by the Hyperdrive driver. " +
      "That driver does not exist yet, so this path is unreachable today — which is the correct " +
      "state at 0 live, and is what makes the acceptance theorem true rather than advertised " +
      "(finding 133)");
  }
  if (typeof bucket !== "string" || bucket.trim() === "") {
    throw new InventoryRefusal("CD-LED-BUCKET",
      "a ledger inventory must name the bucket it enumerates (finding 122)");
  }
  // FINDING 133. Written against `opts` deliberately: the whole defect was that a
  // `query` argument could answer for a `connection` it had nothing to do with,
  // so the ONE line where that could come back is the line a vector anchors on.
  const q = (sql, params) => connection.query(sql, params);

  // FINDING 134. THE ADAPTER OWNS THE TRANSACTION, AND `txid_current()` IS NOT A
  // SNAPSHOT.
  //
  // Round 8.5 read `txid_current()` on every page, compared them for equality,
  // called that "one snapshot", and left a comment saying "the caller is expected
  // to have opened a REPEATABLE READ transaction" — precisely the external
  // convention this system has spent rounds deleting.
  //
  // PostgreSQL, first-party: READ COMMITTED is the DEFAULT, and under it "two
  // successive SELECT commands can see different data, even though they are
  // within a single transaction". A transaction id is stable across all of that,
  // so the equality check proved nothing it claimed. REPEATABLE READ is the level
  // at which "successive SELECT commands within a single transaction see the same
  // data".
  //
  //     A TRANSACTION ID IS NOT A SNAPSHOT. THE PROPERTY IS THE ISOLATION LEVEL,
  //     AND AN ISOLATION LEVEL YOU EXPECT IS NOT ONE YOU HAVE.
  await q("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY", []);
  try {
    // Read back what the transaction ACTUALLY is, rather than what we asked for.
    const idRows = await q(
      "SELECT current_user AS current_user, " +
      "current_setting('transaction_isolation') AS isolation, " +
      "current_setting('transaction_read_only') AS read_only, " +
      "pg_current_snapshot()::text AS snapshot", []);
    const id = Array.isArray(idRows) ? idRows[0] : idRows;

    if (!id || typeof id.snapshot !== "string" || id.snapshot === "") {
      throw new InventoryRefusal("CD-LED-NO-SNAPSHOT",
        "the DATABASE did not report pg_current_snapshot(), so this read cannot name the " +
        "snapshot its pages belong to. Distinct from a CALLER failing to name one — finding 129 " +
        "is about not conflating those, and finding 134 is about not calling a transaction id a " +
        "snapshot");
    }
    if (id.isolation !== "repeatable read") {
      throw new InventoryRefusal("CD-LED-ISOLATION",
        `the transaction reports isolation ${JSON.stringify(id.isolation ?? null)}, not ` +
        '"repeatable read". Under READ COMMITTED — PostgreSQL\'s default — each statement gets ' +
        "its own snapshot, so a paged read is a union of several and its completeness claim is " +
        "false (finding 134)");
    }
    if (id.read_only !== "on") {
      throw new InventoryRefusal("CD-LED-READ-ONLY",
        "the ledger scan's transaction is not READ ONLY. A pass that establishes what the " +
        "ledger says must not be able to change what it says");
    }
    const authority = ledgerAuthorityFor(id.current_user);

    const inv = beginLedgerInventory({ bucket, authority, snapshot: id.snapshot });
    let after = null;
    for (;;) {
      const rows = await q(
        "SELECT object_key, size_bytes, etag, ambiguous, " +
        "pg_current_snapshot()::text AS snapshot " +
        "FROM cd.storage_objects WHERE bucket = $1 AND ($2::text IS NULL OR object_key > $2) " +
        "ORDER BY object_key ASC LIMIT $3",
        [bucket, after, pageSize]);
      if (!Array.isArray(rows)) {
        throw new InventoryRefusal("CD-LED-ROWS", "the ledger query did not return rows");
      }
      for (const r of rows) {
        // Belt and braces on top of the isolation level: under REPEATABLE READ
        // this cannot drift, and asserting it costs nothing and would catch a
        // connection that silently ended its transaction underneath us.
        if (r.snapshot !== undefined && r.snapshot !== id.snapshot) {
          throw new InventoryRefusal("CD-LED-SNAPSHOT-DRIFT",
            `a page reported snapshot ${JSON.stringify(r.snapshot)} against ` +
            `${JSON.stringify(id.snapshot)} — the read left its transaction, so its pages are ` +
            "two ledgers and their union is neither");
        }
      }
      // FINALITY IS MEASURED, NOT DECLARED. A short page is the end of the keyset.
      const final = rows.length < pageSize;
      inv.addPage(rows.map((r) => ({
        objectKey: r.object_key, sizeBytes: r.size_bytes, etag: r.etag, ambiguous: r.ambiguous,
      })), { after, final });
      if (final) break;
      after = rows[rows.length - 1].object_key;
    }

    const ledger = inv.finish();
    AUTHORITATIVE_LEDGERS.add(ledger);
    return ledger;
  } finally {
    // READ ONLY, so there is nothing to roll back — but leaving a transaction
    // open on a pooled connection is how the next caller inherits this snapshot.
    await q("COMMIT", []).catch(() => {});
  }
}

/**
 * Convenience for the single-statement case, and for tests.
 *
 * CALLER-ATTESTED, and therefore protocol-complete but NEVER authoritative — the
 * exact counterpart of `sweepFromPages()`. It exists so the set-difference logic
 * stays exercisable without a database (round 4.1's law), and finding 129 is the
 * reason it can no longer certify who read the rows.
 */
export function ledgerFromRows(rows, { bucket, authority, snapshot }) {
  return beginLedgerInventory({ bucket, authority, snapshot })
    .addPage([...rows].sort((a, b) => (a.objectKey < b.objectKey ? -1 : 1)), { after: null, final: true })
    .finish();
}

/**
 * The listing surfaces this normalizer knows, and what each one is FOR.
 *
 * CLOSED, like PRODUCER_TYPES in check-queue-authority.mjs and CREATE_ACTIONS in
 * reconcile.mjs. A shape it does not positively recognise is a refusal, never a
 * guess — duck-typing three provider shapes is how you get finding 96 back with
 * the field names right and the semantics wrong.
 */
export const LISTING_SOURCES = Object.freeze({
  s3: "S3-compatible ListObjectsV2, Object Read only token, bucket-scoped. THE CHOSEN SURFACE.",
  workers: "Workers R2 binding .list(). No token — but an r2_bucket binding carries write.",
  rest: "Cloudflare REST List Objects. REFUSED: needs an account-wide Admin token.",
});

/**
 * How a caller came to believe an inventory repair's provider action (finding
 * 109), and — FINDING 118 — exactly what each basis does and does not prove.
 *
 * CLOSED. `upload_intent` is the only basis that exists today, and it proves
 * AUTHORITY, not CAUSATION: a ComputeDriven intent covering this key means we
 * authorized a capability to write it. It does not mean the bytes now in R2 were
 * written by that capability — an out-of-band write is exactly the condition this
 * pass exists to detect, and the lost notification is exactly the causal record
 * we no longer have. Round 8.2 wrote "we minted the credential that performed
 * it", which assumes the conclusion.
 */
export const PROVENANCE_BASES = Object.freeze({
  upload_intent: Object.freeze({
    proves: "authority",
    doesNotProve: "causation",
    why: "an intent records that we authorized a write of this key, not that the object " +
         "currently there is the one that write produced (finding 118)",
  }),
});

/**
 * FINDING 117. What would license typing a listing's `LastModified` as the
 * observer's `p_event_time`.
 *
 * DELIBERATELY EMPTY, and that is the finding. Cloudflare defines a
 * notification's `eventTime` as when the triggering ACTION occurred; a listing's
 * `LastModified` is a statement about the object's current state. No first-party
 * source equates them. They may be equal in practice — case N and case D can
 * measure it, and the first member of this list is earned by that measurement.
 *
 * Until then `observeArgsFor()` refuses every call, which is the point: an
 * inventory repair is a CANDIDATE, and a general auto-application path that
 * silently retypes one clock as the other is R74 happening a second time.
 */
export const EVENT_TIME_BASES = Object.freeze([]);

/**
 * FINDING 124. Which provenance bases establish that the object now in R2 was
 * CAUSED by the authority named — the second, independent condition on applying
 * an inventory repair.
 *
 * ALSO DELIBERATELY EMPTY, and separately so. Round 8.3 recorded finding 118 as
 * a `blocked` string next to an enforcement point that checked only the clock,
 * which meant the first successful case-N clock measurement would have unlocked
 * BOTH. Two independent blockers need two independent lists; satisfying one must
 * never satisfy the other.
 *
 * `upload_intent` will never be a member: authority is not causation, and no
 * measurement of timestamps can change that. A member here would be something
 * like a provider-side causal record — which is the thing whose loss created
 * this pass.
 */
export const CAUSATION_BASES = Object.freeze([]);

// Raw hex, optionally with S3's multipart `-N` part-count suffix, which
// CompleteMultipartUpload produces and which is a legitimate etag the ledger
// must be able to hold.
const ETAG_RE = /^[0-9a-f]{32}(-[1-9][0-9]{0,4})?$/;

/**
 * RFC 7232 quoting, removed. Idempotent, so it is safe on the raw spellings too
 * — and it is applied to ALL sources deliberately: the cost of stripping quotes
 * that were never there is zero, and the cost of not stripping ones that were is
 * every object in the bucket reported divergent (finding 100).
 */
function unquoteEtag(v) {
  if (typeof v !== "string") return null;
  const t = v.trim();
  // W/"..." is a weak validator. R2 does not mint them for objects, and a weak
  // etag is by definition not a byte-equality claim, so it cannot be compared.
  if (/^W\//i.test(t)) return null;
  const inner = t.length >= 2 && t.startsWith('"') && t.endsWith('"') ? t.slice(1, -1) : t;
  return inner.toLowerCase();
}

/** A provider instant, as an ISO 8601 string, or null. Accepts Date or string. */
function isoTime(v) {
  if (v instanceof Date) return Number.isNaN(v.getTime()) ? null : v.toISOString();
  if (typeof v !== "string" || v.trim() === "") return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function intOrNull(v) {
  if (typeof v === "number" && Number.isInteger(v) && v >= 0) return v;
  // S3 XML parsers hand back Size as a string more often than not.
  if (typeof v === "string" && /^\d+$/.test(v)) return Number(v);
  return null;
}

/**
 * ONE PROVIDER RESPONSE. Not a bucket, not a scan, and it carries no notion of
 * completeness — that is finding 107 and the reason this function was renamed.
 *
 * @param response  the provider's listing response, verbatim
 * @param opts      { source }  one of LISTING_SOURCES. REQUIRED — not sniffed.
 * @returns { entries, presentKeys, unowned, malformed, truncated, nextToken, source }
 *
 * `entries` is { key, size, etag, providerStateTime } and nothing else — in
 * particular there is no field called `uploaded`, because that name belongs to
 * one surface and reading it as the general case is what finding 96 was.
 *
 * `presentKeys` is EVERY owned key the provider named, including the ones whose
 * metadata was unusable. Absence is checked against this and state against
 * `entries`, because presence and usable state are independent facts (108).
 */
export function normalizeR2ListingPage(response, { source } = {}) {
  if (!Object.hasOwn(LISTING_SOURCES, source ?? "")) {
    throw new InventoryRefusal("CD-INV-SOURCE",
      `unknown listing source ${JSON.stringify(source ?? null)}; expected one of ` +
      Object.keys(LISTING_SOURCES).join(", "));
  }
  if (source === "rest") {
    throw new InventoryRefusal("CD-INV-REST",
      "the Cloudflare REST List Objects API is not a supported reconciliation surface: " +
      "object-scoped tokens do not authenticate against it, so it would require an " +
      "account-wide Admin token to read one bucket, and Cloudflare documents it as rate " +
      "limited and less suited to object operations than the S3-compatible API. Use " +
      "source:\"s3\" with an Object Read only token scoped to this bucket");
  }
  if (response === null || typeof response !== "object") {
    throw new InventoryRefusal("CD-INV-RESPONSE",
      "the listing response was not an object; a missing listing is not an empty one");
  }

  // TRUNCATION FIRST. Both supported surfaces state it on a whole response, so
  // its absence means we were handed a fragment — and a fragment must not be
  // able to look like a terminating page.
  const truncated = source === "s3" ? response.IsTruncated : response.truncated;
  if (typeof truncated !== "boolean") {
    throw new InventoryRefusal("CD-INV-TRUNCATION",
      `the ${source} response states no truncation flag, so it cannot take its place in a ` +
      "cursor chain (finding 107)");
  }

  let raw = source === "s3" ? response.Contents : response.objects;

  // FINDING 110. `Contents` is optional and an empty bucket omits it. Accepted
  // ONLY against a positive proof of emptiness, so a genuinely unreadable
  // response is still a refusal rather than a clean bucket.
  if (raw === undefined && source === "s3" && response.KeyCount === 0 && truncated === false) {
    raw = [];
  }
  if (!Array.isArray(raw)) {
    throw new InventoryRefusal("CD-INV-ENUM",
      `the ${source} response carried no enumerable object list and did not positively state ` +
      `that the bucket is empty (keys seen: ${Object.keys(response).join(", ") || "none"})`);
  }
  // Cross-checked when present, for the same reason case P compares
  // producers_total_count against the producer array: a count disagreeing with
  // the list means the missing entries are the interesting ones.
  if (source === "s3" && typeof response.KeyCount === "number" && response.KeyCount !== raw.length) {
    throw new InventoryRefusal("CD-INV-KEYCOUNT",
      `KeyCount is ${response.KeyCount} but ${raw.length} object(s) were returned — the page is ` +
      "incomplete and the omitted entries are unexamined");
  }

  const entries = [];
  const presentKeys = [];
  const malformed = [];
  const unowned = [];
  for (const o of raw) {
    const key = source === "s3" ? o?.Key : o?.key;
    if (typeof key !== "string" || key === "") { malformed.push({ entry: o, why: "no object key" }); continue; }
    // ONE GRAMMAR (finding 98). This used to be a local regex weak enough to
    // accept a nil uuid and thirty-six dashes, in the file whose job is deciding
    // which keys are ours.
    if (!parseObjectKey(key)) { unowned.push(key); continue; }

    // PRESENCE IS RECORDED BEFORE ANYTHING ELSE CAN FAIL (finding 108). R2 named
    // this key; that fact survives whatever is wrong with the rest of the row.
    presentKeys.push(key);

    const size = intOrNull(source === "s3" ? o?.Size : o?.size);
    const etag = unquoteEtag(source === "s3" ? o?.ETag : o?.etag);
    // FINDING 117. NOT `eventTime`, and deliberately not named as though it
    // could become one. This is what the listing says about the object's state;
    // a notification's eventTime is when an action occurred.
    const providerStateTime = isoTime(source === "s3" ? o?.LastModified : o?.uploaded);

    if (size === null) { malformed.push({ key, why: "size is not a non-negative integer" }); continue; }
    if (etag === null || !ETAG_RE.test(etag)) {
      malformed.push({ key, why: `etag ${JSON.stringify(etag)} is not a hex digest, ` +
                                 "optionally with a multipart part-count suffix" });
      continue;
    }
    if (providerStateTime === null) {
      malformed.push({ key, why: "no parseable provider state timestamp" });
      continue;
    }
    entries.push(Object.freeze({ key, size, etag, providerStateTime }));
  }

  const nextToken = source === "s3"
    ? (response.NextContinuationToken ?? null)
    : (response.cursor ?? null);

  // FINDING 115. THE PROVIDER'S OWN STATEMENT ABOUT WHICH REQUEST THIS ANSWERS.
  // AWS, first-party: "If ContinuationToken was sent with the request, it is
  // included in the response." Absent on the first page by construction, and
  // absent entirely on a surface that does not echo — which is why the chain
  // check treats it as corroboration rather than a requirement, and why the
  // sweep counts how many pages actually carried one.
  const echoedToken = source === "s3" ? (response.ContinuationToken ?? null) : null;

  return Object.freeze({ entries, presentKeys, unowned, malformed, truncated, echoedToken,
                         nextToken: truncated ? nextToken : null, source });
}

/**
 * THE PROTOCOL THAT EARNS COMPLETENESS (finding 107).
 *
 * A scan is a sequence of pages plus three facts about how they were obtained,
 * none of which any single page can know:
 *
 *     startedAtBeginning   the first request carried no continuation token
 *     chainVerified        every later request carried exactly the token the
 *                          previous page returned — not a token, THE token
 *     terminatedNormally   the last page said it was not truncated
 *
 * The chain check is the one that matters and it is the one a hand-rolled loop
 * gets wrong: re-listing from the start halfway through, or resuming from a
 * saved token after a crash, yields pages that are each individually valid and a
 * union that is missing a range. Absence read from that union is a fabricated
 * deletion.
 */
export function beginSweep({ bucket, source } = {}) {
  if (typeof bucket !== "string" || bucket.trim() === "") {
    // Same law as R77 for the queue: the subject of an attestation has to be
    // named, or the plan could be applied against another bucket.
    throw new InventoryRefusal("CD-INV-BUCKET", "a scan must name the bucket it enumerates");
  }
  if (!Object.hasOwn(LISTING_SOURCES, source ?? "")) {
    throw new InventoryRefusal("CD-INV-SOURCE",
      `unknown listing source ${JSON.stringify(source ?? null)}`);
  }

  const entries = [];
  const presentKeys = new Set();
  const malformed = [];
  const unowned = [];
  let pages = 0;
  let expectToken = null;      // what the NEXT request must carry
  let done = false;
  let broken = null;
  let echoVerifiedPages = 0;   // pages where the PROVIDER confirmed the cursor (115)

  return {
    /**
     * @param page          a normalizeR2ListingPage() result
     * @param requestedWith the continuation token used to FETCH this page —
     *                      null for the first. REQUIRED, and it is the whole
     *                      point: without it the chain is unverifiable and the
     *                      scan would be a hopeful union of pages.
     */
    addPage(page, { requestedWith = undefined } = {}) {
      if (done) throw new InventoryRefusal("CD-INV-SCAN-CLOSED",
        "this scan already terminated; a page after the terminating page means two " +
        "enumerations were spliced together");
      if (requestedWith === undefined) throw new InventoryRefusal("CD-INV-NO-CURSOR",
        "addPage needs the continuation token this page was fetched with (null for the " +
        "first page). Without it the cursor chain cannot be verified, and an unverified " +
        "chain cannot support absence (finding 107)");
      if (page?.source !== source) throw new InventoryRefusal("CD-INV-SOURCE-MIX",
        `this scan enumerates via ${source} and was handed a ${page?.source ?? "null"} page`);

      const want = expectToken;
      if ((want ?? null) !== (requestedWith ?? null)) {
        broken = pages === 0
          ? "the first page was fetched WITH a continuation token, so the enumeration did not " +
            "start at the beginning of the bucket and everything before that token is unseen"
          : `page ${pages + 1} was fetched with ${JSON.stringify(requestedWith)} but the previous ` +
            `page returned ${JSON.stringify(want)} — the chain is spliced, and the range between ` +
            "them was never enumerated";
        throw new InventoryRefusal("CD-INV-CHAIN", broken);
      }

      // FINDING 115. THE PROVIDER GETS A VOTE ON WHICH REQUEST THIS ANSWERS.
      // Above, `requestedWith` is compared to what the previous page returned —
      // both of which reach here through the caller. `echoedToken` comes from
      // this response's own body, so it is the one statement in the comparison
      // the claimant did not author.
      if (page.echoedToken !== null) {
        if (page.echoedToken !== (requestedWith ?? null)) {
          throw new InventoryRefusal("CD-INV-ECHO",
            `page ${pages + 1} was said to be fetched with ${JSON.stringify(requestedWith ?? null)} ` +
            `but the provider echoed ContinuationToken ${JSON.stringify(page.echoedToken)} — the ` +
            "response answers a different request than the one claimed, and a cursor chain " +
            "attested by the caller alone is not attested (finding 115)");
        }
        echoVerifiedPages++;
      }

      for (const e of page.entries) entries.push(e);
      for (const k of page.presentKeys) presentKeys.add(k);
      for (const m of page.malformed) malformed.push(m);
      for (const u of page.unowned) unowned.push(u);
      pages++;

      if (page.truncated) {
        if (typeof page.nextToken !== "string" || page.nextToken === "") {
          throw new InventoryRefusal("CD-INV-NO-NEXT",
            "the page says it is truncated and returned no continuation token, so the " +
            "enumeration cannot be continued and cannot be completed");
        }
        expectToken = page.nextToken;
      } else {
        done = true;
      }
      return this;
    },

    /**
     * @returns a CompletedSweep, the ONLY value reconciliationPlan() accepts.
     *          REFUSES rather than degrading: a sweep that stopped early is not a
     *          sweep with a caveat, it is a set of pages.
     *
     * FINDING 116. What this value asserts, exactly: every provider page was
     * traversed through a verified cursor chain from the beginning to normal
     * termination. It does NOT assert a point-in-time image of the bucket —
     * Cloudflare documents that guarantee for ONE list operation, and this is a
     * sequence of them.
     *
     * FINDING 113. There is no `__completeScan`. Membership in COMPLETED_SWEEPS
     * is the proof, it is granted here and nowhere else, and it cannot be
     * copied onto a hand-built object.
     */
    finish() {
      if (!done) {
        throw new InventoryRefusal("CD-INV-INCOMPLETE",
          `the enumeration stopped after ${pages} page(s) with continuation token ` +
          `${JSON.stringify(expectToken)} still outstanding. A partial sweep cannot establish ` +
          "absence, and absence is the only thing this pass needs a whole bucket for " +
          "(finding 107)");
      }
      const sweep = Object.freeze({
        bucket, source, pages,
        entries: deepFreezeList(entries.slice()),
        presentKeys: sealedPresence(presentKeys),
        malformed: deepFreezeList(malformed.slice()),
        unowned: Object.freeze(unowned.slice()),
        startedAtBeginning: true,
        chainVerified: true,
        terminatedNormally: true,
        // What the PROVIDER corroborated, as a count rather than a boolean, so
        // "the chain was checked" cannot quietly mean "on one of nine pages".
        echoVerifiedPages,
        // FINDING 116, stated on the artifact itself so a reader of the plan
        // cannot mistake it for a snapshot.
        asserts: "every provider page traversed through a verified cursor chain, " +
                 "beginning to normal termination",
        doesNotAssert: "a point-in-time image of the bucket; Cloudflare documents " +
                       "point-in-time consistency for one list operation, not for a " +
                       "multi-page sweep under concurrent writes (finding 116)",
      });
      COMPLETED_SWEEPS.add(sweep);
      return sweep;
    },

    /** For a caller driving the loop: has the provider said there is no more? */
    get done() { return done; },
    /** The token the next request must carry. */
    get nextToken() { return expectToken; },
  };
}

/**
 * THE SWEEP DRIVES ITS OWN PAGINATION (finding 115).
 *
 * The defect this closes is not that callers were malicious — it is that
 * `addPage(page, { requestedWith })` asked the caller to state which token it
 * used, which makes the cursor chain a claim by the party whose work is being
 * checked. Here `listPage` receives the token the PREVIOUS PAGE returned, and
 * nothing else is threaded through a caller at all:
 *
 *     request page  ->  read nextToken  ->  make the next request with it
 *
 * so `requestedWith` is a fact about what this function did rather than a report
 * about what someone else did. The only thing a caller supplies is the I/O.
 *
 * @param listPage  async (continuationToken | null) -> the provider's response,
 *                  verbatim. THE ONLY I/O. It must pass the token it is given
 *                  and must not retry with a different one.
 * @param maxPages  a runaway guard. A bucket needing more pages than this is a
 *                  refusal, not a truncated answer — see finding 107.
 */
export async function sweepBucket({ bucket, source, listPage, maxPages = 100_000 } = {}) {
  if (typeof listPage !== "function") {
    throw new InventoryRefusal("CD-INV-NO-LISTER",
      "sweepBucket needs the function that fetches one page; it owns the cursor and the caller " +
      "owns the I/O, which is the whole point of finding 115");
  }
  // FINDING 137. A credentialed lister is a capability FOR a specific bucket on a
  // specific account. Round 8.5 let one be handed to a sweep of a different
  // bucket and branded the result authoritative — MEASURED, with the provider's
  // own `<Name>` saying otherwise. The subject must cross the boundary with the
  // capability, which is finding 105 for the fourth time.
  const subject = LISTER_SUBJECT.get(listPage);
  if (subject !== undefined && subject.bucket !== bucket) {
    throw new InventoryRefusal("CD-INV-LISTER-SUBJECT",
      `this lister is a capability for ${JSON.stringify(subject.bucket)} and was asked to ` +
      `enumerate ${JSON.stringify(bucket)}. An authority for one bucket cannot mint an ` +
      "authoritative statement about another (finding 137)");
  }

  const sweep = beginSweep({ bucket, source });
  let token = null;
  let n = 0;
  while (true) {
    if (++n > maxPages) {
      throw new InventoryRefusal("CD-INV-PAGE-CAP",
        `the enumeration of ${bucket} passed ${maxPages} pages without terminating. Stopping ` +
        "here yields a partial union, and absence read from a partial union is a fabricated " +
        "deletion — so this refuses instead");
    }
    const page = normalizeR2ListingPage(await listPage(token), { source });
    sweep.addPage(page, { requestedWith: token });
    if (sweep.done) break;
    token = sweep.nextToken;
  }
  const done = sweep.finish();
  // FINDING 123. The second brand, and it is granted by WHERE THE PAGES CAME
  // FROM rather than by what happened to them afterwards. An arbitrary closure
  // yields a protocol-complete sweep and nothing more.
  // FINDINGS 123 + 128. BOTH: the pages were fetched by a request this module
  // signed, AND the bytes came off the runtime's own network. Either alone is a
  // well-named closure.
  if (CREDENTIALED_LISTERS.has(listPage) && NETWORK_VERIFIED_LISTERS.has(listPage)) {
    AUTHORITATIVE_SWEEPS.add(done);
  }
  return done;
}

/**
 * MINIMAL ListObjectsV2 XML READER.
 *
 * R2's S3 API answers in XML, and `normalizeR2ListingPage()` takes the parsed
 * shape. Written here rather than pulled in, because this package has zero
 * runtime dependencies on purpose — and kept to exactly the elements
 * ListObjectsV2 defines, so an element it does not know is absent rather than
 * guessed. The field NAMES are Cloudflare's and AWS's, not ours (finding 96).
 */
export function parseListObjectsV2Xml(xml) {
  if (typeof xml !== "string" || !/<ListBucketResult/.test(xml)) {
    throw new InventoryRefusal("CD-INV-XML",
      "the response is not a ListBucketResult document, so it is not a listing this pass can " +
      "read — and an unreadable response is not an empty bucket");
  }
  const un = (t) => t.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"')
                     .replace(/&#39;/g, "'").replace(/&amp;/g, "&");
  const one = (src, tag) => {
    const m = new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`).exec(src);
    return m ? un(m[1]) : undefined;
  };
  const contents = [...xml.matchAll(/<Contents>([\s\S]*?)<\/Contents>/g)].map((m) => ({
    Key: one(m[1], "Key"),
    Size: one(m[1], "Size"),
    ETag: one(m[1], "ETag"),
    LastModified: one(m[1], "LastModified"),
  }));
  const truncated = one(xml, "IsTruncated");
  const keyCount = one(xml, "KeyCount");
  const out = {
    Name: one(xml, "Name"),
    IsTruncated: truncated === undefined ? undefined : truncated === "true",
    KeyCount: keyCount === undefined ? undefined : Number(keyCount),
    ContinuationToken: one(xml, "ContinuationToken"),
    NextContinuationToken: one(xml, "NextContinuationToken"),
  };
  // `Contents` is OMITTED for an empty bucket (finding 110) and the normalizer
  // distinguishes that from an unreadable response, so it must stay absent here
  // rather than become [].
  if (contents.length) out.Contents = contents;
  return out;
}

/**
 * THE ONLY THING THAT MINTS PROVIDER AUTHORITY (findings 123, 128).
 *
 * ROUND 8.4's VERSION DID NOT AUTHENTICATE ANYTHING. It took a `transport`
 * callback from the caller, checked that four strings were non-empty, and
 * branded the result credentialed. REPRODUCED with a fake key, a fake secret and
 * a transport returning an object literal: `isAuthoritativeSweep()` was **true**
 * with no R2 and no network anywhere. The wrapper added a name, not provenance.
 *
 *     IF THE ADAPTER DOES NOT PERFORM THE AUTHENTICATED ACT, IT CANNOT ATTEST
 *     THAT THE ACT OCCURRED.
 *
 * So this owns the authentication. It builds and SIGNS a ListObjectsV2 request
 * with SigV4 (`s3sig.mjs`, verified against AWS's own published worked example)
 * and parses the provider's XML. The seam a test may replace is `fetchImpl`,
 * which sits BELOW the signer — so an injected network cannot skip signing, and
 * a test can assert the request was properly signed before answering it.
 *
 * AND AN INJECTED NETWORK STILL DOES NOT EARN AUTHORITY. `networkVerified` is
 * true only when the transport is the runtime's own `fetch`. That keeps GPT's
 * crisp gate true by construction:
 *
 *     NO R2 AND NO POSTGRES  =>  absenceEstablished can never be true.
 *
 * The signing is pure and exhaustively tested; the network is not testable and
 * is therefore not something a test may certify. Both halves of round 4.1's law
 * are satisfied: the judgement is exercisable without an account, and the part
 * that needs an account cannot be faked into passing.
 */
/**
 * Cloudflare's R2 S3 endpoint, DERIVED. Not a parameter.
 *
 * FINDING 132. Round 8.5 took `endpoint` from the caller and decided authority
 * from `net === globalThis.fetch`. REPRODUCED with an ordinary local HTTP server
 * and the REAL global fetch — no monkey-patching, nothing injected:
 *
 *     endpoint: "http://127.0.0.1:39775"
 *     -> networkVerified: true, isAuthoritativeSweep: true
 *
 * The signature authenticates the request TO WHOEVER OWNS THE ENDPOINT. It says
 * nothing about who that is. So the round shipped an acceptance theorem — *no R2
 * and no PostgreSQL means absence can never be established* — that was FALSE in
 * the tree that published it, and my own verification missed it because I tested
 * the injected-transport attack and asserted the general case from it.
 *
 *     A REAL NETWORK IS NOT A PROVIDER. PROVIDER AUTHORITY REQUIRES
 *     AUTHENTICATED I/O TO THE PROVIDER'S RULED IDENTITY.
 *
 * Cloudflare documents the S3 endpoint as the account-specific host below, and
 * that host — reached over TLS, so the certificate is what names the
 * counterparty — is the identity. It is derived from the account id and cannot
 * be supplied.
 */
export const R2_S3_HOST_SUFFIX = ".r2.cloudflarestorage.com";
const ACCOUNT_ID_RE = /^[0-9a-f]{32}$/;

export function r2Endpoint(accountId) {
  if (typeof accountId !== "string" || !ACCOUNT_ID_RE.test(accountId)) {
    throw new InventoryRefusal("CD-INV-ACCOUNT",
      `${JSON.stringify(accountId ?? null)} is not a Cloudflare account id (32 lowercase hex ` +
      "digits). The R2 endpoint is DERIVED from it and never supplied, because an endpoint a " +
      "caller chooses is an endpoint a caller controls (finding 132)");
  }
  return `https://${accountId}${R2_S3_HOST_SUFFIX}`;
}

/**
 * THE ONLY THING THAT MINTS PROVIDER AUTHORITY (findings 123, 128, 132, 137).
 *
 * It signs (SigV4, `s3sig.mjs`, verified against AWS's published vector), it
 * talks to Cloudflare's derived R2 host over TLS, and IT OWNS ITS BUCKET.
 *
 * FINDING 137 is why `sweep()` is the interface rather than a `listPage` the
 * caller passes to `sweepBucket()`. REPRODUCED: an adapter built for bucket A,
 * handed to `sweepBucket({ bucket: "bucket-B" })`, produced an AUTHORITATIVE
 * sweep whose subject was B while the provider's own `<Name>` said A. That is
 * finding 105 again — the subject must cross the boundary with the capability,
 * not be recombinable with it.
 */
export function r2ListingAdapter({ accountId, bucket, accessKeyId, secretAccessKey,
                                   region = "auto", fetchImpl, now } = {}) {
  for (const [name, v] of Object.entries({ bucket, accessKeyId, secretAccessKey })) {
    if (typeof v !== "string" || v.trim() === "") {
      throw new InventoryRefusal("CD-INV-ADAPTER",
        `an R2 listing adapter needs ${name}; a credential missing one of its parts is not a ` +
        "credential (findings 123, 128)");
    }
  }
  const endpoint = r2Endpoint(accountId);          // DERIVED (finding 132)
  const base = new URL(endpoint);

  const net = fetchImpl ?? globalThis.fetch;
  if (typeof net !== "function") {
    throw new InventoryRefusal("CD-INV-ADAPTER",
      "no fetch is available and none was supplied, so this adapter cannot make a request");
  }
  // FINDING 132. TWO facts, not one. The transport must be the runtime's own —
  // an injected one proves nothing — AND the host must be Cloudflare's derived
  // R2 identity, reached over TLS. Round 8.5 checked only the first.
  const networkVerified = net === globalThis.fetch;
  const endpointVerified = base.protocol === "https:"
                        && base.host === `${accountId}${R2_S3_HOST_SUFFIX}`;
  const signedRequests = [];

  const listPage = async (continuationToken) => {
    const query = [["list-type", "2"]];
    if (continuationToken !== null) query.push(["continuation-token", continuationToken]);

    const path = `/${bucket}`;
    const signed = await signS3Get({
      accessKeyId, secretAccessKey, region, host: base.host, path, query,
      when: now ? new Date(now) : new Date(),
    });
    signedRequests.push(signed);

    const url = `${base.origin}${path}?` +
                query.map(([k, v]) => `${uriEncode(k)}=${uriEncode(v)}`).sort().join("&");
    const res = await net(url, { method: "GET", headers: signed.headers });
    if (!res || typeof res.text !== "function") {
      throw new InventoryRefusal("CD-INV-TRANSPORT",
        "the transport did not return a Response; a listing this pass cannot read is not an " +
        "empty bucket (finding 110's law, one layer down)");
    }
    if (res.ok === false) {
      throw new InventoryRefusal("CD-INV-HTTP",
        `the provider refused the listing with HTTP ${res.status}. Cannot see is not "nothing ` +
        'was wrong" — this refuses rather than reporting an empty bucket');
    }
    const page = parseListObjectsV2Xml(await res.text());
    // FINDING 137, second half: the PROVIDER also names the bucket. When it does,
    // it must be ours — a response about another bucket is not a response about
    // this one however correctly it was signed.
    if (page.Name !== undefined && page.Name !== bucket) {
      throw new InventoryRefusal("CD-INV-BUCKET-NAME",
        `the listing is for bucket ${JSON.stringify(page.Name)} and this adapter enumerates ` +
        `${JSON.stringify(bucket)} — a correctly signed answer about the wrong subject`);
    }
    return page;
  };

  CREDENTIALED_LISTERS.add(listPage);
  if (networkVerified && endpointVerified) NETWORK_VERIFIED_LISTERS.add(listPage);
  // FINDING 137. The subject travels WITH the capability, so `sweepBucket()` can
  // refuse a request to enumerate anything else with it.
  LISTER_SUBJECT.set(listPage, Object.freeze({ accountId, bucket, endpoint }));

  // FINDING 137. NOTE WHAT IS ABSENT: `listPage`. Round 8.5 returned it, and an
  // adapter for bucket A could then be handed to `sweepBucket({bucket: "B"})`.
  // The capability and its subject are one object; there is nothing to recombine.
  return Object.freeze({
    accountId, bucket, endpoint, networkVerified, endpointVerified,
    /** What was actually signed, so a test can check the request, not the answer. */
    signedRequests,
    /**
     * THE INTERFACE. The adapter enumerates ITS bucket; there is no argument
     * through which another one could be named (finding 137).
     */
    sweep: (opts = {}) => sweepBucket({ ...opts, bucket, source: "s3", listPage }),
  });
}

/**
 * Convenience for the common whole-bucket case, and for tests.
 * Pages are (response, tokenUsedToFetchIt) in order.
 *
 * NOTE this is the caller-attested form, kept because tests need to construct
 * chains that are deliberately broken. It is protocol-complete and NEVER
 * authoritative (finding 123). Production paths use `sweepBucket()` with an
 * adapter from `r2ListingAdapter()`.
 */
export function sweepFromPages(pages, { bucket, source }) {
  const sweep = beginSweep({ bucket, source });
  for (const [response, requestedWith = null] of pages) {
    sweep.addPage(normalizeR2ListingPage(response, { source }), { requestedWith });
  }
  return sweep.finish();
}

/**
 * TWO PROOFS, OR NOTHING (finding 122).
 *
 * @param sweep   a CompletedSweep from beginSweep(...).finish(). NOT a page.
 * @param ledger  a CompleteLedgerInventory from beginLedgerInventory(...).finish().
 *                **NOT an array** — that was the defect: a set-difference theorem
 *                requires completeness of both operands, and only one side had it.
 * @returns { repairs, ambiguityCandidates, unreadable, refusals, absenceUnknown,
 *            unowned, summary }
 */
export function reconciliationPlan(sweep, ledger) {
  // FINDING 113. This used to read `sweep.__completeScan !== true`, which a hand-
  // written object literal satisfies. Membership is granted by finish() and by
  // nothing else, so a structural clone of a completed sweep is refused for the
  // same reason jwt.mjs refuses a structural clone of verified claims.
  assertCompletedSweep(sweep);

  // FINDING 122. The symmetric half, and the one two rounds missed.
  if (!isCompleteLedger(ledger)) {
    throw new InventoryRefusal("CD-INV-LEDGER",
      "reconciliationPlan takes a COMPLETE LEDGER INVENTORY, not an array of rows. A partial " +
      "ledger fabricates repairs for objects it did not read AND hides the out-of-band deletes " +
      "this pass exists to find — MEASURED both directions. Build one with " +
      "beginLedgerInventory()/addPage()/finish() (finding 122)");
  }
  if (ledger.bucket !== sweep.bucket) {
    throw new InventoryRefusal("CD-INV-LEDGER-BUCKET",
      `the sweep enumerated ${JSON.stringify(sweep.bucket)} and the ledger inventory is about ` +
      `${JSON.stringify(ledger.bucket)}. Differencing two buckets reports every object in each ` +
      "as missing from the other");
  }

  const bucket = sweep.bucket;
  const known = ledger.rows;

  // FINDING 123. Absence needs provider authority, not just protocol completeness.
  const authoritative = isAuthoritativeSweep(sweep);
  // FINDING 136. The ledger's own authority, needed by any conclusion that
  // rests on the ledger NOT saying something.
  const ledgerIsAuthoritative = isAuthoritativeLedger(ledger);
  // FINDING 122. And it needs a reader that could see every row.
  const ledgerSeesAll = ledger.seesAllTenants;

  const byKey = new Map();
  for (const k of known) byKey.set(k.objectKey, k);

  const repairs = [];
  const ambiguityCandidates = [];
  const unreadable = [];
  const refusals = [];
  const absenceUnknown = [];

  for (const o of sweep.entries) {
    const have = byKey.get(o.key);

    if (!have) {
      repairs.push({ kind: "missing", key: o.key, bucket, etag: o.etag, size: o.size,
                     providerStateTime: o.providerStateTime,
                     // FINDING 130. Presence is a PROVIDER FACT too. "R2 named
                     // this key" is only true if R2 named it.
                     providerAuthoritative: authoritative,
                     // FINDING 136. A `missing` repair is R2 PRESENT **and
                     // LEDGER ABSENT** — it rests on negative evidence from the
                     // ledger, and round 8.5 gated only the provider half.
                     ledgerAuthoritative: ledgerIsAuthoritative,
                     ledgerSeesAllTenants: ledgerSeesAll,
                     // FINDING 109: what the listing establishes, and no more. The
                     // etag's multipart suffix is recorded as an OBSERVATION, not
                     // promoted to a derived action — a copy can carry one too,
                     // and inventing the narrower claim is the defect.
                     etagIsMultipartShaped: o.etag.includes("-"),
                     providerAction: null,
                     why: "R2 holds this object and the ledger has never seen it — the " +
                          "notification was lost or never delivered" });
      continue;
    }
    if (have.ambiguous) {
      // FINDING 97. This used to be a `repair`, and R79 claimed "a tied tip the
      // database could not settle is settled by the listing". IT IS NOT.
      // app.project_object_state() calls a tip ambiguous when
      //
      //     count(DISTINCT (etag, size_bytes)) > 1  over  event_time = max(event_time)
      //
      // and a repair enters as an ordinary observation at the provider's own
      // instant — which, in a tie, IS that instant. So:
      //
      //     tip   A/10 @T   B/20 @T      -> ambiguous
      //     + inventory     B/20 @T      -> ambiguous, still
      //
      // The distinct-pair count is unchanged, size_bytes = max() is unchanged,
      // and only event_count moves. `T + 1ms` is refused too: manufacturing
      // provider chronology is exactly what R75 declined to do. What is actually
      // true is epistemic and the schema cannot say it — a direct read of R2's
      // state is stronger evidence than an unordered notification set, and today
      // both enter as the same row type at the same rank. Case J decides whether
      // that is ever worth a migration.
      ambiguityCandidates.push({
        kind: "ambiguous", key: o.key, bucket, etag: o.etag, size: o.size,
        providerStateTime: o.providerStateTime, applied: false, providerAction: null,
        providerAuthoritative: authoritative,
        ledgerAuthoritative: ledgerIsAuthoritative, ledgerSeesAllTenants: ledgerSeesAll,
        why: "the ledger holds a tied tip it could not resolve (R75) and the listing says " +
             "which body is actually there. THIS IS A RESOLUTION CANDIDATE, NOT A " +
             "RESOLUTION: applied as an ordinary observation at the same provider instant " +
             "it would leave the tie intact, because the tip would still hold two distinct " +
             "(etag, size) pairs. Settling it needs provenance rank, which the observation " +
             "type does not have (finding 97)",
      });
      continue;
    }
    if (have.etag !== o.etag || have.sizeBytes !== o.size) {
      repairs.push({ kind: "divergent", key: o.key, bucket, etag: o.etag, size: o.size,
                     providerStateTime: o.providerStateTime,
                     providerAuthoritative: authoritative,
                     // A divergence is a claim about BOTH states; a synthetic
                     // ledger row can manufacture one just as easily as a
                     // synthetic listing can (finding 136).
                     ledgerAuthoritative: ledgerIsAuthoritative,
                     ledgerSeesAllTenants: ledgerSeesAll,
                     etagIsMultipartShaped: o.etag.includes("-"),
                     providerAction: null,
                     from: { etag: have.etag, size: have.sizeBytes },
                     why: "the ledger and the provider disagree about this key; R68 says the " +
                          "provider's number wins" });
    }
  }

  // FINDING 108. A key the provider NAMED but whose metadata we cannot use is
  // present-with-unknown-state. It is neither a repair (there is nothing to
  // write) nor an absence (R2 just told us it exists).
  const usable = new Set(sweep.entries.map((e) => e.key));
  for (const key of sweep.presentKeys) {
    if (usable.has(key)) continue;
    unreadable.push({
      key, bucket,
      why: "R2 named this key and returned metadata this pass cannot use. Its PRESENCE is " +
           "established and its STATE is not — so it is neither repaired nor reported absent " +
           "(finding 108)",
    });
  }

  // ABSENCE. Reachable only from here, because only a CompletedSweep gets this
  // far, and `presentKeys` is the presence set rather than the usable-state set.
  //
  // FINDINGS 122 + 123. And it now needs BOTH operands authoritative rather than
  // merely well-formed: pages that actually came from R2 through the credentialed
  // adapter, and a ledger read by a role that could see every tenant's rows.
  // Anything less yields `absenceUnknown` — not a softer refusal, but the honest
  // statement that the difference was not computable. There is deliberately NO
  // option to override this: a flag letting the caller weaken the evidence is the
  // caller attesting to its own work again, which is findings 105/115/123.
  const absenceBlocked = [];
  if (!authoritative) {
    absenceBlocked.push(
      "the sweep is protocol-complete but not provider-authoritative: its pages came from a " +
      "caller-supplied lister rather than the credentialed bucket-scoped adapter, so nothing " +
      "establishes they came from R2 at all (finding 123)");
  }
  if (!ledgerSeesAll) {
    absenceBlocked.push(
      `the ledger inventory was read under the ${JSON.stringify(ledger.authority)} authority — ` +
      `${LEDGER_AUTHORITIES[ledger.authority].why}`);
  }
  // FINDING 129. And the ledger must have come from a real jobs connection, not
  // from rows plus the strings "jobs" and a made-up snapshot.
  if (!isAuthoritativeLedger(ledger)) {
    absenceBlocked.push(
      "the ledger inventory is protocol-complete but not provider-authoritative: its authority " +
      "and snapshot were supplied by the caller rather than derived from a database that " +
      "answered current_user and txid_current() on a registered jobs connection (finding 129)");
  }
  const absenceEstablished = absenceBlocked.length === 0;

  // ONE SELECTION, TWO LABELS. The keys that are in the ledger and not in the
  // sweep are computed by a single path whatever the evidence supports, so a
  // mutation to the SELECTION is always observable — only the label forks.
  //
  // This shape is deliberate. Rounds 8.3 and 8.4 each shipped a correct new
  // refusal that made an older, still-correct decision unreachable, and both
  // times only the mutation battery noticed. Absence-as-refusal now genuinely
  // requires live provider I/O and is therefore not reachable offline at all;
  // putting the selection above the fork is what keeps that from taking the
  // set-difference logic down with it.
  const absentKeys = known.filter((k) => !sweep.presentKeys.has(k.objectKey));

  for (const k of absentKeys) {
    if (!absenceEstablished) {
      absenceUnknown.push({ key: k.objectKey, bucket,
                            blocked: Object.freeze([...absenceBlocked]) });
      continue;
    }
    refusals.push({
      key: k.objectKey, bucket,
      why: `the ledger holds this object and a complete enumeration of ${bucket} ` +
           `(${sweep.pages} page(s), cursor chain verified, provider-authoritative) did not ` +
           `return it, against a ledger of ${known.length} row(s) read under the ` +
           `${ledger.authority} authority in snapshot ${ledger.snapshot}. M2.0 is append-only ` +
           "(R56), so this cannot happen legitimately — an out-of-band delete, the wrong " +
           "bucket, or a lifecycle rule nobody declared. Crediting the bytes back on any of " +
           "those is worse than the divergence, so a human rules",
    });
  }

  return {
    repairs, ambiguityCandidates, unreadable, refusals, absenceUnknown,
    unowned: sweep.unowned,
    malformed: sweep.malformed,
    summary: {
      bucket,
      source: sweep.source,
      pages: sweep.pages,
      sweepComplete: true,
      // FINDING 123. Stated, so a reader of the summary cannot mistake a
      // protocol-complete sweep for an authoritative one.
      sweepAuthoritative: authoritative,
      ledgerAuthority: ledger.authority,
      ledgerSnapshot: ledger.snapshot,
      ledgerPages: ledger.pages,
      absenceEstablished,
      listed: sweep.entries.length,
      present: sweep.presentKeys.size,
      known: known.length,
      missing: repairs.filter((r) => r.kind === "missing").length,
      divergent: repairs.filter((r) => r.kind === "divergent").length,
      ambiguous: ambiguityCandidates.length,
      unreadable: unreadable.length,
      refused: refusals.length,
      absenceUnknown: absenceUnknown.length,
      unowned: sweep.unowned.length,
      malformed: sweep.malformed.length,
    },
  };
}

/**
 * A VALIDATED REPAIR CANDIDATE — everything an application would need, and the
 * standing reasons it is not applied.
 *
 * THIS FUNCTION EXISTS BECAUSE OF WHAT FINDING 117's FIX DID TO THE BATTERY.
 * Making `observeArgsFor()` refuse unconditionally made its argument vector
 * unreachable, and the mutation battery said so immediately: the
 * `inventory-fabricates-action` vector — which replaces `provenance.action` with
 * a hard-coded `"PutObject"`, the exact defect of finding 109 — went from CAUGHT
 * to **MISSED**, because no test could reach the line any more.
 *
 *     A PROTECTION BEHIND AN UNCONDITIONAL REFUSAL IS NOT A PROTECTION. IT IS
 *     DEAD CODE THAT USED TO BE ONE.
 *
 * That is this codebase's own law — *a gate that can only be exercised in
 * production is a gate nobody exercises* (round 4.1) — arriving from the
 * opposite direction: a gate nobody can exercise BECAUSE an earlier gate always
 * fires. So the candidate is a first-class value. It is what "candidate-only"
 * (findings 117, 118) actually means, it is reachable, and every finding-109 and
 * R77 property is asserted on it.
 *
 * FINDING 124 — AND `blocked` IS NOW THE GATE, NOT A CAPTION NEXT TO ONE.
 * Round 8.3 recorded two blockers here and `observeArgsFor()` enforced one; with
 * `EVENT_TIME_BASES` non-empty (the future case N earns) an authority-only basis
 * APPLIED. `applicationBlockers()` below is the single computation, `blocked` is
 * its output, and application refuses while it is non-empty — so a reason cannot
 * be recorded without also being enforced.
 *
 * @param repair      a `missing` or `divergent` repair
 * @param provenance  { action, basis, intentId, eventTimeBasis } — REQUIRED
 * @returns a frozen candidate, with `blocked` naming what stops application
 */
export function repairCandidate(repair, provenance) {
  const { action, basis, intentId } = validateProvenance(repair, provenance);
  return Object.freeze({
    bucket: repair.bucket,
    key: repair.key,
    etag: repair.etag,
    size: repair.size,
    // FINDING 109. The caller's derived action, never a default. The mutation
    // vector that replaces this with "PutObject" anchors HERE, on a line a test
    // can reach.
    action,
    basis,
    intentId,
    // FINDING 117. Named for what it is. It is NOT `eventTime`.
    providerStateTime: repair.providerStateTime,
    // R77. A reconciliation did not arrive on the authority channel, so it has
    // no delivery identity to claim, and 0022's fallback uniqueness key exists
    // for exactly this caller. Synthesizing one would make a repair
    // indistinguishable from a notification in the provenance log.
    messageId: null,
    queue: null,
    blocked: applicationBlockers(provenance, repair),
  });
}

/**
 * EVERY REASON THIS MAY NOT BE APPLIED, COMPUTED ONCE (finding 124).
 *
 * The single source for both the candidate's `blocked` field and
 * `observeArgsFor()`'s refusal, so the printed reasons and the enforced ones
 * cannot diverge — which is exactly what they did in round 8.3.
 *
 *     A BLOCKED REASON THAT IS ONLY PRINTED IS NOT A GATE.
 *
 * Adding a member here adds enforcement. There is no way to record a blocker
 * without it counting, and no way to satisfy one blocker and have another lapse.
 */
function applicationBlockers(provenance, repair) {
  const out = [];

  // FINDING 130. Round 8.4 let a merely protocol-complete sweep produce
  // `missing` and `divergent` repairs, reasoning that positive evidence is true
  // the moment R2 names the key. It is — but only if R2 named it. REPRODUCED: a
  // synthetic page claiming a 10 TB object produced a repair candidate for a key
  // R2 never mentioned. Authority has TWO dimensions and round 8.4 modelled one:
  //
  //     presence  requires provider authority
  //     absence   requires provider authority AND completeness
  //
  // The diff still computes without authority, because that keeps the algorithm
  // testable with no account — but nothing derived from it can be APPLIED.
  if (repair !== undefined && repair?.providerAuthoritative !== true) {
    out.push(
      "this repair came from a sweep that is not provider-authoritative, so the claim that R2 " +
      "holds this object is not evidence about R2 at all — a provider fact needs provider " +
      "provenance whether it is presence or absence (finding 130)");
  }

  // FINDING 136. THE OTHER SIDE OF THE SAME LAW, AND ROUND 8.5 ONLY GATED ONE.
  //
  //     "extra" / delete alarm   ledger PRESENT + R2 ABSENT
  //     "missing" / repair       R2 PRESENT + ledger ABSENT
  //
  // Both rest on a negative, and a negative needs authority and completeness on
  // the side whose absence is asserted. A `missing` repair depends on the LEDGER
  // not holding the key, so a fabricated or RLS-shortened ledger manufactures
  // one — and round 8.5 was saved only by the other two blockers happening to
  // fire first, which is exactly what finding 124 said not to accept.
  if (repair !== undefined && repair?.kind !== undefined) {
    if (repair.ledgerAuthoritative !== true) {
      out.push(
        `a ${repair.kind} repair rests on what the LEDGER does not say, and this ledger ` +
        "inventory is not provider-authoritative — its authority and snapshot did not come from " +
        "a jobs connection the driver opened. A negative fact needs authority on the side whose " +
        "absence is asserted (finding 136)");
    }
    if (repair.ledgerSeesAllTenants !== true) {
      out.push(
        "the ledger inventory was read by a role that cannot see every tenant's rows, so its " +
        "silence about this key is absence from a POLICY rather than from the ledger " +
        "(findings 122, 136)");
    }
  }
  const basis = provenance?.basis;
  const strength = PROVENANCE_BASES[basis];

  // FINDING 118, now enforced rather than described. An event-time measurement
  // says nothing about causation, so earning one must NOT unlock this.
  if (!CAUSATION_BASES.includes(basis)) {
    out.push(
      `the ${JSON.stringify(basis)} basis proves ${strength?.proves ?? "nothing stated"} and not ` +
      `${strength?.doesNotProve ?? "causation"} (finding 118). Applying this row would assert ` +
      "that the object now in R2 was produced by that authority, which no evidence here " +
      "establishes — and the notification carrying the causal history is precisely what was lost");
  }

  // FINDING 117. A listing's LastModified is not the queue's eventTime.
  if (!EVENT_TIME_BASES.includes(provenance?.eventTimeBasis)) {
    out.push(
      "providerStateTime is a listing's LastModified; app.observe_storage_object() takes " +
      "p_event_time, which Cloudflare defines as when the triggering action occurred. No " +
      "first-party source equates them, and EVENT_TIME_BASES is empty on purpose — no " +
      "measurement has earned a member yet (finding 117)");
  }

  return Object.freeze(out);
}

/** Shared by repairCandidate() and observeArgsFor() so the rules cannot diverge. */
function validateProvenance(repair, provenance) {
  if (repair?.applied === false || repair?.kind === "ambiguous") {
    throw new InventoryRefusal("CD-INV-AMBIGUOUS",
      `${JSON.stringify(repair?.key ?? null)} is an ambiguity CANDIDATE, not a repair: applying ` +
      "it as an ordinary observation at the same provider instant leaves the tie intact and " +
      "adds a row claiming otherwise (finding 97)");
  }
  if (provenance === undefined || provenance === null) {
    throw new InventoryRefusal("CD-INV-NO-PROVENANCE",
      `${JSON.stringify(repair?.key ?? null)}: an inventory repair carries no provider action. ` +
      "A listing says what the object IS, not which of PutObject / CopyObject / " +
      "CompleteMultipartUpload produced it, and all three change occupancy. Supply provenance " +
      "derived from an upload intent, or surface this as a candidate for a human — do not " +
      "default to PutObject, which is what this function did until finding 109");
  }
  if (!Object.hasOwn(PROVENANCE_BASES, provenance.basis ?? "")) {
    throw new InventoryRefusal("CD-INV-BASIS",
      `provenance basis ${JSON.stringify(provenance.basis ?? null)} is not one this system ` +
      `recognises (${Object.keys(PROVENANCE_BASES).join(", ")}) — an unrecognised basis is not ` +
      "an established one");
  }
  if (!CREATE_ACTIONS.includes(provenance.action)) {
    throw new InventoryRefusal("CD-INV-ACTION",
      `provenance action ${JSON.stringify(provenance.action ?? null)} is not an R2 object-create ` +
      `action (${CREATE_ACTIONS.join(", ")})`);
  }
  if (typeof provenance.intentId !== "string" || provenance.intentId === "") {
    throw new InventoryRefusal("CD-INV-INTENT",
      "an upload_intent provenance must name the intent it was derived from, or the basis is " +
      "a word rather than a reference (R76)");
  }
  return provenance;
}

/**
 * The arguments a repair hands app.observe_storage_object().
 *
 * NO MESSAGE ID AND NO QUEUE. A reconciliation did not arrive on the authority
 * channel, so under R77 it has no delivery identity to claim; it takes the
 * fallback uniqueness key 0022 built for exactly this caller. A synthesized id
 * would make a repair indistinguishable from a notification in the provenance
 * log, which is the one place the difference matters.
 *
 * AND NO INVENTED ACTION (finding 109). The action is not ours to guess: a
 * listing reports current state, not the API call that produced it, and all
 * three of PutObject / CopyObject / CompleteMultipartUpload change occupancy.
 * The caller must pass provenance saying where the action came from, and the
 * only basis that exists is an upload intent we ourselves minted the credential
 * for — which is a database read, hence the caller's.
 *
 * AND IT REFUSES WHILE ANY BLOCKER STANDS (finding 124). This used to test
 * `EVENT_TIME_BASES` and nothing else, so finding 118's causation blocker was a
 * string in a `blocked` array that no code read. MEASURED against a copy with one
 * line changed to model a successful case N — `EVENT_TIME_BASES =
 * ["measured_equal"]` — an `upload_intent` provenance returned a valid observer
 * argument vector, silently unlocking a blocker nothing had resolved. The gate is
 * now `candidate.blocked`, which is the same computation the candidate prints.
 *
 * @param repair      a `missing` or `divergent` repair
 * @param provenance  { action, basis, intentId, eventTimeBasis } — ALL REQUIRED
 */
export function observeArgsFor(repair, provenance) {
  // Every finding-109 / R76 / R77 rule lives in the candidate, which is
  // reachable and tested. This function adds exactly one thing: whether the
  // candidate may be APPLIED.
  const candidate = repairCandidate(repair, provenance);

  // FINDING 124. ONE COMPUTATION, PRINTED AND ENFORCED. Not `if (clock)` beside
  // a `blocked` array listing two reasons.
  if (candidate.blocked.length) {
    throw new InventoryRefusal("CD-INV-BLOCKED",
      `${JSON.stringify(repair?.key ?? null)} is a repair CANDIDATE and cannot be applied. ` +
      `${candidate.blocked.length} blocker(s) stand:\n` +
      candidate.blocked.map((b, i) => `  ${i + 1}. ${b}`).join("\n") +
      "\nEach is independent: satisfying one does not satisfy another, which is finding 124. " +
      "Surface this candidate; case N decides whether inventory_state becomes a first-class " +
      "observation source in 0028");
  }

  return [candidate.bucket, candidate.key, candidate.etag, candidate.size, candidate.action,
          candidate.providerStateTime, candidate.messageId, candidate.queue];
}
