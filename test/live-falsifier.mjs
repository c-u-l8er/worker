#!/usr/bin/env node
// The LIVE falsifier. Runs against real Cloudflare, provisions NOTHING, and
// refuses to run until credentials are handed to it deliberately.
//
//   node worker/test/live-falsifier.mjs --plan     print the experiment, touch nothing
//   node worker/test/live-falsifier.mjs --run      execute it (needs real bindings)
//
// WHY THIS FILE EXISTS. Six rounds of local batteries have proven what PostgreSQL
// and JavaScript do. Round 7 found the first defect neither could ever have
// caught: R30's advisory lock is correct PostgreSQL, passes every local check,
// and Hyperdrive refuses it.
//
//     A LOCAL BATTERY PROVES THE DATABASE'S BEHAVIOUR, NOT THE TRANSPORT'S.
//
// Everything below is a question about the PROVIDER that no local test can
// answer, written down now so the answers arrive as measurements rather than as
// assumptions someone made under deadline. Each case states what it would falsify
// and what we would do about it, BEFORE it is run -- which is the only way a
// negative result stays informative instead of becoming a thing to explain away.
//
// IT PROVISIONS NOTHING. No account is created, no bucket is made, no queue is
// bound, nothing is purchased. It reads bindings from the environment and exits
// with a plan if they are absent. Spend needs Travis (agents/C-infrastructure.md).

const NEEDED = {
  CF_ACCOUNT_ID:        "Cloudflare account id",
  R2_BUCKET:            "an EXISTING throwaway bucket — do not point this at anything real",
  R2_ACCESS_KEY_ID:     "parent access key id, for local signing",
  R2_SECRET_ACCESS_KEY: "parent secret",
  HYPERDRIVE_URL:       "a Postgres URL reachable THROUGH Hyperdrive (not a direct one)",
};

const CASES = [
  {
    id: "A",
    question: "Does a presigned PUT of EXACTLY the offered byte count succeed?",
    method: "Offer expectedBytes=N for one object key; sign a PutObject; upload N bytes.",
    falsifies: "Nothing — this is the control. If A fails the harness is wrong, not R2.",
    ifItFails: "Stop. Every result below is meaningless until the happy path works.",
  },
  {
    id: "B",
    question: "Can a presigned PUT be made BYTE-EXACT? (R31)",
    // RE-AIMED 2026-08-22 after re-reading both Cloudflare pages. The old method
    // led with Content-Length and listed x-amz-checksum-sha256 beside it. The
    // S3-compatibility page documents NEITHER for PutObject; what it does
    // document is Content-MD5. So the old experiment's most likely outcome was
    // "undocumented header did nothing", which would have told us about our
    // header choice and not about R2.
    // WIDENED 2026-08-23. Cloudflare's own two pages disagree, which is the best
    // possible reason to run an experiment rather than read harder. The S3
    // compatibility table lists Content-MD5 for PutObject and no SHA-256
    // checksum header; the R2 release notes, dated 2023-06-16, say S3 putObject
    // gained sha256 and sha1 checksum support. One of those is stale and no
    // amount of re-reading settles which.
    //
    // The stake is not small. If B2 works we bind THE SAME SHA-256 THE CHUNK IS
    // ALREADY NAMED BY, and MD5 never enters the design.
    method:
      "Three signings against the same N-byte body, each then given a DIFFERENT body — " +
      "(i) N+1 bytes, (ii) N bytes with different content — and required to fail.\n" +
      "         B1  Content-MD5 in SignedHeaders          documented in the compatibility table\n" +
      "         B2  x-amz-checksum-sha256 in SignedHeaders  documented only in the release notes\n" +
      "         B3  Content-Length in SignedHeaders       undocumented; diagnostic only",
    falsifies:
      "R31 as a provider-enforced law. Content-MD5 is documented as supported for PutObject; " +
      "the presigned-URL page documents Content-Type as signed AND enforced (403 " +
      "SignatureDoesNotMatch on mismatch) and does not mention Content-MD5, Content-Length or " +
      "conditionals at all. So there are TWO enforcement questions hiding in one: does the " +
      "signature bind the header, and does R2 verify the DIGEST against the body rather than " +
      "just matching the header string? Only the second one gives R31.",
    ifItFails:
      "THIS IS THE ARCHITECTURAL RESULT, not a bug: hard pre-write quota and fully direct " +
      "client->R2 uploads cannot both be claimed with the current grant primitive. Then choose " +
      "CONSCIOUSLY between (a) a small controlled data-plane boundary for writes and (b) softer " +
      "asynchronous quota via R32 with an over-write alarm. Do not ship a page that says " +
      "'quota enforced' either way until this is answered.",
    ifItPasses:
      "R31 becomes provider-enforced by CONTENT rather than by a byte ceiling, which is " +
      "strictly stronger: a bound digest refuses a longer body, a shorter body and a " +
      "same-length different body alike. WHICH ONE passes decides the design. If B2 works, the " +
      "bound digest IS content_digest — one hash, computed once, naming the chunk and enforcing " +
      "the write. If only B1 works, the client computes an MD5 alongside the sha256 the chunk " +
      "is already named by, and that MD5 does integrity-against-accident, never " +
      "integrity-against-an-adversary. Do not standardize on MD5 before B2 has been tried.",
  },
  {
    id: "C",
    question: "Does If-None-Match: * bind THROUGH a presigned URL?",
    // NARROWED 2026-08-22. The old text said Cloudflare "does not document
    // conditional writes". The S3-compatibility page now lists If-Match,
    // If-None-Match, If-Modified-Since and If-Unmodified-Since as supported for
    // PutObject, so the general capability is no longer in doubt and framing it
    // as unknown would be arguing with a published table.
    method:
      "Sign a PutObject carrying If-None-Match: * in SignedHeaders; upload twice; require the " +
      "second to fail with 412. Then upload twice WITHOUT the header present at request time, " +
      "to find out whether the condition is enforced by the signature or merely permitted by it.",
    falsifies:
      "Not 'does R2 support conditional PutObject' — it does, and the S3-compatibility page " +
      "says so. The open question is narrower: whether the condition survives the presigned " +
      "path, whose own page documents only Content-Type as signed-and-enforced.",
    ifItFails:
      "Overwrites stay possible, so the split in 0021 is load-bearing rather than tidy: " +
      "cd.storage_observations keeps keying on etag and cd.storage_objects stays the only " +
      "thing occupancy may be read from. Cost is accounting complexity, not correctness.",
    ifItPasses:
      "A content-addressed chunk key can be made write-once at the provider, and " +
      "storage_objects.overwrite_count becomes an alarm that should always read zero rather " +
      "than a number to reconcile.",
  },
  {
    // ADDED 2026-08-24, finding 121. IT RUNS BEFORE Q, AND BEFORE EVERYTHING.
    // Every other case attests a subject that comes from scripts/
    // deployment-subjects.mjs, which reads worker/wrangler.toml. That file is a
    // statement of INTENT about the runtime; once a Worker exists, a green P
    // against a drifted deployment is a true statement about a system nobody is
    // running. So the first question is whether the two agree at all.
    id: "S",
    question:
      "Does the DEPLOYED Worker trust exactly the subjects worker/wrangler.toml declares? " +
      "(finding 121)",
    method:
      "GET /accounts/{account}/workers/scripts/{name}/settings and read `bindings[]` in " +
      "Cloudflare's own vocabulary — plain_text.text, hyperdrive.id, r2_bucket.bucket_name, " +
      "queue.queue_name. scripts/check-deployed-subjects.mjs is this check; its predicate is " +
      "pure and unit-tested in worker/test/deployment-subjects.test.mjs. Per subject: the " +
      "binding exists, is of the expected KIND, carries a value, and that value equals the " +
      "manifest's. Across the pair: HYPERDRIVE_CONTROL and HYPERDRIVE_JOBS are DIFFERENT " +
      "configurations, which is R80 asserted at the deployed layer instead of the file layer.",
    falsifies:
      "That subject continuity is closed. Finding 105 closed the caller-chosen half — no gate " +
      "may take a subject from its environment — and left the manifest-versus-runtime half, " +
      "which was unreachable while nothing was deployed and is reachable the moment one is.",
    ifItFails:
      "STOP. Every case after this one is attesting the wrong system, and the failure mode is " +
      "silent and total: objects land in a bucket outside the accounting path with no anomaly " +
      "counter, no DLQ and no retry to notice, exactly as in finding 105's reproduction. " +
      "Redeploy from the manifest, or rule the deployment correct and change the manifest.",
    ifItPasses:
      "The subject chain runs tree -> deployed -> P/P2/Q, and `origin` may finally read " +
      "\"deployed\" rather than \"wrangler.toml\".",
  },
  {
    // ADDED 2026-08-23, finding 95 / R17 / R80. IT RUNS FIRST, before anything
    // is uploaded: it is the only case that can be answered with two GETs and no
    // write, and if it fails the request path and the observer are one authority
    // and every later result is about a system we did not mean to build.
    id: "Q",
    question:
      "Do the two Hyperdrive bindings carry two PostgreSQL credentials, with the SQL " +
      "response cache off? (R17, R80)",
    method:
      "GET both Hyperdrive configurations. scripts/check-hyperdrive-authority.mjs is this " +
      "check; its predicate is pure and unit-tested in worker/test/hyperdrive-authority.test.mjs. " +
      "Per config: origin.user is the expected login, origin.database is Pigsty's, the origin " +
      "matches one of Cloudflare's three documented shapes, and caching.disabled === true. " +
      "Across the pair: distinct ids, distinct users, SAME origin — two authorities over one " +
      "database.\n" +
      "         THEN, once the driver exists, the privilege witness through each connection: " +
      "current_user; the request credential CANNOT execute app.observe_storage_object(); the " +
      "jobs credential can; the jobs credential holds no unrelated request capability.",
    falsifies:
      "R80's separation, at the layer where it is actually implemented. R80 was proved at the " +
      "level of BINDING NAMES — two [[hyperdrive]] entries, two function names, a gate reading " +
      "both. Reproduced (finding 95): point the jobs binding at the request binding's id and " +
      "check-channel-identity.mjs exited 0 saying 'two Hyperdrive authorities'. That half is " +
      "closed in the file now. The half a file CANNOT close is that two distinct ids may still " +
      "authenticate as one PostgreSQL user, and that caching is configured with `wrangler " +
      "hyperdrive create --caching-disabled` — on the CONFIGURATION, not the binding — so NO " +
      "wrangler.toml can ever assert R17. It is provider state and only a provider read attests " +
      "it.",
    ifItFails:
      "Do not go live. A collapsed authority means the request path holds EXECUTE on the " +
      "observer, which is the boundary R68 and R80 exist to draw; a live cache on a " +
      "tenant-sensitive path means Hyperdrive is keyed on a query string that is byte-identical " +
      "across tenants for every RLS-filtered SELECT, and the first cross-tenant read is a " +
      "correctness failure nothing downstream can detect. Recreate the configuration — caching " +
      "is settable on an existing one with `wrangler hyperdrive update <id> --caching-disabled`.",
    ifItPasses:
      "R17 stops being an unattested ruling. NOTE WHAT IT STILL DOES NOT BUY: origin.password " +
      "is write-only and the API never returns it, so this proves WHICH USER each configuration " +
      "names and never that the two secrets differ. Only the privilege witness above proves the " +
      "grant. Re-run it on every provisioning change — a cache re-enabled later is exactly as " +
      "bad as one enabled now, and nothing in the data plane would notice.",
  },
  {
    // ADDED 2026-08-23, finding 84 / R77, and it runs BEFORE D. Every other
    // case in this file assumes the notification queue speaks for R2. That
    // assumption is a provisioning fact, not a code fact, and it is the one
    // thing here that can be false without any experiment failing.
    id: "P",
    question:
      "Is the provider-observation queue a dedicated R2-only authority channel? (R77)",
    method:
      "GET the queue through the Cloudflare API and enumerate BOTH sides. PRODUCER side: " +
      "producers_total_count agrees with the returned list; exactly one entry; its type is " +
      "exactly `r2_bucket`; its bucket_name is exactly ours. CONSUMER side (finding 89): no " +
      "consumer other than the observer Worker, and at least one. scripts/check-queue-authority.mjs " +
      "is this check; its predicate is a pure function unit-tested in " +
      "worker/test/queue-authority.test.mjs, and ANY producer type it does not positively " +
      "recognise is a REFUSAL rather than a note — which is finding 88, where the first version " +
      "of this gate exited 0 on a queue carrying an unclassified producer.",
    falsifies:
      "The premise under every occupancy number this system publishes. observeBatch() trusts " +
      "R2 for size and etag and derives tenancy from the key -- correctly -- but what it " +
      "actually knows is 'a Queue delivered something shaped like an R2 notification'. " +
      "Cloudflare documents that ANY Worker can write to a queue, and the notification body " +
      "carries no cryptographic R2 provenance, so a Worker holding a producer binding on this " +
      "queue can mint occupancy. Checking `account` does not help: a producer that can forge " +
      "the rest of the JSON can forge that string too.",
    ifItFails:
      "Do not go live on the shared queue. Provision a dedicated queue whose only producer is " +
      "the bucket notification rule, and make THAT a standing provisioning gate rather than a " +
      "sentence in an architecture document. If Cloudflare cannot express producer restriction " +
      "at all, the honest fallback is that the consumer HEADs the named object before charging " +
      "it -- slower, and it makes R2 rather than the envelope the authority.",
    ifItPasses:
      "The channel is the credential, and (queue_name, message_id) records which credential " +
      "spoke. Re-run it on every provisioning change: a producer binding added later is exactly " +
      "as bad as one added now, and nothing in the data plane would notice. The runtime half is " +
      "already closed regardless of this case — the Worker's queue() handler refuses any batch " +
      "whose MessageBatch.queue is not env.PROVIDER_QUEUE, BEFORE it connects, and refuses " +
      "everything when no channel is attested at all. Case P is what stops the provisioning " +
      "drifting under a correct handler.",
  },
  {
    // ADDED 2026-08-23, finding 99. THE OTHER HALF OF P, and it exists because
    // case P can pass over a channel that carries a fraction of the truth.
    id: "P2",
    question:
      "Does the R2 notification rule route EVERY admitted write to that channel? (R77, R79)",
    method:
      "GET /accounts/{account}/event_notifications/r2/{bucket}/configuration. " +
      "scripts/check-notification-coverage.mjs is this check; its predicate is pure and " +
      "unit-tested in worker/test/notification-coverage.test.mjs. Asserts: bucketName is ours; " +
      "exactly one queue entry for the attested PROVIDER_QUEUE carrying exactly one rule; the " +
      "rule's actions cover PutObject, CopyObject and CompleteMultipartUpload; NO delete action " +
      "(M2.0 is append-only, R56); nothing outside Cloudflare's five-action enum; no suffix " +
      "filter; and a prefix that is absent or a prefix of `org/`. The required action list is " +
      "IMPORTED from reconcile.mjs rather than retyped, so a fourth admitted action becomes a " +
      "coverage requirement without an edit.",
    falsifies:
      "The completeness of the channel case P proved AUTHENTIC. Case P reads the queue's " +
      "producer and consumer sides; it never opens the bucket's notification configuration, and " +
      "those are two different objects in the account. So this passes case P:\n" +
      "         producer = OUR bucket, consumer = OUR observer, DLQ configured\n" +
      "       while the rule behind it is:\n" +
      "         actions = [PutObject], prefix = \"wrong-prefix/\"\n" +
      "       and every CopyObject, every CompleteMultipartUpload — which is how a large world " +
      "chunk lands — and every key outside that prefix is never produced at all. There is no " +
      "retry budget to exhaust, because no message was ever created. It is finding 65 arriving " +
      "from below the database with no trace anywhere.",
    ifItFails:
      "Re-provision the rule to the exact intended shape rather than adding a second rule to " +
      "patch the gap: Cloudflare allows 100 rules per bucket and prohibits overlaps that fire " +
      "twice for one event, and proving an arbitrary set equivalent to the intended one is a " +
      "harder claim than provisioning the one rule that plainly is it. If a delete action is " +
      "present, that ALSO contradicts the premise inventory.mjs's `extra` refusal rests on, and " +
      "R56 has to be revisited before the rule is.",
    ifItPasses:
      "Case P's 'the channel is the credential' becomes 'the channel is the credential AND it " +
      "carries every admitted write'. Neither case implies the other and both are standing " +
      "provisioning gates: P asks whether the thing speaking is really R2, P2 asks whether R2 " +
      "is speaking about everything.",
  },
  {
    id: "D",
    question: "Does an object-create event arrive, and does object.size match?",
    method: "Configure a notification rule to a queue; PUT N bytes; pull the message.",
    falsifies: "R32's feasibility.",
    ifItFails:
      "Client-asserted finalize stays the only number available, and the honest response is to " +
      "SAY SO on the security page rather than quietly keep trusting it.",
  },
  {
    id: "D2",
    // SPLIT OUT 2026-08-23. 0024 said "live falsifier case D writes the real
    // number" for app.provider_clock_skew_allowance(), and case D had no clock
    // experiment in it at all -- it asks whether a notification arrives and
    // whether object.size matches. A migration cited a measurement that was
    // never going to be taken.
    question:
      "How far can R2's eventTime precede our own clock for a write we caused? (R72)",
    method:
      "Many real cycles: offer (recording intent.created_at from Pigsty), PUT immediately, " +
      "consume the notification, record `intent.created_at - eventTime`. Report the " +
      "distribution and the WORST legitimate negative delta, not the median — the constant has " +
      "to cover the tail or it strips attribution from real writes.",
    falsifies:
      "app.provider_clock_skew_allowance() = 5 minutes, and with it the earned half of R72. The " +
      "ruling has two halves: *a lower bound exists* is measured; *this is the right lower " +
      "bound* is PROPOSED until this runs. Too small and legitimate chunks are recorded " +
      "unattributed, which looks exactly like the defect R72 prevents; too large and a stale " +
      "delayed event can still be credited to an intent that did not cause it.",
    ifItFails:
      "If the observed skew is unbounded or drifts, a timestamp comparison is the wrong " +
      "instrument and attribution needs something the provider echoes back rather than something " +
      "two clocks agree about — which points at case B's bound digest, not at a bigger constant.",
    ifItPasses:
      "The allowance gets a measured value. NOTE WHAT IT STILL DOES NOT BUY: R72 is a lower " +
      "bound only. A write arriving long after expires_at could not plausibly have been caused " +
      "by the intent either, and case I measures that in-flight bound — after which R72 should " +
      "become an interval, `created_at - skew <= provider_event_at <= expires_at + inflight`.",
  },
  {
    id: "E",
    // REWRITTEN round 7.3. This case still described the (bucket, object_key,
    // etag) mechanism that 0022/R57 REPLACED, so it would have tested a dedupe
    // key the code no longer uses -- and "feed the same body twice" is not a
    // redelivery, it is a second call. A redelivery is a property of the
    // ENVELOPE and only the real queue produces one.
    //
    // R57 is also narrowed here. Cloudflare documents Message.id as "a unique,
    // system-generated ID for the message" and `attempts` as consumer
    // processing attempts; the R2 event notification BODY documents account,
    // action, bucket, object{key,size,eTag}, eventTime and copySource -- and no
    // event id at all. So what we possess is QUEUE MESSAGE identity, and the
    // claim must be exactly-once processing OF A QUEUE MESSAGE, not possession
    // of a provider event identity -- which R2 does not expose at all.
    question:
      "Does a redelivered queue message keep the SAME id, and does one object event ever " +
      "produce two different message ids?",
    method:
      "Consume a real R2 notification; record id and attempts. Force a retry (throw, or " +
      "message.retry()). Require the redelivery to carry the SAME id with attempts > 1, and " +
      "require exactly one observation row. Separately: PUT once and watch the queue for the " +
      "full visibility window, requiring exactly one message id for that one write.",
    falsifies:
      "R57's mechanism. `message_id` is UNIQUE in 0022, so it absorbs redelivery ONLY IF the " +
      "id is stable across attempts -- and Cloudflare documents the retry counter without " +
      "documenting that the id survives it. A retry under a NEW id gets past the constraint " +
      "and writes a second observation row.\n" +
      "         CORRECTED 2026-08-23, by outside review, against a claim this file made: that " +
      "second row does NOT double-charge the ledger. 0023 charges `v_after - v_prior` read " +
      "under the inventory row lock, and for the same write 100 -> 100 is a delta of ZERO. " +
      "MEASURED, and pinned by check K43. What unstable ids cost is a duplicated PROVENANCE " +
      "log and an inflated event_count -- which is why this case now ranks BELOW I, B, F and G " +
      "for M2.0, and rises again in M2.1 when delete/create histories make the log load-bearing.",
    ifItFails:
      "Note what is NOT available as a fallback: the documented remedy for at-least-once is " +
      "'generate a unique ID when writing the message and use it as an idempotency key', and " +
      "R2 is the producer here, so we cannot inject one. The remaining options are the " +
      "(bucket, key, etag, event_time) fallback index -- which cannot tell a redelivery from a " +
      "genuine identical re-PUT at the same instant, which is finding 62 coming back -- or " +
      "moving object-create detection off notifications entirely.",
    ifItPasses:
      "R57 is sound as EXACTLY-ONCE QUEUE-MESSAGE PROCESSING. It still does not establish " +
      "that R2 cannot emit two messages for one object event; the docs get us most of the way " +
      "there by forbidding the CONFIGURATION -- 'overlapping or conflicting rules that could " +
      "trigger multiple notifications for the same event are not allowed' -- which makes " +
      "single-notification an obligation on OUR rule set, checked at provisioning, rather than " +
      "a provider guarantee we may assume.",
  },
  {
    id: "F",
    question: "Does the tenant-context transaction survive Hyperdrive's pooling?",
    method:
      "Through HYPERDRIVE_URL: BEGIN; set_organization_context(A); SELECT; COMMIT — then on the " +
      "next transaction, SELECT with no context and require CD-TENANT-MISSING.",
    falsifies:
      "The core §6.1 assumption. set_config(...,true) is transaction-scoped and Hyperdrive is " +
      "transaction-pooled, so this SHOULD hold — and 'should' is what §6.1 already had to " +
      "retract once.",
    ifItFails: "Tenant isolation does not work over the production transport. Stop everything.",
  },
  {
    id: "G",
    question: "Does the request path work with NO advisory locks, over Hyperdrive?",
    method:
      "Through HYPERDRIVE_URL: two concurrent connections, same fresh OIDC subject, " +
      "resolve_principal on both. Require two successes and one principal.",
    falsifies:
      "R30-as-amended. 0015 replaced the advisory lock with unique-index serialization " +
      "specifically because Hyperdrive lists advisory locks as unsupported.",
    ifItFails: "Identity resolution has to move somewhere Hyperdrive is not in the path.",
  },
  {
    id: "I",
    question: "How long after our expiry instant can a write we authorized still show up?",
    // Added round 7.2, RE-AIMED in 7.3. It was written when expiry itself
    // released bytes, and finding 65 showed that was wrong for a reason that
    // needed no in-flight PUT at all: the provider had ALREADY spoken and
    // expiry threw the statement away. 0023 separates the two events, so expiry
    // no longer releases anything and this case is no longer about expiry.
    //
    // What it measures now is the one number 0023 could not derive:
    // app.settlement_quiet_period(), currently 1 hour and openly a guess. It
    // has to cover a PUT R2 admitted before our expiry instant, plus R2 ->
    // Queue -> consumer latency, and no Cloudflare page documents either. The
    // presigned-URL docs give expiry bounds (1 second to 7 days) and say
    // nothing about a request that BEGINS before expiry and completes after it.
    method:
      "Sign a PutObject whose URL expires at T. Begin a large slow body at T-1s so the request " +
      "is in flight across the boundary. Record the interval from T to (a) the object becoming " +
      "readable and (b) the notification arriving on the queue. Repeat with the body started " +
      "AFTER T, which should be refused. Repeat at several body sizes, because (a) is bounded " +
      "by upload duration and (b) is not. The answer is the MAXIMUM of (b) observed, plus " +
      "margin -- not the median.",
    falsifies:
      "app.settlement_quiet_period() = 1 hour. Settling earlier than the real bound releases " +
      "bytes for a write still on its way, which is finding 65 with a smaller window; settling " +
      "much later leaks quota on every crashed client for no reason.",
    ifItFails:
      "ONE HEAD AFTER EXPIRY IS NOT A PROOF and must not be built as one: HEAD 404, in-flight " +
      "PUT completes, object appears. If the bound turns out to be unbounded or unmeasurable, " +
      "settlement has no safe automatic trigger and the honest options are (a) settle only on " +
      "an explicit operator action, (b) a small controlled data-plane boundary for writes so " +
      "the authority is ours to revoke, (c) softer quota semantics stated plainly on the " +
      "security page. Pick one CONSCIOUSLY; do not let the local clock keep standing in for a " +
      "provider guarantee.",
    ifItPasses:
      "settlement_quiet_period() gets a measured value and stops being a guess. Note what " +
      "PASSING does NOT buy: it bounds how late a write we authorized can land, not how late " +
      "an out-of-band write can, and O10 is the check that keeps those separate.",
  },
  {
    // ADDED 2026-08-23, finding 82 / R75. 0026 makes an equal-eventTime tie a
    // representable state (ambiguous_event_at) instead of a coin flip. Whether
    // that state is REACHABLE in production is a provider question.
    id: "J",
    question:
      "Can two genuine writes to one key carry the same eventTime? (R75)",
    method:
      "PUT two different bodies to one key as fast as the API allows, many times, and record " +
      "the eventTime pairs. Cloudflare documents eventTime as the time the triggering action " +
      "occurred and its example has millisecond resolution; it does not document it as a " +
      "sequence number. Separately: does Message.id ever repeat across two queues fed by the " +
      "same bucket? That is the other half of R77 and needs two notification rules.",
    falsifies:
      "Whether cd.storage_objects.ambiguous_event_at is a live alarm or dead code. If ties are " +
      "unreachable it is the second; if they are reachable at any rate at all, every occupancy " +
      "number depends on 0026 having been written.",
    ifItFails:
      "Ties DO occur. Then the reconcile path needs the HEAD-and-settle step 0026 leaves as a " +
      "TODO, and `ambiguous` in storage_divergence() needs an operational response rather than " +
      "a column. Quota stays conservative (max) in the meantime, which is the safe direction.",
    ifItPasses:
      "Ties are unobservable at R2's resolution. 0026 stays -- an unreachable state that is " +
      "correctly represented costs one column -- but the alarm becomes a should-never-fire, " +
      "which is exactly what case C would make it for content-addressed chunks anyway.",
  },
  {
    // ADDED 2026-08-23, finding 92 / R79. The only case here whose subject is a
    // failure we intend to CAUSE rather than a behaviour we hope to observe.
    id: "N",
    question:
      "When a notification exhausts max_retries, is it recoverable? (R79)",
    method:
      "Point the consumer at an unreachable Pigsty, PUT a known object, let all five attempts " +
      "fail. Then: (a) is the message in the dead letter queue, and how long does it stay; " +
      "(b) with the DLQ removed, is it gone as documented; (c) run the R2-listing reconciliation " +
      "and confirm it recovers the same object, with the same bytes, at R2's own upload time. " +
      "Measure the listing's own limits too — page size, and whether a bucket with 10^6 keys can " +
      "be walked inside a Worker's CPU budget or needs a durable cursor.",
    falsifies:
      "R79's second half. The first half is documented -- Cloudflare says an exhausted retry with " +
      "no DLQ deletes the message permanently -- and the second half, that an R2 listing recovers " +
      "what the queue dropped, is asserted by worker/src/inventory.mjs and has never met a bucket.",
    ifItFails:
      "If reconciliation cannot walk the bucket at realistic scale, the repair path needs a cursor " +
      "and a schedule rather than a pass, and until it has one the honest statement on the " +
      "security page is that committed_bytes converges only while the queue holds. That is a " +
      "much weaker claim than the one this system is built to make.",
    ifItPasses:
      "The ledger's correctness stops resting on a transport with a finite retry budget. Note what " +
      "it still does NOT buy: the pass repairs `missing`, `divergent` and `ambiguous` and REFUSES " +
      "`extra`, so an out-of-band delete remains an operator decision -- correctly, under R56.",
  },
  {
    id: "H",
    question: "Which PostgreSQL major does Hyperdrive actually accept?",
    method: "Connect through Hyperdrive to the target cluster and read server_version_num.",
    falsifies:
      "The local battery's relevance. Cloudflare documents known support for 9.0–17.x. This " +
      "said 'this box runs 18.4', which stopped being true when R33 made /opt/pgsql-17 the " +
      "default and the battery banner started printing 17.10 — the same stale-in-prose drift " +
      "as finding 63, in the file that lists what we have not measured.",
    ifItFails:
      "Pin Pigsty to 17.x for v1 and run the battery with CD_PGBIN pointed at a 17 build. That " +
      "is the recommended default REGARDLESS until this case has a result.",
  },
];

// THE ORDER THE CASES RUN IN, and it is not the order they were written in.
//
// Declared 2026-08-23 with cases Q and P2. Until now the array's order WAS the
// sequence, which meant "when was this case added" silently decided "when does
// it run" — and the two have now diverged: Q was written last and must run
// first.
//
//   Q P P2   PROVISIONING ATTESTATION. Three GETs, no write, no upload. If the
//   H        authorities are collapsed, the cache is live, or the rule covers a
//            fraction of our writes, every experiment below measures a system we
//            did not mean to build. H belongs here — it is a capability read
//            through Hyperdrive, not an experiment on our data.
//   A        THE CONTROL. Every case after it is meaningless if it fails.
//   D D2 F   THE NOTIFICATION PATH, which is what M2.0 actually needs.
//   G I
//   B C      WRITE SEMANTICS. These decide R31/R32's design, not M2.0's
//            correctness, and B's result is architectural either way.
//   E        Redelivery, which needs a real envelope and so a real queue.
//   J        Tied provider instants — and it is J that decides whether finding
//            97 needs a migration at all. If ties are unreachable, nothing does.
//   N        LAST, DELIBERATELY. It destroys the normal provider path to test
//            recovery, so it must run after that path is known to work.
//
// A is restored to this sequence explicitly: the reviewer's proposed order
// omitted it, and case A's own text says "Stop. Every result below is
// meaningless until the happy path works."
export const SEQUENCE = ["S", "Q", "P", "P2", "H", "A", "D", "D2", "F", "G", "I", "B", "C", "E", "J", "N"];

// FINDING 111, 2026-08-24. EXPORTED, because the order was ALREADY typed twice
// and the copies had already diverged: the bundle's "Still open" prose said
//
//     P -> D -> D2 -> F -> G -> I -> B -> C -> E -> J
//
// while this file had evolved to the fifteen-case order above. Finding 85 in
// miniature, and the register's oldest doctrine — *a derived number must never
// be typed* — applied to a derived SEQUENCE. `scripts/cloud-status-counts.mjs`
// reads this export and `check-status-prose.mjs` refuses prose that states an
// order of its own.

// DERIVED, NOT TRUSTED. A case added to CASES and forgotten here would silently
// never print, and a case removed from CASES would leave a phantom in the
// sequence. This tree has now had three separate defects from a hand-maintained
// copy of a fact (a column, a config key, an object-key regex), so the two lists
// check each other rather than being kept in step by hand.
{
  const ids = CASES.map((c) => c.id);
  const orphan = ids.filter((i) => !SEQUENCE.includes(i));
  const phantom = SEQUENCE.filter((i) => !ids.includes(i));
  const dupe = ids.filter((i, n) => ids.indexOf(i) !== n);
  if (orphan.length || phantom.length || dupe.length) {
    console.error("\n  REFUSED  the case list and the run order disagree:\n" +
      (orphan.length ? `     cases not in SEQUENCE:  ${orphan.join(", ")}\n` : "") +
      (phantom.length ? `     SEQUENCE ids with no case: ${phantom.join(", ")}\n` : "") +
      (dupe.length ? `     duplicate case ids: ${dupe.join(", ")}\n` : ""));
    process.exit(1);
  }
}
const ORDERED = SEQUENCE.map((id) => CASES.find((c) => c.id === id));

const missing = Object.keys(NEEDED).filter((k) => !process.env[k]);
const run = process.argv.includes("--run");

if (!run || missing.length) {
  console.log("\n  LIVE FALSIFIER — plan only. Nothing has been contacted.\n");
  console.log(`  Run order: ${SEQUENCE.join(" -> ")}\n`);
  for (const c of ORDERED) {
    console.log(`  ${c.id}. ${c.question}`);
    console.log(`     method     ${c.method}`);
    console.log(`     falsifies  ${c.falsifies}`);
    console.log(`     if it fails ${c.ifItFails}`);
    // Printed only where it exists. A case that has one is a case where PASSING
    // also changes what we build, and that is worth stating before the run --
    // the same reason ifItFails is written down in advance.
    if (c.ifItPasses) console.log(`     if it passes ${c.ifItPasses}`);
    console.log("");
  }
  if (missing.length) {
    console.log("  Not runnable. Missing bindings:\n");
    for (const k of missing) console.log(`     ${k.padEnd(22)} ${NEEDED[k]}`);
    console.log("\n  This tool PROVISIONS NOTHING. Creating the account, the bucket and the");
    console.log("  queue is a spend decision and belongs to Travis — agents/C-infrastructure.md.\n");
  } else {
    console.log("  Bindings are present. Re-run with --run to execute.\n");
  }
  process.exit(missing.length && run ? 1 : 0);
}

// ---------------------------------------------------------------------------
// Execution path. Reached only with --run AND every binding present.
//
// Deliberately not implemented against a mocked provider: a falsifier that can
// pass without touching the thing it is falsifying is worse than no falsifier,
// because it produces a green line about an experiment that never happened.
// ---------------------------------------------------------------------------
console.log("\n  LIVE FALSIFIER — execution path is NOT IMPLEMENTED.\n");
console.log("  Bindings were supplied, which means an account now exists. Implement each case");
console.log("  against the real provider at that point — and implement them in order, because");
console.log("  A is the control and every result after it is meaningless if A fails.\n");
console.log("  Refusing to run a stub here is the point: a green line from a fake provider is");
console.log("  exactly the confusion CLOUD_V1.md refuses to allow between `local` and `live`.\n");
process.exit(2);
