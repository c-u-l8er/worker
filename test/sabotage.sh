#!/usr/bin/env bash
# Mutation battery for the Worker's security decisions.
#
#   ./worker/test/sabotage.sh
#
# Exit 0 iff EVERY vector is caught. A vector that survives is a decision the
# suite is not actually testing, and the clean run's green is that much less
# meaningful.
#
# WHY MUTATION AND NOT A FLAG
#
# The SQL battery sabotages by replacing a function at runtime. That is not
# available here -- ESM imports are resolved once and a test-only hook in
# `src/` would be a hole in the authenticated path that exists purely so a test
# can reach past it. So instead: copy the tree, break exactly one decision with
# a textual mutation, and run the UNMODIFIED suite against the copy.
#
# Each vector is a single unambiguous replacement. If the anchor string ever
# stops matching, the vector reports NO-ANCHOR rather than silently passing --
# a mutation that failed to apply would otherwise look exactly like a caught one.

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ -t 1 ]; then G=$'\033[32m'; R=$'\033[31m'; D=$'\033[2m'; Z=$'\033[0m'; else G=; R=; D=; Z=; fi
CAUGHT=0; MISSED=0; BROKEN=0

# name ::: file ::: anchor ::: replacement
#
# The delimiter is ':::' and NOT '|', because JS `||` is everywhere and a
# single-pipe separator silently truncated every anchor containing one. Two
# vectors were mangled that way -- and before the parse gate below existed they
# still scored CAUGHT, because unparseable source fails every test. A mutation
# battery cannot be allowed to grade itself on syntax errors.
VECTORS=(
"alg-unpinned:::src/jwt.mjs:::if (header.alg !== ALG) {:::if (false) {"
"signature-ignored:::src/jwt.mjs:::if (!good) throw new JwtRefusal(\"CD-JWT-SIG\", \"signature does not verify\");:::if (false) throw new JwtRefusal(\"CD-JWT-SIG\", \"x\");"
"audience-ignored:::src/jwt.mjs:::if (!auds.includes(audience)) {:::if (false) {"
"expiry-ignored:::src/jwt.mjs:::if (nowS >= claims.exp + leeway) {:::if (false) {"
"header-key-allowed:::src/jwt.mjs:::for (const forbidden of [\"jwk\", \"jku\", \"x5u\", \"x5c\"]) {:::for (const forbidden of []) {"
"tenant-guard-removed:::src/tenant.mjs:::if (!(org instanceof ServerDerivedOrg)) {:::if (false) {"
"org-ambiguity-defaulted:::src/authz.mjs:::if (entries.length > 1) {:::if (false) {"
"scope-drops-org:::src/r2creds.mjs:::const prefix = \`org/\${organizationId.toLowerCase()}/world/\${worldId.toLowerCase()}/\`;:::const prefix = \`world/\${worldId.toLowerCase()}/\`;"
"ttl-silently-clamped:::src/r2creds.mjs:::if (ttlSeconds > MAX_TTL_SECONDS) {:::if (false) {"
# --- added 2026-08-22, one per finding from the round-3 review ---------------
"alias-used-as-org-id:::src/authz.mjs:::      return { alias, providerOrgId: id };:::      return { alias, providerOrgId: alias };"
"alias-only-accepted:::src/authz.mjs:::  if (Array.isArray(raw) || typeof raw === \"string\") {:::  if (Array.isArray(raw)) { return raw.map((a) => ({ alias: a, providerOrgId: a })); } if (false) {"
"viewer-can-write:::src/authz.mjs:::  viewer: \"object-read\",:::  viewer: \"object-write\","
"role-check-removed:::src/authz.mjs:::  if (typeof resolved.role !== \"string\" || !Object.hasOwn(MAX_PERMISSION, resolved.role)) {:::  if (false) {"
"write-overreach-allowed:::src/authz.mjs:::    if (max !== \"object-write\") {:::    if (false) {"
"archived-world-writable:::src/authz.mjs:::    if (worldStatus !== \"active\") {:::    if (false) {"
"crit-ignored:::src/jwt.mjs:::  if (\"crit\" in header) {:::  if (false) {"
"iat-optional-again:::src/jwt.mjs:::  if (typeof claims.iat !== \"number\") {:::  if (false) {"
# --- added 2026-08-22: grant dimensions beyond the action list ---------------
"prefix-dimension-ignored:::src/r2creds.mjs:::  const outside = g.prefixPaths.filter((p) => typeof p !== \"string\" || !p.startsWith(scope.prefix));:::  const outside = [];"
"expiry-dimension-ignored:::src/r2creds.mjs:::  if (effective > authorized) {:::  if (false) {"
"bucket-dimension-ignored:::src/r2creds.mjs:::  if (g.bucket !== scope.bucket) {:::  if (false) {"
# --- added 2026-08-22: temporal / post-verification integrity ----------------
"claims-not-frozen:::src/jwt.mjs:::  deepFreeze(claims);:::  void claims;"
"undergrant-accepted:::src/r2creds.mjs:::  const missing = expected.filter((a) => !got.includes(a));:::  const missing = [];"
# --- added 2026-08-22, round 6: refinement, provenance, expiry, admission ----
#
# One vector per finding, plus one for each new law the fixes introduced. The
# rule this file exists for: a check added after a fix means nothing until it is
# shown to fail before it.
#
# Anchors are single lines and matched with grep -F, so a vector that needs two
# lines has to be expressed as one. `assertAuthorizedScope(scope);` appears three
# times, which would make a line-anchored vector depend on replace-first landing
# in the function the vector's NAME claims. Defanging the guard itself is both
# unambiguous and a stronger mutation: it removes provenance from every caller
# at once.
"provenance-check-defanged:::src/r2creds.mjs:::  if (!isAuthorizedScope(scope)) {:::  if (false) {"
# The FIRST draft of this vector anchored on epochSeconds()'s string guard --
# `if (!Number.isFinite(ms))` -- and it MISSED. Not a hole: Date.parse garbage
# becomes NaN, Math.floor(NaN/1000) is NaN, and the integer check below catches
# it. So that guard is defence in depth and the integer check is the control.
# The vector now targets the control, and the redundancy is recorded rather than
# papered over by moving the anchor quietly.
"malformed-expiry-tolerated:::src/r2creds.mjs:::  if (!Number.isFinite(secs) || !Number.isInteger(secs)) {:::  if (false) {"
"usable-floor-removed:::src/r2creds.mjs:::  if (effective - nowSecs < MIN_TTL_SECONDS) {:::  if (false) {"
"unknown-action-tolerated:::src/r2creds.mjs:::  const unknown = got.filter((a) => typeof a !== \"string\" || !vocabulary.known.has(a));:::  const unknown = [];"
"object-paths-unchecked:::src/r2creds.mjs:::  const strayObjects = (g.objectPaths ?? []).filter(:::  const strayObjects = [].filter("
"write-needs-no-admission:::src/r2creds.mjs:::  if (WRITE_PERMISSIONS.includes(permission)) {:::  if (false) {"
"admission-world-unchecked:::src/r2creds.mjs:::    if (admission.worldId !== worldId.toLowerCase()) {:::    if (false) {"
"admission-provenance-dropped:::src/admission.mjs:::  if (!isAdmitted(admission)) {:::  if (false) {"
"finalize-overrun-allowed:::src/admission.mjs:::  if (actualBytes > admission.bytes) {:::  if (false) {"
# The refinement table itself. Half a translation is the failure mode a
# vocabulary seam introduces that a rename never could: a credential that can
# list one way and not the other, which works in every test written against one
# S3 client.
"r2-list-half-translated:::src/r2native.mjs:::  ListObjects: Object.freeze([\"ListObjectsV1\", \"ListObjectsV2\"]),:::  ListObjects: Object.freeze([\"ListObjectsV2\"]),"
"r2-payload-unchecked:::src/r2native.mjs:::  if (!same(payload.actions ?? [], grant.actions)) {:::  if (false) {"
# --- added 2026-08-22, round 7: object-scoped authority and the event consumer -
#
# The key parser is the tenancy boundary for R2 events, so its vectors are the
# most consequential in this file: a parser that accepts a key we did not mint
# accounts somebody else's bytes to one of our organizations.
#
# RE-ANCHORED 2026-08-23 to src/objectkey.mjs (finding 98). Both vectors went
# NO-ANCHOR when the grammar moved out of reconcile.mjs, and the battery reported
# them as STALE rather than crediting them — which is the property this file
# claims and the second time it has held. A stale vector is a mutation that
# silently tests nothing, so `3 stale` was a defect in the evidence and not a
# rounding error. THE MUTATIONS THEMSELVES ARE UNCHANGED: they are the same two
# weakenings, now applied where the grammar actually lives, and they must catch
# in BOTH consumers — reconcile.mjs and inventory.mjs — which is the whole point
# of there being one file.
"key-parser-unanchored:::src/objectkey.mjs:::  \"^org/([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\" +:::  \"org/([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\" +"
"key-parser-accepts-prefix:::src/objectkey.mjs:::  \"/world/([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})/(.+)$\":::  \"/world/([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})/(.*)$\""
# THE VECTOR THAT ONLY EXISTS BECAUSE OF FINDING 98: weaken the uuid grammar to
# the one inventory.mjs had written for itself. It accepted a nil uuid and
# thirty-six dashes, and the reconciliation planner claimed ownership of keys
# this control plane never mints. With one grammar, the shared fixture catches it
# in both consumers at once; with three, it caught it in none.
"key-parser-uuid-version-dropped:::src/objectkey.mjs:::  \"^org/([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\" +:::  \"^org/([0-9a-f-]{36})\" +"
"delete-events-ignored:::src/reconcile.mjs:::  if (DELETE_ACTIONS.includes(action)) {:::  if (false) {"
"observe-size-coerced:::src/reconcile.mjs:::  if (!Number.isInteger(object.size) || object.size < 0) {:::  if (false) {"
# Including eventTime in the dedupe key makes every REDELIVERY look like a new
# write, which is exactly the bug at-least-once delivery sets for you.
#
# SINGLE-quoted, unlike every other vector here. The anchor is a JS template
# literal, and inside bash double quotes the backticks and ${...} need escaping
# that did not survive -- the vector scored NO-ANCHOR, which the parse gate
# reported honestly rather than crediting it. Single quotes pass the text through.
'dedupe-key-includes-time:::src/reconcile.mjs:::  return [event.bucket, event.object?.key, event.object?.eTag].join(SEP);:::  return [event.bucket, event.object?.key, event.object?.eTag, event.eventTime].join(SEP);'
"batch-aborts-on-refusal:::src/reconcile.mjs:::      if (err instanceof ReconcileRefusal) {:::      if (false) {"
# 0021. `?? 0` is what keeps "this database reports no overwrites" apart from
# "this database does not report overwrites at all". Number(undefined) is NaN,
# and NaN makes every downstream comparison false -- so dropping the coalesce
# turns an unknown into a silent clean bill of health.
"divergence-overwrites-nan:::src/reconcile.mjs:::    overwrites: Number(row.overwrites ?? 0),:::    overwrites: Number(row.overwrites),"
# 0026 / finding 87. The SQL layer raises an ambiguity alarm and this adapter is
# the only thing between it and the consumer. It shipped without the column for
# a full round: each layer correct in isolation, the property destroyed between
# them. Dropping it here must break a test, or nothing is holding the seam.
"divergence-ambiguity-dropped:::src/reconcile.mjs:::    ambiguous: Number(row.ambiguous ?? 0),:::    ambiguous: 0,"
# 0026+4.1 / finding 89 / R77. IDENTITY is which queue delivered this; AUTHORITY
# is whether that queue was allowed to assert provider truth. The entrypoint
# answers the second, before it connects. Admitting a foreign channel must break
# a test, and so must admitting one when no channel is attested at all -- the
# second is the subtler half, because "no rule configured" reads as permissive
# in almost every system that has ever had this bug.
"queue-foreign-channel-admitted:::src/index.mjs:::  if (batchQueue !== expected) {:::  if (false) {"
"queue-unattested-channel-admitted:::src/index.mjs:::  if (typeof expected !== \"string\" || expected.trim() === \"\") {:::  if (false) {"
# 4.1 review / finding 94 / R80. Two PostgreSQL authorities, two Hyperdrive
# credentials. Pointing the observer's connection at the request role's binding
# is a one-word edit that collapses a boundary dozens of rounds went into making
# explicit, and both function names still read correctly afterwards.
"jobs-uses-request-credential:::src/index.mjs:::  if (!env?.HYPERDRIVE_JOBS) {:::  if (!env?.HYPERDRIVE_CONTROL) {"
# 4.1 review / finding 92 / R79. The repair path stands between a notification
# the queue deleted and occupancy the ledger never learns about. Treating an
# object the ledger holds and R2 does not as REPAIRABLE would auto-credit bytes
# back on an out-of-band delete or a truncated listing.
"inventory-extra-auto-repaired:::src/inventory.mjs:::  const absentKeys = known.filter((k) => !sweep.presentKeys.has(k.objectKey));:::  const absentKeys = [];"
# RETIRED 2026-08-23 and replaced by the three below. `inventory-malformed-entry-skipped`
# anchored on a refusal inside reconciliationPlan() that no longer exists: malformed
# provider entries are now rejected in normalizeR2Listing(), because the planner
# does not see provider shapes at all (finding 96). It scored NO-ANCHOR, which is
# the battery refusing to credit a mutation that did not apply.
#
# --- round 8.1 / findings 96, 100, 103. THE PROVIDER BOUNDARY -----------------
#
# Everything the normalizer does is a security decision, and all three of these
# were undefended when the file shipped, because the file's declared input shape
# was invented by its own author.
#
# 96/103: a malformed entry that reaches `entries` is a claim about an object we
# could not actually read. Admitting it makes a garbled listing look like a clean
# bucket, in the pass whose entire job is noticing absence.
"inventory-malformed-entry-admitted:::src/inventory.mjs:::    if (etag === null || !ETAG_RE.test(etag)) {:::    if (false) {"
# 100: THE ONE THAT WOULD HAVE HIT PRODUCTION. The ledger's etags come from the
# notification body, which is raw hex; the S3 listing carries the same digest in
# RFC 7232 quotes. Skip the strip and EVERY object in the bucket reports
# `divergent`, and the pass rewrites every etag to a quoted one.
"inventory-etag-quotes-kept:::src/inventory.mjs:::  return inner.toLowerCase();:::  return t.toLowerCase();"
# --- round 8.2 / findings 105-112. THE SUBJECT, THE SCAN, AND THE PROVENANCE ---
#
# 107. RETIRED: `inventory-truncation-assumed-complete` anchored on a `complete`
# flag that a PAGE no longer carries, because completeness is not a property a
# single provider response has. The three below break the PROTOCOL that earns it.
#
# An unterminated scan becoming complete is the finding in its purest form: the
# enumeration stopped with a continuation token outstanding and every unseen key
# is then reported as an out-of-band delete.
"scan-accepts-unterminated:::src/inventory.mjs:::      if (!done) {:::      if (false) {"
# A spliced cursor chain: both pages are real, both are from this bucket, and the
# range between them was never enumerated.
"scan-accepts-spliced-cursor:::src/inventory.mjs:::      if ((want ?? null) !== (requestedWith ?? null)) {:::      if (false) {"
# A page arriving after the terminating page means two enumerations were joined.
"scan-accepts-page-after-end:::src/inventory.mjs:::      if (done) throw new InventoryRefusal(\"CD-INV-SCAN-CLOSED\",:::      if (false) throw new InventoryRefusal(\"CD-INV-SCAN-CLOSED\","
# 108. PRESENCE AND USABLE STATE ARE INDEPENDENT FACTS. Checking absence against
# the usable-metadata set reports a key R2 just named as an out-of-band delete.
"malformed-entry-becomes-absent:::src/inventory.mjs:::  const absentKeys = known.filter((k) => !sweep.presentKeys.has(k.objectKey));:::  const absentKeys = known.filter((k) => !usable.has(k.objectKey));"
# 109. THE ACTION IS NOT OURS TO GUESS. A listing reports current state, not the
# API call that produced it, and all three create actions change occupancy.
# RE-ANCHORED, round 8.3. Finding 117 made observeArgsFor() refuse before its
# return, and this vector went CAUGHT -> MISSED because no test could reach the
# line any more. The action now lives on repairCandidate(), which is reachable.
# THE BATTERY CAUGHT THE FIX MAKING A PROTECTION UNREACHABLE.
"inventory-fabricates-action:::src/inventory.mjs:::    action,:::    action: \"PutObject\","
"inventory-provenance-optional:::src/inventory.mjs:::  if (provenance === undefined || provenance === null) {:::  if (false) {"
# 110. An empty bucket is legal ONLY when the response positively proves it; a
# response missing both the list and the count is one we could not read.
'empty-listing-assumed:::src/inventory.mjs:::  if (raw === undefined && source === "s3" && response.KeyCount === 0 && truncated === false) {:::  if (raw === undefined) {'
# A repair must not claim a delivery identity it does not have (R77): a
# synthesized message id makes a reconciliation indistinguishable from a
# notification in the provenance log.
"repair-claims-a-delivery-identity:::src/inventory.mjs:::    messageId: null,:::    messageId: \"synthesized\","
# --- round 8.3 / findings 113-118. THE EVIDENCE ITSELF -----------------------
#
# 113. A PROOF OBJECT IS NOT PROVED BY CONTAINING THE FIELD THAT SAYS SO. The
# admission check was a field read, so a hand-written literal was accepted as a
# completed enumeration and the planner read absence out of it.
"forged-completed-sweep:::src/inventory.mjs:::  assertCompletedSweep(sweep);:::  if (sweep?.__completeScan !== true && !isCompletedSweep(sweep)) throw new TypeError(\"x\");"
# 113, second half. Object.freeze froze the POINTER; presentKeys was a live Set,
# so a frozen sweep could be edited into alleging a deletion that never happened.
"completed-sweep-present-set-mutable:::src/inventory.mjs:::        presentKeys: sealedPresence(presentKeys),:::        presentKeys,"
# 115. PROVENANCE SUPPLIED BY THE CLAIMANT IS NOT PROVENANCE. The provider echoes
# the token it answered; ignoring the echo leaves the chain attested by the caller.
"provider-cursor-echo-ignored:::src/inventory.mjs:::        if (page.echoedToken !== (requestedWith ?? null)) {:::        if (false) {"
# 115, structural half. If the sweeper stops threading its own token and takes
# the caller's word, the chain check is asking the claimant about itself again.
"sweep-does-not-own-its-cursor:::src/inventory.mjs:::    const page = normalizeR2ListingPage(await listPage(token), { source });:::    const page = normalizeR2ListingPage(await listPage(null), { source });"
# 117. TWO R2 CLOCKS BECOMING ONE. A listing's LastModified typed as the queue
# eventTime the observer writes to p_event_time.
"inventory-lastmodified-treated-as-eventtime:::src/inventory.mjs:::  if (!EVENT_TIME_BASES.includes(provenance?.eventTimeBasis)) {:::  if (false) {"
# 118. AUTHORITY IS NOT CAUSATION. An upload intent proves we authorized a write
# of this key, not that the bytes now in R2 came from it.
"upload-intent-treated-as-causal-proof:::src/inventory.mjs:::    doesNotProve: \"causation\",:::    doesNotProve: \"nothing\","
# 114. A PROVIDER FIXTURE MUST USE THE PROVIDER'S ACTUAL VOCABULARY. Cloudflare
# identifies a connectivity service with `service_id`; reading `id` returns
# undefined against every real response, and the old guard then skipped the check.
"vpc-service-id-wrong-provider-shape:::../scripts/check-hyperdrive-authority.mjs:::  observed.id = service.service_id ?? null;:::  observed.id = service.id ?? null;"
"vpc-service-id-absent-accepted:::../scripts/check-hyperdrive-authority.mjs:::  if (typeof service.service_id !== \"string\" || service.service_id === \"\") {:::  if (false) {"
# 114, the endpoint. /vpc/services/{id} is not an endpoint; the real path is
# /accounts/{account}/connectivity/directory/services/{service_id}.
# SINGLE-quoted: the anchor is a JS template literal, and in a double-quoted
# bash string its backticks are command substitution and ${...} is expansion.
# The first draft of this vector was double-quoted and scored NO-ANCHOR --
# the battery refusing to credit a mutation that never applied.
'q-old-vpc-endpoint:::../scripts/check-hyperdrive-authority.mjs:::    get(`/connectivity/directory/services/${ruledTopologyServiceId(ruled)}`),:::    get(`/vpc/services/${ruledTopologyServiceId(ruled)}`),'
# --- round 8.4 / findings 121-126. BOTH OPERANDS, AND BOTH GATES --------------
#
# 122. A SET-DIFFERENCE THEOREM REQUIRES COMPLETENESS OF BOTH OPERANDS. Two
# rounds earned the sweep's completeness and compared it to an ordinary array.
# Direction 1: a short ledger fabricates repairs for rows it never read.
"partial-ledger-fabricates-missing-object:::src/inventory.mjs:::  if (!isCompleteLedger(ledger)) {:::  if (false) {"
# Direction 2, the bad one: a short ledger HIDES the R56-impossible out-of-band
# delete this pass exists to find.
"partial-ledger-hides-extra-object:::src/inventory.mjs:::      if (!sealed) {:::      if (false) {"
# The ledger's keyset chain, the same theorem as the sweep's cursor chain.
"ledger-accepts-spliced-chain:::src/inventory.mjs:::      if ((expectAfter ?? null) !== (after ?? null)) {:::      if (false) {"
# An RLS-policied read returns a SUBSET, which is indistinguishable from a clean
# bucket. The likeliest way direction 2 actually happens in production.
"tenant-ledger-supports-absence:::src/inventory.mjs:::  const ledgerSeesAll = ledger.seesAllTenants;:::  const ledgerSeesAll = true;"
# Differencing two buckets reports every object in each as missing from the other.
"ledger-bucket-unchecked:::src/inventory.mjs:::  if (ledger.bucket !== sweep.bucket) {:::  if (false) {"
# 123. AN I/O CALLBACK SUPPLIED BY THE CLAIMANT IS STILL CLAIMANT-SUPPLIED
# PROVENANCE. A synthetic lister with no R2 anywhere minted a sweep that could
# conclude absence.
"synthetic-lister-mints-authoritative-sweep:::src/inventory.mjs:::  if (CREDENTIALED_LISTERS.has(listPage) && NETWORK_VERIFIED_LISTERS.has(listPage)) {:::  if (true) {"
"unauthoritative-sweep-reads-absence:::src/inventory.mjs:::  const authoritative = isAuthoritativeSweep(sweep);:::  const authoritative = true;"
# 124. A BLOCKED REASON THAT IS ONLY PRINTED IS NOT A GATE. Round 8.3 enforced
# the clock and printed the causation blocker; earning the first event-time basis
# would have unlocked both.
"event-time-basis-bypasses-causation:::src/inventory.mjs:::  if (!CAUSATION_BASES.includes(basis)) {:::  if (provenance?.eventTimeBasis === undefined && !CAUSATION_BASES.includes(basis)) {"
"blocked-reasons-not-enforced:::src/inventory.mjs:::  if (candidate.blocked.length) {:::  if (false) {"
# 121. THE DEPLOYMENT MANIFEST IS AN INTENTION; THE RUNTIME DEPLOYMENT IS THE
# SUBJECT. A drifted deployment leaves every later case attesting the wrong system.
"deployed-binding-differs-from-wrangler:::../scripts/deployment-subjects.mjs:::    if (t !== d) {:::    if (false) {"
"deployed-binding-kind-unchecked:::../scripts/deployment-subjects.mjs:::    if (b.type !== type) {:::    if (false) {"
# 125. A PREDICATE OVER A UNION MUST NAME THE VARIANT. `??` picks a winner and
# calls the rest unseen: a dual-stack service reached Pigsty over an unreviewed
# second address and passed.
"vpc-dual-stack-extra-target:::../scripts/check-hyperdrive-authority.mjs:::    if (extra.length) {:::    if (false) {"
"vpc-host-variant-unchecked:::../scripts/check-hyperdrive-authority.mjs:::    } else if (variant !== expect.hostVariant) {:::    } else if (false) {"
# 125, TLS. verify_ca verifies the chain and SKIPS THE HOSTNAME, and the code
# said "acceptable for an IP target" while accepting it for a hostname target.
"hostname-verify-ca-accepted:::../scripts/check-hyperdrive-authority.mjs:::    } else if (mode === \"verify_ca\" && variant === \"hostname\") {:::    } else if (false) {"
"vpc-tls-mode-not-ruled:::../scripts/check-hyperdrive-authority.mjs:::    } else if (mode !== expect.certVerification) {:::    } else if (false) {"
# --- round 8.5 / findings 127-131. AUTHORITATIVE I/O CAPABILITIES -------------
#
# 128. IF THE ADAPTER DOES NOT PERFORM THE AUTHENTICATED ACT, IT CANNOT ATTEST
# THAT THE ACT OCCURRED. Round 8.4's "credentialed adapter" wrapped a caller's
# transport and branded it; with a fake key and a fake secret and no network,
# isAuthoritativeSweep() was true.
"fake-transport-mints-authoritative-r2:::src/inventory.mjs:::  const networkVerified = net === globalThis.fetch;:::  const networkVerified = true;"
"unsigned-r2-request-mints-authority:::src/inventory.mjs:::    const res = await net(url, { method: \"GET\", headers: signed.headers });:::    const res = await net(url, { method: \"GET\" });"
# SINGLE-quoted: the anchor is a JS template literal. Second time this file has
# needed the reminder -- round 8.3's q-old-vpc-endpoint was the first.
'r2-signature-not-scoped-to-secret:::src/s3sig.mjs:::  let key = await hmac(`AWS4${secretAccessKey}`, datestamp);:::  let key = await hmac(`AWS4`, datestamp);'
"r2-payload-hash-unsigned:::src/s3sig.mjs:::    \"x-amz-content-sha256\": EMPTY_PAYLOAD_SHA256,:::"
# 129. The symmetric hole: the caller stated which authority read the rows, which
# snapshot they came from, and whether a page was final.
"fake-jobs-label-mints-complete-ledger:::src/inventory.mjs:::    const authority = ledgerAuthorityFor(id.current_user);:::    const authority = \"jobs\";"
"fake-snapshot-label-mints-complete-ledger:::src/inventory.mjs:::    if (!id || typeof id.snapshot !== \"string\" || id.snapshot === \"\") {:::    if (false) {"
"caller-final-mints-complete-ledger:::src/inventory.mjs:::      const final = rows.length < pageSize;:::      const final = true;"
"ledger-snapshot-drift-ignored:::src/inventory.mjs:::        if (r.snapshot !== undefined && r.snapshot !== id.snapshot) {:::        if (false) {"
# RETIRED, round 8.6: `LIVE_LEDGER_CONNECTIONS` and the public registrar are gone
# (finding 133). Its successors are `public-register-fake-connection-earns-ledger`
# and `registered-connection-plus-unrelated-query-earns-ledger` below.
"unauthoritative-ledger-supports-absence:::src/inventory.mjs:::  if (!isAuthoritativeLedger(ledger)) {:::  if (false) {"
# 130. A PROVIDER FACT NEEDS PROVIDER PROVENANCE, PRESENCE INCLUDED. A synthetic
# page manufactured a 10 TB repair candidate for a key R2 never mentioned.
"nonauthoritative-sweep-fabricates-positive-repair:::src/inventory.mjs:::  if (repair !== undefined && repair?.providerAuthoritative !== true) {:::  if (false) {"
# 127. A PRIOR CHECK IS NOT A CAPABILITY. Case S compared the manifest to the
# deployment and then Q/P/P2 each re-read the manifest.
"q-rereads-manifest-after-S:::../scripts/check-hyperdrive-authority.mjs:::import { refuseRetiredSubjectEnv, ruledTopology, resolveLiveSubjects } from \"./deployment-subjects.mjs\";:::import { refuseRetiredSubjectEnv, ruledTopology, requireSubjects } from \"./deployment-subjects.mjs\";"
"p-rereads-manifest-after-S:::../scripts/check-queue-authority.mjs:::import { refuseRetiredSubjectEnv, resolveLiveSubjects } from \"./deployment-subjects.mjs\";:::import { refuseRetiredSubjectEnv, requireSubjects } from \"./deployment-subjects.mjs\";"
"p2-rereads-manifest-after-S:::../scripts/check-notification-coverage.mjs:::import { refuseRetiredSubjectEnv, resolveLiveSubjects } from \"./deployment-subjects.mjs\";:::import { refuseRetiredSubjectEnv, requireSubjects } from \"./deployment-subjects.mjs\";"
"live-subjects-skip-continuity:::../scripts/deployment-subjects.mjs:::  if (!cont.ok) {:::  if (false) {"
# --- round 8.6 / findings 132-138. PROVIDER IDENTITY + TRANSACTION IDENTITY ---
#
# 132. A REAL NETWORK IS NOT A PROVIDER. Round 8.5 decided authority from
# `net === globalThis.fetch` while taking `endpoint` from the caller. MEASURED
# with an ordinary local HTTP server and the REAL global fetch: authoritative.
# The signature authenticates the request to WHOEVER OWNS THE ENDPOINT.
"native-fetch-to-non-r2-endpoint-earns-authority:::src/inventory.mjs:::  const endpointVerified = base.protocol === \"https:\":::  const endpointVerified = base.protocol === \"http:\""
"r2-endpoint-taken-from-caller:::src/inventory.mjs:::  const endpoint = r2Endpoint(accountId);          // DERIVED (finding 132):::  const endpoint = arguments[0].endpoint ?? r2Endpoint(accountId);"
"r2-account-id-unvalidated:::src/inventory.mjs:::  if (typeof accountId !== \"string\" || !ACCOUNT_ID_RE.test(accountId)) {:::  if (false) {"
# 137. THE SUBJECT MUST CROSS THE BOUNDARY WITH THE CAPABILITY. An adapter built
# for bucket A minted an authoritative sweep whose subject was B, while the
# provider's own <Name> said A.
# RE-AIMED, round 8.6. The old anchor guarded `sweepBucket()` against a lister
# for another bucket -- correct, and now unreachable, because the adapter does
# not expose one. So the vector breaks what makes it unreachable.
"r2-lister-A-mints-sweep-B:::src/inventory.mjs:::    accountId, bucket, endpoint, networkVerified, endpointVerified,:::    accountId, bucket, endpoint, networkVerified, endpointVerified, listPage,"
"provider-bucket-name-unchecked:::src/inventory.mjs:::    if (page.Name !== undefined && page.Name !== bucket) {:::    if (false) {"
# 133. AN AUTHORITY TOKEN AND AN OBSERVATION ARE NOT CONNECTED MERELY BECAUSE THE
# SAME FUNCTION RECEIVED BOTH ARGUMENTS. Round 8.5 branded `connection` and read
# every fact through a separate `query`.
"public-register-fake-connection-earns-ledger:::src/inventory.mjs:::  if (client === null || typeof client !== \"object\" || typeof client.query !== \"function\") {:::  if (false) {"
"registered-connection-plus-unrelated-query-earns-ledger:::src/inventory.mjs:::  const q = (sql, params) => connection.query(sql, params);:::  const q = (sql, params) => (opts.query ?? connection.query)(sql, params);"
"jobs-binding-unchecked:::src/inventory.mjs:::  if (hyperdriveBinding !== \"HYPERDRIVE_JOBS\") {:::  if (false) {"
"unbranded-connection-reaches-ledger-adapter:::src/inventory.mjs:::  if (!isLedgerConnection(connection)) {:::  if (false) {"
# 134. A TRANSACTION ID IS NOT A SNAPSHOT. READ COMMITTED is PostgreSQL's default
# and gives each STATEMENT its own snapshot, while txid_current() is stable
# across all of them -- so 8.5's equality check proved nothing it claimed.
"read-committed-same-txid-two-snapshots:::src/inventory.mjs:::    if (id.isolation !== \"repeatable read\") {:::    if (false) {"
"adapter-does-not-own-transaction:::src/inventory.mjs:::  await q(\"BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY\", []);:::  await q(\"BEGIN\", []);"
"ledger-scan-may-write:::src/inventory.mjs:::    if (id.read_only !== \"on\") {:::    if (false) {"
# 136. A NEGATIVE FACT NEEDS AUTHORITY ON THE SIDE WHOSE ABSENCE IS ASSERTED. A
# `missing` repair is R2 PRESENT *and LEDGER ABSENT*, and 8.5 gated only the first.
"nonauthoritative-ledger-mints-missing-repair:::src/inventory.mjs:::    if (repair.ledgerAuthoritative !== true) {:::    if (false) {"
"tenant-ledger-mints-missing-repair:::src/inventory.mjs:::    if (repair.ledgerSeesAllTenants !== true) {:::    if (false) {"
# 135. AN ATTESTATION ABOUT "THE WORKER" IS MEANINGLESS WHILE MORE THAN ONE
# VERSION CAN BE SERVING IT. Cloudflare deployments route one or two versions by
# percentage; /settings cannot express that.
"active-deployment-two-versions:::../scripts/deployment-subjects.mjs:::  if (versions.length !== 1) {:::  if (false) {"
"active-version-partial-traffic:::../scripts/deployment-subjects.mjs:::  } else if (versions[0]?.percentage !== 100) {:::  } else if (false) {"
"settings-do-not-identify-active-version:::../scripts/deployment-subjects.mjs:::  const av = activeVersionVerdict(d.body.result);:::  const av = { ok: true, deploymentId: null, versionId: \"whatever\" };"
# 0022 / finding 62. DELIVERY identity is the queue envelope's message id; OBJECT
# identity is bucket+key. Dropping the id on the floor silently reverts delivery
# idempotency to object state, under which a genuine identical re-PUT vanishes.
"event-id-not-passed:::src/reconcile.mjs:::      const r = await observeEvent(conn, event, { messageId, queue });:::      const r = await observeEvent(conn, event);"
# 0026 / finding 84 / R77. The channel half of the same identity. Dropping the
# queue leaves a message id whose uniqueness is scoped to something the row does
# not record -- and Cloudflare documents no cross-queue scope for Message.id.
# NOTE: this vector went STALE when 0026 changed the call it anchors on, and a
# stale vector is a mutation that silently tests nothing. `1 stale` in the
# verdict line is a defect in the evidence, not a rounding error.
"delivery-channel-not-passed:::src/reconcile.mjs:::      const r = await observeEvent(conn, event, { messageId, queue });:::      const r = await observeEvent(conn, event, { messageId, queue: queue ?? \"assumed\" });"
"empty-message-id-accepted:::src/reconcile.mjs:::  return typeof id === \"string\" && id !== \"\" ? id : null;:::  return typeof id === \"string\" ? id : null;"
"unidentified-not-counted:::src/reconcile.mjs:::    if (messageId === null) out.unidentified++;:::    if (false) out.unidentified++;"
# Object-scoped authority. A PREFIX grant against an object-scoped scope is a
# widening that looks like a formatting choice.
"object-scope-accepts-prefix:::src/r2creds.mjs:::    if (g.prefixPaths.length) {:::    if (false) {"
"object-scope-any-object:::src/r2creds.mjs:::    if (got.length !== 1 || got[0] !== scope.objectKey) {:::    if (false) {"
"upload-intent-any-permission:::src/r2native.mjs:::  if (scope.permission !== \"object-write\") {:::  if (false) {"
"upload-intent-needs-no-digest:::src/r2native.mjs:::  if (typeof contentDigest !== \"string\" || contentDigest.trim() === \"\") {:::  if (false) {"
# --- added 2026-08-22: the COMPOSITION defects -------------------------------
"jwks-per-request:::src/index.mjs:::        jwksFor(env),:::        new JwksCache({ jwksUri: env.WORKOS_JWKS_URI }),"
"unverified-claims-accepted:::src/authz.mjs:::  assertVerified(claims);:::  void claims;"
"refresh-uncapped:::src/jwt.mjs:::      if (this.now() - this.forcedAt < this.refreshCooldownMs) return null;:::      if (false) return null;"
# --- added 2026-08-23, round 8.1: THE PROVISIONING PREDICATES -----------------
#
# Cases Q and P2 are the first checks in this file that live under `scripts/`
# rather than `worker/src`, and stage() already copies that directory beside the
# worker — so the anchors reach them with a `../` path. That is deliberate: a
# provisioning gate is exactly as load-bearing as a data-plane guard, and until
# now none of them had a single mutation vector. The two gates that DO predate
# this round (queue authority, channel identity) have both false-greened once
# each, which is the argument.
#
# Q / finding 101. THE SUBTLEST ONE IN THIS FILE. `caching.disabled` is not a
# required field and Cloudflare documents its default as false, so `caching: {}`
# means CACHING IS ON. Written as `!== false` the gate passes on absence and
# attests the exact opposite of the truth, on the path where Hyperdrive caches
# by a query string that is byte-identical across tenants (R17).
"hyperdrive-caching-absent-passes:::../scripts/check-hyperdrive-authority.mjs:::      if (cfg.caching.disabled !== true) {:::      if (cfg.caching.disabled === false) {"
# Q / finding 95. Two binding names over one configuration is one credential, and
# the request path would then hold EXECUTE on app.observe_storage_object().
"hyperdrive-same-config-passes:::../scripts/check-hyperdrive-authority.mjs:::    if (c.id && j.id && c.id === j.id) {:::    if (false) {"
"hyperdrive-same-user-passes:::../scripts/check-hyperdrive-authority.mjs:::    if (c.user && j.user && c.user === j.user) {:::    if (false) {"
# P2 / finding 99. An uncovered create action is occupancy that reaches R2 and
# never reaches the ledger, with no message ever produced and so no retry budget
# to exhaust — finding 65 arriving with no trace anywhere.
"notification-missing-action-passes:::../scripts/check-notification-coverage.mjs:::  if (missing.length) {:::  if (false) {"
# P2 / finding 99, the prefix half. `org/a` is the dangerous shape: it is our
# namespace, it matches many real keys, and it silently drops every organization
# whose uuid begins with anything else.
"notification-narrow-prefix-passes:::../scripts/check-notification-coverage.mjs:::    if (p !== undefined && p !== null && p !== \"\" && !NAMESPACE_PREFIX.startsWith(p)) {:::    if (false) {"
# --- round 8.2 / finding 105. THE SUBJECT OF AN ATTESTATION ------------------
#
# Every gate below used to take its subject from the caller's environment, so a
# perfect attestation about the wrong bucket, queue or Hyperdrive config was one
# `export` away. These break the derivation that closed it.
#
# A subject that stops tracking the deployment is the finding itself: the gate
# would attest a constant while the Worker used something else.
"runtime-r2-bucket-not-derived:::../scripts/deployment-subjects.mjs:::  const r2Bucket = one(src, \"R2_BUCKET\", \"[vars]\", \"R2 bucket\", refusals);:::  const r2Bucket = \"cd-worlds\";"
"worker-name-not-derived:::../scripts/deployment-subjects.mjs:::  const workerName = one(src, \"name\", null, \"Worker name\", refusals);:::  const workerName = \"computedriven-cloud-api\";"
# requireSubjects returning a partial set means three subjects attested correctly
# and the fourth against whatever was lying around.
"partial-subjects-accepted:::../scripts/deployment-subjects.mjs:::  if (!d.ok) {:::  if (false) {"
# An operator who exports a retired variable must be TOLD, not silently obeyed.
"retired-subject-env-ignored:::../scripts/deployment-subjects.mjs:::  if (!set.length) return null;:::  return null; if (!set.length) return null;"
# The channel is one fact, checked in the derivation so no gate can obtain a
# coherent subject set from an incoherent deployment.
'incoherent-channel-accepted:::../scripts/deployment-subjects.mjs:::  if (providerQueue && consumerQueue && providerQueue !== consumerQueue) {:::  if (false) {'
# P2 attesting a foreign bucket: a correct answer about the wrong subject.
"p2-attests-foreign-bucket:::../scripts/check-notification-coverage.mjs:::  if (config.bucketName !== expect.bucket) {:::  if (false) {"
"p2-attests-foreign-queue:::../scripts/check-notification-coverage.mjs:::  const ours = config.queues.filter((q) => q?.queueName === expect.queue);:::  const ours = config.queues.slice(0, 1);"
# --- round 8.2 / finding 106. THE RULED TOPOLOGY ----------------------------
#
# Two correct credentials to a public-internet PostgreSQL host PASSED before
# this round. R7 rules the path, not just the pair.
"q-accepts-internet-origin:::../scripts/check-hyperdrive-authority.mjs:::    } else if (variant !== REQUIRED_VARIANT) {:::    } else if (false) {"
"q-accepts-foreign-vpc-service:::../scripts/check-hyperdrive-authority.mjs:::      if (origin.service_id !== expect.vpcServiceId) {:::      if (false) {"
# The Hyperdrive names only a service_id; the tunnel, the target and the TLS mode
# live on the service object one level down.
"vpc-tunnel-unchecked:::../scripts/check-hyperdrive-authority.mjs:::    if (observed.tunnelId !== expect.tunnelId) {:::    if (false) {"
"vpc-target-unchecked:::../scripts/check-hyperdrive-authority.mjs:::    if (absent.length) {:::    if (false) {"
"vpc-tls-disabled-accepted:::../scripts/check-hyperdrive-authority.mjs:::    } else if (mode === \"disabled\") {:::    } else if (false) {"
)

printf '\n%s== worker mutation battery ==%s\n' "$D" "$Z"
printf '  %sEach vector breaks ONE security decision. Every one should be CAUGHT.%s\n\n' "$D" "$Z"

# BASELINE FIRST. Without this the battery is worthless and looks perfect:
# `node --test test/` (a directory, not a glob) fails with MODULE_NOT_FOUND on
# node 25, so an early version of this script reported 10/10 CAUGHT while every
# vector was detecting a broken invocation rather than a broken decision. If the
# UNMUTATED copy does not pass, nothing below it means anything.
# THE STAGE MIRRORS THE REPOSITORY LAYOUT, not just worker/.
#
# It used to copy src/ and test/ into a flat temp dir, which was fine until a
# test imported something outside worker/ -- queue-authority.test.mjs reaches
# ../../scripts/check-queue-authority.mjs, because case P's predicate is a
# repo-level provisioning gate and not Worker runtime code. In a flat stage that
# import resolves outside the copy, the BASELINE fails, and the battery
# correctly refuses to run. Staging worker/ and scripts/ side by side keeps
# every relative import meaning what it means in the tree.
# STAGE THE WHOLE WORKER, NOT A LIST OF ITS PARTS.
#
# 2026-08-24. This copied `src` and `test` only, and the round-8.2 tests read
# `worker/wrangler.toml` and `worker/topology.json` — the deployment's own
# subject declarations, which is the entire point of finding 105. The staged
# tree had neither, so the baseline suite failed.
#
# THE BASELINE GUARD CAUGHT IT AND REFUSED TO RUN, which is what it is for: with
# a broken baseline every vector reports CAUGHT for the wrong reason. But note
# the SHAPE of the bug — a hand-maintained copy list that went stale when the
# thing it copies grew. That is finding 104 exactly, in a second staging list, in
# the same round. So this one is written as "everything the worker is, minus
# build output", which cannot go stale the same way.
stage() {  # dest
  mkdir -p "$1/worker"
  # -a so a file added to worker/ arrives without an edit here. The excludes are
  # things that are large and regenerable, never source.
  ( cd "$ROOT" && tar -cf - --exclude=node_modules --exclude='*.tar.gz' \
      --exclude='CLOUD_V1_REVIEW_BUNDLE.md' . ) | ( cd "$1/worker" && tar -xf - )
  cp -r "$ROOT/../scripts" "$1"/ 2>/dev/null
}
BASE=$(mktemp -d); stage "$BASE"
# EXIT STATUS IS TRUTH. Output parsing is presentation.
#
# The previous version made the grep the truth condition, matching only the
# `ℹ fail N` reporter format. Node's TAP output says `# fail 1` for the same
# failure, so on a runtime emitting TAP a genuinely broken baseline sailed
# through -- and then all 18 vectors would report CAUGHT against a suite that
# was already failing. That is the exact defect this baseline exists to catch,
# reintroduced one layer up. Reproduced before fixing: `# fail 1` is not matched
# by that pattern, and `node --test` exits 1 on failure regardless of reporter.
base_out=$(cd "$BASE/worker" && node --test test/*.test.mjs 2>&1); base_rc=$?
if [ $base_rc -ne 0 ]; then
  printf '  %sBASELINE BROKEN%s  the unmutated suite does not pass; every vector below\n' "$R" "$Z"
  printf '  would report CAUGHT for the wrong reason. Refusing to run.\n\n'
  printf '%s\n' "$base_out" | tail -20
  rm -rf "$BASE"; exit 2
fi
# Display only, and tolerant of both reporter formats.
base_n=$(printf '%s' "$base_out" | grep -oE '(ℹ|#) pass [0-9]+' | grep -oE '[0-9]+$' | tail -1)
printf '  %sbaseline%s   %s tests pass unmutated\n\n' "$G" "$Z" "$base_n"
rm -rf "$BASE"

for v in "${VECTORS[@]}"; do
  # NOT `IFS=':::' read` -- bash treats IFS as a SET of single-char separators,
  # so that would split on every colon, and anchors contain them. These expansions
  # split on the literal three-character sequence.
  name="${v%%:::*}";      rest="${v#*:::}"
  file="${rest%%:::*}";   rest="${rest#*:::}"
  anchor="${rest%%:::*}"; replacement="${rest#*:::}"
  TMP=$(mktemp -d); stage "$TMP"

  if ! grep -qF -- "$anchor" "$TMP/worker/$file"; then
    printf '  %sNO-ANCHOR%s  %-24s the mutation did not apply -- vector is stale\n' "$R" "$Z" "$name"
    BROKEN=$((BROKEN+1)); rm -rf "$TMP"; continue
  fi

  python3 - "$TMP/worker/$file" "$anchor" "$replacement" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); s = p.read_text()
p.write_text(s.replace(sys.argv[2], sys.argv[3], 1))
PY

  # A mutation that makes the source unparseable would fail every test and be
  # credited with detecting the decision it was supposed to break. That is not a
  # caught mutation, it is a broken one -- so parse first and score it separately.
  if ! (cd "$TMP/worker" && node --input-type=module -e "import('./$file')" >/dev/null 2>&1); then
    printf '  %sINVALID%s    %-24s the mutated source does not load; scores nothing\n' \
      "$R" "$Z" "$name"
    BROKEN=$((BROKEN+1)); rm -rf "$TMP"; continue
  fi

  out=$(cd "$TMP/worker" && node --test test/*.test.mjs 2>&1); rc=$?
  if [ $rc -ne 0 ]; then
    n=$(printf '%s' "$out" | grep -oE '(ℹ|#) fail [0-9]+' | grep -oE '[0-9]+$' | tail -1)
    printf '  %sCAUGHT%s     %-24s %s test(s) failed\n' "$G" "$Z" "$name" "${n:-?}"
    CAUGHT=$((CAUGHT+1))
  else
    printf '  %sMISSED%s     %-24s the suite passed with this decision broken\n' "$R" "$Z" "$name"
    MISSED=$((MISSED+1))
  fi
  rm -rf "$TMP"
done

printf '\n%s== verdict ==%s\n' "$D" "$Z"
printf '  %s%d caught%s   %s%d missed%s   %s%d stale%s   (%d vectors)\n' \
  "$G" "$CAUGHT" "$Z" \
  "$([ "$MISSED" -gt 0 ] && printf '%s' "$R")" "$MISSED" "$Z" \
  "$([ "$BROKEN" -gt 0 ] && printf '%s' "$R")" "$BROKEN" "$Z" \
  "${#VECTORS[@]}"
if [ "$MISSED" -gt 0 ] || [ "$BROKEN" -gt 0 ]; then
  printf '  %sA surviving mutation is an untested decision.%s\n\n' "$R" "$Z"
  exit 1
fi
printf '  Every broken decision was detected by the unmodified suite.\n\n'
