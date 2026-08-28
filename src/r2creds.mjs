// Lane D's one job: turn an authorized request into a credential narrow enough
// that possessing it grants nothing extra.
//
// R8. Bulk bytes go client <-> R2 DIRECTLY; the Worker authorizes and mints and
// is never in the byte path. So the credential IS the access control, and the
// most likely real bug in this lane is a credential that works for more than it
// should -- which will not show up in any happy-path test. Everything below is
// arranged so the scope is computed in one pure function that the battery can
// attack directly.
//
// This file holds the PROVIDER-INDEPENDENT half: the ComputeDriven capability
// vocabulary, scope construction, provenance, and the refinement law. R2's own
// action names and the translation into them live in r2native.mjs, because
// putting them here is what produced the contradiction round 6 found.
//
// STATUS: the SCOPE COMPUTATION is real and tested. The PROVIDER is not
// deployed -- no account, no bucket, no parent key, and FakeR2Provider is the
// only implementation. See cloud.computedriven.com/status.json.

export class CredentialRefusal extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.name = "CredentialRefusal";
    this.code = code;
  }
}

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// Permission names, and what each is allowed to do. Deliberately not a boolean:
// "read or write" hides the case we actually care about, which is that a sync
// client needs to PUT chunks and must never be able to DELETE them.
//
// THESE ARE COMPUTEDRIVEN CAPABILITY NAMES, NOT PROVIDER ACTION STRINGS, and
// this round they were renamed so that stops being a claim and becomes a fact.
// It used to say `ListBucket` -- which is AWS IAM's action name, so a reader
// could not tell whether it was our word or a provider's, and the code beneath
// it had already decided it was a provider's. `ListObjects` belongs to no
// provider: S3 spells it ListBucket, R2 spells it ListObjectsV1/ListObjectsV2.
// A name no provider uses cannot be accidentally passed through as one.
export const PERMISSIONS = Object.freeze({
  "object-read": Object.freeze(["GetObject", "HeadObject", "ListObjects"]),
  "object-write": Object.freeze(["PutObject", "GetObject", "HeadObject", "ListObjects"]),
});

// Permissions that consume quota and therefore require a storage admission
// (R24 / M1.5). Reading a world you already store costs no new bytes; writing
// to it does, and no write credential exists without reserved bytes behind it.
export const WRITE_PERMISSIONS = Object.freeze(["object-write"]);

// Capabilities that must NEVER appear in an effective authority, whatever a
// provider's preset happens to bundle. Stated in ComputeDriven words; each
// provider vocabulary states the same refusal in its own (r2native.mjs).
export const FORBIDDEN_ALWAYS = Object.freeze([
  "DeleteObject", "DeleteObjects", "CopyObject",
  "PutBucketPolicy", "DeleteBucket", "PutBucketCors",
]);

const MAX_TTL_SECONDS = 3600;
const DEFAULT_TTL_SECONDS = 900;

// A credential shorter than this is not a narrower credential, it is a broken
// one: the client receives something that expires before it can finish a chunk,
// and fails against R2 with a message about signatures rather than about time.
// The floor is enforced at BOTH ends -- a scope may not authorize less, and a
// provider grant may not deliver less -- so the two can never disagree about
// what "usable" means.
export const MIN_TTL_SECONDS = 60;

// ---------------------------------------------------------------------------
// TIME. The security comparison primitive is an INTEGER of epoch seconds, never
// an ISO string.
//
// Round 6 found expiry validated as `typeof === "string"` and then compared
// with Date.parse(), so "not-a-date" produced NaN, `NaN > authorized` is false,
// and every malformed timestamp CONFORMED. A comparison that returns false for
// garbage is worse than one that throws, because it fails in the permissive
// direction and looks like a pass.
// ---------------------------------------------------------------------------

// 2100-01-01. Not a real limit on anything -- it is here so a value like
// 999999999999999999999 is refused as nonsense at the boundary instead of
// silently becoming a credential that outlives the company.
const EPOCH_CEILING = 4102444800;

/**
 * Normalise a timestamp to a finite integer of epoch SECONDS, or refuse.
 * Accepts an integer (already epoch seconds) or an ISO-8601 string.
 */
export function epochSeconds(value, what = "the timestamp") {
  let secs;
  if (typeof value === "number") {
    secs = value;
  } else if (typeof value === "string") {
    const ms = Date.parse(value);
    if (!Number.isFinite(ms)) {
      throw new CredentialRefusal("CD-CRED-EXPIRY",
        `${what} ${JSON.stringify(value)} is not a parseable timestamp`);
    }
    secs = Math.floor(ms / 1000);
  } else {
    throw new CredentialRefusal("CD-CRED-EXPIRY",
      `${what} must be epoch seconds or an ISO-8601 string, got ${typeof value}`);
  }
  if (!Number.isFinite(secs) || !Number.isInteger(secs)) {
    throw new CredentialRefusal("CD-CRED-EXPIRY",
      `${what} is not a finite integer of epoch seconds: ${JSON.stringify(value)}`);
  }
  if (secs <= 0 || secs > EPOCH_CEILING) {
    throw new CredentialRefusal("CD-CRED-EXPIRY",
      `${what} ${secs} is outside the sane range (0, ${EPOCH_CEILING}]`);
  }
  return secs;
}

// ---------------------------------------------------------------------------
// PROVENANCE.
//
// Round 6, and it is the same defect as round 4's fabricated claims object one
// layer down. grantForScope() documented itself as needing "a scope from
// scopeForWorld()" and then checked `typeof scope.prefix === "string"`. A
// hand-built object with `prefix: ""` -- the entire bucket, every tenant -- and
// a 2099 expiry produced a signable grant, and conformance accepted the pair
// because the forgery agreed with itself.
//
// The HTTP route was never exploitable this way; it really does call
// scopeForWorld(). This is a composition defect waiting for the second caller.
//
// A module-private WeakSet is the whole mechanism. Nothing exported can add to
// it, so a structural clone of a real scope is still refused -- being shaped
// like an authorization is not being one.
// ---------------------------------------------------------------------------
const AUTHORIZED_SCOPES = new WeakSet();

export function isAuthorizedScope(scope) {
  return typeof scope === "object" && scope !== null && AUTHORIZED_SCOPES.has(scope);
}

export function assertAuthorizedScope(scope) {
  if (!isAuthorizedScope(scope)) {
    throw new CredentialRefusal(
      "CD-CRED-SCOPE",
      "this is not an authorized scope; a scope must come from scopeForWorld(), " +
      "which is the only thing that can produce one"
    );
  }
  return scope;
}

/**
 * The whole security surface of this module.
 *
 * The organization id is the FIRST path component and is not optional. That is
 * what makes cross-tenant reach impossible rather than merely unlikely: there is
 * no argument combination that yields a prefix outside the caller's own
 * organization, because the prefix is built from the org id rather than
 * validated against it afterwards.
 *
 * WRITE REQUIRES AN ADMISSION (R24). A read scope costs no bytes. A write scope
 * is the artifact that lets a client put objects into a bucket we pay for, so it
 * may not exist without an accepted storage reservation standing behind it --
 * and the admission must be a real one from admitStorage(), for the same
 * provenance reason as above.
 *
 *     CREDENTIAL AUTHORITY IS THE OUTPUT OF ADMISSION, NOT AN INPUT TO MINTING.
 */
export function scopeForWorld({
  bucket,
  organizationId,
  worldId,
  permission = "object-read",
  ttlSeconds = DEFAULT_TTL_SECONDS,
  admission = null,
  objectKey = null,
  now = Date.now(),
} = {}) {
  if (!bucket || typeof bucket !== "string") {
    throw new CredentialRefusal("CD-CRED-BUCKET", "bucket is required");
  }
  // Both ids must be uuids. This is what stops `../` and every other traversal
  // shape without needing to reason about path normalisation at all -- a uuid
  // cannot contain a slash, a dot or a wildcard.
  if (!UUID_RE.test(organizationId ?? "")) {
    throw new CredentialRefusal("CD-CRED-ORG", "organization id is not a uuid");
  }
  if (!UUID_RE.test(worldId ?? "")) {
    throw new CredentialRefusal("CD-CRED-WORLD", "world id is not a uuid");
  }
  if (!Object.hasOwn(PERMISSIONS, permission)) {
    throw new CredentialRefusal(
      "CD-CRED-PERM",
      `unknown permission ${JSON.stringify(permission)}`
    );
  }
  if (!Number.isInteger(ttlSeconds) || ttlSeconds <= 0) {
    throw new CredentialRefusal("CD-CRED-TTL", "ttlSeconds must be a positive integer");
  }
  if (ttlSeconds < MIN_TTL_SECONDS) {
    throw new CredentialRefusal("CD-CRED-TTL",
      `ttlSeconds ${ttlSeconds} is below the ${MIN_TTL_SECONDS}s usable floor`);
  }
  if (ttlSeconds > MAX_TTL_SECONDS) {
    // Clamping silently would be worse: the caller would believe it had an hour
    // when it had fifteen minutes, and the bug would surface as a mid-sync
    // failure hours later.
    throw new CredentialRefusal(
      "CD-CRED-TTL",
      `ttlSeconds ${ttlSeconds} exceeds the ${MAX_TTL_SECONDS}s ceiling`
    );
  }

  let reservationId = null;
  if (WRITE_PERMISSIONS.includes(permission)) {
    // Imported lazily so r2creds.mjs stays a leaf: admission.mjs already needs
    // CredentialRefusal's sibling, and a cycle here would be resolved by
    // whichever module happened to load first.
    const { assertAdmitted } = admissionGuard();
    // Absence and forgery are different operator problems and must not report
    // the same code: "you did not reserve any bytes" is a caller bug, and "this
    // object is not an admission" is a composition bug somewhere upstream.
    if (admission == null) {
      throw new CredentialRefusal("CD-CRED-ADMISSION",
        `permission ${JSON.stringify(permission)} consumes quota and requires a storage admission (R24)`);
    }
    assertAdmitted(admission);
    if (admission.organizationId !== organizationId.toLowerCase()) {
      throw new CredentialRefusal("CD-CRED-ADMISSION",
        "the admission is for a different organization than the scope");
    }
    if (admission.worldId !== worldId.toLowerCase()) {
      throw new CredentialRefusal("CD-CRED-ADMISSION",
        "the admission is for a different world than the scope");
    }
    // A credential must not outlive the reservation that justifies it, or the
    // client keeps uploading into bytes the ledger has already released.
    const admissionExp = epochSeconds(admission.expiresAt, "the admission expiry");
    if (admissionExp < Math.floor(now / 1000) + ttlSeconds) {
      throw new CredentialRefusal("CD-CRED-ADMISSION",
        `the credential would outlive its storage reservation (reservation expires ${admission.expiresAt})`);
    }
    reservationId = admission.reservationId;
  } else if (admission !== null) {
    // Passing an admission for a read is not harmless -- it means a caller
    // believes bytes were reserved for an operation that will never consume
    // them, and the reservation would sit against the quota until it expired.
    throw new CredentialRefusal("CD-CRED-ADMISSION",
      `permission ${JSON.stringify(permission)} consumes no quota and must not carry an admission`);
  }

  const prefix = `org/${organizationId.toLowerCase()}/world/${worldId.toLowerCase()}/`;
  const expiresAtEpochSeconds = Math.floor(now / 1000) + ttlSeconds;

  // OBJECT-SCOPED authority: one exact key rather than a prefix. This is the M2
  // write shape -- one bounded chunk, one key, one short-lived artifact -- and it
  // is narrower than a prefix scope in the dimension that matters, because a
  // credential for `.../chunk/abc` cannot touch `.../chunk/def`.
  //
  // The key must sit INSIDE the world prefix, and it is checked here rather than
  // trusted, because unlike the prefix it is not built from the tenant ids.
  if (objectKey !== null) {
    if (typeof objectKey !== "string" || objectKey === "") {
      throw new CredentialRefusal("CD-CRED-OBJECT", "objectKey must be a non-empty string");
    }
    if (!scopeCovers({ prefix }, objectKey) || objectKey === prefix) {
      throw new CredentialRefusal("CD-CRED-OBJECT",
        `objectKey ${JSON.stringify(objectKey)} is not an object inside ${prefix}`);
    }
  }

  const scope = Object.freeze({
    bucket,
    prefix,
    objectKey,
    permission,
    operations: PERMISSIONS[permission],
    ttlSeconds,
    reservationId,
    expiresAtEpochSeconds,
    // Derived from the integer above, never stored independently, so the wire
    // form and the comparison form cannot drift.
    expiresAt: new Date(expiresAtEpochSeconds * 1000).toISOString(),
  });
  AUTHORIZED_SCOPES.add(scope);
  return scope;
}

// Set by admission.mjs at import time. A function rather than a direct import so
// r2creds.mjs remains loadable on its own -- and so a scope for a WRITE cannot
// be built at all if the admission module was never loaded, which is the safe
// direction to fail.
let _assertAdmitted = null;
export function registerAdmissionGuard(fn) { _assertAdmitted = fn; }
function admissionGuard() {
  if (!_assertAdmitted) {
    throw new CredentialRefusal("CD-CRED-ADMISSION",
      "no admission guard is registered; import admission.mjs before minting a write scope");
  }
  return { assertAdmitted: _assertAdmitted };
}

/**
 * Does `key` fall inside `scope`? Used by the battery to attack a scope, and by
 * any future server-side validation. Kept here so the containment rule lives
 * next to the construction rule and the two cannot drift.
 */
export function scopeCovers(scope, key) {
  if (typeof key !== "string" || key.length === 0) return false;
  // No normalisation games: a key containing a traversal segment is refused
  // outright rather than resolved and then compared.
  if (key.includes("..") || key.includes("//") || key.startsWith("/")) return false;
  return key.startsWith(scope.prefix);
}

// ---------------------------------------------------------------------------
// VOCABULARIES AND THE REFINEMENT LAW.
//
// A vocabulary is a provider's action names plus the declared translation from
// ComputeDriven capabilities into them. The identity vocabulary -- CD words to
// CD words -- is what a provider-independent grant is checked against, and it
// is not a special case in the code: it is the same law with a table whose rows
// are all one-to-one.
// ---------------------------------------------------------------------------

export function makeVocabulary({ provider, actions, translation, forbidden = [] }) {
  const known = new Set(actions);
  // Inverse map, DERIVED. Hand-writing it is how the two directions drift.
  const inverse = new Map();
  for (const [capability, natives] of Object.entries(translation)) {
    for (const n of natives) {
      if (!known.has(n)) {
        throw new CredentialRefusal("CD-CRED-VOCAB",
          `${provider}: translation maps ${capability} to ${n}, which is not in the action vocabulary`);
      }
      if (!inverse.has(n)) inverse.set(n, new Set());
      inverse.get(n).add(capability);
    }
  }
  return Object.freeze({
    provider,
    known,
    inverse,
    forbidden: Object.freeze([...forbidden]),
    /** Every native action the given capabilities expand to. */
    expand(capabilities) {
      const out = [];
      for (const c of capabilities) {
        const natives = translation[c];
        if (!natives) {
          throw new CredentialRefusal("CD-CRED-UNTRANSLATED",
            `${provider}: no translation is declared for the capability ${JSON.stringify(c)}`);
        }
        for (const n of natives) if (!out.includes(n)) out.push(n);
      }
      return out;
    },
  });
}

/** The trivial vocabulary: ComputeDriven capabilities, unchanged. */
export const COMPUTEDRIVEN = makeVocabulary({
  provider: "computedriven",
  actions: [...new Set(Object.values(PERMISSIONS).flat()), ...FORBIDDEN_ALWAYS],
  translation: Object.fromEntries(
    [...new Set(Object.values(PERMISSIONS).flat())].map((c) => [c, [c]])
  ),
  forbidden: FORBIDDEN_ALWAYS,
});

/**
 * The exact artifact a provider-independent adapter must sign. THE ONLY
 * constructor for one.
 *
 * The rule this exists to enforce: DO NOT ASK AN ADAPTER TO DESCRIBE THE
 * AUTHORITY IT MINTED. Check the same immutable object that is subsequently
 * signed. Otherwise a buggy or hostile adapter can hand the checker a narrow
 * description while signing a broad credential, and every conformance test
 * passes against a side-channel that has nothing to do with the artifact.
 *
 * Frozen, and it demands an AUTHORIZED scope -- provenance, not shape.
 */
export function grantForScope(scope) {
  assertAuthorizedScope(scope);
  return Object.freeze({
    provider: "computedriven",
    bucket: scope.bucket,
    prefixPaths: Object.freeze(scope.objectKey ? [] : [scope.prefix]),
    objectPaths: Object.freeze(scope.objectKey ? [scope.objectKey] : []),
    actions: Object.freeze([...scope.operations]),
    expiresAtEpochSeconds: scope.expiresAtEpochSeconds,
    ttlSeconds: scope.ttlSeconds,
  });
}

// A grant has FOUR dimensions and authority can leak through any of them. An
// operations-only check would pass this:
//
//     authorized   bucket=cd  prefix=org/A/world/W/  Get+Put  15 min
//     effective    bucket=cd  prefix=ENTIRE BUCKET   Get+Put  7 days
//
// -- identical actions, and unrestricted reach over every tenant for a week.
function dimensions(grant, what) {
  if (!grant || typeof grant !== "object" || Array.isArray(grant)) {
    throw new CredentialRefusal("CD-CRED-CONFORMANCE",
      `${what} is not a grant object; use grantForScope() or r2GrantForScope()`);
  }
  const { bucket, prefixPaths, actions } = grant;
  if (typeof bucket !== "string" || !Array.isArray(prefixPaths) || !Array.isArray(actions)) {
    throw new CredentialRefusal("CD-CRED-CONFORMANCE",
      `${what} is missing a dimension (bucket, prefixPaths, actions, expiresAtEpochSeconds)`);
  }
  if (grant.expiresAtEpochSeconds === undefined) {
    throw new CredentialRefusal("CD-CRED-CONFORMANCE",
      `${what} has no expiresAtEpochSeconds; an ISO string is not the comparison primitive`);
  }
  return grant;
}

/**
 * THE REFINEMENT LAW. A provider grant conforms to a ComputeDriven scope when it
 * is the EXACT expansion of that scope through the provider's declared
 * translation -- no wider, no narrower, in all four dimensions.
 *
 *   bucket      equal
 *   paths       every provider prefix inside the authorized one, and the
 *               authorized one covered
 *   actions     set-equal to vocabulary.expand(scope.operations), with any
 *               action outside the provider's own vocabulary refused as unknown
 *   expiry      never later than authorized, never below the usable floor
 *
 * Both directions matter and for different reasons. EXCESS is authority the
 * control plane did not decide. MISSING is the silent downgrade -- a client
 * authorized to upload receives a credential that cannot, and finds out from
 * R2, in a message about storage rather than about permission.
 */
export function assertRefines(scope, grant, vocabulary = COMPUTEDRIVEN, { now = Date.now() } = {}) {
  assertAuthorizedScope(scope);
  const g = dimensions(grant, "the effective grant");

  if (g.bucket !== scope.bucket) {
    throw new CredentialRefusal("CD-CRED-WIDENED",
      `provider bucket ${JSON.stringify(g.bucket)} is not ${JSON.stringify(scope.bucket)}`);
  }

  // Every provider prefix must sit INSIDE the authorized prefix. A shorter
  // prefix is a wider reach, which is the failure mode that looks most like
  // success.
  const outside = g.prefixPaths.filter((p) => typeof p !== "string" || !p.startsWith(scope.prefix));
  if (outside.length) {
    throw new CredentialRefusal("CD-CRED-WIDENED",
      `provider prefixes reach outside the scope: ${outside.map((p) => JSON.stringify(p)).join(", ")}`);
  }
  // Exact object paths are a reach too, and a narrower-looking one: an object
  // path outside the prefix is still outside the prefix.
  const strayObjects = (g.objectPaths ?? []).filter(
    (p) => typeof p !== "string" || !p.startsWith(scope.prefix));
  if (strayObjects.length) {
    throw new CredentialRefusal("CD-CRED-WIDENED",
      `provider object paths reach outside the scope: ${strayObjects.map((p) => JSON.stringify(p)).join(", ")}`);
  }
  if (scope.objectKey) {
    // An object-scoped authorization must produce an object-scoped grant. A
    // PREFIX grant here would be a widening that looks like a formatting choice:
    // same bucket, same actions, same expiry, and reach over every chunk in the
    // world instead of the one that was paid for.
    if (g.prefixPaths.length) {
      throw new CredentialRefusal("CD-CRED-WIDENED",
        `object-scoped authority may not carry prefixes: ${g.prefixPaths.join(", ")}`);
    }
    const got = g.objectPaths ?? [];
    if (got.length !== 1 || got[0] !== scope.objectKey) {
      throw new CredentialRefusal(
        got.length ? "CD-CRED-WIDENED" : "CD-CRED-UNDERGRANT",
        `provider object paths ${JSON.stringify(got)} are not exactly [${JSON.stringify(scope.objectKey)}]`);
    }
  } else if (!g.prefixPaths.some((p) => p === scope.prefix || scope.prefix.startsWith(p))) {
    throw new CredentialRefusal("CD-CRED-UNDERGRANT",
      `no provider prefix covers the authorized ${scope.prefix}`);
  }

  // --- expiry, as integers ------------------------------------------------
  const authorized = epochSeconds(scope.expiresAtEpochSeconds, "the authorized expiry");
  const effective = epochSeconds(g.expiresAtEpochSeconds, "the provider expiry");
  const nowSecs = Math.floor(now / 1000);
  if (effective > authorized) {
    throw new CredentialRefusal("CD-CRED-WIDENED",
      `provider expiry ${effective} outlives the authorized ${authorized}`);
  }
  // Deliberately NOT byte-for-byte equality. A provider that rounds a second
  // off its own signing clock has not widened anything and refusing it would be
  // a false alarm forever. The floor is what makes the shorter grant safe to
  // accept: below it the credential is not narrower, it is unusable.
  if (effective - nowSecs < MIN_TTL_SECONDS) {
    throw new CredentialRefusal("CD-CRED-UNDERGRANT",
      `provider expiry leaves ${effective - nowSecs}s, below the ${MIN_TTL_SECONDS}s usable floor`);
  }

  // --- actions, through the translation, in both directions ---------------
  const expected = vocabulary.expand(scope.operations);
  const got = g.actions;

  const unknown = got.filter((a) => typeof a !== "string" || !vocabulary.known.has(a));
  if (unknown.length) {
    // A closed vocabulary, not a deny-list. An action the provider does not
    // define is a refusal whether or not anyone thought to forbid it.
    throw new CredentialRefusal("CD-CRED-UNKNOWNACTION",
      `${vocabulary.provider} does not define: ${unknown.map((a) => JSON.stringify(a)).join(", ")}`);
  }
  const forbidden = got.filter((a) => vocabulary.forbidden.includes(a));
  if (forbidden.length) {
    throw new CredentialRefusal("CD-CRED-FORBIDDEN",
      `provider authority includes always-forbidden operations: ${forbidden.join(", ")}`);
  }
  const excess = got.filter((a) => !expected.includes(a));
  if (excess.length) {
    throw new CredentialRefusal("CD-CRED-WIDENED",
      `provider authority exceeds the scope by: ${excess.join(", ")}`);
  }
  const missing = expected.filter((a) => !got.includes(a));
  if (missing.length) {
    throw new CredentialRefusal("CD-CRED-UNDERGRANT",
      `provider authority is missing authorized operations: ${missing.join(", ")}`);
  }

  return g;
}

/**
 * A mint may proceed only when the grant refines the scope exactly, in the
 * ComputeDriven vocabulary. For a real provider use that provider's own
 * conformance -- assertR2Conformance() -- which is this law with R2's table.
 */
export function assertProviderConformance(scope, effectiveGrant, opts = {}) {
  return assertRefines(scope, effectiveGrant, COMPUTEDRIVEN, opts);
}

/**
 * Provider boundary. The real implementation must issue credentials narrow
 * enough to pass its vocabulary's conformance -- which, given R2's coarse
 * presets bundle deletion, points at locally-signed credentials with an
 * explicit action list rather than the REST preset API. A provider that cannot
 * express the scope exactly must REFUSE rather than approximate it upward.
 *
 * Not deployed: no account, no bucket, no adapter.
 */
export class R2Provider {
  async mint(_scope) {
    throw new CredentialRefusal(
      "CD-CRED-NOTDEPLOYED",
      "no R2 provider is configured; this capability is spec, not local"
    );
  }
}

/**
 * Deterministic fake, for tests only.
 *
 * The credentials it returns are UNMISTAKABLY fake -- the access key literally
 * says so. A fake that returned realistic-looking credentials could be mistaken
 * for a working integration in a log, a screenshot or a demo, and that is
 * exactly the confusion CLOUD_V1.md refuses to allow between `local` and `live`.
 */
export class FakeR2Provider extends R2Provider {
  constructor({ now = Date.now } = {}) {
    super();
    this.now = now;
    this.minted = [];
  }
  async mint(scope) {
    assertAuthorizedScope(scope);
    const record = Object.freeze({
      accessKeyId: "FAKE-NOT-A-REAL-R2-CREDENTIAL",
      secretAccessKey: "FAKE-NOT-A-REAL-R2-CREDENTIAL",
      sessionToken: `fake:${scope.permission}:${scope.prefix}`,
      bucket: scope.bucket,
      prefix: scope.prefix,
      operations: scope.operations,
      expiresAt: scope.expiresAt,
      deployed: false,
    });
    this.minted.push(record);
    return record;
  }
}
