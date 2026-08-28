// OIDC token verification. Verifies tokens Keycloak issued; issues none.
//
// ZERO DEPENDENCIES, and WebCrypto rather than a Node built-in, so the same file
// runs unmodified on workerd and under `node --test`. That is not a stunt: it is
// the only way the battery in test/jwt.test.mjs is testing the code that will
// actually run in production.
//
// WHY NOT `jose`
//
// agents/D-worker-auth.md names `jose` and it is the right call for a service
// verifying many token shapes. This verifies exactly one: RS256, from one
// issuer, against one JWKS. That is ~120 lines of WebCrypto, and every attack it
// has to survive is enumerated in the battery. If the token surface grows past
// one algorithm and one issuer, swap this for `jose` rather than extending it --
// the seam is `verifyToken()` and nothing else imports the internals.
//
// THE RULE THAT MATTERS MOST
//
// The algorithm is a PARAMETER OF THIS MODULE, never a field read from the
// token. `alg: none` and algorithm-confusion attacks both work by getting the
// verifier to take the attacker's word for how to verify. We refuse the token if
// its header disagrees with what we already decided to accept.

export class JwtRefusal extends Error {
  constructor(code, message, detail) {
    super(`${code}: ${message}`);
    this.name = "JwtRefusal";
    this.code = code;
    this.detail = detail;
  }
}

// Proof that a claims object came out of verifyToken(), and not out of a JSON
// body that happens to have the right shape.
//
// A WeakSet rather than a branded class, for one reason that matters: NOTHING
// EXPORTED FROM THIS MODULE CAN ADD TO IT. assertVerified() only reads. So the
// brand cannot be applied by trusted-but-mistaken code elsewhere in the bundle,
// which is exactly the gap the ServerDerivedOrg symbol guard still leaves open
// (deriveTenant() is exported and can be handed anything).
const VERIFIED = new WeakSet();

/**
 * Recursive freeze. Shallow Object.freeze() is not enough here: the Keycloak
 * organization claim is nested, so `claims.organization.acme.id` stays writable
 * under a shallow freeze -- and that field decides which tenant the request
 * lands in.
 *
 * A JWT payload is JSON.parse output, so it is a finite tree with no cycles.
 */
function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const key of Object.getOwnPropertyNames(value)) deepFreeze(value[key]);
  return value;
}

/**
 * Throws unless `claims` is the exact object a successful verifyToken() returned.
 * Structural equality is not enough and is not accepted.
 *
 * The brand alone proved only that an object WAS ONCE verified -- an outside
 * review demonstrated mutating `sub` and a nested organization id after
 * verification while assertVerified() kept saying yes, and authorizeClaims()
 * then resolved the mutated values. Provenance of an object is not provenance of
 * its later contents. So verification now deep-freezes before branding, and the
 * invariant is the stronger one:
 *
 *     THESE EXACT CLAIMS are the verified facts.
 */
export function assertVerified(claims) {
  if (claims === null || typeof claims !== "object" || !VERIFIED.has(claims)) {
    throw new JwtRefusal("CD-JWT-UNVERIFIED",
      "these claims were not produced by verifyToken()");
  }
  return claims;
}

const ALG = "RS256";
const WEBCRYPTO_ALG = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };

// ---------------------------------------------------------------------------
// base64url
// ---------------------------------------------------------------------------

export function b64uToBytes(s) {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s)) {
    throw new JwtRefusal("CD-JWT-B64", "segment is not base64url");
  }
  // A length of 1 mod 4 cannot be produced by any base64 encoding. Rejecting it
  // stops a malformed segment from being silently padded into something valid.
  if (s.length % 4 === 1) {
    throw new JwtRefusal("CD-JWT-B64", "impossible base64url length");
  }
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") +
    (s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4)));
  let bin;
  try {
    bin = atob(b64);
  } catch {
    throw new JwtRefusal("CD-JWT-B64", "segment failed base64 decode");
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64uToJson(s, what) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(b64uToBytes(s));
  } catch (e) {
    if (e instanceof JwtRefusal) throw e;
    throw new JwtRefusal("CD-JWT-UTF8", `${what} is not valid UTF-8`);
  }
  let val;
  try {
    val = JSON.parse(text);
  } catch {
    throw new JwtRefusal("CD-JWT-JSON", `${what} is not JSON`);
  }
  if (val === null || typeof val !== "object" || Array.isArray(val)) {
    throw new JwtRefusal("CD-JWT-JSON", `${what} is not a JSON object`);
  }
  return val;
}

// ---------------------------------------------------------------------------
// JWKS
//
// Cached briefly. A fetch that fails REFUSES rather than falling back to a
// cached key forever -- an issuer that has rotated away from a compromised key
// must be able to make that stick, and a verifier that serves stale keys
// indefinitely defeats rotation entirely.
// ---------------------------------------------------------------------------

export class JwksCache {
  constructor({ jwksUri, fetchImpl = fetch, maxAgeMs = 300_000,
                refreshCooldownMs = 30_000, now = Date.now }) {
    if (!jwksUri) throw new JwtRefusal("CD-JWKS-CONFIG", "jwksUri is required");
    this.jwksUri = jwksUri;
    this.fetchImpl = fetchImpl;
    this.maxAgeMs = maxAgeMs;
    this.refreshCooldownMs = refreshCooldownMs;
    this.now = now;
    this.keys = null;
    this.fetchedAt = 0;
    this.forcedAt = 0;
    this.inflight = null;
  }

  fresh() {
    return this.keys !== null && this.now() - this.fetchedAt < this.maxAgeMs;
  }

  async load(force = false) {
    if (!force && this.fresh()) return this.keys;
    // Collapse concurrent misses onto one fetch. Without this a burst of
    // requests after expiry stampedes the issuer.
    if (this.inflight) return this.inflight;
    this.inflight = (async () => {
      let res;
      try {
        res = await this.fetchImpl(this.jwksUri);
      } catch (e) {
        throw new JwtRefusal("CD-JWKS-FETCH", "JWKS fetch failed", e?.message);
      }
      if (!res || !res.ok) {
        throw new JwtRefusal("CD-JWKS-FETCH", `JWKS fetch returned ${res?.status}`);
      }
      let doc;
      try {
        doc = await res.json();
      } catch {
        throw new JwtRefusal("CD-JWKS-PARSE", "JWKS body is not JSON");
      }
      if (!doc || !Array.isArray(doc.keys)) {
        throw new JwtRefusal("CD-JWKS-PARSE", "JWKS has no keys array");
      }
      this.keys = doc.keys;
      this.fetchedAt = this.now();
      return this.keys;
    })().finally(() => {
      this.inflight = null;
    });
    return this.inflight;
  }

  async findKey(kid) {
    let keys = await this.load();
    let hit = keys.find((k) => k.kid === kid);
    if (!hit && !this.fresh()) return null;
    if (!hit) {
      // An unknown kid is the normal shape of a rotation, so a forced refresh is
      // warranted -- but "one refresh per verification" still lets a caller with
      // 1000 invented kids force 1000 fetches, i.e. choose our request rate
      // against the issuer. The cooldown makes rotation responsive without
      // making the refresh rate an attacker-controlled parameter.
      if (this.now() - this.forcedAt < this.refreshCooldownMs) return null;
      this.forcedAt = this.now();
      keys = await this.load(true);
      hit = keys.find((k) => k.kid === kid);
    }
    return hit ?? null;
  }
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

/**
 * @param token    the compact JWS
 * @param jwks     a JwksCache
 * @param expected { issuer, audience, leewaySeconds?, now?, maxLifetimeSeconds? }
 * @returns the verified claims. Throws JwtRefusal otherwise -- never returns
 *          a "valid: false" object, because a caller can forget to check that.
 */
export async function verifyToken(token, jwks, expected) {
  const { issuer, audience } = expected ?? {};
  if (!issuer || !audience) {
    throw new JwtRefusal("CD-JWT-CONFIG", "issuer and audience are required");
  }
  const leeway = expected.leewaySeconds ?? 60;
  const nowS = Math.floor((expected.now ?? Date.now()) / 1000);

  if (typeof token !== "string" || token.length === 0) {
    throw new JwtRefusal("CD-JWT-SHAPE", "token is not a string");
  }
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new JwtRefusal("CD-JWT-SHAPE", `expected 3 segments, got ${parts.length}`);
  }
  const [h64, p64, s64] = parts;
  if (s64.length === 0) {
    throw new JwtRefusal("CD-JWT-UNSIGNED", "token carries no signature");
  }

  const header = b64uToJson(h64, "header");

  // --- the pin. Read nothing about HOW to verify from the token itself. ---
  if (header.alg !== ALG) {
    throw new JwtRefusal(
      "CD-JWT-ALG",
      `algorithm ${JSON.stringify(header.alg)} refused; only ${ALG} is accepted`
    );
  }
  // A JWK embedded in the header is an attacker handing us the key to check
  // their own signature with. There is no legitimate use here.
  for (const forbidden of ["jwk", "jku", "x5u", "x5c"]) {
    if (forbidden in header) {
      throw new JwtRefusal("CD-JWT-HEADER", `header carries ${forbidden}; refused`);
    }
  }
  // RFC 7515 4.1.11: a recipient that does not understand every extension named
  // in `crit` MUST reject the JWS. We support none, so any crit is a refusal.
  // Accepting a token while ignoring the extensions it declares CRITICAL is the
  // precise thing the field exists to prevent.
  if ("crit" in header) {
    throw new JwtRefusal("CD-JWT-CRIT",
      "header declares critical extensions; none are supported");
  }
  if (typeof header.kid !== "string" || header.kid === "") {
    throw new JwtRefusal("CD-JWT-KID", "header has no kid");
  }

  const jwk = await jwks.findKey(header.kid);
  if (!jwk) throw new JwtRefusal("CD-JWT-KID", `no key for kid ${header.kid}`);
  if (jwk.alg && jwk.alg !== ALG) {
    throw new JwtRefusal("CD-JWT-ALG", `key ${header.kid} is for ${jwk.alg}`);
  }
  if (jwk.use && jwk.use !== "sig") {
    throw new JwtRefusal("CD-JWT-KEYUSE", `key ${header.kid} is not a signing key`);
  }

  let key;
  try {
    key = await crypto.subtle.importKey("jwk", { ...jwk, alg: "RS256", ext: true },
      WEBCRYPTO_ALG, false, ["verify"]);
  } catch (e) {
    throw new JwtRefusal("CD-JWT-KEYIMPORT", "JWKS key could not be imported", e?.message);
  }

  // Signature FIRST. Nothing below this line may act on an unverified claim.
  const signed = new TextEncoder().encode(`${h64}.${p64}`);
  const sig = b64uToBytes(s64);
  const good = await crypto.subtle.verify(WEBCRYPTO_ALG, key, sig, signed);
  if (!good) throw new JwtRefusal("CD-JWT-SIG", "signature does not verify");

  const claims = b64uToJson(p64, "payload");

  if (claims.iss !== issuer) {
    throw new JwtRefusal("CD-JWT-ISS", `issuer ${JSON.stringify(claims.iss)} is not ${issuer}`);
  }

  // aud may be a string or an array. A valid signature on a token minted for a
  // different audience is not authorization for this one.
  const auds = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!auds.includes(audience)) {
    throw new JwtRefusal("CD-JWT-AUD", `audience ${JSON.stringify(claims.aud)} excludes ${audience}`);
  }

  if (typeof claims.exp !== "number") {
    throw new JwtRefusal("CD-JWT-EXP", "token has no numeric exp");
  }
  if (nowS >= claims.exp + leeway) {
    throw new JwtRefusal("CD-JWT-EXP", `expired at ${claims.exp}, now ${nowS}`);
  }
  if (typeof claims.nbf === "number" && nowS + leeway < claims.nbf) {
    throw new JwtRefusal("CD-JWT-NBF", `not valid before ${claims.nbf}, now ${nowS}`);
  }
  // iat is OPTIONAL in RFC 7519, and required HERE, because the lifetime ceiling
  // below is a claimed invariant and cannot be enforced without it. The previous
  // version guarded the ceiling on `typeof iat === "number"`, so a token simply
  // omitting iat skipped the check entirely -- the invariant was advertised and
  // trivially bypassable. A policy that only applies when the caller cooperates
  // is not a policy.
  if (typeof claims.iat !== "number") {
    throw new JwtRefusal("CD-JWT-IAT",
      "token has no numeric iat; the lifetime ceiling cannot be enforced without it");
  }
  if (nowS + leeway < claims.iat) {
    throw new JwtRefusal("CD-JWT-IAT", `issued in the future (${claims.iat}), now ${nowS}`);
  }
  // A token good for a year is a password with extra steps.
  const maxLife = expected.maxLifetimeSeconds ?? 86_400;
  if (claims.exp - claims.iat > maxLife) {
    throw new JwtRefusal("CD-JWT-LIFETIME",
      `lifetime ${claims.exp - claims.iat}s exceeds the ${maxLife}s ceiling`);
  }

  if (typeof claims.sub !== "string" || claims.sub === "") {
    throw new JwtRefusal("CD-JWT-SUB", "token has no sub");
  }

  // Freeze BEFORE branding: an object that could still change must never carry
  // the mark that says it cannot.
  deepFreeze(claims);
  VERIFIED.add(claims);
  return claims;
}
