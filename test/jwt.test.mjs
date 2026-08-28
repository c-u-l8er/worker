// Token-verification battery. Mostly negative, for the same reason the SQL one
// is: a happy-path suite here would pass against a verifier that checked nothing
// but the signature, and every interesting attack on a JWT verifier gets past
// exactly that verifier.
//
// Runs under plain `node --test`. No account, no network, no dependencies -- the
// keypair is generated in-process and the JWKS is served from a function.

import { test, describe, before } from "node:test";
import assert from "node:assert/strict";
import { verifyToken, JwksCache, JwtRefusal, b64uToBytes } from "../src/jwt.mjs";

const WEBCRYPTO_ALG = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
const ISS = "https://auth.computedriven.com/realms/cd";
const AUD = "computedriven-cloud";

let pair, otherPair, jwksDoc, fetchCalls;

const b64uStr = (s) => Buffer.from(s, "utf8").toString("base64url");
const b64uBytes = (b) => Buffer.from(b).toString("base64url");

async function publicJwk(p, kid) {
  const jwk = await crypto.subtle.exportKey("jwk", p.publicKey);
  return { ...jwk, kid, use: "sig", alg: "RS256" };
}

/** Mint a token. Every knob an attacker would turn is a parameter. */
async function mint(payloadOverrides = {}, opts = {}) {
  const {
    kid = "k1",
    alg = "RS256",
    extraHeader = {},
    signWith = pair.privateKey,
    tamperPayload = null,
    signature = null,
  } = opts;
  const nowS = Math.floor(Date.now() / 1000);
  const payload = {
    iss: ISS, aud: AUD, sub: "user-1",
    iat: nowS, exp: nowS + 300,
    organization: ["acme"],
    ...payloadOverrides,
  };
  const h = b64uStr(JSON.stringify({ alg, kid, typ: "JWT", ...extraHeader }));
  const p = b64uStr(JSON.stringify(payload));
  const signed = `${h}.${p}`;
  const sig = signature ?? b64uBytes(
    new Uint8Array(await crypto.subtle.sign(WEBCRYPTO_ALG, signWith,
      new TextEncoder().encode(signed)))
  );
  const finalPayload = tamperPayload ? b64uStr(JSON.stringify(tamperPayload)) : p;
  return `${h}.${finalPayload}.${sig}`;
}

function cache(doc = jwksDoc, { fail = false } = {}) {
  return new JwksCache({
    jwksUri: "https://auth.invalid/jwks",
    fetchImpl: async () => {
      fetchCalls++;
      if (fail) throw new Error("network down");
      return { ok: true, status: 200, json: async () => doc };
    },
  });
}

const expected = () => ({ issuer: ISS, audience: AUD });

async function refuses(fn, code) {
  await assert.rejects(fn, (e) => {
    assert.ok(e instanceof JwtRefusal, `expected JwtRefusal, got ${e?.name}: ${e?.message}`);
    assert.equal(e.code, code, `expected ${code}, got ${e.code} (${e.message})`);
    return true;
  });
}

before(async () => {
  const gen = () => crypto.subtle.generateKey(
    { ...WEBCRYPTO_ALG, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
    true, ["sign", "verify"]);
  pair = await gen();
  otherPair = await gen();
  jwksDoc = { keys: [await publicJwk(pair, "k1")] };
  fetchCalls = 0;
});

describe("happy path", () => {
  test("a well-formed token verifies and returns its claims", async () => {
    const claims = await verifyToken(await mint(), cache(), expected());
    assert.equal(claims.sub, "user-1");
    assert.equal(claims.iss, ISS);
  });

  test("aud may be an array containing our audience", async () => {
    const claims = await verifyToken(
      await mint({ aud: ["someone-else", AUD] }), cache(), expected());
    assert.deepEqual(claims.aud, ["someone-else", AUD]);
  });

  test("an expiry inside the leeway is still accepted", async () => {
    const nowS = Math.floor(Date.now() / 1000);
    const claims = await verifyToken(
      await mint({ exp: nowS - 30 }), cache(), { ...expected(), leewaySeconds: 60 });
    assert.equal(claims.sub, "user-1");
  });
});

describe("algorithm is a parameter of the verifier, never of the token", () => {
  // The classic alg:none attack ships an EMPTY signature, and that is refused a
  // step earlier than the algorithm pin -- by the unsigned check. Both paths are
  // asserted rather than picking whichever one happened to fire, because the
  // ordering is deliberate: refuse an unsigned token before touching anything
  // else about it.
  test("alg: none with an empty signature is refused as unsigned", async () => {
    await refuses(async () => verifyToken(
      await mint({}, { alg: "none", signature: "" }), cache(), expected()), "CD-JWT-UNSIGNED");
  });

  test("alg: none carrying a bogus signature is refused by the algorithm pin", async () => {
    await refuses(async () => verifyToken(
      await mint({}, { alg: "none", signature: "ZmFrZQ" }), cache(), expected()), "CD-JWT-ALG");
  });

  test("alg: HS256 is refused (algorithm confusion)", async () => {
    await refuses(async () => verifyToken(
      await mint({}, { alg: "HS256" }), cache(), expected()), "CD-JWT-ALG");
  });

  test("alg: RS512 is refused even though it is stronger", async () => {
    await refuses(async () => verifyToken(
      await mint({}, { alg: "RS512" }), cache(), expected()), "CD-JWT-ALG");
  });

  test("a key whose JWKS alg disagrees with the pin is refused", async () => {
    const doc = { keys: [{ ...(await publicJwk(pair, "k1")), alg: "RS512" }] };
    await refuses(async () => verifyToken(await mint(), cache(doc), expected()), "CD-JWT-ALG");
  });

  test("an encryption key is not a signing key", async () => {
    const doc = { keys: [{ ...(await publicJwk(pair, "k1")), use: "enc" }] };
    await refuses(async () => verifyToken(await mint(), cache(doc), expected()), "CD-JWT-KEYUSE");
  });
});

describe("the token does not get to supply its own key", () => {
  for (const field of ["jwk", "jku", "x5u", "x5c"]) {
    test(`a header carrying ${field} is refused`, async () => {
      await refuses(async () => verifyToken(
        await mint({}, { extraHeader: { [field]: "anything" } }), cache(), expected()),
        "CD-JWT-HEADER");
    });
  }

  test("a missing kid is refused rather than trying every key", async () => {
    const h = b64uStr(JSON.stringify({ alg: "RS256", typ: "JWT" }));
    const p = b64uStr(JSON.stringify({ iss: ISS, aud: AUD, sub: "u", exp: 9e9 }));
    const sig = b64uBytes(new Uint8Array(await crypto.subtle.sign(
      WEBCRYPTO_ALG, pair.privateKey, new TextEncoder().encode(`${h}.${p}`))));
    await refuses(async () => verifyToken(`${h}.${p}.${sig}`, cache(), expected()), "CD-JWT-KID");
  });

  test("an unknown kid is refused", async () => {
    await refuses(async () => verifyToken(
      await mint({}, { kid: "nope" }), cache(), expected()), "CD-JWT-KID");
  });
});

describe("signature", () => {
  test("a token signed by a different key with the same kid is refused", async () => {
    await refuses(async () => verifyToken(
      await mint({}, { signWith: otherPair.privateKey }), cache(), expected()), "CD-JWT-SIG");
  });

  test("a tampered payload invalidates the signature", async () => {
    const nowS = Math.floor(Date.now() / 1000);
    const token = await mint({}, {
      tamperPayload: { iss: ISS, aud: AUD, sub: "admin", exp: nowS + 300 },
    });
    await refuses(async () => verifyToken(token, cache(), expected()), "CD-JWT-SIG");
  });

  test("an empty signature is refused before any crypto runs", async () => {
    const t = await mint();
    const [h, p] = t.split(".");
    await refuses(async () => verifyToken(`${h}.${p}.`, cache(), expected()), "CD-JWT-UNSIGNED");
  });
});

describe("claims", () => {
  test("a different issuer is refused", async () => {
    await refuses(async () => verifyToken(
      await mint({ iss: "https://evil.invalid/realms/cd" }), cache(), expected()), "CD-JWT-ISS");
  });

  test("a token minted for another audience is refused", async () => {
    await refuses(async () => verifyToken(
      await mint({ aud: "some-other-service" }), cache(), expected()), "CD-JWT-AUD");
  });

  test("an expired token is refused", async () => {
    const nowS = Math.floor(Date.now() / 1000);
    await refuses(async () => verifyToken(
      await mint({ iat: nowS - 4000, exp: nowS - 3600 }), cache(), expected()), "CD-JWT-EXP");
  });

  test("a not-yet-valid token is refused", async () => {
    const nowS = Math.floor(Date.now() / 1000);
    await refuses(async () => verifyToken(
      await mint({ nbf: nowS + 3600 }), cache(), expected()), "CD-JWT-NBF");
  });

  test("a token issued in the future is refused", async () => {
    const nowS = Math.floor(Date.now() / 1000);
    await refuses(async () => verifyToken(
      await mint({ iat: nowS + 3600, exp: nowS + 7200 }), cache(), expected()), "CD-JWT-IAT");
  });

  test("a token with a year-long lifetime is refused", async () => {
    const nowS = Math.floor(Date.now() / 1000);
    await refuses(async () => verifyToken(
      await mint({ iat: nowS, exp: nowS + 31_536_000 }), cache(), expected()), "CD-JWT-LIFETIME");
  });

  test("a token with no sub is refused", async () => {
    await refuses(async () => verifyToken(
      await mint({ sub: undefined }), cache(), expected()), "CD-JWT-SUB");
  });

  test("exp must be a number, not a string", async () => {
    await refuses(async () => verifyToken(
      await mint({ exp: "9999999999" }), cache(), expected()), "CD-JWT-EXP");
  });
});

describe("the three edges an outside review found", () => {
  test("a header declaring critical extensions is refused (RFC 7515 4.1.11)", async () => {
    await refuses(async () => verifyToken(
      await mint({}, { extraHeader: { crit: ["exp"] } }), cache(), expected()), "CD-JWT-CRIT");
  });

  test("an empty crit array is still refused rather than special-cased", async () => {
    await refuses(async () => verifyToken(
      await mint({}, { extraHeader: { crit: [] } }), cache(), expected()), "CD-JWT-CRIT");
  });

  // The lifetime ceiling used to be guarded on `typeof iat === "number"`, so a
  // token simply OMITTING iat skipped it. The invariant was advertised and
  // trivially bypassable: exp a year out, no iat, accepted.
  test("a token with no iat is refused, because the lifetime ceiling needs it", async () => {
    const nowS = Math.floor(Date.now() / 1000);
    await refuses(async () => verifyToken(
      await mint({ iat: undefined, exp: nowS + 31_536_000 }), cache(), expected()),
      "CD-JWT-IAT");
  });

  test("a year-long token cannot evade the ceiling by dropping iat", async () => {
    const nowS = Math.floor(Date.now() / 1000);
    // with iat -> LIFETIME; without iat -> IAT. Either way, refused.
    await refuses(async () => verifyToken(
      await mint({ iat: nowS, exp: nowS + 31_536_000 }), cache(), expected()),
      "CD-JWT-LIFETIME");
  });

  // "One forced refresh per verification" still lets 1000 invented kids force
  // 1000 fetches -- the caller choosing our request rate against the issuer.
  test("unknown kids cannot flood the issuer with forced refreshes", async () => {
    let calls = 0, t = 0;
    const c = new JwksCache({
      jwksUri: "https://auth.invalid/jwks",
      now: () => t,
      refreshCooldownMs: 30_000,
      fetchImpl: async () => {
        calls++;
        return { ok: true, status: 200, json: async () => jwksDoc };
      },
    });
    for (let i = 0; i < 50; i++) {
      await refuses(async () => verifyToken(
        await mint({}, { kid: `bogus-${i}` }), c, expected()), "CD-JWT-KID");
    }
    assert.ok(calls <= 2, `expected at most 2 fetches for 50 bogus kids, got ${calls}`);
  });

  test("but rotation still works once the cooldown has elapsed", async () => {
    let t = 0, doc = { keys: [] };
    const c = new JwksCache({
      jwksUri: "https://auth.invalid/jwks",
      now: () => t,
      refreshCooldownMs: 30_000,
      maxAgeMs: 300_000,
      fetchImpl: async () => ({ ok: true, status: 200, json: async () => doc }),
    });
    await refuses(async () => verifyToken(await mint(), c, expected()), "CD-JWT-KID");
    doc = jwksDoc;
    t += 31_000;                     // cooldown elapsed
    const claims = await verifyToken(await mint(), c, expected());
    assert.equal(claims.sub, "user-1");
  });
});

describe("shape", () => {
  test("a two-segment token is refused", async () => {
    await refuses(async () => verifyToken("a.b", cache(), expected()), "CD-JWT-SHAPE");
  });
  test("an empty string is refused", async () => {
    await refuses(async () => verifyToken("", cache(), expected()), "CD-JWT-SHAPE");
  });
  test("a non-base64url header is refused", async () => {
    await refuses(async () => verifyToken("!!!.e30.sig", cache(), expected()), "CD-JWT-B64");
  });
  test("an impossible base64url length is refused", () => {
    assert.throws(() => b64uToBytes("AAAAA".slice(0, 5)), /CD-JWT-B64/);
  });
  test("a header that is a JSON array is refused", async () => {
    const h = b64uStr(JSON.stringify(["alg", "RS256"]));
    await refuses(async () => verifyToken(`${h}.e30.sig`, cache(), expected()), "CD-JWT-JSON");
  });
});

describe("JWKS handling", () => {
  test("a JWKS fetch failure refuses; it does not fall back to a cached key", async () => {
    const c = cache(jwksDoc, { fail: true });
    await refuses(async () => verifyToken(await mint(), c, expected()), "CD-JWKS-FETCH");
  });

  test("a non-200 JWKS response refuses", async () => {
    const c = new JwksCache({
      jwksUri: "https://auth.invalid/jwks",
      fetchImpl: async () => ({ ok: false, status: 503, json: async () => ({}) }),
    });
    await refuses(async () => verifyToken(await mint(), c, expected()), "CD-JWKS-FETCH");
  });

  test("a JWKS with no keys array refuses", async () => {
    const c = new JwksCache({
      jwksUri: "https://auth.invalid/jwks",
      fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({ nope: 1 }) }),
    });
    await refuses(async () => verifyToken(await mint(), c, expected()), "CD-JWKS-PARSE");
  });

  test("an unknown kid triggers exactly one refresh, not one per attempt", async () => {
    let calls = 0;
    const c = new JwksCache({
      jwksUri: "https://auth.invalid/jwks",
      fetchImpl: async () => {
        calls++;
        return { ok: true, status: 200, json: async () => jwksDoc };
      },
    });
    await refuses(async () => verifyToken(await mint({}, { kid: "rotated" }), c, expected()),
      "CD-JWT-KID");
    assert.equal(calls, 2, "expected initial load + one forced refresh");
  });

  test("rotation works: a key that appears on refresh verifies", async () => {
    let doc = { keys: [] };
    const c = new JwksCache({
      jwksUri: "https://auth.invalid/jwks",
      fetchImpl: async () => ({ ok: true, status: 200, json: async () => doc }),
    });
    await c.load();                 // prime with the empty set
    doc = jwksDoc;                  // issuer rotates in the real key
    const claims = await verifyToken(await mint(), c, expected());
    assert.equal(claims.sub, "user-1");
  });

  test("the cache is used: a second verify does not refetch", async () => {
    let calls = 0;
    const c = new JwksCache({
      jwksUri: "https://auth.invalid/jwks",
      fetchImpl: async () => {
        calls++;
        return { ok: true, status: 200, json: async () => jwksDoc };
      },
    });
    await verifyToken(await mint(), c, expected());
    await verifyToken(await mint(), c, expected());
    assert.equal(calls, 1);
  });
});

describe("configuration", () => {
  test("verifying without an expected audience is refused, not defaulted", async () => {
    await refuses(async () => verifyToken(await mint(), cache(), { issuer: ISS }), "CD-JWT-CONFIG");
  });
  test("verifying without an expected issuer is refused", async () => {
    await refuses(async () => verifyToken(await mint(), cache(), { audience: AUD }), "CD-JWT-CONFIG");
  });
});
