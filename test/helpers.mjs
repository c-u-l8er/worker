// Shared test rig: a real RSA keypair, a real JWKS, and real signed tokens.
//
// Every knob an attacker would turn is a parameter, so a negative test can bend
// exactly one thing. Nothing here mocks verifyToken -- the tokens are genuinely
// signed and genuinely verified, which is the only way a suite named "unverified
// claims are refused" can mean anything.

export const WEBCRYPTO_ALG = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
export const ISS = "https://auth.computedriven.com/realms/cd";
export const AUD = "computedriven-cloud";
export const KC_ORG_ID = "42c3e46f-0000-4000-8000-00000000abcd";

export const b64uStr = (s) => Buffer.from(s, "utf8").toString("base64url");
export const b64uBytes = (b) => Buffer.from(b).toString("base64url");

export async function makeKeys() {
  const gen = () => crypto.subtle.generateKey(
    { ...WEBCRYPTO_ALG, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
    true, ["sign", "verify"]);
  const pair = await gen();
  const other = await gen();
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  return {
    pair,
    other,
    jwksDoc: { keys: [{ ...jwk, kid: "k1", use: "sig", alg: "RS256" }] },
  };
}

export async function mintWith(pair, payloadOverrides = {}, opts = {}) {
  const {
    kid = "k1", alg = "RS256", extraHeader = {},
    signWith = pair.privateKey, tamperPayload = null, signature = null,
  } = opts;
  const nowS = Math.floor(Date.now() / 1000);
  const payload = {
    iss: ISS, aud: AUD, sub: "user-1",
    iat: nowS, exp: nowS + 300,
    organization: { acme: { id: KC_ORG_ID } },
    ...payloadOverrides,
  };
  const h = b64uStr(JSON.stringify({ alg, kid, typ: "JWT", ...extraHeader }));
  const p = b64uStr(JSON.stringify(payload));
  const sig = signature ?? b64uBytes(new Uint8Array(
    await crypto.subtle.sign(WEBCRYPTO_ALG, signWith,
      new TextEncoder().encode(`${h}.${p}`))));
  return `${h}.${tamperPayload ? b64uStr(JSON.stringify(tamperPayload)) : p}.${sig}`;
}

/** Records every statement in order and answers from a scripted table. */
export function fakeConn(answers = {}, { failRollback = false } = {}) {
  const log = [];
  return {
    log,
    async query(sql, params) {
      log.push({ sql, params });
      if (failRollback && sql === "ROLLBACK") throw new Error("rollback failed");
      for (const [needle, rows] of Object.entries(answers)) {
        if (sql.includes(needle)) return { rows };
      }
      return { rows: [] };
    },
  };
}
