// AWS SIGNATURE VERSION 4, FOR S3 GET REQUESTS. NO DEPENDENCIES.
//
// FINDING 128, 2026-08-24. Round 8.4 introduced `r2ListingAdapter()` to close
// finding 123 — only a "credentialed adapter" could mint an authoritative sweep.
// It took `{bucket, accessKeyId, secretAccessKey, endpoint, transport}`, checked
// that the strings were non-empty, and branded a closure that called
//
//     transport(url, { method, accessKeyId, secretAccessKey, bucket })
//
// There was no signing anywhere in it. `transport` was supplied by the caller.
// REPRODUCED with a fake key, a fake secret and a transport returning a literal:
//
//     isAuthoritativeSweep(sweep) === true    with NO R2 and NO network
//
// So the defect did not close; it moved one wrapper deeper. An arbitrary
// callback wrapped by a function that validates string lengths is still an
// arbitrary callback.
//
//     A CAPABILITY IS NOT CONFERRED BY THE NAME OF THE FUNCTION THAT WRAPS IT.
//     IF THE ADAPTER DOES NOT PERFORM THE AUTHENTICATED ACT, IT CANNOT ATTEST
//     THAT THE ACT OCCURRED.
//
// Cloudflare documents R2's S3 API as authenticating with an Access Key ID and
// Secret Access Key over **AWS Signature Version 4**. So the adapter has to
// actually sign. This module is that signing, kept separate for one reason: it
// is PURE and therefore exhaustively testable, while the network is not. The
// test seam sits BELOW the signer, so injecting a network cannot skip it.
//
// VERIFIED AGAINST AWS'S OWN PUBLISHED TEST VECTOR — their "Get Bucket (List
// Objects)" worked example, which is the exact request shape this is for. If the
// signature this produces did not equal the one AWS publishes, everything built
// on it would be a well-structured guess. That is the same standard finding 90
// set: the provider's own documented artifact, pasted rather than paraphrased.
//
// R2 specifics: region is `auto` and service is `s3`. Cloudflare accepts `auto`
// as the region for R2's S3 endpoint.

const ENC = new TextEncoder();

/** SHA-256 of an empty body, which every GET has. S3 requires it be SIGNED. */
export const EMPTY_PAYLOAD_SHA256 =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

const hex = (buf) =>
  [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

async function sha256Hex(s) {
  return hex(await crypto.subtle.digest("SHA-256", ENC.encode(s)));
}

async function hmac(key, msg) {
  const k = await crypto.subtle.importKey(
    "raw", key instanceof Uint8Array ? key : ENC.encode(key),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, ENC.encode(msg)));
}

/**
 * RFC 3986 encoding, which is NOT what encodeURIComponent does: it leaves
 * !'()* alone and AWS requires them percent-encoded. Getting this wrong produces
 * a signature that is correct for a request nobody made.
 */
export function uriEncode(str, encodeSlash = true) {
  let out = "";
  for (const ch of String(str)) {
    if (/[A-Za-z0-9\-._~]/.test(ch)) { out += ch; continue; }
    if (ch === "/" && !encodeSlash) { out += ch; continue; }
    for (const b of ENC.encode(ch)) out += "%" + b.toString(16).toUpperCase().padStart(2, "0");
  }
  return out;
}

/** `20130524T000000Z` and `20130524`, from a Date. */
export function amzDate(when) {
  const iso = when.toISOString().replace(/[:-]|\.\d{3}/g, "");
  return { amzdate: iso, datestamp: iso.slice(0, 8) };
}

/**
 * The canonical request (AWS's step 1), returned rather than hidden so the tests
 * can assert it against AWS's published example line for line.
 *
 * @param query  entries as [name, value] pairs. Sorted here by ENCODED name,
 *               which is what AWS specifies — sorting the raw names differs on
 *               exactly the characters that need encoding.
 */
export function canonicalRequest({ method, path, query, headers, payloadSha256 }) {
  const canonicalQuery = [...query]
    .map(([k, v]) => [uriEncode(k), uriEncode(v ?? "")])
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : (a[1] < b[1] ? -1 : 1)))
    .map(([k, v]) => `${k}=${v}`)
    .join("&");

  const lower = Object.entries(headers)
    .map(([k, v]) => [k.toLowerCase(), String(v).trim().replace(/\s+/g, " ")])
    .sort((a, b) => (a[0] < b[0] ? -1 : 1));

  const canonicalHeaders = lower.map(([k, v]) => `${k}:${v}\n`).join("");
  const signedHeaders = lower.map(([k]) => k).join(";");

  return {
    signedHeaders,
    canonical: [
      method,
      uriEncode(path, false) || "/",
      canonicalQuery,
      canonicalHeaders,
      signedHeaders,
      payloadSha256,
    ].join("\n"),
  };
}

/**
 * Sign an S3 GET and return the headers it must carry.
 *
 * @returns { headers, canonical, stringToSign, signature } — everything, because
 *          a signer that returns only its answer cannot be checked against the
 *          provider's worked example.
 */
export async function signS3Get({ accessKeyId, secretAccessKey, region = "auto",
                                  host, path = "/", query = [], when }) {
  const { amzdate, datestamp } = amzDate(when);
  const headers = {
    host,
    "x-amz-content-sha256": EMPTY_PAYLOAD_SHA256,
    "x-amz-date": amzdate,
  };

  const { canonical, signedHeaders } = canonicalRequest({
    method: "GET", path, query, headers, payloadSha256: EMPTY_PAYLOAD_SHA256,
  });

  const scope = `${datestamp}/${region}/s3/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", amzdate, scope, await sha256Hex(canonical)].join("\n");

  let key = await hmac(`AWS4${secretAccessKey}`, datestamp);
  key = await hmac(key, region);
  key = await hmac(key, "s3");
  key = await hmac(key, "aws4_request");
  const signature = hex(await hmac(key, stringToSign));

  return {
    canonical,
    stringToSign,
    signature,
    headers: {
      ...headers,
      Authorization: `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${scope}, ` +
                     `SignedHeaders=${signedHeaders}, Signature=${signature}`,
    },
  };
}
