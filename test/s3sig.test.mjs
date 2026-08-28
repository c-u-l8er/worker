// SIGV4, AGAINST AWS'S OWN PUBLISHED WORKED EXAMPLE.
//
// FINDING 128, 2026-08-24. Round 8.4's "credentialed adapter" performed no
// authentication at all — it wrapped a caller-supplied `transport` and branded
// the result. The fix is only worth anything if the signing is actually correct,
// and "correct" here means BYTE-EQUAL TO WHAT THE PROVIDER PUBLISHES. A signer
// checked against its own author's expectations is finding 90 exactly.
//
// AWS publishes worked examples for SigV4 with S3, including "Get Bucket (List
// Objects)" — the same request shape this system makes. Its canonical request,
// its string to sign and its final signature are all fixed values.

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { signS3Get, canonicalRequest, uriEncode, amzDate, EMPTY_PAYLOAD_SHA256 }
  from "../src/s3sig.mjs";

// AWS's published example credentials. Not real, and famously so.
const AWS_EXAMPLE = {
  accessKeyId: "AKIAIOSFODNN7EXAMPLE",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  region: "us-east-1",
  host: "examplebucket.s3.amazonaws.com",
  when: new Date("2013-05-24T00:00:00Z"),
};

describe("SigV4 reproduces AWS's published signature", () => {
  test("Get Bucket (List Objects) — the exact shape this system signs", async () => {
    const r = await signS3Get({
      ...AWS_EXAMPLE, path: "/", query: [["max-keys", "2"], ["prefix", "J"]],
    });
    assert.equal(r.signature,
      "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
      "if this ever differs, everything built on this signer is a well-structured guess");
  });

  test("the canonical request matches AWS's published text, line for line", async () => {
    const r = await signS3Get({
      ...AWS_EXAMPLE, path: "/", query: [["max-keys", "2"], ["prefix", "J"]],
    });
    assert.equal(r.canonical, [
      "GET",
      "/",
      "max-keys=2&prefix=J",
      "host:examplebucket.s3.amazonaws.com",
      `x-amz-content-sha256:${EMPTY_PAYLOAD_SHA256}`,
      "x-amz-date:20130524T000000Z",
      "",
      "host;x-amz-content-sha256;x-amz-date",
      EMPTY_PAYLOAD_SHA256,
    ].join("\n"));
  });

  test("the string to sign carries the scope AWS specifies", async () => {
    const r = await signS3Get({ ...AWS_EXAMPLE, path: "/", query: [] });
    const lines = r.stringToSign.split("\n");
    assert.equal(lines[0], "AWS4-HMAC-SHA256");
    assert.equal(lines[1], "20130524T000000Z");
    assert.equal(lines[2], "20130524/us-east-1/s3/aws4_request");
    assert.match(lines[3], /^[0-9a-f]{64}$/);
  });
});

describe("the encoding rules that quietly produce a valid signature for the wrong request", () => {
  test("uriEncode is RFC 3986, not encodeURIComponent", () => {
    // encodeURIComponent leaves !'()* alone; AWS requires them encoded. A signer
    // that gets this wrong signs a request nobody made.
    assert.equal(uriEncode("!'()*"), "%21%27%28%29%2A");
    assert.equal(uriEncode("a~b_c-d.e"), "a~b_c-d.e", "unreserved characters stay");
    assert.equal(uriEncode("a/b"), "a%2Fb");
    assert.equal(uriEncode("a/b", false), "a/b", "except in the path");
    assert.equal(uriEncode("é"), "%C3%A9", "UTF-8 bytes, not code points");
  });

  test("the canonical query is sorted by ENCODED name", () => {
    // Sorting raw names differs from sorting encoded ones on exactly the
    // characters that need encoding, which is the subtlest way to be wrong here.
    const { canonical } = canonicalRequest({
      method: "GET", path: "/", query: [["list-type", "2"], ["continuation-token", "t"]],
      headers: { host: "h" }, payloadSha256: EMPTY_PAYLOAD_SHA256,
    });
    assert.match(canonical, /continuation-token=t&list-type=2/);
  });

  test("headers are lowercased, trimmed and sorted, and signed headers agree", () => {
    const { canonical, signedHeaders } = canonicalRequest({
      method: "GET", path: "/", query: [],
      headers: { "X-Amz-Date": "  20130524T000000Z  ", Host: "h" },
      payloadSha256: EMPTY_PAYLOAD_SHA256,
    });
    assert.equal(signedHeaders, "host;x-amz-date");
    assert.match(canonical, /host:h\nx-amz-date:20130524T000000Z\n/);
  });

  test("amzDate produces both forms the signature needs", () => {
    const { amzdate, datestamp } = amzDate(new Date("2026-08-24T13:05:09.123Z"));
    assert.equal(amzdate, "20260824T130509Z");
    assert.equal(datestamp, "20260824");
  });

  test("a different secret produces a different signature", async () => {
    const a = await signS3Get({ ...AWS_EXAMPLE, path: "/", query: [] });
    const b = await signS3Get({ ...AWS_EXAMPLE, secretAccessKey: "different", path: "/", query: [] });
    assert.notEqual(a.signature, b.signature);
  });

  test("R2's region is `auto`, and it reaches the scope", async () => {
    const r = await signS3Get({ ...AWS_EXAMPLE, region: "auto", path: "/cd-worlds", query: [] });
    assert.match(r.headers.Authorization, /\/auto\/s3\/aws4_request/);
  });
});
