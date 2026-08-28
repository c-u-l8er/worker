// Battery for the tenant helper, credential scoping and the authenticated path.
//
// The connection is a recording fake, so these assert the SQL CONTRACT and the
// ORDER of operations. Whether PostgreSQL then enforces isolation is a different
// question, answered by test/tenant-isolation.sh against a real cluster. Neither
// suite substitutes for the other: this one proves the Worker asks correctly,
// that one proves the database refuses correctly.

import { test, describe, before } from "node:test";
import assert from "node:assert/strict";
import { JwksCache, verifyToken, assertVerified, JwtRefusal } from "../src/jwt.mjs";
import { makeKeys, mintWith, fakeConn, ISS, AUD, KC_ORG_ID } from "./helpers.mjs";
import {
  withTenant, withoutTenant, deriveTenant, ServerDerivedOrg, TenantRefusal,
} from "../src/tenant.mjs";
import {
  scopeForWorld, scopeCovers, PERMISSIONS, R2Provider, FakeR2Provider,
  assertProviderConformance, grantForScope, isAuthorizedScope,
  FORBIDDEN_ALWAYS, CredentialRefusal, MIN_TTL_SECONDS, epochSeconds,
} from "../src/r2creds.mjs";
import { admitStorage, finalizeStorage, abortStorage } from "../src/admission.mjs";
import {
  authenticate, authorizeClaims, organizationEntries, chooseOrganization,
  permissionFor, AuthzRefusal,
} from "../src/authz.mjs";

const ORG_A = "aaaaaaaa-0000-4000-8000-000000000001";
const ORG_B = "bbbbbbbb-0000-4000-8000-000000000002";
const WORLD = "11111111-0000-4000-8000-00000000000a";

const refusesWith = (fn, Type, code) =>
  assert.rejects(fn, (e) => {
    assert.ok(e instanceof Type, `expected ${Type.name}, got ${e?.name}: ${e?.message}`);
    assert.equal(e.code, code, `expected ${code}, got ${e.code}`);
    return true;
  });

describe("tenant context is server-derived, by construction", () => {
  test("a raw string organization id is refused", async () => {
    await refusesWith(() => withTenant(fakeConn(), ORG_A, async () => 1),
      TenantRefusal, "CD-TENANT-UNVERIFIED");
  });

  test("an object shaped like a tenant is still refused", async () => {
    const forgery = { organizationId: ORG_A, provenance: "trust me" };
    await refusesWith(() => withTenant(fakeConn(), forgery, async () => 1),
      TenantRefusal, "CD-TENANT-UNVERIFIED");
  });

  test("ServerDerivedOrg cannot be constructed directly", () => {
    assert.throws(() => new ServerDerivedOrg(Symbol("nope"), ORG_A, "x"), /CD-TENANT-FORGED/);
  });

  test("deriveTenant refuses a non-uuid", () => {
    assert.throws(() => deriveTenant("'; DROP TABLE cd.worlds; --", "kc:x#y"),
      /CD-TENANT-MALFORMED/);
  });

  test("deriveTenant refuses a tenant with no provenance", () => {
    assert.throws(() => deriveTenant(ORG_A), /CD-TENANT-UNPROVENANCED/);
  });

  test("a derived tenant is frozen", () => {
    const t = deriveTenant(ORG_A, "kc:iss#sub");
    assert.throws(() => { t.organizationId = ORG_B; }, TypeError);
  });
});

describe("withTenant establishes context before any application query", () => {
  test("the order is BEGIN, set context, work, COMMIT", async () => {
    const conn = fakeConn();
    const t = deriveTenant(ORG_A, "kc:iss#sub");
    await withTenant(conn, t, async (tx) => tx.query("SELECT * FROM cd.worlds"));
    assert.deepEqual(conn.log.map((q) => q.sql.split(" ").slice(0, 2).join(" ")), [
      "BEGIN", "SELECT app.set_organization_context($1)", "SELECT *", "COMMIT",
    ].map((s) => s.split(" ").slice(0, 2).join(" ")));
  });

  test("the org id reaches the database as a parameter, never interpolated", async () => {
    const conn = fakeConn();
    await withTenant(conn, deriveTenant(ORG_A, "kc:iss#sub"), async () => {});
    const ctx = conn.log.find((q) => q.sql.includes("set_organization_context"));
    assert.deepEqual(ctx.params, [ORG_A]);
    assert.ok(!ctx.sql.includes(ORG_A), "the uuid must not appear in the SQL text");
  });

  test("context is set before the callback runs, not after", async () => {
    const conn = fakeConn();
    let sawContextFirst = false;
    await withTenant(conn, deriveTenant(ORG_A, "kc:iss#sub"), async () => {
      sawContextFirst = conn.log.some((q) => q.sql.includes("set_organization_context"));
    });
    assert.ok(sawContextFirst);
  });

  test("a throwing callback rolls back and does not commit", async () => {
    const conn = fakeConn();
    await assert.rejects(
      withTenant(conn, deriveTenant(ORG_A, "kc:iss#sub"), async () => {
        throw new Error("application failure");
      }), /application failure/);
    const sqls = conn.log.map((q) => q.sql);
    assert.ok(sqls.includes("ROLLBACK"), "expected ROLLBACK");
    assert.ok(!sqls.includes("COMMIT"), "must not COMMIT after a failure");
  });

  test("a failing ROLLBACK does not mask the original error", async () => {
    const conn = fakeConn({}, { failRollback: true });
    await assert.rejects(
      withTenant(conn, deriveTenant(ORG_A, "kc:iss#sub"), async () => {
        throw new Error("the interesting one");
      }), /the interesting one/);
  });

  test("withoutTenant never establishes a tenant context", async () => {
    const conn = fakeConn();
    await withoutTenant(conn, async (tx) => tx.query("SELECT app.resolve_principal($1,$2,$3)"));
    assert.ok(!conn.log.some((q) => q.sql.includes("set_organization_context")));
  });
});

describe("credential scope is built from the tenant, not checked against it", () => {
  test("the prefix carries the organization id", () => {
    const s = scopeForWorld({ bucket: "cd", organizationId: ORG_A, worldId: WORLD });
    assert.ok(s.prefix.startsWith(`org/${ORG_A}/`), s.prefix);
  });

  test("org A's credential cannot reach org B's objects", () => {
    const a = scopeForWorld({ bucket: "cd", organizationId: ORG_A, worldId: WORLD });
    assert.equal(scopeCovers(a, `org/${ORG_B}/world/${WORLD}/chunk/1`), false);
    assert.equal(scopeCovers(a, `org/${ORG_A}/world/${WORLD}/chunk/1`), true);
  });

  test("traversal in a key is refused rather than normalised", () => {
    const a = scopeForWorld({ bucket: "cd", organizationId: ORG_A, worldId: WORLD });
    for (const evil of [
      `org/${ORG_A}/world/${WORLD}/../../${ORG_B}/x`,
      `/org/${ORG_A}/world/${WORLD}/x`,
      `org/${ORG_A}//world/${WORLD}/x`,
    ]) {
      assert.equal(scopeCovers(a, evil), false, evil);
    }
  });

  test("a non-uuid world id is refused, which is what makes traversal impossible", () => {
    assert.throws(() => scopeForWorld({
      bucket: "cd", organizationId: ORG_A, worldId: "../../etc",
    }), /CD-CRED-WORLD/);
  });

  test("a non-uuid organization id is refused", () => {
    assert.throws(() => scopeForWorld({
      bucket: "cd", organizationId: "*", worldId: WORLD,
    }), /CD-CRED-ORG/);
  });

  test("read permission does not include PutObject", () => {
    assert.ok(!PERMISSIONS["object-read"].includes("PutObject"));
  });

  test("neither permission includes DeleteObject", () => {
    for (const ops of Object.values(PERMISSIONS)) {
      assert.ok(!ops.includes("DeleteObject"), `${ops} must not allow deletion`);
    }
  });

  test("an unknown permission is refused, not defaulted to read", () => {
    assert.throws(() => scopeForWorld({
      bucket: "cd", organizationId: ORG_A, worldId: WORLD, permission: "admin",
    }), /CD-CRED-PERM/);
  });

  test("an over-long ttl is REFUSED rather than silently clamped", () => {
    assert.throws(() => scopeForWorld({
      bucket: "cd", organizationId: ORG_A, worldId: WORLD, ttlSeconds: 86_400,
    }), /CD-CRED-TTL/);
  });
});

describe("a grant has four dimensions and authority leaks through any of them", () => {
  const scope = () => scopeForWorld({
    bucket: "cd", organizationId: ORG_A, worldId: WORLD, permission: "object-read" });
  // grantForScope() is the only constructor. `bend` produces a deviant grant the
  // way a buggy adapter would.
  const bend = (s, over = {}) => Object.freeze({ ...grantForScope(s), ...over });

  test("the grant derived from a scope conforms to it", () => {
    const s = scope();
    assert.deepEqual(assertProviderConformance(s, grantForScope(s)), grantForScope(s));
  });

  test("the derived grant is frozen, so what was checked is what gets signed", () => {
    const g = grantForScope(scope());
    assert.ok(Object.isFrozen(g) && Object.isFrozen(g.actions) && Object.isFrozen(g.prefixPaths));
    assert.throws(() => { g.bucket = "elsewhere"; }, TypeError);
  });

  // --- dimension 1: actions ---
  test("a coarse read-write preset that bundles deletion is REFUSED", () => {
    assert.throws(() => assertProviderConformance(
      scope(), bend(scope(), { actions: ["GetObject", "PutObject", "DeleteObject"] })),
      /CD-CRED-WIDENED|CD-CRED-FORBIDDEN/);
  });

  test("every always-forbidden operation is caught", () => {
    for (const op of FORBIDDEN_ALWAYS) {
      assert.throws(() => assertProviderConformance(scope(), bend(scope(), { actions: [op] })),
        /CD-CRED-WIDENED|CD-CRED-FORBIDDEN|CD-CRED-UNDERGRANT/, op);
    }
  });

  test("an under-grant is refused by the same law as an over-grant", () => {
    // Under-granting is SAFE and is not CONFORMANCE. A client authorized to read
    // and list receives a credential that cannot list, and finds out from R2 in
    // a message about storage rather than about permission.
    assert.throws(() => assertProviderConformance(scope(), bend(scope(), {
      actions: ["GetObject"] })), /CD-CRED-UNDERGRANT/);
  });

  // --- dimension 2: bucket ---
  test("a grant on a different bucket is refused", () => {
    assert.throws(() => assertProviderConformance(
      scope(), bend(scope(), { bucket: "some-other-bucket" })), /CD-CRED-WIDENED/);
  });

  // --- dimension 3: prefix. The leak that looks most like success. ---
  test("a whole-bucket grant with IDENTICAL actions is refused", () => {
    // Same operations, same bucket, same expiry -- and unrestricted reach across
    // every tenant. An operations-only check passed this.
    assert.throws(() => assertProviderConformance(
      scope(), bend(scope(), { prefixPaths: [""] })), /CD-CRED-WIDENED/);
  });

  test("a grant on another organization's prefix is refused", () => {
    assert.throws(() => assertProviderConformance(
      scope(), bend(scope(), { prefixPaths: [`org/${ORG_B}/`] })), /CD-CRED-WIDENED/);
  });

  test("a narrower prefix cannot satisfy the scope", () => {
    const narrow = bend(scope(), {
      prefixPaths: [`${grantForScope(scope()).prefixPaths[0]}chunk/`] });
    assert.throws(() => assertProviderConformance(scope(), narrow), /CD-CRED-UNDERGRANT/);
  });

  test("an object path outside the scope is a reach, not a narrowing", () => {
    assert.throws(() => assertProviderConformance(scope(), bend(scope(), {
      objectPaths: [`org/${ORG_B}/world/${WORLD}/secret`] })), /CD-CRED-WIDENED/);
  });

  // --- dimension 4: expiry ---
  test("a grant that outlives the authorized expiry is refused", () => {
    const s = scope();
    assert.throws(() => assertProviderConformance(s, bend(s, {
      expiresAtEpochSeconds: s.expiresAtEpochSeconds + 7 * 86400,
    })), /CD-CRED-WIDENED/);
  });

  test("a slightly shorter expiry conforms -- provider rounding is not widening", () => {
    const s = scope();
    assert.ok(assertProviderConformance(s, bend(s, {
      expiresAtEpochSeconds: s.expiresAtEpochSeconds - 1,
    })));
  });

  // --- shape ---
  test("a bare action array is no longer accepted as a grant", () => {
    assert.throws(() => assertProviderConformance(scope(), ["GetObject", "PutObject"]),
      /CD-CRED-CONFORMANCE/);
  });

  test("a grant missing a dimension is refused, not partially checked", () => {
    assert.throws(() => assertProviderConformance(scope(), { actions: ["GetObject"] }),
      /CD-CRED-CONFORMANCE/);
  });
});

// ---------------------------------------------------------------------------
// ROUND 6, finding 3. Expiry was validated as `typeof === "string"` and compared
// with Date.parse(). "not-a-date" parses to NaN, `NaN > authorized` is false, and
// every malformed timestamp CONFORMED -- a comparison that returns false for
// garbage, which is the permissive direction.
// ---------------------------------------------------------------------------
describe("expiry is an integer, and malformed time is a refusal not a pass", () => {
  const scope = () => scopeForWorld({
    bucket: "cd", organizationId: ORG_A, worldId: WORLD });
  const bend = (s, over = {}) => Object.freeze({ ...grantForScope(s), ...over });

  test("REPRODUCTION: every malformed expiry that used to conform is now refused", () => {
    for (const bad of ["not-a-date", "", "Invalid Date", NaN, Infinity, null,
                       undefined, {}, 1.5, -1, 999999999999999999999]) {
      assert.throws(
        () => assertProviderConformance(scope(), bend(scope(), { expiresAtEpochSeconds: bad })),
        /CD-CRED-EXPIRY|CD-CRED-CONFORMANCE/,
        `expiry ${JSON.stringify(bad)} must be refused`);
    }
  });

  test("REPRODUCTION: an ALREADY-EXPIRED provider grant no longer conforms", () => {
    const s = scope();
    assert.throws(() => assertProviderConformance(s, bend(s, {
      expiresAtEpochSeconds: Math.floor(Date.now() / 1000) - 60,
    })), /CD-CRED-UNDERGRANT/);
  });

  test("a grant below the usable floor is refused as unusable, not accepted as narrow", () => {
    const s = scope();
    assert.throws(() => assertProviderConformance(s, bend(s, {
      expiresAtEpochSeconds: Math.floor(Date.now() / 1000) + MIN_TTL_SECONDS - 5,
    })), /CD-CRED-UNDERGRANT/);
  });

  test("the floor is enforced at BOTH ends, so the two cannot disagree", () => {
    // A scope may not authorize less than the floor either -- otherwise a caller
    // could ask for 30s and the provider check would refuse its own exact match.
    assert.throws(() => scopeForWorld({
      bucket: "cd", organizationId: ORG_A, worldId: WORLD, ttlSeconds: 30,
    }), /CD-CRED-TTL/);
  });

  test("ISO and epoch are the same instant; the integer is what gets compared", () => {
    const s = scope();
    assert.equal(epochSeconds(s.expiresAt), s.expiresAtEpochSeconds);
  });
});

// ---------------------------------------------------------------------------
// ROUND 6, finding 2. Same defect as round 4's fabricated claims object, one
// layer down: grantForScope() documented itself as needing a scope from
// scopeForWorld() and then checked `typeof scope.prefix === "string"`.
// ---------------------------------------------------------------------------
describe("a scope's authority is proven by provenance, not by shape", () => {
  const FORGED = Object.freeze({
    bucket: "cd",
    prefix: "",                                     // the entire bucket
    permission: "object-write",
    operations: ["GetObject", "PutObject"],
    ttlSeconds: 3600,
    expiresAtEpochSeconds: 4102444799,              // 2099
    expiresAt: "2099-01-01T00:00:00.000Z",
  });

  test("REPRODUCTION: the hand-built whole-bucket scope no longer mints a grant", () => {
    assert.throws(() => grantForScope(FORGED), /CD-CRED-SCOPE/);
  });

  test("and it cannot be laundered through conformance either", () => {
    // The forgery used to agree with itself, so the pair passed.
    assert.throws(() => assertProviderConformance(FORGED, { ...FORGED }), /CD-CRED-SCOPE/);
  });

  test("even a structural CLONE of a real scope is refused", () => {
    const real = scopeForWorld({ bucket: "cd", organizationId: ORG_A, worldId: WORLD });
    const clone = Object.freeze({ ...real });
    assert.deepEqual({ ...clone }, { ...real }, "the clone is field-identical");
    assert.equal(isAuthorizedScope(real), true);
    assert.equal(isAuthorizedScope(clone), false);
    assert.throws(() => grantForScope(clone), /CD-CRED-SCOPE/);
  });

  test("the fake provider will not mint from an unauthorized scope either", async () => {
    await refusesWith(() => new FakeR2Provider().mint(FORGED),
      CredentialRefusal, "CD-CRED-SCOPE");
  });
});

// ---------------------------------------------------------------------------
// R24 / M1.5. The order that makes the sentence true:
//     credential authority is the OUTPUT of admission, not an INPUT to minting.
// ---------------------------------------------------------------------------
describe("a write scope cannot exist without a storage admission", () => {
  const RESERVATION = "dddddddd-0000-4000-8000-00000000000d";
  // A conn that answers reserve_storage the way 0014 does. The DATABASE proves
  // the atomicity (concurrency.sh, group P); this proves the Worker cannot get
  // a write credential without having gone through it.
  const admittingConn = (over = {}) => ({
    async query() {
      return { rows: [{
        reservation_id: RESERVATION, organization_id: ORG_A, world_id: WORLD,
        bytes: 4096, expires_at: new Date(Date.now() + 3600_000),
        tier: "driver", byte_limit: 107374182400,
        committed_bytes: 0, reserved_bytes: 4096, replayed: false, ...over,
      }] };
    },
  });
  const admit = (over) => admitStorage(admittingConn(over), {
    worldId: WORLD, principalId: ORG_B, bytes: 4096, idempotencyKey: "k",
  });

  test("a write scope with NO admission is refused", () => {
    assert.throws(() => scopeForWorld({
      bucket: "cd", organizationId: ORG_A, worldId: WORLD, permission: "object-write",
    }), /CD-CRED-ADMISSION/);
  });

  test("a hand-built admission is refused; only admitStorage() makes one", () => {
    const forged = Object.freeze({
      reservationId: RESERVATION, organizationId: ORG_A, worldId: WORLD,
      bytes: 4096, expiresAt: new Date(Date.now() + 3600_000).toISOString(),
    });
    assert.throws(() => scopeForWorld({
      bucket: "cd", organizationId: ORG_A, worldId: WORLD,
      permission: "object-write", admission: forged,
    }), /CD-ADMISSION-FORGED/);
  });

  test("a real admission mints a write scope, and it records the reservation", async () => {
    const admission = await admit();
    const s = scopeForWorld({
      bucket: "cd", organizationId: ORG_A, worldId: WORLD,
      permission: "object-write", admission,
    });
    assert.equal(s.reservationId, RESERVATION);
    assert.ok(s.operations.includes("PutObject"));
  });

  test("an admission for ANOTHER world cannot mint this world's credential", async () => {
    const admission = await admit({ world_id: "99999999-0000-4000-8000-00000000000f" });
    assert.throws(() => scopeForWorld({
      bucket: "cd", organizationId: ORG_A, worldId: WORLD,
      permission: "object-write", admission,
    }), /CD-CRED-ADMISSION/);
  });

  test("an admission for ANOTHER organization cannot mint this one's credential", async () => {
    const admission = await admit({ organization_id: ORG_B });
    assert.throws(() => scopeForWorld({
      bucket: "cd", organizationId: ORG_A, worldId: WORLD,
      permission: "object-write", admission,
    }), /CD-CRED-ADMISSION/);
  });

  test("a credential may not outlive the reservation that justifies it", async () => {
    // Otherwise the client keeps uploading into bytes the ledger has released.
    const admission = await admit({ expires_at: new Date(Date.now() + 120_000) });
    assert.throws(() => scopeForWorld({
      bucket: "cd", organizationId: ORG_A, worldId: WORLD,
      permission: "object-write", admission, ttlSeconds: 900,
    }), /CD-CRED-ADMISSION/);
  });

  test("a READ scope must NOT carry an admission", async () => {
    // Not harmless: it means bytes were reserved for an operation that will
    // never consume them, and they would hold quota until they expired.
    const admission = await admit();
    assert.throws(() => scopeForWorld({
      bucket: "cd", organizationId: ORG_A, worldId: WORLD,
      permission: "object-read", admission,
    }), /CD-CRED-ADMISSION/);
  });

  test("an idempotency key is required rather than generated", async () => {
    await refusesWith(() => admitStorage(admittingConn(), {
      worldId: WORLD, principalId: ORG_B, bytes: 1,
    }), Error, "CD-ADMISSION-IDEMPOTENCY");
  });

  // Found by the mutation battery, not by review: deleting the overrun check in
  // admission.mjs changed nothing, because only the DATABASE's version of it was
  // tested (battery K14/K25). A duplicated check that only one layer tests is a
  // check with a silent half.
  test("finalizing more bytes than were reserved is refused before the round trip", async () => {
    const admission = await admit();
    await refusesWith(() => finalizeStorage(admittingConn(), admission, {
      actualBytes: admission.bytes + 1,
    }), Error, "CD-FINALIZE-OVERRUN");
  });

  test("the refusal names the reservation the client holds, not a constraint", async () => {
    const admission = await admit();
    await assert.rejects(
      () => finalizeStorage(admittingConn(), admission, { actualBytes: 9999999 }),
      /9999999 bytes written against a 4096 byte reservation/);
  });

  test("finalizing a forged admission is refused", async () => {
    await refusesWith(() => finalizeStorage(admittingConn(),
      { reservationId: RESERVATION, bytes: 10 }, { actualBytes: 1 }),
      Error, "CD-ADMISSION-FORGED");
  });

  test("aborting a forged admission is refused", async () => {
    await refusesWith(() => abortStorage(admittingConn(), { reservationId: RESERVATION }),
      Error, "CD-ADMISSION-FORGED");
  });

  test("a replayed reserve is surfaced, not hidden", async () => {
    const admission = await admit({ replayed: true });
    assert.equal(admission.replayed, true,
      "a client that cannot tell a replay from a fresh reservation double-counts its own uploads");
  });

  test("an empty result from the database is a refusal, not a success", async () => {
    const emptyConn = { async query() { return { rows: [] }; } };
    await refusesWith(() => admitStorage(emptyConn, {
      worldId: WORLD, principalId: ORG_B, bytes: 1, idempotencyKey: "k",
    }), Error, "CD-ADMISSION-EMPTY");
  });

  test("a database refusal keeps its CD- code instead of becoming a 500", async () => {
    const refusing = { async query() {
      throw new Error('CD-QUOTA-EXCEEDED: 8 bytes would exceed the 10 limit');
    } };
    await refusesWith(() => admitStorage(refusing, {
      worldId: WORLD, principalId: ORG_B, bytes: 8, idempotencyKey: "k",
    }), Error, "CD-QUOTA-EXCEEDED");
  });

  test("an UNRECOGNISED database error is re-thrown, not flattened into a refusal", async () => {
    // An unrecognised error is not an admission decision and must not be
    // reported as one -- "connection reset" is not "you are over quota".
    const broken = { async query() { throw new Error("connection reset by peer"); } };
    await assert.rejects(() => admitStorage(broken, {
      worldId: WORLD, principalId: ORG_B, bytes: 8, idempotencyKey: "k",
    }), (e) => {
      assert.equal(e.name, "Error", `expected a plain Error, got ${e.name}`);
      assert.match(e.message, /connection reset/);
      return true;
    });
  });
});

describe("the R2 provider is not deployed and says so", () => {
  test("the base provider refuses by name", async () => {
    await refusesWith(() => new R2Provider().mint({}), CredentialRefusal, "CD-CRED-NOTDEPLOYED");
  });

  test("fake credentials are unmistakably fake", async () => {
    const cred = await new FakeR2Provider().mint(
      scopeForWorld({ bucket: "cd", organizationId: ORG_A, worldId: WORLD }));
    assert.match(cred.accessKeyId, /FAKE-NOT-A-REAL/);
    assert.equal(cred.deployed, false);
  });
});

describe("organizations resolve by STABLE ID, never by alias", () => {
  // R10, and the place the Worker previously undid it: an earlier version fed
  // the ALIAS into resolve_organization()'s p_provider_org_id -- the very column
  // 0003 documents as "Recorded for debugging. Never matched against."
  const KC_ID = "42c3e46f-0000-4000-8000-00000000abcd";

  test("the documented Keycloak shape yields alias AND id", () => {
    assert.deepEqual(
      organizationEntries({ organization: { acme: { id: KC_ID } } }),
      [{ alias: "acme", providerOrgId: KC_ID }]);
  });

  test("no organization claim at all is an empty list, not an error", () => {
    assert.deepEqual(organizationEntries({}), []);
  });

  test("an alias-only array is REFUSED, not silently accepted as an id", () => {
    assert.throws(() => organizationEntries({ organization: ["acme"] }),
      /CD-AUTHZ-ORGID-MISSING/);
  });

  test("an alias-only string is refused too", () => {
    assert.throws(() => organizationEntries({ organization: "acme" }),
      /CD-AUTHZ-ORGID-MISSING/);
  });

  test("an entry whose id is missing names the mapper that has to be fixed", () => {
    try {
      organizationEntries({ organization: { acme: { displayName: "Acme" } } });
      assert.fail("should have thrown");
    } catch (e) {
      assert.equal(e.code, "CD-AUTHZ-ORGID-MISSING");
      assert.match(e.message, /Add organization id/);
    }
  });

  test("an unusable claim shape is refused, not guessed", () => {
    assert.throws(() => organizationEntries({ organization: 42 }), /CD-AUTHZ-ORGCLAIM/);
  });

  test("selection is by alias; resolution carries the id", () => {
    const entries = organizationEntries({ organization: { acme: { id: KC_ID } } });
    assert.equal(chooseOrganization(entries, "acme").providerOrgId, KC_ID);
  });

  test("RENAMING an alias keeps the same organization id", () => {
    const before = organizationEntries({ organization: { acme: { id: KC_ID } } });
    const after  = organizationEntries({ organization: { "acme-inc": { id: KC_ID } } });
    assert.equal(before[0].providerOrgId, after[0].providerOrgId,
      "a rename must not change what resolve_organization is asked for");
    assert.notEqual(before[0].alias, after[0].alias);
  });

  test("REUSING a freed alias for a different org yields a different id", () => {
    const old = organizationEntries({ organization: { acme: { id: KC_ID } } });
    const neu = organizationEntries({
      organization: { acme: { id: "99999999-0000-4000-8000-0000000fffff" } } });
    assert.notEqual(old[0].providerOrgId, neu[0].providerOrgId,
      "alias reuse must not resolve to the previous organization");
  });

  test("two organizations and no request is ambiguous, so it refuses", () => {
    const e = organizationEntries({ organization: { a: { id: KC_ID }, b: { id: "x" } } });
    assert.throws(() => chooseOrganization(e), /CD-AUTHZ-ORGAMBIGUOUS/);
  });

  test("requesting an organization the token does not assert is refused", () => {
    const e = organizationEntries({ organization: { a: { id: KC_ID } } });
    assert.throws(() => chooseOrganization(e, "b"), /CD-AUTHZ-ORGMISMATCH/);
  });

  test("the refusal does not disclose which organizations the token holds", () => {
    const e = organizationEntries({ organization: { "secret-corp": { id: KC_ID } } });
    try {
      chooseOrganization(e, "b");
      assert.fail("should have thrown");
    } catch (err) {
      assert.ok(!err.message.includes("secret-corp"), err.message);
    }
  });

  test("no organization at all is refused", () => {
    assert.throws(() => chooseOrganization([]), /CD-AUTHZ-NOORG/);
  });
});

describe("the client requests an operation; the server decides authority", () => {
  test("a viewer may not obtain write authority", () => {
    assert.throws(() => permissionFor({ role: "viewer", requested: "object-write" }),
      /CD-AUTHZ-WRITEDENIED/);
  });

  test("a viewer may still read", () => {
    assert.equal(permissionFor({ role: "viewer", requested: "object-read" }), "object-read");
  });

  for (const role of ["owner", "admin", "member"]) {
    test(`a ${role} may obtain write authority`, () => {
      assert.equal(permissionFor({ role, requested: "object-write" }), "object-write");
    });
  }

  test("an over-reach is REFUSED, not silently downgraded to read", () => {
    // A silent downgrade fails later, against R2, with a message about storage
    // rather than about permission.
    try {
      permissionFor({ role: "viewer", requested: "object-write" });
      assert.fail("should have thrown");
    } catch (e) {
      assert.equal(e.code, "CD-AUTHZ-WRITEDENIED");
    }
  });

  test("an unknown role grants nothing", () => {
    assert.throws(() => permissionFor({ role: "superuser", requested: "object-read" }),
      /CD-AUTHZ-NOROLE/);
    assert.throws(() => permissionFor({ role: undefined, requested: "object-read" }),
      /CD-AUTHZ-NOROLE/);
  });

  test("an archived world refuses writes even for an owner", () => {
    assert.throws(() => permissionFor({
      role: "owner", requested: "object-write", worldStatus: "archived",
    }), /CD-AUTHZ-WORLDARCHIVED/);
  });

  test("an archived world still permits reads", () => {
    assert.equal(permissionFor({
      role: "owner", requested: "object-read", worldStatus: "archived",
    }), "object-read");
  });

  test("an unknown permission is refused, not defaulted", () => {
    assert.throws(() => permissionFor({ role: "owner", requested: "object-delete" }),
      /CD-AUTHZ-PERM/);
  });
});

describe("membership is the gate, not the token", () => {
  // These drive authenticate() with REAL signed tokens rather than handing
  // authorizeClaims() a plain object. An outside review pointed out that the
  // old block's "claims that were never verified are refused" passed only
  // because `iss` was missing -- it tested SHAPE and was named for PROVENANCE.
  // Now the provenance is what is actually under test.
  const PRINCIPAL = "99999999-0000-4000-8000-00000000000f";
  const ok = {
    "resolve_principal": [{ id: PRINCIPAL }],
    "resolve_organization": [{ id: ORG_A }],
    "membership_role": [{ role: "member" }],
  };
  let keys;
  const jwks = () => new JwksCache({
    jwksUri: "https://auth.invalid/jwks",
    fetchImpl: async () => ({ ok: true, status: 200, json: async () => keys.jwksDoc }),
  });
  const expected = () => ({ issuer: ISS, audience: AUD });
  const auth = (conn, extra = {}) => authenticate({
    token: extra.token, jwks: jwks(), expected: expected(), conn, ...extra,
  });

  before(async () => { keys = await makeKeys(); });

  test("a fully authorized principal yields a usable tenant", async () => {
    const conn = fakeConn(ok);
    const res = await auth(conn, { token: await mintWith(keys.pair) });
    assert.equal(res.organizationId, ORG_A);
    assert.equal(res.principalId, PRINCIPAL);
    assert.ok(res.tenant instanceof ServerDerivedOrg);
    const conn2 = fakeConn();
    await withTenant(conn2, res.tenant, async () => {});
    assert.ok(conn2.log.some((q) => q.sql.includes("set_organization_context")));
  });

  test("resolution carries the STABLE id, not the alias", async () => {
    const conn = fakeConn(ok);
    await auth(conn, { token: await mintWith(keys.pair) });
    const q = conn.log.find((x) => x.sql.includes("resolve_organization"));
    assert.equal(q.params[2], KC_ORG_ID, "resolve_organization must receive the id");
    assert.notEqual(q.params[2], "acme");
  });

  test("the tenant's provenance names the subject it came from", async () => {
    const res = await auth(fakeConn(ok), { token: await mintWith(keys.pair) });
    assert.equal(res.tenant.provenance, `keycloak:${ISS}#user-1`);
  });

  test("resolving is NOT authorizing: a null role yields no tenant", async () => {
    const conn = fakeConn({ ...ok, "membership_role": [{ role: null }] });
    await refusesWith(async () => auth(conn, { token: await mintWith(keys.pair) }),
      AuthzRefusal, "CD-AUTHZ-DENIED");
  });

  test("the role reaches the caller, so authority can be derived from it", async () => {
    const conn = fakeConn({ ...ok, "membership_role": [{ role: "viewer" }] });
    assert.equal((await auth(conn, { token: await mintWith(keys.pair) })).role, "viewer");
  });

  test("a role the policy does not know grants nothing", async () => {
    for (const weird of ["superuser", "", 1, {}, true]) {
      const conn = fakeConn({ ...ok, "membership_role": [{ role: weird }] });
      await refusesWith(async () => auth(conn, { token: await mintWith(keys.pair) }),
        AuthzRefusal, "CD-AUTHZ-DENIED");
    }
  });

  test("a resolver returning no row refuses rather than yielding undefined", async () => {
    const conn = fakeConn({ ...ok, "resolve_organization": [] });
    await refusesWith(async () => auth(conn, { token: await mintWith(keys.pair) }),
      AuthzRefusal, "CD-AUTHZ-ORG");
  });

  test("the resolvers run with NO tenant context", async () => {
    const conn = fakeConn(ok);
    await auth(conn, { token: await mintWith(keys.pair) });
    assert.ok(!conn.log.some((q) => q.sql.includes("set_organization_context")));
  });

  test("a request naming another organization is refused before any query", async () => {
    const conn = fakeConn(ok);
    await refusesWith(
      async () => auth(conn, { token: await mintWith(keys.pair), requestedOrganization: "not-acme" }),
      AuthzRefusal, "CD-AUTHZ-ORGMISMATCH");
    assert.equal(conn.log.length, 0);
  });
});

describe("verified claims are immutable, not merely branded", () => {
  // The brand alone proved an object WAS ONCE verified. Mutating it afterwards
  // kept the brand, and authorizeClaims() then resolved the mutated subject and
  // organization id. Provenance of an object is not provenance of its contents.
  let keys, real;
  const jwks = () => new JwksCache({
    jwksUri: "https://auth.invalid/jwks",
    fetchImpl: async () => ({ ok: true, status: 200, json: async () => keys.jwksDoc }),
  });
  before(async () => {
    keys = await makeKeys();
    real = await verifyToken(await mintWith(keys.pair), jwks(), { issuer: ISS, audience: AUD });
  });

  test("the top level is frozen", () => {
    assert.ok(Object.isFrozen(real));
    assert.throws(() => { real.sub = "attacker"; }, TypeError);
    assert.equal(real.sub, "user-1");
  });

  test("the NESTED organization claim is frozen too", () => {
    // The field that decides which tenant the request lands in. A shallow
    // Object.freeze() would have left this writable.
    assert.ok(Object.isFrozen(real.organization));
    assert.ok(Object.isFrozen(real.organization.acme));
    assert.throws(() => { real.organization.acme.id = ORG_B; }, TypeError);
    assert.equal(real.organization.acme.id, KC_ORG_ID);
  });

  test("a new organization cannot be grafted onto verified claims", () => {
    assert.throws(() => { real.organization.evil = { id: ORG_B }; }, TypeError);
    assert.deepEqual(Object.keys(real.organization), ["acme"]);
  });

  test("authorizeClaims still resolves the ORIGINAL id after a mutation attempt", async () => {
    try { real.organization.acme.id = ORG_B; } catch { /* expected */ }
    const conn = fakeConn({
      "resolve_principal": [{ id: "99999999-0000-4000-8000-00000000000f" }],
      "resolve_organization": [{ id: ORG_A }],
      "membership_role": [{ role: "member" }],
    });
    await authorizeClaims({ claims: real, conn });
    const q = conn.log.find((x) => x.sql.includes("resolve_organization"));
    assert.equal(q.params[2], KC_ORG_ID);
  });
});

describe("verified-claims provenance is proven, not assumed", () => {
  // The brand is a WeakSet inside jwt.mjs. Nothing exported can add to it, so a
  // structurally perfect forgery cannot acquire it -- which is strictly stronger
  // than the ServerDerivedOrg symbol guard, whose factory IS exported.
  let keys;
  before(async () => { keys = await makeKeys(); });

  test("a fabricated claims object is refused by PROVENANCE, not by shape", async () => {
    const forgery = {
      iss: ISS, sub: "attacker", aud: AUD,
      iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 300,
      organization: { acme: { id: KC_ORG_ID } },
    };
    // Every field verifyToken() would have checked is present and correct.
    await refusesWith(() => authorizeClaims({ claims: forgery, conn: fakeConn() }),
      JwtRefusal, "CD-JWT-UNVERIFIED");
  });

  test("even a structural CLONE of verified claims is refused", async () => {
    const real = await verifyToken(await mintWith(keys.pair), new JwksCache({
      jwksUri: "https://auth.invalid/jwks",
      fetchImpl: async () => ({ ok: true, status: 200, json: async () => keys.jwksDoc }),
    }), { issuer: ISS, audience: AUD });
    const clone = JSON.parse(JSON.stringify(real));
    assert.deepEqual(clone, real, "the clone is structurally identical");
    await refusesWith(() => authorizeClaims({ claims: clone, conn: fakeConn() }),
      JwtRefusal, "CD-JWT-UNVERIFIED");
  });

  test("assertVerified accepts the object verifyToken actually returned", async () => {
    const real = await verifyToken(await mintWith(keys.pair), new JwksCache({
      jwksUri: "https://auth.invalid/jwks",
      fetchImpl: async () => ({ ok: true, status: 200, json: async () => keys.jwksDoc }),
    }), { issuer: ISS, audience: AUD });
    assert.equal(assertVerified(real), real);
  });
});
