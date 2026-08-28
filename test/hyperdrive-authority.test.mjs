// CASE Q's predicate (R17, R80, findings 95 / 101 / 102).
//
// A gate that can only be exercised by having a Cloudflare account is a gate
// nobody exercises — finding 88's lesson, and the reason check-queue-authority
// was split into a pure verdict plus a thin runner. Same shape here.
//
// THE FIXTURES ARE PROVIDER-SHAPED ON PURPOSE. They are built from Cloudflare's
// OpenAPI schema for GET /accounts/{account_id}/hyperdrive/configs/{id}:
// `caching` is the oneOf discriminated on `disabled`; `origin` is the oneOf over
// internet / over-Access / VPC-service, all three of which carry the
// database-full fields (scheme, database, user) and none of which return
// `password`, which the schema marks write-only.
//
// That matters because finding 96 in the file next door was exactly this mistake
// one layer down: a battery that passes against a shape the provider does not
// return proves the shape, not the property.

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  hyperdriveAuthorityVerdict, vpcServiceVerdict, originVariant, EXPECTED,
} from "../../scripts/check-hyperdrive-authority.mjs";

const DB = "computedriven";
const VPC = "0123456789abcdef0123456789abcdef";
const TUNNEL = "0191dce4-9ab4-7fce-b660-8e5dec5172da";  // CF's own example id
const TARGET = "10.0.0.5";
const PORT = 5432;

/** CLOUD_V1's topology: Hyperdrive -> Workers VPC -> Cloudflare Tunnel -> Pigsty. */
const cfg = (role, over = {}) => ({
  id: role === "CONTROL" ? "aaaa1111" : "bbbb2222",
  name: `cd-${role.toLowerCase()}`,
  caching: { disabled: true },
  origin: {
    scheme: "postgres",
    database: DB,
    user: EXPECTED[role].user,
    service_id: VPC,
    ...(over.origin ?? {}),
  },
  ...(() => { const { origin, ...rest } = over; return rest; })(),
});

const ok = (over = {}) =>
  hyperdriveAuthorityVerdict(cfg("CONTROL", over.control), cfg("JOBS", over.jobs),
                             { database: DB, vpcServiceId: VPC });

const refusedBy = (v, re) => {
  assert.equal(v.ok, false, "expected a refusal, got ok");
  assert.ok(v.refusals.some((r) => re.test(r)),
    `no refusal matched ${re}\n  got: ${v.refusals.join("\n       ")}`);
};

describe("the control case", () => {
  test("two configs, two logins, one database, cache off — passes", () => {
    const v = ok();
    assert.equal(v.ok, true, v.refusals.join(" | "));
    assert.equal(v.observed.CONTROL.user, "computedriven_api_login");
    assert.equal(v.observed.JOBS.user, "computedriven_jobs_login");
  });

  test("it says out loud what it CANNOT prove", () => {
    // The password is write-only and never returned, so this gate attests the
    // named user and not the secret. A gate that stays quiet about its own
    // blind spot is how "attested" comes to mean more than it does.
    assert.ok(ok().notes.some((n) => /write-only/.test(n)));
  });
});

describe("finding 95 — the reproduction, at the provider this time", () => {
  test("two bindings resolving to ONE configuration is REFUSED", () => {
    // check-channel-identity.mjs exited 0 on exactly this before R80.1: it read
    // binding NAMES, and two names over one id is one credential wearing two
    // hats — finding 94 surviving one level up.
    const v = hyperdriveAuthorityVerdict(cfg("CONTROL"), cfg("JOBS", { id: "aaaa1111" }),
                                         { database: DB, vpcServiceId: VPC });
    refusedBy(v, /SAME Hyperdrive configuration/);
  });

  test("two DISTINCT configurations authenticating as one user is REFUSED", () => {
    // The subtler half, and the one no file can catch: distinct config ids may
    // still carry the same origin credential. Then connect() and connectJobs()
    // are separate functions over separate bindings over separate configs over
    // ONE PostgreSQL role, and the request path holds EXECUTE on
    // app.observe_storage_object().
    const v = hyperdriveAuthorityVerdict(
      cfg("CONTROL"),
      cfg("JOBS", { origin: { user: EXPECTED.CONTROL.user } }),
      { database: DB, vpcServiceId: VPC });
    refusedBy(v, /authenticate as/);
  });

  test("the WRONG user in the right binding is REFUSED", () => {
    const v = ok({ jobs: { origin: { user: "postgres" } } });
    refusedBy(v, /HYPERDRIVE_JOBS: origin\.user is "postgres"/);
  });

  test("an absent user is REFUSED, not defaulted", () => {
    const v = hyperdriveAuthorityVerdict(
      cfg("CONTROL"),
      { ...cfg("JOBS"), origin: { scheme: "postgres", database: DB, service_id: VPC } },
      { database: DB, vpcServiceId: VPC });
    refusedBy(v, /states no user/);
  });

  test("two authorities over DIFFERENT databases is REFUSED", () => {
    // The observer writing where the request path does not read would make every
    // occupancy number in the control plane describe a database nobody queries.
    const v = ok({ jobs: { origin: { service_id: "ffff0000ffff0000ffff0000ffff0000" } } });
    refusedBy(v, /DIFFERENT origins/);
  });

  test("the check must be told which database AND which VPC service to expect", () => {
    refusedBy(hyperdriveAuthorityVerdict(cfg("CONTROL"), cfg("JOBS"), {}), /subject is unnamed/);
    refusedBy(hyperdriveAuthorityVerdict(cfg("CONTROL"), cfg("JOBS"), { database: DB }),
              /which Workers VPC Service/);
  });
});

describe("finding 101 — `disabled` is not required, and absent means ON", () => {
  test("caching.disabled absent is REFUSED, because the documented default is false", () => {
    // hyperdrive_hyperdrive-caching-common lists `disabled` with no `required`
    // and the description "Default is false." So `caching: {}` is legal, means
    // caching is ENABLED, and a gate written as `!== false` would attest the
    // exact opposite of the truth.
    const v = ok({ jobs: { caching: {} } });
    refusedBy(v, /caching\.disabled is null, not true/);
  });

  test("caching.disabled === false is REFUSED", () => {
    refusedBy(ok({ control: { caching: { disabled: false } } }), /caching\.disabled is false/);
  });

  test("a MISSING caching object is REFUSED, not treated as off", () => {
    const { caching, ...noCaching } = cfg("JOBS");
    refusedBy(hyperdriveAuthorityVerdict(cfg("CONTROL"), noCaching, { database: DB, vpcServiceId: VPC }),
              /states no caching object/);
  });

  test("the string \"true\" is not true", () => {
    // A JSON field that arrives stringified by a proxy or a shell pipeline must
    // not satisfy a boolean assertion.
    refusedBy(ok({ jobs: { caching: { disabled: "true" } } }), /caching\.disabled is "true"/);
  });

  test("R17 is named in the refusal, so the reader learns WHY the cache matters", () => {
    const v = ok({ jobs: { caching: {} } });
    assert.ok(v.refusals.some((r) => /byte-identical across tenants/.test(r)));
  });
});

describe("finding 106 — the origin VARIANT is not a free choice; R7 named it", () => {
  test("all three documented shapes are recognised", () => {
    assert.equal(originVariant({ service_id: VPC }), "vpc_service");
    assert.equal(originVariant({ host: "db.internal", access_client_id: "x.access" }), "over_access");
    assert.equal(originVariant({ host: "db.example.com", port: 5432 }), "internet");
    assert.equal(originVariant(null), null);
    assert.equal(originVariant("nope"), null);
  });

  test("THE REPRODUCTION: a correct pair of credentials to a PUBLIC INTERNET host", () => {
    // Reproduced by the reviewer against the shipped predicate: distinct config
    // ids, the two correct logins, the right database, caching disabled — and
    // `host: "wrong-public-db.example"`. It PASSED. R7 rules the path Worker ->
    // Hyperdrive -> Workers VPC -> Tunnel -> Pigsty, and an internet origin means
    // Pigsty answers the public internet with a password, which is exactly what
    // the tunnel exists to make untrue.
    const internet = (role) => ({
      id: role === "CONTROL" ? "aaaa1111" : "bbbb2222",
      caching: { disabled: true },
      origin: { scheme: "postgres", database: DB, user: EXPECTED[role].user,
                host: "wrong-public-db.example", port: 5432 },
    });
    const v = hyperdriveAuthorityVerdict(internet("CONTROL"), internet("JOBS"),
                                         { database: DB, vpcServiceId: VPC });
    refusedBy(v, /is a internet origin, not a Workers VPC service/);
    assert.equal(v.refusals.filter((r) => /not a Workers VPC service/.test(r)).length, 2,
      "both configurations must be named, not just the first");
  });

  test("an Access origin is refused too — it is a different product, not a near miss", () => {
    const access = (role) => ({
      id: role === "CONTROL" ? "aaaa1111" : "bbbb2222",
      caching: { disabled: true },
      origin: { scheme: "postgres", database: DB, user: EXPECTED[role].user,
                host: "db.internal", access_client_id: "x.access" },
    });
    refusedBy(hyperdriveAuthorityVerdict(access("CONTROL"), access("JOBS"),
                                         { database: DB, vpcServiceId: VPC }),
              /over-access origin, not a Workers VPC service/);
  });

  test("the RIGHT variant pointed at the WRONG VPC service is refused", () => {
    // A private path to somewhere else is still a private path. This is finding
    // 105's law inside finding 106: the variant is right and the subject is not.
    refusedBy(ok({ jobs: { origin: { service_id: "ffff0000ffff0000ffff0000ffff0000" } } }),
              /origin\.service_id is "ffff0000/);
  });

  test("a VPC origin passes WITHOUT a host — the variant carries service_id and nothing else", () => {
    // A check demanding origin.host would refuse the correct topology.
    assert.equal(ok().ok, true);
  });

  test("an origin matching NONE of the three is REFUSED, not passed with a note", () => {
    // Finding 88's law: a vocabulary this gate does not positively recognise is
    // a refusal. A fourth origin shape in a future API version must stop it.
    const v = hyperdriveAuthorityVerdict(
      cfg("CONTROL"), { ...cfg("JOBS"), origin: { scheme: "postgres", database: DB, user: "x" } },
      { database: DB, vpcServiceId: VPC });
    refusedBy(v, /matches none of Cloudflare's three documented shapes/);
  });

  test("a mysql scheme is REFUSED", () => {
    refusedBy(ok({ jobs: { origin: { scheme: "mysql" } } }), /not a PostgreSQL scheme/);
  });

  test("the wrong database is REFUSED", () => {
    refusedBy(ok({ jobs: { origin: { database: "postgres" } } }), /origin\.database is "postgres"/);
  });
});

describe("finding 106 — and the VPC SERVICE itself, because that is where R7 lives", () => {
  // Cloudflare's documented TCP service for a PostgreSQL target, pasted:
  //   { type, name, tcp_port, app_protocol, host:{ipv4, network:{tunnel_id}},
  //     tls_settings:{cert_verification_mode} }
  const svc = (over = {}) => ({
    // FINDING 114. This fixture said `id`, which Cloudflare does not return.
    // The identity of a Workers VPC connectivity service is `service_id`, and
    // the invented spelling is what disabled the check — the guard read
    // `service.id !== undefined`, so a real response skipped the comparison.
    service_id: VPC, type: "tcp", name: "cd-pigsty", tcp_port: PORT, app_protocol: "postgresql",
    host: { ipv4: TARGET, network: { tunnel_id: TUNNEL }, ...(over.host ?? {}) },
    tls_settings: { cert_verification_mode: "verify_full" },
    ...(() => { const { host, ...rest } = over; return rest; })(),
  });
  // FINDING 125. The ruling names the host VARIANT and the COMPLETE target set,
  // because `host.ipv4 ?? host.ipv6 ?? host.hostname` proved one target matched
  // and called the rest unseen — and it names the TLS mode, because the code used
  // to state a policy in a comment and enforce a weaker one.
  const want = { serviceId: VPC, tunnelId: TUNNEL, port: PORT,
                 hostVariant: "ipv4", targets: [TARGET], certVerification: "verify_full" };
  const sv = (over = {}) => vpcServiceVerdict(svc(over), want);

  test("the ruled service passes", () => {
    const v = sv();
    assert.equal(v.ok, true, v.refusals.join(" | "));
    assert.equal(v.observed.tunnelId, TUNNEL);
  });

  test("the Hyperdrive names only a service_id — everything else is HERE", () => {
    // The point of the second attestation. A Hyperdrive config with the right
    // service_id proves a private path exists; it does not say which tunnel,
    // which host, which port, or whether TLS is verified at all.
    for (const [over, re] of [
      [{ host: { ipv4: TARGET, network: { tunnel_id: "0191dce4-0000-0000-0000-000000000000" } } },
       /different tunnel/],
      [{ host: { ipv4: "10.9.9.9", network: { tunnel_id: TUNNEL } } },
       /also routes to \["10\.9\.9\.9"\]/],
      [{ tcp_port: 6432 }, /tcp_port is 6432/],
      [{ type: "http" }, /not "tcp"/],
      [{ app_protocol: "mysql" }, /not "postgresql"/],
    ]) refusedBy(sv(over), re);
  });

  test("TLS verification DISABLED is refused", () => {
    // Finding 102 recorded that TLS cannot be set on the Hyperdrive and stopped
    // there. It CAN be set here, and `disabled` is a legal value — a plaintext-
    // trust path to the database inside the private network this gate proves.
    refusedBy(sv({ tls_settings: { cert_verification_mode: "disabled" } }),
              /would not verify the server certificate/);
  });

  test("verify_ca is a RULING, not a note — finding 125", () => {
    // It used to pass with a note saying "acceptable for an IP target with a
    // private CA", while accepting it for a HOSTNAME target too. A prose
    // condition the predicate does not enforce is not a condition. The mode the
    // service reports must now equal the one topology.json rules.
    refusedBy(sv({ tls_settings: { cert_verification_mode: "verify_ca" } }),
      /the ruling requires "verify_full"/);
    // With the ruling changed, an IP target may have it.
    const ip = vpcServiceVerdict({ ...svc(), tls_settings: { cert_verification_mode: "verify_ca" } },
                                 { ...want, certVerification: "verify_ca" });
    assert.equal(ip.ok, true, ip.refusals.join(" | "));
    // A HOSTNAME target may not, even then: verify_ca skips exactly the check a
    // hostname target most needs.
    refusedBy(vpcServiceVerdict(
      { ...svc(), tls_settings: { cert_verification_mode: "verify_ca" },
        host: { hostname: "pigsty.internal", resolver_network: { tunnel_id: TUNNEL } } },
      { ...want, hostVariant: "hostname", targets: ["pigsty.internal"],
        certVerification: "verify_ca" }),
      /skips the hostname check/);
  });

  test("an ABSENT tls_settings is the provider default verify_full, and passes", () => {
    // Unlike caching.disabled (finding 101), the documented default here is the
    // SAFE one. Recording which way each provider default falls is the whole
    // reason 101 was a finding and this is not.
    const { tls_settings, ...noTls } = svc();
    const v = vpcServiceVerdict(noTls, want);
    assert.equal(v.ok, true, v.refusals.join(" | "));
    assert.match(v.observed.certVerification, /verify_full/);
  });

  test("an unrecognised verification mode is refused", () => {
    refusedBy(sv({ tls_settings: { cert_verification_mode: "sometimes" } }),
              /not one of verify_full/);
  });

  test("a hostname target must carry a resolver_network", () => {
    // A hostname with no resolver inside the private network cannot be resolved
    // there, so the tunnel it would actually use is unstated.
    const hostWant = { ...want, hostVariant: "hostname", targets: ["pigsty.internal"] };
    const v = vpcServiceVerdict({ ...svc(), host: { hostname: "pigsty.internal" } }, hostWant);
    refusedBy(v, /exactly one of network \/ resolver_network/);
    // ...and with one, it passes.
    const good = vpcServiceVerdict(
      { ...svc(), host: { hostname: "pigsty.internal",
                          resolver_network: { tunnel_id: TUNNEL, resolver_ips: ["10.0.0.1"] } } },
      hostWant);
    assert.equal(good.ok, true, good.refusals.join(" | "));
  });

  test("a service whose own id is not the one the Hyperdrive named is refused", () => {
    // Finding 105 one level down: reading the right shape from the wrong object.
    refusedBy(vpcServiceVerdict({ ...svc(), service_id: "some-other-service" }, want),
              /this is a reading of a different service/);
  });

  test("it must be told what to expect, and refuses an unreadable response", () => {
    refusedBy(vpcServiceVerdict(svc(), {}), /R7 is a claim about WHICH tunnel/);
    refusedBy(vpcServiceVerdict(null, want), /the private path is unexamined/);
    refusedBy(vpcServiceVerdict({ ...svc(), host: null }, want), /states no host object/);
  });
});

describe("it refuses rather than passes when it cannot see", () => {
  test("a non-object response learns nothing and says so", () => {
    refusedBy(hyperdriveAuthorityVerdict(null, cfg("JOBS"), { database: DB, vpcServiceId: VPC }),
              /was not an object/);
    refusedBy(hyperdriveAuthorityVerdict(cfg("CONTROL"), "error", { database: DB, vpcServiceId: VPC }),
              /was not an object/);
  });

  test("a configuration with no id is REFUSED", () => {
    const { id, ...noId } = cfg("JOBS");
    refusedBy(hyperdriveAuthorityVerdict(cfg("CONTROL"), noId, { database: DB, vpcServiceId: VPC }),
              /states no id/);
  });

  test("every refusal names which binding it is about", () => {
    const v = ok({ jobs: { caching: {}, origin: { user: "wrong" } } });
    const perBinding = v.refusals.filter((r) => /^HYPERDRIVE_/.test(r));
    assert.ok(perBinding.length >= 2, v.refusals.join(" | "));
  });
});

describe("finding 114 — a provider fixture must use the provider's actual vocabulary", () => {
  const VPC2 = "0191dce4-1111-2222-3333-444444444444";
  const TUNNEL2 = "0191dce4-aaaa-bbbb-cccc-dddddddddddd";
  const want = { serviceId: VPC2, tunnelId: TUNNEL2, port: 5432,
                 hostVariant: "ipv4", targets: ["10.0.0.5"], certVerification: "verify_full" };
  // Cloudflare's InfraTCPServiceConfig, generated from their API schema:
  // { host, name, type, app_protocol?, created_at?, service_id?, tcp_port?,
  //   tls_settings?, updated_at? }  —  THERE IS NO `id`.
  const providerShaped = (over = {}) => ({
    service_id: VPC2, name: "cd-pigsty", type: "tcp", tcp_port: 5432,
    app_protocol: "postgresql", created_at: "2026-08-01T00:00:00Z",
    host: { ipv4: "10.0.0.5", network: { tunnel_id: TUNNEL2 } },
    tls_settings: { cert_verification_mode: "verify_full" },
    ...over,
  });

  test("THE REPRODUCTION: a WRONG service_id in the provider's own spelling was accepted", () => {
    // Round 8.2 read `service.id` and guarded the comparison with
    // `service.id !== undefined`. Against a real response that guard is always
    // false, so the identity check never ran:
    //     ok: true   refusals: []   observed.id: null
    const v = vpcServiceVerdict(providerShaped({ service_id: "WRONG-SERVICE-ENTIRELY" }), want);
    assert.equal(v.ok, false);
    assert.equal(v.observed.id, "WRONG-SERVICE-ENTIRELY");
    assert.match(v.refusals.join(" "), /returned service_id .* but the Hyperdrive origin names/);
  });

  test("a correct provider-shaped service passes, and reports its identity", () => {
    const v = vpcServiceVerdict(providerShaped(), want);
    assert.deepEqual(v.refusals, []);
    assert.equal(v.ok, true);
    assert.equal(v.observed.id, VPC2, "observed.id must be populated from service_id");
  });

  test("an ABSENT service_id is a refusal — Cloudflare marks the field optional", () => {
    // An identity we did not read is not an identity that matched. This is the
    // half that made the old guard silent, so it is asserted rather than assumed.
    const { service_id, ...noId } = providerShaped();
    const v = vpcServiceVerdict(noId, want);
    assert.equal(v.ok, false);
    assert.match(v.refusals.join(" "), /carries no service_id/);
  });

  test("an `id` field means this is not the object the check was written against", () => {
    const v = vpcServiceVerdict({ ...providerShaped(), id: VPC2 }, want);
    assert.equal(v.ok, false);
    assert.match(v.refusals.join(" "), /identifies itself with `service_id`/);
  });

  test("the target set is compared in BOTH directions", () => {
    // Ruling: dual-stack over A and B. Service: dual-stack over A and C.
    // `extra` alone would report C and say nothing about B, so a reader would
    // learn the service routes somewhere unreviewed and NOT that the address the
    // ruling actually names is unreachable. Both messages, or the comparison is
    // half a comparison. (The mutation battery found this: `vpc-target-unchecked`
    // was unobservable because `absent` never fires as the sole cause.)
    const v = vpcServiceVerdict(
      { ...providerShaped(), host: { ipv4: "10.0.0.5", ipv6: "2001:db8::c",
                                     network: { tunnel_id: TUNNEL2 } } },
      { ...want, hostVariant: "dual_stack", targets: ["10.0.0.5", "2001:db8::b"] });
    assert.equal(v.ok, false);
    const all = v.refusals.join(" ");
    assert.match(all, /also routes to \["2001:db8::c"\]/, "the unreviewed route");
    assert.match(all, /names \["2001:db8::b"\] and the service does not offer it/, "the ruled one");
  });

  test("a variant mismatch is caught even when the target SET agrees", () => {
    // Isolates finding 125's variant check from its target-set check: same single
    // target, different variant. Without this the dual-stack case fails on the
    // extra address and the variant predicate is never exercised.
    const v = vpcServiceVerdict(
      { ...providerShaped(), host: { hostname: "10.0.0.5", resolver_network: { tunnel_id: TUNNEL2 } } },
      { ...want, hostVariant: "ipv4", targets: ["10.0.0.5"] });
    assert.equal(v.ok, false);
    assert.match(v.refusals.join(" "), /host variant is "hostname" and the ruling names "ipv4"/);
  });

  test("the live runner reads Cloudflare's real endpoint, not a guessed one", () => {
    // GET /accounts/{account_id}/connectivity/directory/services/{service_id}
    // Round 8.2 shipped /vpc/services/{id}, which is not an endpoint, with a
    // comment saying so. A gate that can only 404 is a gate that never runs.
    const src = readFileSync(new URL("../../scripts/check-hyperdrive-authority.mjs", import.meta.url),
                             "utf8");
    assert.match(src, /\/connectivity\/directory\/services\/\$\{/);
    assert.equal(/get\(`\/vpc\/services\//.test(src), false,
      "the guessed endpoint must be gone, not merely commented");
  });
});
