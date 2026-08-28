// THE DEPLOYMENT NAMES ITS OWN SUBJECTS (finding 105).
//
// Every live gate in this system attests something about a Cloudflare resource.
// Until this round, four of those resources were named by the CALLER — and
// finding 91 had already ruled, one round earlier, that an attestation about
// queue A is worthless when the runtime trusts queue B. The law was closed for
// the queue and then broken three more times, including by re-adding the exact
// variable finding 91 deleted.
//
//     AN ATTESTATION WHOSE SUBJECT IS CALLER-CHOSEN IS A CAPABILITY TO ATTEST
//     THE WRONG SYSTEM.
//
// These tests drive the parser against synthetic wrangler.toml text AND against
// the repository's real one, because a subject derivation that works on fixtures
// and not on the actual deployment file is the same defect one layer out.

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  deployedSubjects, subjectContinuityVerdict, CONTINUITY_SUBJECTS, BINDING_VALUE_FIELD,
  resolveLiveSubjects, activeVersionVerdict,
  deploymentSubjects, requireSubjects, ruledTopology, tomlScalars,
  refuseRetiredSubjectEnv, RETIRED_SUBJECT_ENV, CREDENTIAL_ENV, WRANGLER, TOPOLOGY,
} from "../../scripts/deployment-subjects.mjs";

const TOML = `
name = "computedriven-cloud-api"
main = "src/index.mjs"

[[hyperdrive]]
binding = "HYPERDRIVE_CONTROL"
id = "hd-control"

[[hyperdrive]]
binding = "HYPERDRIVE_JOBS"
id = "hd-jobs"

[vars]
R2_BUCKET = "cd-worlds"
PROVIDER_QUEUE = "cd-notifications"

[[queues.consumers]]
queue = "cd-notifications"
dead_letter_queue = "cd-notifications-dlq"
`;

const without = (line) => TOML.split("\n").filter((l) => !l.includes(line)).join("\n");

describe("the real deployment file derives a complete subject set", () => {
  test("worker/wrangler.toml names every subject a live gate needs", () => {
    // If this ever fails, no gate can run — which is the point. The alternative
    // was each gate silently accepting whatever the environment held.
    const d = deploymentSubjects();
    assert.equal(d.ok, true, d.refusals.join(" | "));
    for (const f of ["workerName", "r2Bucket", "providerQueue", "consumerQueue",
                     "deadLetterQueue", "hyperdriveControlId", "hyperdriveJobsId"]) {
      assert.ok(d.subjects[f], `${f} is absent from ${WRANGLER}`);
    }
    assert.equal(d.origin, "wrangler.toml");
  });

  test("worker/topology.json declares the ruled path case Q compares against", () => {
    const t = ruledTopology();
    for (const f of ["database", "vpcServiceId", "tunnelId", "hostVariant",
                     "certVerification"]) assert.ok(t[f], f);
    assert.ok(Array.isArray(t.targets) && t.targets.length > 0, "targets");
    assert.equal(t.port, 5432, "PostgreSQL, and not a placeholder");
  });

  test("the two files are the ONLY places a subject or expectation comes from", () => {
    // Stated as a test so that adding a third source is a visible failure rather
    // than a quiet convenience.
    assert.match(WRANGLER, /worker\/wrangler\.toml$/);
    assert.match(TOPOLOGY, /worker\/topology\.json$/);
    assert.deepEqual(CREDENTIAL_ENV, ["CF_ACCOUNT_ID", "CF_API_TOKEN"],
      "the environment may supply credentials and nothing else");
  });
});

describe("finding 105 — a subject the deployment does not name is not a subject", () => {
  test("the control case derives everything", () => {
    const d = deploymentSubjects(TOML);
    assert.equal(d.ok, true, d.refusals.join(" | "));
    assert.deepEqual(d.subjects, {
      workerName: "computedriven-cloud-api",
      r2Bucket: "cd-worlds",
      providerQueue: "cd-notifications",
      consumerQueue: "cd-notifications",
      deadLetterQueue: "cd-notifications-dlq",
      hyperdriveControlId: "hd-control",
      hyperdriveJobsId: "hd-jobs",
    });
  });

  test("an ABSENT subject refuses — it does not fall back to anything", () => {
    for (const [line, re] of [
      ["R2_BUCKET", /no R2 bucket/],
      ["PROVIDER_QUEUE", /no provider queue/],
      ["dead_letter_queue", /no dead letter queue/],
      ['name = "computedriven', /no Worker name/],
    ]) {
      const d = deploymentSubjects(without(line));
      assert.equal(d.ok, false, line);
      assert.ok(d.refusals.some((r) => re.test(r)), `${line}: ${d.refusals.join(" | ")}`);
    }
  });

  test("a PLURAL subject is refused — a subject that is two things is not a subject", () => {
    const d = deploymentSubjects(TOML + '\n[vars]\nR2_BUCKET = "other-bucket"\n');
    assert.equal(d.ok, false);
    assert.ok(d.refusals.some((r) => /plural/.test(r)));
  });

  test("the channel is checked HERE, so no gate can get a coherent subject set from an incoherent deployment", () => {
    // finding 91's property, moved from a standalone gate into the derivation
    // itself. A caller cannot obtain "queue = A" while the consumer binding says
    // B, because the derivation refuses before returning either.
    const d = deploymentSubjects(TOML.replace('queue = "cd-notifications"\n', 'queue = "other"\n'));
    assert.equal(d.ok, false);
    assert.ok(d.refusals.some((r) => /the Worker trusts .* but the consumer binding delivers/.test(r)));
  });

  test("an unpaired Hyperdrive binding is refused", () => {
    const d = deploymentSubjects(without('id = "hd-jobs"'));
    assert.equal(d.ok, false);
    assert.ok(d.refusals.some((r) => /binding\(s\) declare .* id\(s\)/.test(r)));
  });

  test("requireSubjects THROWS rather than returning a partial set", () => {
    // A caller that got `ok: false` and used `subjects` anyway would attest
    // three subjects correctly and the fourth against whatever was lying around.
    assert.throws(() => requireSubjects(without("R2_BUCKET")),
      (e) => e.code === "CD-SUBJECTS" && /does not coherently name its own subjects/.test(e.message));
    assert.equal(requireSubjects(TOML).subjects.r2Bucket, "cd-worlds");
  });
});

describe("the retired environment variables are REFUSED, not ignored", () => {
  test("every subject variable a gate used to accept is named", () => {
    // Silently ignoring them would leave an operator who exports the old
    // variable believing the gate honoured it. Being told is the difference
    // between a fixed defect and a defect with a workaround.
    for (const n of ["CD_R2_BUCKET", "CD_QUEUE_NAME", "HYPERDRIVE_CONTROL_ID",
                     "HYPERDRIVE_JOBS_ID", "CD_CONSUMER_SCRIPT", "PIGSTY_DATABASE"]) {
      assert.ok(RETIRED_SUBJECT_ENV.includes(n), n);
      const msg = refuseRetiredSubjectEnv({ [n]: "something" });
      assert.match(msg, new RegExp(n));
      assert.match(msg, /capability to attest the wrong system/);
    }
  });

  test("a clean environment produces no refusal", () => {
    assert.equal(refuseRetiredSubjectEnv({ CF_ACCOUNT_ID: "a", CF_API_TOKEN: "b" }), null);
    assert.equal(refuseRetiredSubjectEnv({ CD_R2_BUCKET: "" }), null, "empty is unset");
  });

  test("CD_QUEUE_NAME is on the list, because it was deleted once and came back", () => {
    // Finding 91 removed it; finding 99's new gate reintroduced it one round
    // later. A deleted name that nothing forbids is a name that returns.
    assert.ok(RETIRED_SUBJECT_ENV.includes("CD_QUEUE_NAME"));
  });
});

describe("the TOML reader is the ONE reader (finding 98's law, again)", () => {
  test("it reads section-scoped scalars and ignores comments", () => {
    assert.deepEqual(tomlScalars(TOML, "binding", { section: "[[hyperdrive]]" }),
                     ["HYPERDRIVE_CONTROL", "HYPERDRIVE_JOBS"]);
    assert.deepEqual(tomlScalars('# id = "commented"\n[vars]\nX = "y"', "X", { section: "[vars]" }),
                     ["y"]);
    assert.deepEqual(tomlScalars(TOML, "R2_BUCKET", { section: "[[hyperdrive]]" }), [],
      "a key in the wrong section is not found");
  });

  test("the repository's own wrangler.toml is what the parser was built against", () => {
    const src = readFileSync(WRANGLER, "utf8");
    assert.deepEqual(tomlScalars(src, "binding", { section: "[[hyperdrive]]" }),
                     ["HYPERDRIVE_CONTROL", "HYPERDRIVE_JOBS"]);
  });
});

describe("the ruled topology is a ruling, not an argument", () => {
  test("an incomplete topology throws rather than degrading", () => {
    assert.throws(() => ruledTopology(JSON.stringify({ database: "d", port: 5432 })),
      (e) => e.code === "CD-TOPOLOGY" && /declares no vpcServiceId/.test(e.message));
    assert.throws(() => ruledTopology(JSON.stringify({
      database: "d", vpcServiceId: "v", tunnelId: "t", target: "x", port: 0,
    })), (e) => /no valid TCP port/.test(e.message));
  });

  test("it names exactly the seven things case Q compares", () => {
    const t = ruledTopology(JSON.stringify({
      database: "d", vpcServiceId: "v", tunnelId: "t", port: 5432,
      hostVariant: "ipv4", targets: ["x"], certVerification: "verify_full", extra: "ignored",
    }));
    assert.deepEqual(Object.keys(t).sort(),
                     ["certVerification", "database", "hostVariant", "port", "targets",
                      "tunnelId", "vpcServiceId"]);
  });
});

// ===========================================================================

describe("finding 121 — the manifest is an intention; the runtime is the subject", () => {
  const NAME = "computedriven-cloud-api";
  // Cloudflare's WorkersBindingKind* union, in the provider's own vocabulary.
  // Inventing a field name here is finding 114, which cost a round.
  const bindings = (over = {}) => [
    { type: "plain_text", name: "R2_BUCKET",         text: over.bucket ?? "cd-worlds" },
    { type: "plain_text", name: "PROVIDER_QUEUE",    text: over.queue ?? "cd-provider-events" },
    { type: "hyperdrive", name: "HYPERDRIVE_CONTROL", id: over.control ?? "hd-control" },
    { type: "hyperdrive", name: "HYPERDRIVE_JOBS",    id: over.jobs ?? "hd-jobs" },
  ];
  const deployed = (over) => deployedSubjects({ bindings: bindings(over) }, { workerName: NAME });
  const treeLike = (subjects) => ({ ok: true, origin: "wrangler.toml", refusals: [], subjects });

  test("the deployed bindings are read by their PROVIDER field names", () => {
    assert.deepEqual(BINDING_VALUE_FIELD, {
      plain_text: "text", hyperdrive: "id", r2_bucket: "bucket_name", queue: "queue_name",
    });
    const d = deployed();
    assert.equal(d.ok, true, d.refusals.join(" | "));
    assert.equal(d.origin, "deployed");
    assert.equal(d.subjects.r2Bucket, "cd-worlds");
    assert.equal(d.subjects.hyperdriveJobsId, "hd-jobs");
  });

  test("THE REPRODUCTION: a deployment that drifted from the manifest is REFUSED", () => {
    // Every gate would attest the manifest's bucket while the Worker writes to
    // another one — finding 105's catastrophe, one layer out.
    const tree = treeLike({ workerName: NAME, r2Bucket: "bucket-A",
                            providerQueue: "cd-provider-events",
                            hyperdriveControlId: "hd-control", hyperdriveJobsId: "hd-jobs" });
    const v = subjectContinuityVerdict(tree, deployed({ bucket: "bucket-B" }));
    assert.equal(v.ok, false);
    assert.equal(v.compared.r2Bucket.agrees, false);
    assert.match(v.refusals.join(" "), /wrangler\.toml says "bucket-A" and the DEPLOYED Worker says "bucket-B"/);
  });

  test("an agreeing deployment passes, and every continuity subject is compared", () => {
    const tree = treeLike({ workerName: NAME, r2Bucket: "cd-worlds",
                            providerQueue: "cd-provider-events",
                            hyperdriveControlId: "hd-control", hyperdriveJobsId: "hd-jobs" });
    const v = subjectContinuityVerdict(tree, deployed());
    assert.equal(v.ok, true, v.refusals.join(" | "));
    assert.deepEqual(Object.keys(v.compared).sort(), [...CONTINUITY_SUBJECTS].sort());
  });

  test("a binding of the WRONG KIND is a refusal, not a value read from elsewhere", () => {
    // An r2_bucket binding carries bucket_name, not text. Reading it as
    // plain_text would yield undefined and, guarded loosely, skip the check —
    // which is exactly finding 114's shape.
    const d = deployedSubjects({ bindings: [
      { type: "r2_bucket", name: "R2_BUCKET", bucket_name: "cd-worlds" },
      ...bindings().slice(1),
    ] }, { workerName: NAME });
    assert.equal(d.ok, false);
    assert.match(d.refusals.join(" "), /is a "r2_bucket", expected "plain_text"/);
  });

  test("an ABSENT binding is unstated, not agreeing", () => {
    const d = deployedSubjects({ bindings: bindings().slice(1) }, { workerName: NAME });
    assert.equal(d.ok, false);
    assert.match(d.refusals.join(" "), /no "R2_BUCKET" binding/);
  });

  test("R80 is asserted at the DEPLOYED layer, not only in the file", () => {
    const d = deployed({ control: "same-id", jobs: "same-id" });
    assert.equal(d.ok, false);
    assert.match(d.refusals.join(" "), /one credential wearing two binding names/);
  });

  test("an unread deployment is not an agreeing one", () => {
    const d = deployedSubjects({}, { workerName: NAME });
    assert.equal(d.ok, false);
    assert.match(d.refusals.join(" "), /carried no bindings array/);
    // And comparing two incoherent sets proves only that they are equally wrong.
    assert.equal(subjectContinuityVerdict({ ok: false }, d).ok, false);
  });

  test("a response cannot name its own subject", () => {
    const d = deployedSubjects({ bindings: bindings() }, {});
    assert.equal(d.ok, false);
    assert.match(d.refusals.join(" "), /cannot name its own subject/);
  });

  test("a duplicated binding name is refused rather than resolved by guess", () => {
    const d = deployedSubjects({ bindings: [...bindings(),
      { type: "plain_text", name: "R2_BUCKET", text: "second-one" }] }, { workerName: NAME });
    assert.equal(d.ok, false);
    assert.match(d.refusals.join(" "), /more than once/);
  });
});

describe("finding 127 — a prior check is not a capability", () => {
  const NAME = "computedriven-cloud-api";
  // DERIVED FROM THE MANIFEST THE REPOSITORY ACTUALLY SHIPS. The first draft of
  // this test invented "cd-worlds"/"hd-control" and failed against the real
  // placeholders — which is finding 90's lesson landing on the test that exists
  // to check subject continuity.
  const T = deploymentSubjects().subjects;
  const bindings = (over = {}) => [
    { type: "plain_text", name: "R2_BUCKET",          text: over.bucket ?? T.r2Bucket },
    { type: "plain_text", name: "PROVIDER_QUEUE",     text: over.queue ?? T.providerQueue },
    { type: "hyperdrive", name: "HYPERDRIVE_CONTROL", id: over.control ?? T.hyperdriveControlId },
    { type: "hyperdrive", name: "HYPERDRIVE_JOBS",    id: over.jobs ?? T.hyperdriveJobsId },
  ];
  // FINDING 135. TWO CALLS NOW, and the first one decides which version the
  // second reads: /deployments -> the active version at 100% -> /versions/{id}.
  // `/settings` cannot express a gradual rollout at all.
  const VER = "8f1c0a4e-1111-2222-3333-444444444444";
  const DEP = "d3f0b2a1-5555-6666-7777-888888888888";
  const netFor = ({ deployments, version, depStatus = 200, verStatus = 200 } = {}) =>
    async (url) => {
      const isDep = /\/deployments$/.test(url);
      const status = isDep ? depStatus : verStatus;
      return {
        status, ok: status < 400,
        json: async () => status >= 400
          ? { success: false, errors: [{ code: status, message: "no" }] }
          : { success: true, result: isDep ? deployments : version },
      };
    };
  const oneVersionAt100 = { deployments: [{ id: DEP, strategy: "percentage",
                                            versions: [{ version_id: VER, percentage: 100 }] }] };
  const live = (over, deployments = oneVersionAt100) => resolveLiveSubjects({
    accountId: "acct", apiToken: "tok",
    fetchImpl: netFor({ deployments, version: { resources: { bindings: bindings(over) } } }),
  });

  test("the active deployment must route exactly one version at 100%", () => {
    // A gradual rollout is not refused for being wrong; it is refused because
    // attesting one version's bindings says nothing about the traffic the other
    // serves, and no rule has been made for that (finding 135).
    const two = activeVersionVerdict({ deployments: [{ id: DEP, strategy: "percentage", versions: [
      { version_id: VER, percentage: 90 }, { version_id: "other", percentage: 10 }] }] });
    assert.equal(two.ok, false);
    assert.match(two.refusals.join(" "), /routes 2 version\(s\)/);

    const partial = activeVersionVerdict({ deployments: [{ id: DEP, strategy: "percentage",
      versions: [{ version_id: VER, percentage: 50 }] }] });
    assert.equal(partial.ok, false);
    assert.match(partial.refusals.join(" "), /the remainder goes somewhere this gate cannot name/);

    const good = activeVersionVerdict(oneVersionAt100);
    assert.equal(good.ok, true, good.refusals.join(" | "));
    assert.equal(good.versionId, VER);
    assert.equal(good.deploymentId, DEP);
  });

  test("no deployments at all is NOT DEPLOYED, not agreement", () => {
    const v = activeVersionVerdict({ deployments: [] });
    assert.equal(v.ok, false);
    assert.equal(v.notDeployed, true);
  });

  test("an unclassified routing strategy is a refusal", () => {
    const v = activeVersionVerdict({ deployments: [{ id: DEP, strategy: "canary-by-header",
      versions: [{ version_id: VER, percentage: 100 }] }] });
    assert.equal(v.ok, false);
    assert.match(v.refusals.join(" "), /does not classify/);
  });

  test("the live gates no longer read the manifest for their subjects", () => {
    // THE REPRODUCTION, as source: case S compared tree to deployment, and then
    // Q/P/P2 each called requireSubjects() — the FILE — again. Between S and Q
    // the deployment can change, and nothing sequences them because
    // `live-falsifier --run` does not exist.
    for (const g of ["check-hyperdrive-authority", "check-notification-coverage",
                     "check-queue-authority"]) {
      const src = readFileSync(new URL(`../../scripts/${g}.mjs`, import.meta.url), "utf8");
      assert.match(src, /resolveLiveSubjects\(/, g);
      assert.match(src, /import \{[^}]*resolveLiveSubjects[^}]*\} from "\.\/deployment-subjects\.mjs"/,
        `${g} must IMPORT the live resolver, not alias something else to its name`);
      // Comments quoting the history are legitimate — the same distinction
      // finding 126 had to make between asserting a number and quoting one. The
      // CODE is what must not call it.
      const code = src.split("\n").filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join("\n");
      assert.equal(/requireSubjects/.test(code), false,
        `${g} must not resolve its subject from the manifest (finding 127)`);
    }
  });

  test("resolveLiveSubjects returns the ACTIVE VERSION's values, not the manifest's", async () => {
    const r = await live({});
    assert.equal(r.origin, "deployed");
    assert.equal(r.subjects.r2Bucket, T.r2Bucket);
    assert.equal(r.subjects.workerName, T.workerName);
  });

  test("a drifted deployment refuses, and the refusal reaches the gate", async () => {
    await assert.rejects(live({ bucket: "somewhere-else" }),
      (e) => e.code === "CD-SUBJ-DRIFT" && /DEPLOYED Worker says "somewhere-else"/.test(e.message));
  });

  test("NOT DEPLOYED, UNREADABLE and SPLIT-TRAFFIC are three different answers", async () => {
    await assert.rejects(resolveLiveSubjects({ accountId: "a", apiToken: "t",
      fetchImpl: netFor({ depStatus: 404 }) }), (e) => e.code === "CD-SUBJ-NOTDEPLOYED");
    await assert.rejects(resolveLiveSubjects({ accountId: "a", apiToken: "t",
      fetchImpl: netFor({ depStatus: 500 }) }), (e) => e.code === "CD-SUBJ-UNREADABLE");
    await assert.rejects(resolveLiveSubjects({ accountId: "a", apiToken: "t",
      fetchImpl: netFor({ deployments: { deployments: [] } }) }),
      (e) => e.code === "CD-SUBJ-NOTDEPLOYED");
    // A gradual rollout is its own code: nothing drifted, and nothing is unreadable.
    await assert.rejects(live({}, { deployments: [{ id: DEP, strategy: "percentage", versions: [
        { version_id: VER, percentage: 90 }, { version_id: "other", percentage: 10 }] }] }),
      (e) => e.code === "CD-SUBJ-ROUTING");
  });

  test("the resolved subject names WHICH VERSION, by the provider's identifiers", async () => {
    // FINDING 135. Round 8.5 recorded an opportunistic ETag from /settings, which
    // names nothing. The evidence sentence is now: these attestations describe
    // version V, which deployment D routes at 100%.
    const r = await live({});
    assert.equal(r.versionId, VER);
    assert.equal(r.deploymentId, DEP);
    assert.equal(r.deploymentEtag, undefined);
  });

  test("a retired subject variable still refuses, before any network call", async () => {
    process.env.CD_R2_BUCKET = "sneaky";
    try {
      await assert.rejects(
        resolveLiveSubjects({ accountId: "a", apiToken: "t",
                              fetchImpl: async () => { throw new Error("must not be reached"); } }),
        (e) => e.code === "CD-SUBJ-RETIRED");
    } finally { delete process.env.CD_R2_BUCKET; }
  });
});
