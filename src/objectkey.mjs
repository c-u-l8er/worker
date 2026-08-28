// THE OBJECT-KEY GRAMMAR. ONE GRAMMAR, ONE FILE.
//
// FINDING 98, 2026-08-23. This module exists because the format had already
// been written down three times:
//
//     worker/src/reconcile.mjs   KEY_RE           the queue consumer
//     app.parse_object_key()     SQL              where the constraint is
//     worker/src/inventory.mjs   OWNED            the repair path — NEW, WEAKER
//
// The first two were deliberately pinned together by a shared fixture, and the
// header comment on KEY_RE says exactly why: "the parse that decides tenancy has
// to be where the constraint is; battery check M4 pins the two together so they
// cannot drift." A third spelling then arrived in the reconciliation planner one
// round later, `/^org\/[0-9a-f-]{36}\/world\/[0-9a-f-]{36}\/.+/`, and it did not
// read the fixture.
//
// It already disagreed. Reproduced:
//
//     org/00000000-0000-0000-0000-000000000000/world/<valid>/chunk/x
//         canonical  null          (a nil uuid is not v1-v5)
//         inventory  REPAIRABLE    -> claims ownership of a key we never mint
//
//     org/------------------------------------/world/------------------------------------/x
//         canonical  null
//         inventory  REPAIRABLE    -> thirty-six dashes is not a uuid at all
//
// THE FIX IS NOT A THIRD PARITY SUITE. It is deleting the third grammar. Two
// implementations are unavoidable because one of them has to be in SQL, next to
// the constraint, in a language that cannot import this file. Three is a choice.
//
//     A FORMAT PARSED IN N PLACES DISAGREES IN N-1 WAYS. THE ONLY DEFENSIBLE N
//     IS THE ONE THE SUBSTRATE FORCES.
//
// This is R76's law again — a column copying another table's fact must be a
// foreign key to it or it is a second independent claim — for the third time in
// three rounds, and the third different substrate: a database column (R76), a
// config key (finding 91), and now a regular expression.

/**
 * The prefix format minted by scopeForWorld().
 *
 * Duplicated in SQL as app.parse_object_key() because the parse that decides
 * tenancy has to be where the constraint is; battery check M4 pins the two
 * together so they cannot drift. THAT IS THE ONLY LEGITIMATE DUPLICATE. Every
 * JavaScript caller imports from here.
 *
 * v1–v5 and variant 8/9/a/b, deliberately: a nil uuid, a v6/v7/v8 uuid and a
 * run of hex that is merely 36 characters long are all things this control plane
 * does not mint, and a key it did not mint is not one it may account for.
 */
export const KEY_RE = new RegExp(
  "^org/([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})" +
  "/world/([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})/(.+)$"
);

/**
 * Parse a key into the tenancy it names, or null.
 *
 *     R2 is authoritative for WHAT WAS WRITTEN        (size, etag)
 *     the key prefix is authoritative for WHOSE IT IS
 *     and WE MINTED THAT PREFIX                       (scopeForWorld)
 *
 * Nothing else in a provider message is trusted. In particular the organization
 * is never read from a field — an event is a report about an object, not a claim
 * about a tenant.
 */
export function parseObjectKey(key) {
  if (typeof key !== "string") return null;
  const m = KEY_RE.exec(key);
  if (!m) return null;
  return Object.freeze({ organizationId: m[1], worldId: m[2], objectPath: m[3] });
}
