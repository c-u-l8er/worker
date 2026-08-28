-- 0004 — worlds, at three named sizes
--
-- R11 / CLOUD_V1.md §2. WORLD_SIZE.md §11 records this being got wrong once:
-- the world layer was measured at 247 KB realistic / 212.70 MB at the shell's
-- caps, and then reported as a conclusion about the product -- which is 100 GB
-- to 10 TB of the user's machine. 0.21% was mistaken for the whole.
--
--   WORLD         the persistent machine-sized environment      10 GB - 10 TB
--   WORLD VERSION a content-addressed root describing it        KB (a root)
--   WRL GRAPH     the semantic layer inside it                  247 KB - 212 MB
--
-- THERE IS NO `current_head` COLUMN ANYWHERE, and there must never be one. A
-- head is always qualified: `manifest_root` is the machine, `wrl_head` is the
-- graph. A column that could hold either is the relapse.

BEGIN;

SET LOCAL ROLE computedriven_migrations;

CREATE TABLE cd.worlds (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES cd.organizations(id) ON DELETE RESTRICT,
  name            text NOT NULL,
  status          text NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active', 'archived')),
  created_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, name),
  -- target for the composite FKs below
  CONSTRAINT worlds_id_org_uq UNIQUE (id, organization_id)
);

COMMENT ON TABLE cd.worlds IS
  'A WORLD is the machine-sized persistent environment (10 GB - 10 TB), not the '
  'shell graph. R11.';

-- One row per synced machine state. Immutable by convention: a new state is a
-- new version, never an UPDATE, so history cannot be rewritten.
CREATE TABLE cd.world_versions (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  world_id        uuid NOT NULL,
  organization_id uuid NOT NULL,
  manifest_root   text   NOT NULL,
  byte_size       bigint NOT NULL CHECK (byte_size  >= 0),
  chunk_count     integer NOT NULL CHECK (chunk_count >= 0),
  created_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (world_id, manifest_root),
  -- The denormalised organization_id is what RLS filters on, so it must be
  -- impossible for it to disagree with the parent world's. This composite FK
  -- makes a cross-tenant row a CONSTRAINT VIOLATION rather than something a
  -- policy has to catch -- structure beats policy where structure can do it.
  FOREIGN KEY (world_id, organization_id)
    REFERENCES cd.worlds (id, organization_id) ON DELETE RESTRICT
);

CREATE INDEX world_versions_world_created_idx
  ON cd.world_versions (world_id, created_at DESC);

COMMENT ON COLUMN cd.world_versions.manifest_root IS
  'Content address of the MACHINE state. The manifest itself lives in R2; Pigsty '
  'holds refs only, never bytes.';
COMMENT ON COLUMN cd.world_versions.byte_size IS
  'Machine-sized. Expect values in the 1e10 - 1e13 range; bigint is not optional.';

-- The small one. Separate table, separate name, so it can never be confused with
-- a manifest root. ~0.2% of a backup at its ceiling -- it rides along free
-- inside a tier priced for the bulk (WORLD_SIZE.md §11.1).
CREATE TABLE cd.wrl_heads (
  world_id        uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  wrl_head        text,
  semantic_head   text,
  updated_at      timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (world_id, organization_id)
    REFERENCES cd.worlds (id, organization_id) ON DELETE RESTRICT
);

COMMENT ON TABLE cd.wrl_heads IS
  'The WRL GRAPH head -- the small semantic/topological layer INSIDE a world '
  '(247 KB - 212 MB). Not the machine state. R11.';

COMMIT;
