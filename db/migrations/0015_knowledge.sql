-- Offline knowledge search (docs/offline-knowledge-search.md). An imported pack
-- (ExploitDB, NVD, technique docs) is indexed into these tables, which back the
-- search_* / lookup_* agent tools. The pack's data files live under the data
-- directory; only the search index and metadata are stored here.
--
-- No extension is created here. pg_trgm (trigram GIN indexes that speed up the
-- ILIKE fallback for identifiers) and pgvector (Phase 2) are created at runtime,
-- best effort (knowledge/store.go, knowledge/vector.go): a managed or external
-- Postgres whose role lacks CREATE EXTENSION rights must still be able to run
-- this migration, and search works without either (more slowly / lexical-only).

-- One row per imported pack. A pack id can have at most one active version at a
-- time (the partial unique index); importing a new version deactivates the old.
-- dir is the pack's files directory, relative to the knowledge directory
-- (<pack_id>/<version>-<suffix>); it is '' once a superseded version's files are
-- removed. key_fingerprint is the SHA-256 of the public key that verified the
-- manifest.
CREATE TABLE IF NOT EXISTS kb_packs (
    id              BIGSERIAL PRIMARY KEY,
    pack_id         TEXT NOT NULL,
    version         TEXT NOT NULL,
    key_id          TEXT NOT NULL,
    key_fingerprint TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    sources         JSONB NOT NULL DEFAULT '[]'::jsonb,
    file_count      INTEGER NOT NULL DEFAULT 0,
    dir             TEXT NOT NULL DEFAULT '',
    active          BOOLEAN NOT NULL DEFAULT false,
    imported_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (pack_id, version)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_kb_packs_active ON kb_packs(pack_id) WHERE active;

-- Signing-key pin per pack id (trust on first import). A later pack of the same
-- id must be signed by the key with this fingerprint unless the operator
-- re-pins explicitly, so a key added later (e.g. through the environment)
-- cannot silently take over an existing knowledge set.
CREATE TABLE IF NOT EXISTS kb_key_pins (
    pack_id         TEXT PRIMARY KEY,
    key_id          TEXT NOT NULL,
    key_fingerprint TEXT NOT NULL,
    pinned_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One row per indexed document: a CVE, an exploit, a technique-doc file, a
-- template. ext_id is the natural id (a CVE id, an EDB-ID) when there is one.
-- source_path points at the file under the pack directory (NULL for a CVE, which
-- has no file). cve_ids / cpe_tags support the lookup joins; meta holds the
-- structured fields lookup_cve returns (cvss, cwe, references).
CREATE TABLE IF NOT EXISTS kb_documents (
    id            BIGSERIAL PRIMARY KEY,
    pack_id       BIGINT NOT NULL REFERENCES kb_packs(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL CHECK (kind IN ('cve', 'exploit', 'doc', 'template')),
    ext_id        TEXT,
    source_path   TEXT,
    title         TEXT NOT NULL DEFAULT '',
    cve_ids       TEXT[] NOT NULL DEFAULT '{}',
    cpe_tags      TEXT[] NOT NULL DEFAULT '{}',
    meta          JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_kb_documents_pack ON kb_documents(pack_id);
CREATE INDEX IF NOT EXISTS idx_kb_documents_kind ON kb_documents(kind);
-- lookup_cve by CVE id; a lower(ext_id) index keeps the lookup case-insensitive.
CREATE INDEX IF NOT EXISTS idx_kb_documents_extid ON kb_documents(kind, lower(ext_id));
-- lookup_cve → EDB-ID: find exploits whose cve_ids contain the CVE.
CREATE INDEX IF NOT EXISTS idx_kb_documents_cveids ON kb_documents USING gin(cve_ids);

-- Body chunks for full-text search. tsv is an english-config tsvector generated
-- from the body; the GIN index on it backs search ranking (ts_rank_cd). The
-- trigram index on the body that speeds up the ILIKE fallback for identifiers
-- (CVE-2021-41773, wp-config.php) is created at runtime when pg_trgm is available.
CREATE TABLE IF NOT EXISTS kb_chunks (
    id          BIGSERIAL PRIMARY KEY,
    document_id BIGINT NOT NULL REFERENCES kb_documents(id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL,
    body        TEXT NOT NULL,
    tsv         TSVECTOR GENERATED ALWAYS AS (to_tsvector('english', body)) STORED,
    UNIQUE (document_id, chunk_index)
);
CREATE INDEX IF NOT EXISTS idx_kb_chunks_tsv ON kb_chunks USING gin(tsv);

-- CPE applicability rows for lookup_software: one per (CVE document, cpeMatch).
-- The query filters by vendor/product (indexed) then evaluates the version range
-- in Go (knowledge/version.go), which handles the inclusive/exclusive bounds and
-- the odd version strings CPE data carries.
CREATE TABLE IF NOT EXISTS kb_cpe_matches (
    id                      BIGSERIAL PRIMARY KEY,
    document_id             BIGINT NOT NULL REFERENCES kb_documents(id) ON DELETE CASCADE,
    vendor                  TEXT NOT NULL,
    product                 TEXT NOT NULL,
    criteria                TEXT NOT NULL,
    vulnerable              BOOLEAN NOT NULL DEFAULT true,
    version_start_including TEXT NOT NULL DEFAULT '',
    version_start_excluding TEXT NOT NULL DEFAULT '',
    version_end_including   TEXT NOT NULL DEFAULT '',
    version_end_excluding   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_kb_cpe_product ON kb_cpe_matches(product, vendor);
