-- Offline knowledge search (docs/offline-knowledge-search.md). An imported pack
-- (ExploitDB, NVD, technique docs) is indexed into these tables, which back the
-- search_* / lookup_* agent tools. The pack's data files live under the data
-- directory; only the search index and metadata are stored here.
--
-- pg_trgm backs identifier/partial matching (CVE, CPE, function names); it is a
-- contrib module shipped in the stock postgres image, so CREATE EXTENSION is
-- safe in a migration. pgvector is deliberately NOT here: it is not in the stock
-- image, so it is created at runtime when available (Phase 2).
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- One row per imported pack. A pack id can have at most one active version at a
-- time (the partial unique index); importing a new version deactivates the old.
CREATE TABLE IF NOT EXISTS kb_packs (
    id              BIGSERIAL PRIMARY KEY,
    pack_id         TEXT NOT NULL,
    version         TEXT NOT NULL,
    key_id          TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    sources         JSONB NOT NULL DEFAULT '[]'::jsonb,
    file_count      INTEGER NOT NULL DEFAULT 0,
    active          BOOLEAN NOT NULL DEFAULT false,
    imported_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (pack_id, version)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_kb_packs_active ON kb_packs(pack_id) WHERE active;

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
-- from the body; the GIN index on it backs search ranking (ts_rank_cd). A second
-- GIN trigram index on the body catches identifiers and partial tokens the
-- english parser would stem or split (CVE-2021-41773, wp-config.php).
CREATE TABLE IF NOT EXISTS kb_chunks (
    id          BIGSERIAL PRIMARY KEY,
    document_id BIGINT NOT NULL REFERENCES kb_documents(id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL,
    body        TEXT NOT NULL,
    tsv         TSVECTOR GENERATED ALWAYS AS (to_tsvector('english', body)) STORED,
    UNIQUE (document_id, chunk_index)
);
CREATE INDEX IF NOT EXISTS idx_kb_chunks_tsv ON kb_chunks USING gin(tsv);
CREATE INDEX IF NOT EXISTS idx_kb_chunks_trgm ON kb_chunks USING gin(body gin_trgm_ops);

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
-- Partial-name product search (e.g. "http_server" from "Apache httpd").
CREATE INDEX IF NOT EXISTS idx_kb_cpe_product_trgm ON kb_cpe_matches USING gin(product gin_trgm_ops);
