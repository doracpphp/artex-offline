-- Phase 4 of the offline knowledge search (docs/offline-knowledge-search.md §8):
-- MITRE ATT&CK techniques, and technique tags on the other documents.
--
-- A new document kind, 'technique', holds one ATT&CK technique (ext_id is its id,
-- e.g. T1190); technique_ids lists the ATT&CK ids a cve/exploit/doc/template
-- relates to, the way cve_ids links documents to CVEs. The column is added to the
-- existing kb_documents, so 0015's table definition stays as it was.

ALTER TABLE kb_documents
    ADD COLUMN IF NOT EXISTS technique_ids TEXT[] NOT NULL DEFAULT '{}';

-- lookup_technique -> related documents: find rows whose technique_ids contain
-- the technique id.
CREATE INDEX IF NOT EXISTS idx_kb_documents_techids ON kb_documents USING gin(technique_ids);

-- 'technique' joins the document kinds. The 0015 CHECK constraint is replaced;
-- Postgres auto-named it kb_documents_kind_check.
ALTER TABLE kb_documents DROP CONSTRAINT IF EXISTS kb_documents_kind_check;
ALTER TABLE kb_documents
    ADD CONSTRAINT kb_documents_kind_check
    CHECK (kind IN ('cve', 'exploit', 'doc', 'template', 'technique'));
