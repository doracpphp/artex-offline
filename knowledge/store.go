package knowledge

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// Store is the Postgres-backed index for imported knowledge packs. It owns the
// kb_* tables (db/migrations/0015_knowledge.sql): indexing a pack's documents and
// chunks, and the search_* / lookup_* queries the agent tools run. It holds a
// *sql.DB (the server passes the shared pool) and the resolved config.
type Store struct {
	db  *sql.DB
	cfg Config

	// embedder and vector state back the optional vector half of hybrid search
	// (embed.go, vector.go). embedder is nil when no local embedding model is
	// configured; then search is lexical-only. vec* is lazily resolved once.
	embedder Embedder
	vecMu    sync.Mutex
	vecOnce  bool // whether vector availability has been resolved
	vecReady bool // extension present, model configured, table built at the model's dim
	vecDim   int
	// embedMu serialises the background embedding worker, so a startup build and
	// an import build (or two imports) do not create the vector schema or insert
	// concurrently. A second caller finds no unembedded chunks and returns.
	embedMu sync.Mutex
}

// NewStore returns a Store over db with cfg.
func NewStore(db *sql.DB, cfg Config) *Store { return &Store{db: db, cfg: cfg} }

// SetEmbedder installs the local embedding model used for the vector half of
// hybrid search. nil (the default) keeps search lexical-only.
func (s *Store) SetEmbedder(e Embedder) { s.embedder = e }

// Config returns the store's configuration.
func (s *Store) Config() Config { return s.cfg }

// docMeta is the structured part of a CVE document, stored in kb_documents.meta
// and returned by lookup_cve.
type docMeta struct {
	Published  string   `json:"published,omitempty"`
	CVSS       *CVSS    `json:"cvss,omitempty"`
	CWEs       []string `json:"cwes,omitempty"`
	References []string `json:"references,omitempty"`
}

// ActivePack returns the active pack row for packID, or ok=false when none is
// active. Used to decide whether the tools have data and to enforce the
// downgrade rule on import.
func (s *Store) ActivePack(ctx context.Context, packID string) (version string, ok bool, err error) {
	err = s.db.QueryRowContext(ctx,
		`SELECT version FROM kb_packs WHERE pack_id=$1 AND active`, packID).Scan(&version)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return version, true, nil
}

// HasActivePack reports whether any pack is active, so the tools can be omitted
// when there is nothing to search.
func (s *Store) HasActivePack(ctx context.Context) bool {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT 1 FROM kb_packs WHERE active LIMIT 1`).Scan(&n); err != nil {
		return false
	}
	return n == 1
}

// ListPacks returns every imported pack, newest first, for the management UI.
func (s *Store) ListPacks(ctx context.Context) ([]PackRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT pack_id, version, key_id, file_count, active, imported_at
		   FROM kb_packs ORDER BY imported_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PackRow
	for rows.Next() {
		var p PackRow
		if err := rows.Scan(&p.PackID, &p.Version, &p.KeyID, &p.FileCount, &p.Active, &p.ImportedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// indexer accumulates a pack's documents inside one import transaction. The
// caller (index.go) feeds it CVEs, exploits and docs, then Commit activates the
// pack and deactivates the previous active one of the same id.
type indexer struct {
	tx     *sql.Tx
	ctx    context.Context
	cfg    Config
	packPK int64
}

// beginImport inserts the pack row (inactive) and returns an indexer bound to a
// transaction. The pack is activated only by Commit, so a failed import — which
// rolls back — leaves no partial pack and does not touch the active one.
func (s *Store) beginImport(ctx context.Context, m *Manifest, manifestSHA string) (*indexer, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	sources, _ := json.Marshal(m.Sources)
	var pk int64
	err = tx.QueryRowContext(ctx,
		`INSERT INTO kb_packs(pack_id, version, key_id, manifest_sha256, sources, file_count, active)
		 VALUES ($1,$2,$3,$4,$5,$6,false)
		 ON CONFLICT (pack_id, version) DO UPDATE SET
		   key_id=EXCLUDED.key_id, manifest_sha256=EXCLUDED.manifest_sha256,
		   sources=EXCLUDED.sources, file_count=EXCLUDED.file_count, imported_at=NOW()
		 RETURNING id`,
		m.PackID, m.Version, m.KeyID, manifestSHA, sources, len(m.Files)).Scan(&pk)
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("insert pack: %w", err)
	}
	// A re-import of the same version replaces its documents.
	if _, err := tx.ExecContext(ctx, `DELETE FROM kb_documents WHERE pack_id=$1`, pk); err != nil {
		tx.Rollback()
		return nil, err
	}
	return &indexer{tx: tx, ctx: ctx, cfg: s.cfg, packPK: pk}, nil
}

// addDocument inserts one document and its body chunks. bodyText is chunked
// together with the title so a title-only query still matches a chunk. extID and
// sourcePath may be empty. It returns the new document id.
func (ix *indexer) addDocument(kind, extID, sourcePath, title string, cveIDs, cpeTags []string, meta any, bodyText string) (int64, error) {
	metaJSON := []byte("{}")
	if meta != nil {
		if b, err := json.Marshal(meta); err == nil {
			metaJSON = b
		}
	}
	var docID int64
	err := ix.tx.QueryRowContext(ix.ctx,
		`INSERT INTO kb_documents(pack_id, kind, ext_id, source_path, title, cve_ids, cpe_tags, meta)
		 VALUES ($1,$2,$3,$4,$5,$6::text[],$7::text[],$8) RETURNING id`,
		ix.packPK, kind, nullIf(extID), nullIf(sourcePath), title,
		pgTextArray(cveIDs), pgTextArray(cpeTags), metaJSON).Scan(&docID)
	if err != nil {
		return 0, fmt.Errorf("insert document: %w", err)
	}
	indexText := title
	if strings.TrimSpace(bodyText) != "" {
		indexText = title + "\n\n" + bodyText
	}
	for _, c := range ChunkText(indexText, ix.cfg.MaxChunkBytes) {
		if _, err := ix.tx.ExecContext(ix.ctx,
			`INSERT INTO kb_chunks(document_id, chunk_index, body) VALUES ($1,$2,$3)`,
			docID, c.Index, c.Text); err != nil {
			return 0, fmt.Errorf("insert chunk: %w", err)
		}
	}
	return docID, nil
}

// addCPEMatch inserts one applicability row for a CVE document.
func (ix *indexer) addCPEMatch(docID int64, m CPEMatch) error {
	p, ok := ParseCPE(m.Criteria)
	if !ok {
		return nil // skip a criterion we cannot parse rather than fail the import
	}
	_, err := ix.tx.ExecContext(ix.ctx,
		`INSERT INTO kb_cpe_matches(document_id, vendor, product, criteria, vulnerable,
		   version_start_including, version_start_excluding, version_end_including, version_end_excluding)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		docID, p.Vendor, p.Product, m.Criteria, m.Vulnerable,
		m.VersionStartIncluding, m.VersionStartExcluding, m.VersionEndIncluding, m.VersionEndExcluding)
	return err
}

// commit activates this pack and deactivates the previously active pack of the
// same id, atomically with the inserts.
func (ix *indexer) commit(packID string) error {
	if _, err := ix.tx.ExecContext(ix.ctx,
		`UPDATE kb_packs SET active=false WHERE pack_id=$1 AND active AND id<>$2`, packID, ix.packPK); err != nil {
		ix.tx.Rollback()
		return err
	}
	if _, err := ix.tx.ExecContext(ix.ctx,
		`UPDATE kb_packs SET active=true WHERE id=$1`, ix.packPK); err != nil {
		ix.tx.Rollback()
		return err
	}
	return ix.tx.Commit()
}

func (ix *indexer) rollback() { _ = ix.tx.Rollback() }

// DeletePack removes a pack and its indexed rows (ON DELETE CASCADE). Its
// extracted files are removed separately by the importer.
func (s *Store) DeletePack(ctx context.Context, packID, version string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM kb_packs WHERE pack_id=$1 AND version=$2`, packID, version)
	return err
}

func nullIf(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// pgTextArray renders a []string as a PostgreSQL text[] literal for a $N::text[]
// parameter, matching db/assets.go's convention (the pgx stdlib driver takes the
// literal and the cast does the rest).
func pgTextArray(items []string) string {
	if len(items) == 0 {
		return "{}"
	}
	esc := make([]string, len(items))
	for i, s := range items {
		s = strings.ReplaceAll(s, `\`, `\\`)
		s = strings.ReplaceAll(s, `"`, `\"`)
		esc[i] = `"` + s + `"`
	}
	return "{" + strings.Join(esc, ",") + "}"
}
