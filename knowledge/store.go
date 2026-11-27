package knowledge

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
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
	// importMu serialises imports (import.go): one staging directory, one
	// activation and one cleanup of superseded files at a time.
	importMu sync.Mutex
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

// activePack is the active version of a pack id, as an import needs it.
type activePack struct {
	Version     string
	Dir         string // kb_packs.dir, relative to the packs directory
	ManifestSHA string // hash of the manifest.json stored in Dir
}

// activePackRow returns the active version of packID, if any.
func (s *Store) activePackRow(ctx context.Context, packID string) (activePack, bool, error) {
	var a activePack
	err := s.db.QueryRowContext(ctx,
		`SELECT version, dir, manifest_sha256 FROM kb_packs WHERE pack_id=$1 AND active`, packID).Scan(&a.Version, &a.Dir, &a.ManifestSHA)
	if err == sql.ErrNoRows {
		return activePack{}, false, nil
	}
	if err != nil {
		return activePack{}, false, err
	}
	return a, true, nil
}

// documentChunks is how a document becomes chunks: its title and body,
// sanitised, joined so a title-only query still matches, and cut at maxBytes.
// The importer and the builder (precomputed vectors, keyed by chunk text) must
// produce identical chunks, so both go through here.
func documentChunks(title, body string, maxBytes int) []Chunk {
	title, body = sanitizeText(title), sanitizeText(body)
	text := title
	if strings.TrimSpace(body) != "" {
		text = title + "\n\n" + body
	}
	return ChunkText(text, maxBytes)
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

// ListPacks returns every imported pack, newest first, with the fingerprint of
// the key that verified it.
func (s *Store) ListPacks(ctx context.Context) ([]PackRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT pack_id, version, key_id, key_fingerprint, file_count, active, imported_at
		   FROM kb_packs ORDER BY imported_at DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PackRow
	for rows.Next() {
		var p PackRow
		if err := rows.Scan(&p.PackID, &p.Version, &p.KeyID, &p.KeyFingerprint, &p.FileCount, &p.Active, &p.ImportedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// KeyPin is the signing key a pack id is pinned to (trust on first import).
type KeyPin struct {
	PackID         string    `json:"pack_id"`
	KeyID          string    `json:"key_id"`
	KeyFingerprint string    `json:"key_fingerprint"`
	PinnedAt       time.Time `json:"pinned_at"`
}

// KeyPins returns every pack id's pinned signing key.
func (s *Store) KeyPins(ctx context.Context) ([]KeyPin, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT pack_id, key_id, key_fingerprint, pinned_at FROM kb_key_pins ORDER BY pack_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KeyPin
	for rows.Next() {
		var p KeyPin
		if err := rows.Scan(&p.PackID, &p.KeyID, &p.KeyFingerprint, &p.PinnedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// checkKeyPin refuses a pack signed by a key other than the one its pack id is
// pinned to, unless repin. It is checked before extraction (fail fast) and
// again inside the activation transaction (commit), which also sets the pin.
func (s *Store) checkKeyPin(ctx context.Context, vm *VerifiedManifest, repin bool) error {
	var pinnedID, pinnedFP string
	err := s.db.QueryRowContext(ctx, `SELECT key_id, key_fingerprint FROM kb_key_pins WHERE pack_id=$1`, vm.PackID).Scan(&pinnedID, &pinnedFP)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	return pinMismatch(vm, pinnedID, pinnedFP, repin)
}

func pinMismatch(vm *VerifiedManifest, pinnedID, pinnedFP string, repin bool) error {
	if pinnedFP == vm.Fingerprint || repin {
		return nil
	}
	return fmt.Errorf("pack %s is pinned to signing key %s (fingerprint %s), but this pack is signed by key %s (fingerprint %s); "+
		"if the signing key was rotated on purpose, compare the fingerprint out of band and re-import with repin=1",
		vm.PackID, pinnedID, pinnedFP, vm.KeyID, vm.Fingerprint)
}

// EnsureTrigramIndexes creates pg_trgm and the trigram GIN indexes that speed
// up the ILIKE fallback for identifiers and partial product names. Best effort:
// without the extension (no rights, or a Postgres without contrib) search still
// works, just with sequential scans for that fallback.
func (s *Store) EnsureTrigramIndexes(ctx context.Context) error {
	for _, q := range []string{
		`CREATE EXTENSION IF NOT EXISTS pg_trgm`,
		`CREATE INDEX IF NOT EXISTS idx_kb_chunks_trgm ON kb_chunks USING gin(body gin_trgm_ops)`,
		`CREATE INDEX IF NOT EXISTS idx_kb_cpe_product_trgm ON kb_cpe_matches USING gin(product gin_trgm_ops)`,
	} {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return nil
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

// beginImport inserts the pack row and returns an indexer bound to a
// transaction. The pack is activated only by commit, so a failed import — which
// rolls back — leaves no partial pack and does not touch the active one. dir is
// the pack's files directory relative to the packs directory.
//
// Re-importing the active version updates its row in place (pack_id, version
// is unique): its old documents are deleted and the new ones inserted in the
// same transaction, and the row points at the new directory only once it
// commits.
//
// vm is the verified pack (its key and fingerprint); m is the manifest the
// directory is indexed from (the merged one for a delta), and manifestSHA the
// hash of its stored bytes.
func (s *Store) beginImport(ctx context.Context, vm *VerifiedManifest, m *Manifest, manifestSHA, dir string) (*indexer, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	sources := sanitizeJSON(mustJSON(m.Sources))
	var pk int64
	err = tx.QueryRowContext(ctx,
		`INSERT INTO kb_packs(pack_id, version, key_id, key_fingerprint, manifest_sha256, sources, file_count, dir, active)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,false)
		 ON CONFLICT (pack_id, version) DO UPDATE SET
		   key_id=EXCLUDED.key_id, key_fingerprint=EXCLUDED.key_fingerprint,
		   manifest_sha256=EXCLUDED.manifest_sha256, sources=EXCLUDED.sources,
		   file_count=EXCLUDED.file_count, dir=EXCLUDED.dir, imported_at=NOW()
		 RETURNING id`,
		vm.PackID, vm.Version, vm.KeyID, vm.Fingerprint, manifestSHA, sources, len(m.Files), dir).Scan(&pk)
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
			metaJSON = sanitizeJSON(b)
		}
	}
	// Pack data is signed, not clean: make every value storable (import.go).
	extID, sourcePath, title, bodyText = sanitizeText(extID), sanitizeText(sourcePath), sanitizeText(title), sanitizeText(bodyText)
	cveIDs, cpeTags = sanitizeAll(cveIDs), sanitizeAll(cpeTags)
	var docID int64
	err := ix.tx.QueryRowContext(ix.ctx,
		`INSERT INTO kb_documents(pack_id, kind, ext_id, source_path, title, cve_ids, cpe_tags, meta)
		 VALUES ($1,$2,$3,$4,$5,$6::text[],$7::text[],$8) RETURNING id`,
		ix.packPK, kind, nullIf(extID), nullIf(sourcePath), title,
		pgTextArray(cveIDs), pgTextArray(cpeTags), metaJSON).Scan(&docID)
	if err != nil {
		return 0, fmt.Errorf("insert document: %w", err)
	}
	for _, c := range documentChunks(title, bodyText, ix.cfg.MaxChunkBytes) {
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
		docID, sanitizeText(p.Vendor), sanitizeText(p.Product), sanitizeText(m.Criteria), m.Vulnerable,
		sanitizeText(m.VersionStartIncluding), sanitizeText(m.VersionStartExcluding),
		sanitizeText(m.VersionEndIncluding), sanitizeText(m.VersionEndExcluding))
	return err
}

// commit activates this pack, deactivates the previously active pack of the
// same id and records the signing-key pin, atomically with the inserts. The pin
// is re-checked under a row lock, so two servers importing at once cannot both
// pass the pre-check with different keys.
func (ix *indexer) commit(vm *VerifiedManifest, repin bool) error {
	var pinnedID, pinnedFP string
	err := ix.tx.QueryRowContext(ix.ctx,
		`SELECT key_id, key_fingerprint FROM kb_key_pins WHERE pack_id=$1 FOR UPDATE`, vm.PackID).Scan(&pinnedID, &pinnedFP)
	switch {
	case err == sql.ErrNoRows:
	case err != nil:
		ix.tx.Rollback()
		return err
	default:
		if perr := pinMismatch(vm, pinnedID, pinnedFP, repin); perr != nil {
			ix.tx.Rollback()
			return perr
		}
	}
	if _, err := ix.tx.ExecContext(ix.ctx,
		`INSERT INTO kb_key_pins(pack_id, key_id, key_fingerprint) VALUES ($1,$2,$3)
		 ON CONFLICT (pack_id) DO UPDATE SET key_id=EXCLUDED.key_id, key_fingerprint=EXCLUDED.key_fingerprint, pinned_at=NOW()
		 WHERE kb_key_pins.key_fingerprint <> EXCLUDED.key_fingerprint`,
		vm.PackID, vm.KeyID, vm.Fingerprint); err != nil {
		ix.tx.Rollback()
		return err
	}
	if _, err := ix.tx.ExecContext(ix.ctx,
		`UPDATE kb_packs SET active=false WHERE pack_id=$1 AND active AND id<>$2`, vm.PackID, ix.packPK); err != nil {
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

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("[]")
	}
	return b
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
