package knowledge

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"time"
)

// Hybrid search (docs §4.2, Phase 2): a lexical ranking (tsvector) and, when a
// local embedding model and pgvector are available, a vector ranking, fused with
// Reciprocal Rank Fusion. Without the vector half it degrades to the lexical
// ranking, so an install with no embedding model, or whose vectors are still
// being built, keeps working.

// rrfK is the RRF constant: score contribution of a result at rank r is
// 1/(rrfK+r). 60 is the value from the original RRF paper; it damps the weight of
// lower ranks without letting the top result dominate.
const rrfK = 60

// embedBatch is how many chunks are embedded per request during background
// indexing — large enough to amortise the round-trip, small enough to bound
// memory and keep each request quick.
const embedBatch = 64

// chunkRow is one search hit at the chunk level, before a tool formats it.
type chunkRow struct {
	chunkID    int64
	packID     string
	docID      int64
	kind       string
	extID      sql.NullString
	sourcePath sql.NullString
	title      sql.NullString
	metaRaw    []byte
	cveArr     sql.NullString
	chunkIndex int
	body       string
	lexRank    float64
}

// searchChunks runs the hybrid search for the given document kinds and optional
// exploit type/platform filters, returning the top chunk rows. It always runs the
// lexical query; when vectors are ready it runs the vector query too and fuses.
func (s *Store) searchChunks(ctx context.Context, kinds []string, query, typ, platform string, limit int) ([]chunkRow, error) {
	limit = clampLimit(limit, s.cfg.MaxChunks)
	lex, err := s.lexicalChunks(ctx, kinds, query, typ, platform, limit*4)
	if err != nil {
		return nil, err
	}
	if !s.vectorReady(ctx) {
		if len(lex) > limit {
			lex = lex[:limit]
		}
		return lex, nil
	}
	qv, err := s.embedQuery(ctx, query)
	if err != nil {
		// Embedding failed (server down?). Fall back to lexical rather than error.
		log.Printf("[knowledge] query embedding failed, using lexical search: %v", err)
		if len(lex) > limit {
			lex = lex[:limit]
		}
		return lex, nil
	}
	vec, err := s.vectorChunks(ctx, kinds, typ, platform, qv, limit*4)
	if err != nil {
		log.Printf("[knowledge] vector search failed, using lexical search: %v", err)
		if len(lex) > limit {
			lex = lex[:limit]
		}
		return lex, nil
	}
	return fuseRRF(lex, vec, limit), nil
}

// fuseRRF merges two rankings of chunk rows by Reciprocal Rank Fusion and returns
// the top limit, keeping the row data from whichever ranking carried it.
func fuseRRF(lex, vec []chunkRow, limit int) []chunkRow {
	score := map[int64]float64{}
	row := map[int64]chunkRow{}
	accumulate := func(list []chunkRow) {
		for rank, r := range list {
			score[r.chunkID] += 1.0 / float64(rrfK+rank+1)
			if _, ok := row[r.chunkID]; !ok {
				row[r.chunkID] = r
			}
		}
	}
	accumulate(lex)
	accumulate(vec)
	ids := make([]int64, 0, len(score))
	for id := range score {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		if score[ids[i]] != score[ids[j]] {
			return score[ids[i]] > score[ids[j]]
		}
		return ids[i] < ids[j] // stable tie-break
	})
	if len(ids) > limit {
		ids = ids[:limit]
	}
	out := make([]chunkRow, 0, len(ids))
	for _, id := range ids {
		out = append(out, row[id])
	}
	return out
}

// lexicalChunks runs the tsvector ranking (with the trigram/ILIKE fallback for
// identifiers) for the given kinds and optional exploit filters.
func (s *Store) lexicalChunks(ctx context.Context, kinds []string, query, typ, platform string, limit int) ([]chunkRow, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT c.id, p.pack_id, d.id, d.kind, d.ext_id, d.source_path, d.title, d.meta, d.cve_ids,
       c.chunk_index, c.body,
       ts_rank_cd(c.tsv, websearch_to_tsquery('english', $1)) AS rank
FROM kb_chunks c
JOIN kb_documents d ON d.id = c.document_id
JOIN kb_packs p ON p.id = d.pack_id AND p.active
WHERE d.kind = ANY($2)
  AND (c.tsv @@ websearch_to_tsquery('english', $1) OR c.body ILIKE '%'||$1||'%')
  AND ($3 = '' OR d.meta->>'type' = $3)
  AND ($4 = '' OR d.meta->>'platform' = $4)
ORDER BY rank DESC, d.id, c.chunk_index
LIMIT $5`, query, pgTextArray(kinds), typ, platform, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanChunkRows(rows)
}

// vectorChunks runs the pgvector nearest-neighbour search (cosine distance) for
// the given kinds and optional exploit filters.
func (s *Store) vectorChunks(ctx context.Context, kinds []string, typ, platform string, qv []float32, limit int) ([]chunkRow, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT c.id, p.pack_id, d.id, d.kind, d.ext_id, d.source_path, d.title, d.meta, d.cve_ids,
       c.chunk_index, c.body,
       1 - (e.embedding <=> $1::vector) AS score
FROM kb_embeddings e
JOIN kb_chunks c ON c.id = e.chunk_id
JOIN kb_documents d ON d.id = c.document_id
JOIN kb_packs p ON p.id = d.pack_id AND p.active
WHERE d.kind = ANY($2)
  AND ($3 = '' OR d.meta->>'type' = $3)
  AND ($4 = '' OR d.meta->>'platform' = $4)
  AND e.model = $6
ORDER BY e.embedding <=> $1::vector
LIMIT $5`, formatVector(qv), pgTextArray(kinds), typ, platform, limit, s.embedder.Model())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanChunkRows(rows)
}

func scanChunkRows(rows *sql.Rows) ([]chunkRow, error) {
	var out []chunkRow
	for rows.Next() {
		var r chunkRow
		if err := rows.Scan(&r.chunkID, &r.packID, &r.docID, &r.kind, &r.extID, &r.sourcePath,
			&r.title, &r.metaRaw, &r.cveArr, &r.chunkIndex, &r.body, &r.lexRank); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// vectorReady reports whether the vector half of search is usable: an embedder is
// configured, the extension is available, the table is built at the model's
// dimension, and it holds at least one row. It is resolved once (the extension
// and table do not appear mid-process) but the row-count is re-checked while the
// table is still empty, so search turns hybrid as soon as background embedding
// lands its first vectors.
func (s *Store) vectorReady(ctx context.Context) bool {
	if s.embedder == nil {
		return false
	}
	s.vecMu.Lock()
	defer s.vecMu.Unlock()
	if !s.vecOnce {
		s.vecReady = VectorExtensionAvailable(ctx, s.db)
		s.vecOnce = true
	}
	if !s.vecReady {
		return false
	}
	// The table may not exist until the first embedding batch created it, and
	// vectors of a previous model are not comparable with this model's query
	// vectors: only this model's rows count.
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT 1 FROM kb_embeddings WHERE model=$1 LIMIT 1`, s.embedder.Model()).Scan(&n); err != nil {
		return false
	}
	return true
}

// queryEmbedTimeout bounds the embedding of one search query, so a slow or hung
// local embedder delays a tool call by seconds, not by the embedder client's
// batch timeout, before search falls back to lexical.
const queryEmbedTimeout = 15 * time.Second

// embedQuery embeds a single query string.
func (s *Store) embedQuery(ctx context.Context, query string) ([]float32, error) {
	ctx, cancel := context.WithTimeout(ctx, queryEmbedTimeout)
	defer cancel()
	vecs, err := s.embedder.Embed(ctx, []string{query})
	if err != nil {
		return nil, err
	}
	if len(vecs) != 1 || len(vecs[0]) == 0 {
		return nil, errNoEmbedding
	}
	return vecs[0], nil
}

var errNoEmbedding = &embedError{"embedder returned no vector"}

type embedError struct{ msg string }

func (e *embedError) Error() string { return e.msg }

// embedPackAsync embeds the chunks of a freshly imported pack in the background,
// so Import returns promptly and search stays lexical until vectors land. It is a
// no-op without an embedder or pgvector. Each call runs under its own context so
// it is not tied to the import request.
func (s *Store) embedPackAsync(packID string) {
	if s.embedder == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
		defer cancel()
		if err := s.embedActivePack(ctx); err != nil {
			log.Printf("[knowledge] background embedding stopped: %v", err)
		}
	}()
}

// EmbedActivePackAsync builds the vector index for the currently active pack in
// the background. The server calls it at startup so a pack imported before the
// embedder was configured, or a restart, resumes building vectors.
func (s *Store) EmbedActivePackAsync() { s.embedPackAsync("") }

// embedActivePack embeds every chunk of the active pack that has no embedding
// yet, in batches, creating the vector schema on the first batch. It is safe to
// re-run: it only processes chunks missing from kb_embeddings.
func (s *Store) embedActivePack(ctx context.Context) error {
	if s.embedder == nil {
		return nil
	}
	// Serialise: only one embedding worker builds the schema / inserts at a time.
	s.embedMu.Lock()
	defer s.embedMu.Unlock()
	if !VectorExtensionAvailable(ctx, s.db) {
		log.Printf("[knowledge] pgvector not available; vector search disabled (lexical only)")
		return nil
	}
	// A changed embedding model makes every stored vector stale, even at the
	// same dimension: drop them so the active pack is re-embedded with this one.
	if err := dropStaleEmbeddings(ctx, s.db, s.embedder.Model()); err != nil {
		return err
	}
	// Vectors shipped in the pack for this model and chunking come first: they
	// cost no embedding call (embedfile.go).
	if n, err := s.applyPrecomputed(ctx); err != nil {
		log.Printf("[knowledge] precomputed vectors: %v (the rest is embedded locally)", err)
	} else if n > 0 {
		log.Printf("[knowledge] applied %d precomputed vectors from the pack", n)
	}
	schemaReady := false
	total := 0
	for {
		ids, bodies, err := s.unembeddedChunks(ctx, embedBatch)
		if err != nil {
			return err
		}
		if len(ids) == 0 {
			break
		}
		vecs, err := s.embedder.Embed(ctx, bodies)
		if err != nil {
			return err
		}
		if len(vecs) != len(ids) || len(vecs[0]) == 0 {
			return errNoEmbedding
		}
		dim := len(vecs[0])
		if s.vecDimKnown() && dim != s.currentDim() {
			return fmt.Errorf("embedding model %s now returns %d-dimensional vectors, the index holds %d; restart ARTEX to rebuild the vector index", s.embedder.Model(), dim, s.currentDim())
		}
		if !schemaReady {
			if err := ensureVectorSchema(ctx, s.db, dim, s.embedder.Model()); err != nil {
				return err
			}
			s.vecMu.Lock()
			s.vecReady, s.vecOnce, s.vecDim = true, true, dim
			s.vecMu.Unlock()
			schemaReady = true
		}
		n, err := s.insertEmbeddings(ctx, ids, vecs, dim)
		if err != nil {
			return err
		}
		if n < len(ids) {
			// The skipped chunks stay unembedded and would be fetched again
			// forever: stop instead, and say why.
			return fmt.Errorf("embedding model %s returned %d of %d vectors at the index dimension %d; vector indexing stopped (search stays lexical for the rest)", s.embedder.Model(), n, len(ids), dim)
		}
		total += n
	}
	if total > 0 {
		log.Printf("[knowledge] embedded %d chunks with %s; vector search is active", total, s.embedder.Model())
	}
	return nil
}

// unembeddedChunks returns up to n active-pack chunks that have no embedding row,
// with their bodies to embed. When kb_embeddings does not exist yet the NOT
// EXISTS subquery is replaced by selecting all chunks (the table is created on
// the first batch).
func (s *Store) unembeddedChunks(ctx context.Context, n int) (ids []int64, bodies []string, err error) {
	hasTable, err := tableExists(ctx, s.db, "kb_embeddings")
	if err != nil {
		return nil, nil, err
	}
	q := `
SELECT c.id, c.body
FROM kb_chunks c
JOIN kb_documents d ON d.id = c.document_id
JOIN kb_packs p ON p.id = d.pack_id AND p.active`
	if hasTable {
		q += `
WHERE NOT EXISTS (SELECT 1 FROM kb_embeddings e WHERE e.chunk_id = c.id)`
	}
	q += `
ORDER BY c.id
LIMIT $1`
	rows, err := s.db.QueryContext(ctx, q, n)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var body string
		if err := rows.Scan(&id, &body); err != nil {
			return nil, nil, err
		}
		ids = append(ids, id)
		bodies = append(bodies, body)
	}
	return ids, bodies, rows.Err()
}

// insertEmbeddings writes a batch of vectors and returns how many it wrote. A
// vector of the wrong dimension (an inconsistent model response) is skipped;
// the caller stops when anything was skipped (embedActivePack).
func (s *Store) insertEmbeddings(ctx context.Context, ids []int64, vecs [][]float32, dim int) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO kb_embeddings(chunk_id, model, embedding) VALUES ($1,$2,$3::vector)
		 ON CONFLICT (chunk_id) DO UPDATE SET model=EXCLUDED.model, embedding=EXCLUDED.embedding`)
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	defer stmt.Close()
	model := s.embedder.Model()
	n := 0
	for i, id := range ids {
		if len(vecs[i]) != dim {
			continue
		}
		if _, err := stmt.ExecContext(ctx, id, model, formatVector(vecs[i])); err != nil {
			tx.Rollback()
			return 0, err
		}
		n++
	}
	return n, tx.Commit()
}

func (s *Store) vecDimKnown() bool {
	s.vecMu.Lock()
	defer s.vecMu.Unlock()
	return s.vecDim > 0
}

func (s *Store) currentDim() int {
	s.vecMu.Lock()
	defer s.vecMu.Unlock()
	return s.vecDim
}

func tableExists(ctx context.Context, db *sql.DB, name string) (bool, error) {
	var n int
	err := db.QueryRowContext(ctx, `SELECT 1 FROM pg_class WHERE relname=$1 AND relkind='r' LIMIT 1`, name).Scan(&n)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

// exploitMetaOf decodes an exploit document's meta (shared by the formatters).
func exploitMetaOf(raw []byte) exploitMeta {
	var em exploitMeta
	_ = json.Unmarshal(raw, &em)
	return em
}
