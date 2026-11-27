package knowledge

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
)

// pgvector runtime setup (docs §4.2). pgvector is NOT in the stock postgres image
// and NOT in the checksum-locked migration (0015); it is created here at runtime
// when the extension is available, so the stock image runs lexical-only and a
// deployment that swaps in a pgvector image gets hybrid search without a schema
// migration. kb_embeddings carries one vector per chunk; its column dimension is
// fixed, so a change of embedding model (different dimension) recreates the table
// — the vectors are a derived cache, safe to drop.

// VectorExtensionAvailable reports whether the server can create the vector
// extension (it is listed in pg_available_extensions). A false result means
// lexical-only, with no error: the stock image simply lacks pgvector.
func VectorExtensionAvailable(ctx context.Context, db *sql.DB) bool {
	var n int
	err := db.QueryRowContext(ctx,
		`SELECT 1 FROM pg_available_extensions WHERE name='vector' LIMIT 1`).Scan(&n)
	return err == nil && n == 1
}

// ensureVectorSchema creates the vector extension and the kb_embeddings table for
// a given embedding dimension and model, if not already present at that
// dimension. It returns an error the caller treats as "vectors unavailable"
// (e.g. an external role without CREATE EXTENSION rights), falling back to
// lexical search.
func ensureVectorSchema(ctx context.Context, db *sql.DB, dim int, model string) error {
	if dim <= 0 || dim > 2000 {
		return fmt.Errorf("embedding dimension %d is out of pgvector's HNSW range (1..2000)", dim)
	}
	if _, err := db.ExecContext(ctx, `CREATE EXTENSION IF NOT EXISTS vector`); err != nil {
		return fmt.Errorf("create vector extension: %w", err)
	}
	cur, exists, err := currentVectorDim(ctx, db)
	if err != nil {
		return err
	}
	if exists && cur != dim {
		// Model/dimension changed: drop the cache and rebuild at the new dimension.
		if _, err := db.ExecContext(ctx, `DROP TABLE IF EXISTS kb_embeddings`); err != nil {
			return err
		}
		exists = false
	}
	if !exists {
		// vector(dim) needs a literal dimension, so it is interpolated (validated above).
		create := `CREATE TABLE IF NOT EXISTS kb_embeddings (
			chunk_id  BIGINT PRIMARY KEY REFERENCES kb_chunks(id) ON DELETE CASCADE,
			model     TEXT NOT NULL,
			embedding vector(` + strconv.Itoa(dim) + `) NOT NULL
		)`
		if _, err := db.ExecContext(ctx, create); err != nil {
			return fmt.Errorf("create kb_embeddings: %w", err)
		}
		// HNSW index with cosine distance; the search orders by embedding <=> query.
		if _, err := db.ExecContext(ctx,
			`CREATE INDEX IF NOT EXISTS idx_kb_embeddings_hnsw ON kb_embeddings USING hnsw (embedding vector_cosine_ops)`); err != nil {
			return fmt.Errorf("create hnsw index: %w", err)
		}
	}
	_ = model
	return nil
}

// currentVectorDim returns the dimension of the existing kb_embeddings.embedding
// column, if the table exists. pgvector stores the declared dimension directly in
// the column's type modifier (atttypmod).
func currentVectorDim(ctx context.Context, db *sql.DB) (dim int, exists bool, err error) {
	var typmod sql.NullInt64
	err = db.QueryRowContext(ctx, `
SELECT a.atttypmod
FROM pg_attribute a
JOIN pg_class c ON c.oid = a.attrelid
WHERE c.relname='kb_embeddings' AND a.attname='embedding' AND NOT a.attisdropped`).Scan(&typmod)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if !typmod.Valid || typmod.Int64 <= 0 {
		return 0, true, nil // present but unconstrained; treat as needing rebuild
	}
	return int(typmod.Int64), true, nil
}

// formatVector renders a float32 vector as a pgvector literal ("[1,2,3]") for a
// $N::vector parameter.
func formatVector(v []float32) string {
	var b strings.Builder
	b.WriteByte('[')
	for i, f := range v {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.FormatFloat(float64(f), 'f', -1, 32))
	}
	b.WriteByte(']')
	return b.String()
}
