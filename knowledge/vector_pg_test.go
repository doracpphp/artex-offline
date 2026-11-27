package knowledge

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// conceptEmbedder is a deterministic test embedder: it maps text to a one-hot-ish
// vector over a few security "concepts" by keyword, so a query and a document
// that share a concept are near in vector space even when they share no words.
// This lets the test prove the vector half adds recall the lexical half misses.
type conceptEmbedder struct{ model string }

var conceptKeywords = map[string]int{
	// concept 0: SQL injection
	"sql": 0, "injection": 0, "union": 0, "select": 0, "sqli": 0,
	// concept 1: privilege escalation
	"privilege": 1, "escalation": 1, "sudo": 1, "gtfobins": 1, "setuid": 1,
	// concept 2: path traversal
	"traversal": 2, "path": 2, "lfi": 2, "directory": 2,
}

func (conceptEmbedder) Model() string { return "concept-test" }

func (conceptEmbedder) Embed(_ context.Context, texts []string) ([][]float32, error) {
	out := make([][]float32, len(texts))
	for i, t := range texts {
		var v [3]float32
		for _, w := range strings.FieldsFunc(strings.ToLower(t), func(r rune) bool {
			return !(r >= 'a' && r <= 'z')
		}) {
			if c, ok := conceptKeywords[w]; ok {
				v[c] += 1
			}
		}
		// Normalise; an all-zero vector gets a tiny uniform value so it is valid.
		norm := float32(0)
		for _, x := range v {
			norm += x * x
		}
		if norm == 0 {
			out[i] = []float32{0.577, 0.577, 0.577}
			continue
		}
		s := float32(1) / float32(sqrt32(norm))
		out[i] = []float32{v[0] * s, v[1] * s, v[2] * s}
	}
	return out, nil
}

func sqrt32(x float32) float32 {
	// Newton's method, enough for a 3-dim unit vector in a test.
	z := x
	for i := 0; i < 20; i++ {
		z = (z + x/z) / 2
	}
	return z
}

func buildConceptPack(t *testing.T) (string, map[string]ed25519.PublicKey) {
	t.Helper()
	pub, priv, _ := GenerateKey()
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	write := func(rel, body string) {
		abs := filepath.Join(src, filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(abs), 0o755)
		os.WriteFile(abs, []byte(body), 0o644)
	}
	write("docs/sqli.md", "# SQL injection\nExtract columns with a UNION SELECT payload.\n")
	write("docs/privesc.md", "# Privilege escalation\nAbuse sudo misconfigurations and setuid binaries to become root.\n")
	in := PackInput{PackID: "artex-core", Version: "2026.11.27", KeyID: "test-key",
		Files: map[string]string{
			"docs/sqli.md":    filepath.Join(src, "docs/sqli.md"),
			"docs/privesc.md": filepath.Join(src, "docs/privesc.md"),
		}}
	p := filepath.Join(dir, "pack.tar.gz")
	if err := BuildPackFile(p, in, priv); err != nil {
		t.Fatal(err)
	}
	return p, trustFor(pub)
}

// TestHybridVectorSearch needs a pgvector-enabled database (pgvector/pgvector
// image). It is skipped when ARTEX_PG_DSN is unset or the extension is absent.
func TestHybridVectorSearch(t *testing.T) {
	s, ctx, done := openTestStore(t)
	defer done()
	if !VectorExtensionAvailable(ctx, s.db) {
		t.Skip("pgvector not available in this database; set ARTEX_PG_DSN to a pgvector image to run")
	}
	s.SetEmbedder(conceptEmbedder{})
	packPath, trust := buildConceptPack(t)

	if _, err := s.Import(ctx, packPath, trust, ImportOptions{}); err != nil {
		t.Fatalf("import: %v", err)
	}
	// Import kicks off async embedding; run it synchronously here for determinism.
	if err := s.embedActivePack(ctx); err != nil {
		t.Fatalf("embed: %v", err)
	}
	if !s.vectorReady(ctx) {
		t.Fatal("vector search should be ready after embedding")
	}
	var nEmb, nChunks int
	s.db.QueryRowContext(ctx, "SELECT count(*) FROM kb_embeddings").Scan(&nEmb)
	s.db.QueryRowContext(ctx, "SELECT count(*) FROM kb_chunks c JOIN kb_documents d ON d.id=c.document_id JOIN kb_packs p ON p.id=d.pack_id AND p.active").Scan(&nChunks)
	if nEmb == 0 || nEmb != nChunks {
		t.Fatalf("every active-pack chunk should be embedded: %d embeddings, %d chunks", nEmb, nChunks)
	}

	// Vector-only recall: "gtfobins" shares no word with the privesc doc (which
	// says sudo/setuid), but maps to the same concept, so the vector half finds it
	// while lexical alone would not.
	if lex, _ := s.lexicalChunks(ctx, []string{"doc"}, "gtfobins", "", "", 10); len(lex) != 0 {
		t.Fatalf("control: 'gtfobins' should not match lexically, got %d", len(lex))
	}
	hits, err := s.SearchTechnique(ctx, "gtfobins", 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) == 0 || hits[0].Path != "docs/privesc.md" {
		t.Fatalf("hybrid search should surface the privesc doc via vectors: %+v", hits)
	}

	// Re-embedding is idempotent (no new rows, no error).
	if err := s.embedActivePack(ctx); err != nil {
		t.Fatalf("re-embed: %v", err)
	}
	var nEmb2 int
	s.db.QueryRowContext(ctx, "SELECT count(*) FROM kb_embeddings").Scan(&nEmb2)
	if nEmb2 != nEmb {
		t.Errorf("re-embedding changed the row count: %d → %d", nEmb, nEmb2)
	}
}

// renamedEmbedder is conceptEmbedder under another model name: same vectors,
// but a different model as far as the index is concerned.
type renamedEmbedder struct{ conceptEmbedder }

func (renamedEmbedder) Model() string { return "concept-test-v2" }

// badDimEmbedder returns a vector of the wrong dimension for every text but the
// first, like an inconsistent embedding server.
type badDimEmbedder struct{ conceptEmbedder }

func (badDimEmbedder) Model() string { return "bad-dim" }

func (b badDimEmbedder) Embed(ctx context.Context, texts []string) ([][]float32, error) {
	out, err := b.conceptEmbedder.Embed(ctx, texts)
	for i := 1; i < len(out); i++ {
		out[i] = append(out[i], 0)
	}
	return out, err
}

// A changed embedding model re-embeds the active pack: no vector of the old
// model is left, and every chunk has one of the new model.
func TestVectorModelChangeRebuilds(t *testing.T) {
	s, ctx, done := openTestStore(t)
	defer done()
	if !VectorExtensionAvailable(ctx, s.db) {
		t.Skip("pgvector not available")
	}
	s.db.ExecContext(ctx, "DROP TABLE IF EXISTS kb_embeddings")
	// Import without an embedder, so no background worker races the steps below.
	packPath, trust := buildConceptPack(t)
	if _, err := s.Import(ctx, packPath, trust, ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	s.SetEmbedder(conceptEmbedder{})
	if err := s.embedActivePack(ctx); err != nil {
		t.Fatal(err)
	}
	// Restart with another model: a new store, as the server builds at startup.
	s2 := NewStore(s.db, s.cfg)
	s2.SetEmbedder(renamedEmbedder{})
	if err := s2.embedActivePack(ctx); err != nil {
		t.Fatal(err)
	}
	var old, cur, chunks int
	s.db.QueryRowContext(ctx, "SELECT count(*) FROM kb_embeddings WHERE model='concept-test'").Scan(&old)
	s.db.QueryRowContext(ctx, "SELECT count(*) FROM kb_embeddings WHERE model='concept-test-v2'").Scan(&cur)
	s.db.QueryRowContext(ctx, "SELECT count(*) FROM kb_chunks c JOIN kb_documents d ON d.id=c.document_id JOIN kb_packs p ON p.id=d.pack_id AND p.active").Scan(&chunks)
	if old != 0 || cur != chunks {
		t.Fatalf("after a model change: %d old vectors, %d new, %d chunks", old, cur, chunks)
	}
	if !s2.vectorReady(ctx) {
		t.Error("vector search must be ready with the new model")
	}
}

// An embedder that returns vectors of the wrong dimension stops the worker with
// an error instead of fetching the same chunks forever.
func TestVectorBadDimensionStops(t *testing.T) {
	s, ctx, done := openTestStore(t)
	defer done()
	if !VectorExtensionAvailable(ctx, s.db) {
		t.Skip("pgvector not available")
	}
	s.db.ExecContext(ctx, "DROP TABLE IF EXISTS kb_embeddings")
	packPath, trust := buildConceptPack(t)
	if _, err := s.Import(ctx, packPath, trust, ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	s.SetEmbedder(badDimEmbedder{})
	ctx2, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	err := s.embedActivePack(ctx2)
	if err == nil || ctx2.Err() != nil || !strings.Contains(err.Error(), "vector indexing stopped") {
		t.Fatalf("a bad-dimension embedder must stop with an error, not loop: err=%v ctx=%v", err, ctx2.Err())
	}
}

// TestVectorDimChangeRebuilds verifies the table is rebuilt when the embedding
// dimension changes (a different model).
func TestVectorDimChangeRebuilds(t *testing.T) {
	s, ctx, done := openTestStore(t)
	defer done()
	if !VectorExtensionAvailable(ctx, s.db) {
		t.Skip("pgvector not available")
	}
	if err := ensureVectorSchema(ctx, s.db, 3, "m3"); err != nil {
		t.Fatal(err)
	}
	dim, ok, _ := currentVectorDim(ctx, s.db)
	if !ok || dim != 3 {
		t.Fatalf("dim after create: %d ok=%v", dim, ok)
	}
	if err := ensureVectorSchema(ctx, s.db, 8, "m8"); err != nil {
		t.Fatal(err)
	}
	dim, _, _ = currentVectorDim(ctx, s.db)
	if dim != 8 {
		t.Fatalf("table should have been rebuilt at dim 8, got %d", dim)
	}
}
