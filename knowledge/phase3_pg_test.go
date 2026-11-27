package knowledge

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildPackFrom builds a signed pack from a file tree (pack path -> body) plus
// optional extra fields, and returns its path.
func buildPackFrom(t *testing.T, priv ed25519.PrivateKey, in PackInput, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	src := writeTree(t, filepath.Join(dir, "src"), files)
	if in.Files == nil {
		in.Files = map[string]string{}
	}
	for p, abs := range src {
		in.Files[p] = abs
	}
	out := filepath.Join(dir, "pack.tar.gz")
	if err := BuildPackFile(out, in, priv); err != nil {
		t.Fatal(err)
	}
	return out
}

// nuclei templates: indexed with their id, CVEs and severity; lookup_cve links
// them; a hit names the local file when this installation has it; and a
// templates version that differs from the image's is reported.
func TestStoreTemplatesAndLookupCVE(t *testing.T) {
	s, ctx, done := openTestStore(t)
	defer done()
	pub, priv, _ := GenerateKey()
	rel := "http/cves/2021/CVE-2021-41773.yaml"
	pack := buildPackFrom(t, priv, PackInput{PackID: "artex-core", Version: "2026.12.01", KeyID: "test-key",
		Sources: []Source{{Name: "nuclei-templates", Version: "v10.4.0"}}}, map[string]string{
		"nvd/recent.json":                  nvdSample,
		"templates/" + rel:                 sampleTemplate,
		"templates/helpers/payloads/x.yml": "- not a template\n",
	})
	// This installation's templates: only the CVE template exists locally.
	s.cfg.TemplatesDir = filepath.Join(t.TempDir(), "nuclei-templates")
	writeTree(t, s.cfg.TemplatesDir, map[string]string{rel: sampleTemplate})

	res, err := s.Import(ctx, pack, trustFor(pub), ImportOptions{ImageTemplatesVersion: "v10.5.1 (79fb682)"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Templates != 2 || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "v10.4.0") {
		t.Fatalf("import: %d templates, warnings %v", res.Templates, res.Warnings)
	}

	info, ok, err := s.LookupCVE(ctx, "CVE-2021-41773")
	if err != nil || !ok || len(info.Templates) != 1 {
		t.Fatalf("lookup_cve templates: %+v ok=%v err=%v", info.Templates, ok, err)
	}
	tr := info.Templates[0]
	wantLocal := filepath.Join(s.cfg.TemplatesDir, filepath.FromSlash(rel))
	if tr.ID != "CVE-2021-41773" || tr.Severity != "high" || tr.Path != "templates/"+rel || tr.LocalPath != wantLocal {
		t.Errorf("template ref: %+v (want local %s)", tr, wantLocal)
	}

	hits, err := s.SearchTechnique(ctx, "apache path traversal", 8)
	if err != nil || len(hits) == 0 {
		t.Fatalf("search_technique: %v %+v", err, hits)
	}
	if h := hits[0]; h.Kind != "template" || h.TemplateID != "CVE-2021-41773" || h.LocalPath != wantLocal {
		t.Errorf("template hit: %+v", h)
	}
	// The helper file is indexed as plain text, with no local path (not in the
	// local set) and no template id.
	if helper, _ := s.SearchTechnique(ctx, "not a template", 8); len(helper) == 0 || helper[0].TemplateID != "" || helper[0].LocalPath != "" {
		t.Errorf("non-template file: %+v", helper)
	}
	// Without a local templates directory there is no local path.
	s.cfg.TemplatesDir = ""
	if info, _, _ := s.LookupCVE(ctx, "CVE-2021-41773"); info.Templates[0].LocalPath != "" {
		t.Error("no local templates directory, no local path")
	}
	// A CVE known only from a template is still found.
	s.cfg.TemplatesDir = ""
	pack2 := buildPackFrom(t, priv, PackInput{PackID: "artex-core", Version: "2026.12.02", KeyID: "test-key"}, map[string]string{
		"templates/" + rel: sampleTemplate,
	})
	if _, err := s.Import(ctx, pack2, trustFor(pub), ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	if info, ok, _ := s.LookupCVE(ctx, "CVE-2021-41773"); !ok || info.Description != "" || len(info.Templates) != 1 {
		t.Errorf("CVE known only from a template: %+v ok=%v", info, ok)
	}
}

// A delta applies on top of exactly its base and gives the same searchable
// content as the full pack of the new version; deltas chain.
func TestStoreDeltaImport(t *testing.T) {
	s, ctx, done := openTestStore(t)
	defer done()
	pub, priv, _ := GenerateKey()
	trust := trustFor(pub)
	v1Files := map[string]string{
		"docs/keep.md":   "# Keep\nunchanged kerberoasting notes\n",
		"docs/change.md": "# Change\nold xylophone text\n",
		"docs/remove.md": "# Remove\nobsolete zeppelin text\n",
	}
	v1 := buildPackFrom(t, priv, PackInput{PackID: "artex-core", Version: "1", KeyID: "test-key"}, v1Files)
	v1m, err := PackManifest(v1)
	if err != nil {
		t.Fatal(err)
	}

	// v2: change one doc, remove one, add one.
	v2Src := writeTree(t, filepath.Join(t.TempDir(), "v2"), map[string]string{
		"docs/keep.md":   v1Files["docs/keep.md"],
		"docs/change.md": "# Change\nnew marimba text\n",
		"docs/add.md":    "# Add\nfresh quokka text\n",
	})
	v2In := PackInput{PackID: "artex-core", Version: "2", KeyID: "test-key", Files: v2Src}
	d2In, err := DeltaInput(v2In, v1m)
	if err != nil {
		t.Fatal(err)
	}
	d2 := filepath.Join(t.TempDir(), "delta2.tar.gz")
	if err := BuildPackFile(d2, d2In, priv); err != nil {
		t.Fatal(err)
	}

	// No active base: refused.
	if _, err := s.Import(ctx, d2, trust, ImportOptions{}); err == nil || !strings.Contains(err.Error(), "delta for base version 1") {
		t.Fatalf("a delta without its base must be refused: %v", err)
	}
	if _, err := s.Import(ctx, v1, trust, ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	res, err := s.Import(ctx, d2, trust, ImportOptions{})
	if err != nil {
		t.Fatalf("delta import: %v", err)
	}
	if res.BaseVersion != "1" || res.Version != "2" || res.Docs != 3 {
		t.Fatalf("delta result: %+v", res)
	}
	if v, _, _ := s.ActivePack(ctx, "artex-core"); v != "2" {
		t.Fatalf("active version after the delta: %s", v)
	}
	for q, want := range map[string]string{"kerberoasting": "docs/keep.md", "marimba": "docs/change.md", "quokka": "docs/add.md"} {
		if h, _ := s.SearchTechnique(ctx, q, 8); len(h) == 0 || h[0].Path != want {
			t.Errorf("after the delta, %q should find %s: %+v", q, want, h)
		}
	}
	for _, gone := range []string{"xylophone", "zeppelin"} {
		if h, _ := s.SearchTechnique(ctx, gone, 8); len(h) != 0 {
			t.Errorf("after the delta, %q must be gone: %+v", gone, h)
		}
	}
	// The carried-over file is on disk in the new version's directory.
	if data, _, _, ok, err := s.ReadDocumentFile(ctx, "docs/keep.md", MaxDocumentFileBytes); err != nil || !ok || !strings.Contains(string(data), "kerberoasting") {
		t.Errorf("unchanged file after the delta: %q ok=%v err=%v", data, ok, err)
	}

	// The same delta again: its base (1) is no longer active.
	if _, err := s.Import(ctx, d2, trust, ImportOptions{}); err == nil {
		t.Error("a delta whose base is not the active version must be refused")
	}

	// v3: a delta against the v2 FULL pack applies on the v2 that came from a
	// delta, because both describe the same files.
	v2Full := filepath.Join(t.TempDir(), "v2.tar.gz")
	if err := BuildPackFile(v2Full, v2In, priv); err != nil {
		t.Fatal(err)
	}
	v2m, _ := PackManifest(v2Full)
	v3Src := writeTree(t, filepath.Join(t.TempDir(), "v3"), map[string]string{
		"docs/keep.md":   v1Files["docs/keep.md"],
		"docs/change.md": "# Change\nnew marimba text\n",
		"docs/add.md":    "# Add\nfresh quokka text, more wombat\n",
	})
	d3In, err := DeltaInput(PackInput{PackID: "artex-core", Version: "3", KeyID: "test-key", Files: v3Src}, v2m)
	if err != nil {
		t.Fatal(err)
	}
	d3 := filepath.Join(t.TempDir(), "delta3.tar.gz")
	if err := BuildPackFile(d3, d3In, priv); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Import(ctx, d3, trust, ImportOptions{}); err != nil {
		t.Fatalf("chained delta: %v", err)
	}
	if h, _ := s.SearchTechnique(ctx, "wombat", 8); len(h) == 0 || h[0].Path != "docs/add.md" {
		t.Errorf("after the chained delta: %+v", h)
	}

	// A tampered stored manifest of the base is detected.
	var dir string
	s.db.QueryRowContext(ctx, `SELECT dir FROM kb_packs WHERE active`).Scan(&dir)
	abs, _ := s.cfg.packFilesDir(dir)
	os.WriteFile(filepath.Join(abs, storedManifestName), []byte("{}"), 0o640)
	v4In, _ := DeltaInput(PackInput{PackID: "artex-core", Version: "4", KeyID: "test-key", Files: v3Src}, v2m)
	v4In.BaseVersion = "3"
	d4 := filepath.Join(t.TempDir(), "delta4.tar.gz")
	if err := BuildPackFile(d4, v4In, priv); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Import(ctx, d4, trust, ImportOptions{}); err == nil || !strings.Contains(err.Error(), "does not match its recorded hash") {
		t.Errorf("a tampered stored manifest must be refused: %v", err)
	}
}

// Vectors shipped in the pack are used instead of calling the embedding model,
// when the model and chunk size match.
func TestPrecomputedVectorsApplied(t *testing.T) {
	s, ctx, done := openTestStore(t)
	defer done()
	if !VectorExtensionAvailable(ctx, s.db) {
		t.Skip("pgvector not available")
	}
	s.db.ExecContext(ctx, "DROP TABLE IF EXISTS kb_embeddings")
	pub, priv, _ := GenerateKey()
	dir := t.TempDir()
	src := writeTree(t, filepath.Join(dir, "src"), map[string]string{
		"docs/sqli.md":    "# SQL injection\nUNION SELECT payloads.\n",
		"docs/privesc.md": "# Privilege escalation\nsudo and setuid abuse.\n",
	})
	builder := &countingEmbedder{model: "count-test"}
	set, _, err := BuildEmbeddings(ctx, EmbedBuild{Files: src, ChunkBytes: s.cfg.MaxChunkBytes, Embedder: builder, FullOut: filepath.Join(dir, "v.akv")})
	if err != nil {
		t.Fatal(err)
	}
	set.Path = EmbeddingFileName("count-test", "1")
	files := copyMap(src)
	files[set.Path] = filepath.Join(dir, "v.akv")
	pack := filepath.Join(dir, "pack.tar.gz")
	if err := BuildPackFile(pack, PackInput{PackID: "artex-core", Version: "1", KeyID: "test-key", Files: files, Embeddings: []EmbeddingSet{set}}, priv); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Import(ctx, pack, trustFor(pub), ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	// The offline side has the same model: the worker must not need it.
	local := &countingEmbedder{model: "count-test"}
	s.SetEmbedder(local)
	if err := s.embedActivePack(ctx); err != nil {
		t.Fatal(err)
	}
	var vecs, chunks int
	s.db.QueryRowContext(ctx, "SELECT count(*) FROM kb_embeddings").Scan(&vecs)
	s.db.QueryRowContext(ctx, "SELECT count(*) FROM kb_chunks c JOIN kb_documents d ON d.id=c.document_id JOIN kb_packs p ON p.id=d.pack_id AND p.active").Scan(&chunks)
	if vecs != chunks || chunks == 0 || local.calls() != 0 {
		t.Fatalf("precomputed: %d vectors for %d chunks, %d local embed calls (want all chunks, no calls)", vecs, chunks, local.calls())
	}

	// Another model ignores the shipped vectors and embeds locally.
	s.db.ExecContext(ctx, "DROP TABLE IF EXISTS kb_embeddings")
	other := &countingEmbedder{model: "other-model"}
	s2 := NewStore(s.db, s.cfg)
	s2.SetEmbedder(other)
	if err := s2.embedActivePack(ctx); err != nil {
		t.Fatal(err)
	}
	if other.calls() != chunks {
		t.Errorf("another model must embed every chunk locally: %d calls for %d chunks", other.calls(), chunks)
	}
}

// After an update, unchanged chunks keep their vectors: only the changed text
// is sent to the embedding model.
func TestCarryOverEmbeddings(t *testing.T) {
	s, ctx, done := openTestStore(t)
	defer done()
	if !VectorExtensionAvailable(ctx, s.db) {
		t.Skip("pgvector not available")
	}
	s.db.ExecContext(ctx, "DROP TABLE IF EXISTS kb_embeddings")
	pub, priv, _ := GenerateKey()
	files := map[string]string{
		"docs/a.md": "# A\nalpha text\n",
		"docs/b.md": "# B\nbeta text\n",
		"docs/c.md": "# C\ngamma text\n",
	}
	v1 := buildPackFrom(t, priv, PackInput{PackID: "artex-core", Version: "1", KeyID: "test-key"}, files)
	if _, err := s.Import(ctx, v1, trustFor(pub), ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	emb := &countingEmbedder{model: "count-test"}
	s.SetEmbedder(emb)
	if err := s.embedActivePack(ctx); err != nil {
		t.Fatal(err)
	}
	first := emb.calls()
	if first != 3 {
		t.Fatalf("v1 embedded %d chunks, want 3", first)
	}

	files["docs/b.md"] = "# B\nbeta text, revised\n"
	v2 := buildPackFrom(t, priv, PackInput{PackID: "artex-core", Version: "2", KeyID: "test-key"}, files)
	res, err := s.Import(ctx, v2, trustFor(pub), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.embedActivePack(ctx); err != nil {
		t.Fatal(err)
	}
	if res.Carried != 2 || emb.calls()-first != 1 {
		t.Fatalf("v2: %d vectors reused (want 2), %d embedded (want 1)", res.Carried, emb.calls()-first)
	}
	var vecs int
	s.db.QueryRowContext(ctx, "SELECT count(*) FROM kb_embeddings").Scan(&vecs)
	if vecs != 3 {
		t.Errorf("after the update: %d vectors, want 3 (the old version's are gone)", vecs)
	}
}
