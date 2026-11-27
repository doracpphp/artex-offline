package knowledge

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

const sampleTemplate = `id: CVE-2021-41773

info:
  name: Apache 2.4.49 - Path Traversal and Remote Code Execution
  author: daffainfo, pdteam
  severity: high
  description: |
    A path traversal flaw in Apache HTTP Server 2.4.49.
  reference:
    - https://httpd.apache.org/security/vulnerabilities_24.html
  classification:
    cvss-score: 7.5
    cve-id: cve-2021-41773
    cwe-id: CWE-22
  metadata:
    vendor: Apache
    product: http_server
  tags: cve,cve2021,apache,lfi

http:
  - method: GET
    path:
      - "{{BaseURL}}/cgi-bin/.%2e/.%2e/.%2e/etc/passwd"
`

func TestParseNucleiTemplate(t *testing.T) {
	tpl, ok := ParseNucleiTemplate([]byte(sampleTemplate))
	if !ok {
		t.Fatal("a valid template must parse")
	}
	if tpl.ID != "CVE-2021-41773" || tpl.Severity != "high" || !strings.HasPrefix(tpl.Name, "Apache 2.4.49") {
		t.Errorf("fields: %+v", tpl)
	}
	if len(tpl.CVEs) != 1 || tpl.CVEs[0] != "CVE-2021-41773" || len(tpl.CWEs) != 1 || tpl.CWEs[0] != "CWE-22" {
		t.Errorf("classification: %+v", tpl)
	}
	if tpl.Vendor != "apache" || tpl.Product != "http_server" {
		t.Errorf("metadata: %+v", tpl)
	}
	if len(tpl.Tags) != 4 || tpl.Tags[0] != "cve" || len(tpl.Authors) != 2 {
		t.Errorf("comma lists: tags %v authors %v", tpl.Tags, tpl.Authors)
	}
	// Lists in sequence form, several CVEs, junk ignored.
	seq := "id: multi\ninfo:\n  name: Multi\n  tags: [a, b]\n  classification:\n    cve-id: [CVE-2020-0001, not-a-cve, CVE-2020-0002]\n"
	if m, ok := ParseNucleiTemplate([]byte(seq)); !ok || len(m.CVEs) != 2 || len(m.Tags) != 2 {
		t.Errorf("sequence form: %+v ok=%v", m, ok)
	}
	for _, bad := range []string{"info:\n  name: no id\n", "{not yaml", "- a\n- b\n"} {
		if _, ok := ParseNucleiTemplate([]byte(bad)); ok {
			t.Errorf("%q must not parse as a template", bad)
		}
	}
}

func TestEmbedFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	w, err := newEmbedRecordWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	texts := []string{"alpha", "beta", "gamma"}
	for i, s := range texts {
		if err := w.add(chunkHash(s), []float32{float32(i), 0.5, -1}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.add(chunkHash("bad"), []float32{1}); err == nil {
		t.Fatal("a vector of another dimension must be refused")
	}
	out := filepath.Join(dir, "v.akv")
	set, err := w.finish(out, "m", 4096)
	if err != nil || set.Count != 3 || set.Dimension != 3 || set.Model != "m" || set.ChunkBytes != 4096 {
		t.Fatalf("finish: %+v %v", set, err)
	}
	data, _ := os.ReadFile(out)
	got := map[[32]byte][]float32{}
	if _, err := readEmbedFile(bytes.NewReader(data), set, func(h [32]byte, v []float32) error {
		got[h] = append([]float32(nil), v...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[chunkHash("beta")][0] != 1 || got[chunkHash("gamma")][2] != -1 {
		t.Fatalf("records: %v", got)
	}
	// A declaration that does not match the header, a truncated file and
	// trailing data are refused.
	other := set
	other.Model = "n"
	if _, err := readEmbedFile(bytes.NewReader(data), other, func([32]byte, []float32) error { return nil }); err == nil {
		t.Error("a header that differs from the manifest must be refused")
	}
	if _, err := readEmbedFile(bytes.NewReader(data[:len(data)-5]), set, func([32]byte, []float32) error { return nil }); err == nil {
		t.Error("a truncated file must be refused")
	}
	if _, err := readEmbedFile(bytes.NewReader(append(append([]byte(nil), data...), 0)), set, func([32]byte, []float32) error { return nil }); err == nil {
		t.Error("trailing data must be refused")
	}
}

// countingEmbedder is a deterministic embedder that counts the texts it is
// asked to embed.
type countingEmbedder struct {
	model string
	mu    sync.Mutex
	texts []string
}

func (c *countingEmbedder) Model() string { return c.model }

func (c *countingEmbedder) Embed(_ context.Context, texts []string) ([][]float32, error) {
	c.mu.Lock()
	c.texts = append(c.texts, texts...)
	c.mu.Unlock()
	out := make([][]float32, len(texts))
	for i, s := range texts {
		h := chunkHash(s)
		out[i] = []float32{float32(h[0]) + 1, float32(h[1]) + 1, float32(h[2]) + 1}
	}
	return out, nil
}

func (c *countingEmbedder) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.texts)
}

func writeTree(t *testing.T, root string, files map[string]string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for p, body := range files {
		abs := filepath.Join(root, filepath.FromSlash(p))
		os.MkdirAll(filepath.Dir(abs), 0o755)
		if err := os.WriteFile(abs, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		out[p] = abs
	}
	return out
}

// The builder embeds each distinct chunk once, reuses the previous full pack's
// vectors for chunks that did not change, and writes only the new vectors to
// the delta file.
func TestBuildEmbeddingsReusesBase(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := GenerateKey()
	emb := &countingEmbedder{model: "count-test"}
	v1 := writeTree(t, filepath.Join(dir, "v1"), map[string]string{
		"docs/a.md": "# A\nalpha text",
		"docs/b.md": "# B\nbeta text",
		"docs/c.md": "# A\nalpha text", // same chunk as a.md: embedded once
	})
	fullSet, _, err := BuildEmbeddings(context.Background(), EmbedBuild{Files: v1, ChunkBytes: 4096, Embedder: emb, FullOut: filepath.Join(dir, "v1.akv")})
	if err != nil {
		t.Fatal(err)
	}
	if fullSet.Count != 2 || emb.calls() != 2 {
		t.Fatalf("v1: %d vectors, %d embed calls; want 2 and 2 (a and c share a chunk)", fullSet.Count, emb.calls())
	}
	path := EmbeddingFileName("count-test", "1")
	fullSet.Path = path
	files := copyMap(v1)
	files[path] = filepath.Join(dir, "v1.akv")
	pack1 := filepath.Join(dir, "v1.tar.gz")
	if err := BuildPackFile(pack1, PackInput{PackID: "p", Version: "1", KeyID: "k", Files: files, Embeddings: []EmbeddingSet{fullSet}}, priv); err != nil {
		t.Fatal(err)
	}

	v2 := writeTree(t, filepath.Join(dir, "v2"), map[string]string{
		"docs/a.md": "# A\nalpha text", // unchanged
		"docs/b.md": "# B\nbeta text, revised",
		"docs/d.md": "# D\ndelta text",
	})
	before := emb.calls()
	full2, delta2, err := BuildEmbeddings(context.Background(), EmbedBuild{
		Files: v2, ChunkBytes: 4096, Embedder: emb, BasePack: pack1,
		FullOut: filepath.Join(dir, "v2.akv"), DeltaOut: filepath.Join(dir, "v2-delta.akv"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := emb.calls() - before; n != 2 {
		t.Errorf("v2 embedded %d texts; want 2 (b changed, d new; a reused)", n)
	}
	if full2.Count != 3 || delta2.Count != 2 {
		t.Errorf("v2 full %d vectors (want 3), delta %d (want 2)", full2.Count, delta2.Count)
	}
	// A mismatched chunk size reuses nothing.
	before = emb.calls()
	if _, _, err := BuildEmbeddings(context.Background(), EmbedBuild{Files: v2, ChunkBytes: 2048, Embedder: emb, BasePack: pack1, FullOut: filepath.Join(dir, "x.akv")}); err != nil {
		t.Fatal(err)
	}
	if n := emb.calls() - before; n != 3 {
		t.Errorf("another chunk size must not reuse vectors: %d embedded, want 3", n)
	}
}

func copyMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// DeltaInput keeps only changed and new files and lists the removed ones;
// applyDelta rebuilds the new version from the base directory plus the delta.
func TestDeltaInputAndApply(t *testing.T) {
	dir := t.TempDir()
	baseSrc := writeTree(t, filepath.Join(dir, "base"), map[string]string{
		"docs/a.md": "same", "docs/b.md": "old b", "docs/c.md": "removed",
	})
	base := &Manifest{Format: FormatVersion, Kind: KindKnowledge, PackID: "p", Version: "1", KeyID: "k"}
	for p, src := range baseSrc {
		size, sum, _ := hashFile(src)
		base.Files = append(base.Files, FileEntry{Path: p, Size: size, SHA256: sum})
	}
	newSrc := writeTree(t, filepath.Join(dir, "new"), map[string]string{
		"docs/a.md": "same", "docs/b.md": "new b", "docs/d.md": "added",
	})
	in, err := DeltaInput(PackInput{PackID: "p", Version: "2", KeyID: "k", Files: newSrc}, base)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for p := range in.Files {
		got = append(got, p)
	}
	sort.Strings(got)
	if in.BaseVersion != "1" || strings.Join(got, ",") != "docs/b.md,docs/d.md" || strings.Join(in.Deletions, ",") != "docs/c.md" {
		t.Fatalf("delta input: base %q files %v deletions %v", in.BaseVersion, got, in.Deletions)
	}
	if _, err := DeltaInput(PackInput{PackID: "p", Version: "1", Files: newSrc}, base); err == nil {
		t.Error("a delta must be newer than its base")
	}
	if _, err := DeltaInput(PackInput{PackID: "q", Version: "2", Files: newSrc}, base); err == nil {
		t.Error("a delta must have the base's pack id")
	}

	// Import side: the base directory holds the base files; staging holds what
	// the delta extracted.
	delta := &Manifest{Format: FormatVersion, Kind: KindKnowledge, PackID: "p", Version: "2", BaseVersion: "1", KeyID: "k", Deletions: in.Deletions}
	for p, src := range in.Files {
		size, sum, _ := hashFile(src)
		delta.Files = append(delta.Files, FileEntry{Path: p, Size: size, SHA256: sum})
	}
	baseDir := filepath.Join(dir, "base")
	staging := filepath.Join(dir, "staging")
	writeTree(t, staging, map[string]string{"docs/b.md": "new b", "docs/d.md": "added"})
	merged, err := applyDelta(baseDir, base, delta, staging)
	if err != nil {
		t.Fatal(err)
	}
	var mergedPaths []string
	for _, f := range merged.Files {
		mergedPaths = append(mergedPaths, f.Path)
	}
	if strings.Join(mergedPaths, ",") != "docs/a.md,docs/b.md,docs/d.md" || merged.Version != "2" || merged.BaseVersion != "" {
		t.Fatalf("merged: %v version %s base %q", mergedPaths, merged.Version, merged.BaseVersion)
	}
	for p, want := range map[string]string{"docs/a.md": "same", "docs/b.md": "new b", "docs/d.md": "added"} {
		if b, err := os.ReadFile(filepath.Join(staging, filepath.FromSlash(p))); err != nil || string(b) != want {
			t.Errorf("%s in the new version: %q %v", p, b, err)
		}
	}
	if _, err := os.Stat(filepath.Join(staging, "docs", "c.md")); !os.IsNotExist(err) {
		t.Error("a deleted file must not be carried over")
	}

	// A deletion of a file the base does not have, and a base file whose size
	// does not match its manifest, are refused.
	bad := *delta
	bad.Deletions = []string{"docs/zzz.md"}
	if _, err := applyDelta(baseDir, base, &bad, t.TempDir()); err == nil {
		t.Error("deleting a file missing from the base must be refused")
	}
	os.WriteFile(filepath.Join(baseDir, "docs", "a.md"), []byte("tampered!"), 0o644)
	if _, err := applyDelta(baseDir, base, delta, t.TempDir()); err == nil {
		t.Error("a base file that no longer matches its manifest must be refused")
	}
}

func TestTemplateWarnings(t *testing.T) {
	m := &Manifest{Sources: []Source{{Name: "nuclei-templates", Version: "v10.5.1"}}}
	if w := templateWarnings(m, "v10.5.1 (79fb682)", 3); len(w) != 0 {
		t.Errorf("same version: %v", w)
	}
	if w := templateWarnings(m, "v10.4.0 (abc)", 3); len(w) != 1 || !strings.Contains(w[0], "differ") {
		t.Errorf("different version: %v", w)
	}
	if w := templateWarnings(m, "", 3); len(w) != 1 || !strings.Contains(w[0], "no baked") {
		t.Errorf("no image templates: %v", w)
	}
	if w := templateWarnings(&Manifest{}, "v10.5.1", 3); len(w) != 1 || !strings.Contains(w[0], "does not record") {
		t.Errorf("unknown pack version: %v", w)
	}
	if w := templateWarnings(m, "v1", 0); len(w) != 0 {
		t.Errorf("no templates, no warning: %v", w)
	}
}
