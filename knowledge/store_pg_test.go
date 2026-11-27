package knowledge

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// Integration test of the Postgres-backed store: build a pack, import it, and
// run every search/lookup tool against it. It needs a database, so it is skipped
// unless ARTEX_PG_DSN is set (the server test suites set the same). db.Open
// applies the 0015 migration and pg_trgm.
func openTestStore(t *testing.T) (*Store, context.Context, func()) {
	t.Helper()
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("set ARTEX_PG_DSN to run the knowledge store integration test")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	ctx := context.Background()
	// Start from a clean index so repeated runs are deterministic.
	for _, tbl := range []string{"kb_cpe_matches", "kb_chunks", "kb_documents", "kb_packs"} {
		if _, err := d.ExecContext(ctx, "DELETE FROM "+tbl); err != nil {
			t.Fatalf("clean %s: %v", tbl, err)
		}
	}
	cfg := Config{Enabled: true, Dir: filepath.Join(t.TempDir(), "knowledge"), MaxChunks: 8, MaxChunkBytes: 4096}
	return NewStore(d.DB, cfg), ctx, func() { d.Close() }
}

func buildSamplePack(t *testing.T) (packPath string, priv ed25519.PrivateKey, pub ed25519.PublicKey) {
	t.Helper()
	pub, priv, _ = GenerateKey()
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	write := func(rel, body string) {
		abs := filepath.Join(src, filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(abs), 0o755)
		if err := os.WriteFile(abs, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("exploitdb/files_exploits.csv",
		"id,file,description,date_published,author,type,platform,port,verified,codes\n"+
			"42,exploitdb/exploits/42.c,Apache 2.4.49 path traversal RCE,2021-10-05,alice,remote,linux,80,1,CVE-2021-41773\n"+
			"43,exploitdb/exploits/43.py,WordPress plugin SQL injection,2020-01-01,bob,webapps,php,,0,\n")
	write("exploitdb/exploits/42.c", "// Apache path traversal proof of concept\nGET /cgi-bin/.%2e/.%2e/etc/passwd\n")
	write("exploitdb/exploits/43.py", "# blind SQL injection via UNION SELECT\nimport requests\n")
	write("nvd/recent.json", nvdSample) // from parse_test.go
	write("docs/sqli.md", "# SQL injection\nUse UNION SELECT to dump columns. Bypass a WAF with inline comments like /*!50000UNION*/.\n")

	in := PackInput{PackID: "artex-core", Version: "2026.11.27", KeyID: "test-key",
		Sources: []Source{{Name: "exploitdb"}}, Files: map[string]string{}}
	filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		in.Files[filepath.ToSlash(rel)] = p
		return nil
	})
	packPath = filepath.Join(dir, "pack.tar.gz")
	if err := BuildPackFile(packPath, in, priv); err != nil {
		t.Fatal(err)
	}
	return packPath, priv, pub
}

func TestStoreImportAndSearch(t *testing.T) {
	s, ctx, done := openTestStore(t)
	defer done()
	packPath, _, pub := buildSamplePack(t)
	trust := func(keyID string) ([]byte, error) {
		if keyID != "test-key" {
			return nil, &notTrustedError{keyID}
		}
		return pub, nil
	}

	res, err := s.Import(ctx, packPath, trust, ImportOptions{})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if res.Exploits != 2 || res.CVEs != 2 || res.Docs != 1 {
		t.Fatalf("import summary: %+v", res)
	}
	if !s.HasActivePack(ctx) {
		t.Fatal("pack should be active after import")
	}

	// search_exploits: the Apache exploit by keyword, and type/platform filters.
	hits, err := s.SearchExploits(ctx, "apache path traversal", "", "", 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) == 0 || hits[0].EDBID != "42" {
		t.Fatalf("search_exploits apache: %+v", hits)
	}
	if hits[0].Source == "" || hits[0].Path == "" {
		t.Errorf("exploit hit missing source/path: %+v", hits[0])
	}
	webapps, _ := s.SearchExploits(ctx, "sql injection", "webapps", "php", 8)
	if len(webapps) != 1 || webapps[0].EDBID != "43" {
		t.Fatalf("search_exploits webapps filter: %+v", webapps)
	}
	if none, _ := s.SearchExploits(ctx, "sql injection", "remote", "", 8); len(none) != 0 {
		t.Errorf("type filter should exclude the webapps exploit: %+v", none)
	}

	// search_technique: the docs page.
	tech, err := s.SearchTechnique(ctx, "WAF bypass union select", 8)
	if err != nil || len(tech) == 0 {
		t.Fatalf("search_technique: %v %+v", err, tech)
	}
	if tech[0].Path != "docs/sqli.md" {
		t.Errorf("technique path: %+v", tech[0])
	}

	// lookup_cve: structured fields + linked exploit.
	info, ok, err := s.LookupCVE(ctx, "cve-2021-41773")
	if err != nil || !ok {
		t.Fatalf("lookup_cve: %v ok=%v", err, ok)
	}
	if info.CVSS == nil || info.CVSS.BaseScore != 7.5 || len(info.CWEs) != 1 || info.CWEs[0] != "CWE-22" {
		t.Errorf("lookup_cve fields: %+v", info)
	}
	if len(info.Exploits) != 1 || info.Exploits[0].EDBID != "42" {
		t.Errorf("lookup_cve linked exploit: %+v", info.Exploits)
	}
	if _, ok, _ := s.LookupCVE(ctx, "CVE-1999-9999"); ok {
		t.Error("an absent CVE must return ok=false")
	}

	// lookup_software: product + version via CPE match (the range CVE from nvdSample).
	sw, err := s.LookupSoftware(ctx, "http_server", "apache", "2.4.49", 20)
	if err != nil {
		t.Fatal(err)
	}
	foundExact, foundRange := false, false
	for _, h := range sw {
		switch h.CVE {
		case "CVE-2021-41773":
			foundExact = true
		case "CVE-2020-0001":
			foundRange = true
		}
	}
	if !foundExact || !foundRange {
		t.Fatalf("lookup_software 2.4.49 should match both CVEs: %+v", sw)
	}
	// A version outside every range matches neither.
	if out, _ := s.LookupSoftware(ctx, "http_server", "apache", "2.2.0", 20); len(out) != 0 {
		t.Errorf("2.2.0 should match no CVE: %+v", out)
	}

	// read_knowledge: the exploit file's first chunk.
	kc, ok, err := s.ReadKnowledge(ctx, "exploitdb/exploits/42.c", 1)
	if err != nil || !ok {
		t.Fatalf("read_knowledge: %v ok=%v", err, ok)
	}
	if kc.TotalChunks < 1 || kc.Text == "" {
		t.Errorf("read_knowledge chunk: %+v", kc)
	}

	// copy_knowledge_file resolution: the on-disk path under the pack dir.
	abs, _, sp, ok, err := s.DocumentFilePath(ctx, "exploitdb/exploits/42.c")
	if err != nil || !ok || sp != "exploitdb/exploits/42.c" {
		t.Fatalf("DocumentFilePath: %v ok=%v sp=%q", err, ok, sp)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Errorf("pack file not on disk at %s: %v", abs, err)
	}
}

func TestStoreDowngradeRefused(t *testing.T) {
	s, ctx, done := openTestStore(t)
	defer done()

	newer, _, pub := buildVersionedPack(t, "2026.12.01")
	older, _, _ := buildVersionedPack(t, "2026.01.01")
	trust := func(string) ([]byte, error) { return pub, nil }

	if _, err := s.Import(ctx, newer, trust, ImportOptions{}); err != nil {
		t.Fatalf("import newer: %v", err)
	}
	if _, err := s.Import(ctx, older, trust, ImportOptions{}); err == nil {
		t.Fatal("importing an older version must be refused by default")
	}
	if _, err := s.Import(ctx, older, trust, ImportOptions{AllowDowngrade: true}); err != nil {
		t.Fatalf("downgrade with the override must work: %v", err)
	}
	if v, _, _ := s.ActivePack(ctx, "artex-core"); v != "2026.01.01" {
		t.Errorf("active version after downgrade = %q", v)
	}
}

// buildVersionedPack builds a tiny pack at a given version, all signed by one key.
var sharedKeyPub ed25519.PublicKey
var sharedKeyPriv ed25519.PrivateKey

func buildVersionedPack(t *testing.T, version string) (string, ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	if sharedKeyPriv == nil {
		sharedKeyPub, sharedKeyPriv, _ = GenerateKey()
	}
	dir := t.TempDir()
	doc := filepath.Join(dir, "docs", "x.md")
	os.MkdirAll(filepath.Dir(doc), 0o755)
	os.WriteFile(doc, []byte("# note\nversion "+version), 0o644)
	in := PackInput{PackID: "artex-core", Version: version, KeyID: "test-key",
		Files: map[string]string{"docs/x.md": doc}}
	p := filepath.Join(dir, "pack.tar.gz")
	if err := BuildPackFile(p, in, sharedKeyPriv); err != nil {
		t.Fatal(err)
	}
	return p, sharedKeyPriv, sharedKeyPub
}
