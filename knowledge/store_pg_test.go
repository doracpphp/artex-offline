package knowledge

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/doracpphp/artex-offline/db"
)

// Integration test of the Postgres-backed store: build a pack, import it, and
// run every search/lookup tool against it. It needs a database, so it is skipped
// unless ARTEX_PG_DSN is set (the server test suites set the same). db.Open
// applies the 0015 migration; pg_trgm is created at runtime (EnsureTrigramIndexes).
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
	for _, tbl := range []string{"kb_cpe_matches", "kb_chunks", "kb_documents", "kb_packs", "kb_key_pins"} {
		if _, err := d.ExecContext(ctx, "DELETE FROM "+tbl); err != nil {
			t.Fatalf("clean %s: %v", tbl, err)
		}
	}
	cfg := Config{Enabled: true, Dir: filepath.Join(t.TempDir(), "knowledge"), MaxChunks: 8, MaxChunkBytes: 4096}
	s := NewStore(d.DB, cfg)
	if err := s.EnsureTrigramIndexes(ctx); err != nil {
		t.Logf("pg_trgm unavailable (search still works): %v", err)
	}
	return s, ctx, func() { d.Close() }
}

// buildSamplePack builds a pack in the real ExploitDB layout: the CSV's file
// column is relative to the ExploitDB root (exploits/...), and the pack stores
// the mirror under exploitdb/. It also carries the dirty data real mirrors have:
// a binary exploit file, Latin-1 text, NUL bytes, and an exploit whose file is
// not in the pack.
func buildSamplePack(t *testing.T) (packPath string, priv ed25519.PrivateKey, pub ed25519.PublicKey) {
	t.Helper()
	pub, priv, _ = GenerateKey()
	return buildSamplePackWith(t, "2026.11.27", priv), priv, pub
}

func buildSamplePackWith(t *testing.T, version string, priv ed25519.PrivateKey) string {
	t.Helper()
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
			"42,exploits/linux/remote/42.c,Apache 2.4.49 path traversal RCE,2021-10-05,alice,remote,linux,80,1,CVE-2021-41773\n"+
			"43,exploits/php/webapps/43.py,WordPress plugin SQL injection,2020-01-01,bob,webapps,php,,0,\n"+
			"44,exploits/windows/local/44.exe,Caf\xe9 binary privilege escalation,2019-01-01,carol,local,windows,,0,\n"+
			"45,exploits/linux/dos/45.txt,Missing file from the mirror,2018-01-01,dave,dos,linux,,0,\n")
	write("exploitdb/exploits/linux/remote/42.c", "// Apache path traversal proof of concept\nGET /cgi-bin/.%2e/.%2e/etc/passwd\n")
	write("exploitdb/exploits/php/webapps/43.py", "# blind SQL injection via UNION SELECT\nimport requests\n")
	write("exploitdb/exploits/windows/local/44.exe", "MZ\x90\x00\x03\x00\x00\x00\x04\x00binary payload")
	write("nvd/recent.json", nvdSample) // from parse_test.go
	write("docs/sqli.md", "# SQL injection\nUse UNION SELECT to dump columns. Bypass a WAF with inline comments like /*!50000UNION*/.\n")
	write("docs/latin1.md", "# Latin-1 note\nna\xefve caf\xe9 text with a stray byte and version "+version+"\n")
	write("docs/nul.md", "# NUL note\nthis text has a NUL\x00 so it is treated as binary\n")
	// NVD text can carry \u0000, which jsonb and TEXT refuse.
	write("nvd/nul.json", `{"vulnerabilities":[{"cve":{"id":"CVE-2022-0002","descriptions":[{"lang":"en","value":"Heap overflow\u0000 in nulparse"}],`+
		`"references":[{"url":"https://example.invalid/\u0000x"}],"weaknesses":[{"description":[{"lang":"en","value":"CWE-122\u0000"}]}]}}]}`)

	in := PackInput{PackID: "artex-core", Version: version, KeyID: "test-key",
		Sources: []Source{{Name: "exploitdb"}}, Files: map[string]string{}}
	filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		in.Files[filepath.ToSlash(rel)] = p
		return nil
	})
	packPath := filepath.Join(dir, "pack.tar.gz")
	if err := BuildPackFile(packPath, in, priv); err != nil {
		t.Fatal(err)
	}
	return packPath
}

func TestStoreImportAndSearch(t *testing.T) {
	s, ctx, done := openTestStore(t)
	defer done()
	packPath, _, pub := buildSamplePack(t)

	res, err := s.Import(ctx, packPath, trustFor(pub), ImportOptions{})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if res.Exploits != 4 || res.CVEs != 3 || res.Docs != 3 || res.KeyFingerprint != KeyFingerprint(pub) {
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
	if hits[0].Source == "" || hits[0].Path != "exploitdb/exploits/linux/remote/42.c" {
		t.Errorf("exploit hit source/path (must be the pack path of the CSV file): %+v", hits[0])
	}
	webapps, _ := s.SearchExploits(ctx, "sql injection", "webapps", "php", 8)
	if len(webapps) != 1 || webapps[0].EDBID != "43" {
		t.Fatalf("search_exploits webapps filter: %+v", webapps)
	}
	if none, _ := s.SearchExploits(ctx, "sql injection", "remote", "", 8); len(none) != 0 {
		t.Errorf("type filter should exclude the webapps exploit: %+v", none)
	}
	// The exploit body was indexed (not only the CSV title).
	if body, _ := s.SearchExploits(ctx, "cgi-bin", "", "", 8); len(body) == 0 || body[0].EDBID != "42" {
		t.Errorf("the exploit file body must be indexed: %+v", body)
	}
	// Latin-1 in the CSV and the binary exploit did not abort the import; the
	// binary one is searchable by its (sanitised) title only.
	if bin, _ := s.SearchExploits(ctx, "binary privilege escalation", "", "", 8); len(bin) == 0 || bin[0].EDBID != "44" {
		t.Errorf("binary exploit must be indexed on its metadata: %+v", bin)
	}
	// An exploit whose file is not in the pack has no path.
	if miss, _ := s.SearchExploits(ctx, "missing file mirror", "", "", 8); len(miss) == 0 || miss[0].Path != "" {
		t.Errorf("exploit without a file must have no path: %+v", miss)
	}

	// search_technique: the docs pages, including the one with invalid UTF-8 / NUL.
	tech, err := s.SearchTechnique(ctx, "WAF bypass union select", 8)
	if err != nil || len(tech) == 0 {
		t.Fatalf("search_technique: %v %+v", err, tech)
	}
	if tech[0].Path != "docs/sqli.md" {
		t.Errorf("technique path: %+v", tech[0])
	}
	if l1, _ := s.SearchTechnique(ctx, "stray byte", 8); len(l1) == 0 || l1[0].Path != "docs/latin1.md" {
		t.Errorf("a doc with Latin-1 bytes must import and be searchable: %+v", l1)
	}
	// A file with a NUL is treated as binary: its body is not read, so it is
	// indexed under its file name only.
	if nul, _ := s.SearchTechnique(ctx, "nul", 8); len(nul) == 0 || nul[0].Path != "docs/nul.md" {
		t.Errorf("a doc with a NUL must still import (title only): %+v", nul)
	}
	if body, _ := s.SearchTechnique(ctx, "treated as binary", 8); len(body) != 0 {
		t.Errorf("the body of a binary file must not be indexed: %+v", body)
	}
	// NVD text with \u0000 imported, sanitised.
	if c, ok, err := s.LookupCVE(ctx, "CVE-2022-0002"); err != nil || !ok || strings.ContainsRune(c.Description, 0) || !strings.Contains(c.Description, "nulparse") {
		t.Errorf("NVD record with NUL: %+v ok=%v err=%v", c, ok, err)
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
		if h.MatchBasis != "exact" || !h.VersionChecked || h.Product != "http_server" || h.Vendor != "apache" {
			t.Errorf("lookup_software hit basis/product: %+v", h)
		}
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
	// "http server" folds to the CPE form; the result order is stable.
	again, _ := s.LookupSoftware(ctx, "HTTP Server", "apache", "2.4.49", 20)
	if len(again) != len(sw) || again[0].CVE != sw[0].CVE {
		t.Errorf("lookup_software must be deterministic and fold spaces: %+v vs %+v", again, sw)
	}
	// No exact product: partial matches, labelled as such.
	part, _ := s.LookupSoftware(ctx, "http", "", "", 20)
	if len(part) == 0 || part[0].MatchBasis != "partial" || part[0].VersionChecked {
		t.Errorf("partial product match must be labelled: %+v", part)
	}
	// LIKE metacharacters in the query are literal.
	if lit, _ := s.LookupSoftware(ctx, "%", "", "", 20); len(lit) != 0 {
		t.Errorf("%% must not match every product: %+v", lit)
	}
	// A version outside every range matches neither.
	if out, _ := s.LookupSoftware(ctx, "http_server", "apache", "2.2.0", 20); len(out) != 0 {
		t.Errorf("2.2.0 should match no CVE: %+v", out)
	}

	// read_knowledge: the exploit file's first chunk.
	kc, ok, err := s.ReadKnowledge(ctx, "exploitdb/exploits/linux/remote/42.c", 1)
	if err != nil || !ok {
		t.Fatalf("read_knowledge: %v ok=%v", err, ok)
	}
	if kc.TotalChunks < 1 || kc.Text == "" {
		t.Errorf("read_knowledge chunk: %+v", kc)
	}

	// copy_knowledge_file: by path and by EDB-ID, confined to the pack directory.
	data, _, sp, ok, err := s.ReadDocumentFile(ctx, "exploitdb/exploits/linux/remote/42.c", MaxDocumentFileBytes)
	if err != nil || !ok || sp != "exploitdb/exploits/linux/remote/42.c" || !strings.Contains(string(data), "cgi-bin") {
		t.Fatalf("ReadDocumentFile by path: %v ok=%v sp=%q data=%q", err, ok, sp, data)
	}
	if data, _, _, ok, err := s.ReadDocumentFile(ctx, "44", MaxDocumentFileBytes); err != nil || !ok || !strings.HasPrefix(string(data), "MZ") {
		t.Fatalf("ReadDocumentFile binary by EDB-ID: %v ok=%v", err, ok)
	}
	if _, _, _, ok, _ := s.ReadDocumentFile(ctx, "45", MaxDocumentFileBytes); ok {
		t.Error("an exploit whose file is not in the pack has nothing to copy")
	}
	if _, _, _, _, err := s.ReadDocumentFile(ctx, "42", 4); err == nil {
		t.Error("a file over the copy limit must be refused")
	}
	// A tampered dir value in the database cannot point outside the packs dir.
	if _, err := s.db.ExecContext(ctx, `UPDATE kb_packs SET dir='../../keys' WHERE active`); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := s.ReadDocumentFile(ctx, "42", MaxDocumentFileBytes); err == nil {
		t.Error("a traversal in kb_packs.dir must be refused")
	}

	packs, err := s.ListPacks(ctx)
	if err != nil || len(packs) != 1 || packs[0].KeyFingerprint != KeyFingerprint(pub) {
		t.Fatalf("ListPacks must carry the key fingerprint: %+v %v", packs, err)
	}
}

func TestStoreDowngradeRefused(t *testing.T) {
	s, ctx, done := openTestStore(t)
	defer done()

	newer, _, pub := buildVersionedPack(t, "2026.12.01")
	older, _, _ := buildVersionedPack(t, "2026.01.01")
	trust := trustFor(pub)

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

// The first import pins the signing key; a pack of the same id signed by any
// other trusted key is refused until the operator re-pins.
func TestStoreKeyPin(t *testing.T) {
	s, ctx, done := openTestStore(t)
	defer done()
	pubA, privA, _ := GenerateKey()
	pubB, privB, _ := GenerateKey()
	first := buildSamplePackWith(t, "2026.11.01", privA)
	byB := buildSamplePackWith(t, "2026.11.02", privB)

	if _, err := s.Import(ctx, first, trustFor(pubA), ImportOptions{}); err != nil {
		t.Fatalf("first import: %v", err)
	}
	pins, err := s.KeyPins(ctx)
	if err != nil || len(pins) != 1 || pins[0].KeyFingerprint != KeyFingerprint(pubA) {
		t.Fatalf("first import must pin key A: %+v %v", pins, err)
	}
	// Key B is trusted (e.g. added through the environment) but not pinned.
	_, err = s.Import(ctx, byB, trustFor(pubB), ImportOptions{})
	if err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("a pack signed by another key must be refused: %v", err)
	}
	if v, _, _ := s.ActivePack(ctx, "artex-core"); v != "2026.11.01" {
		t.Fatalf("a refused import must leave the active pack: %q", v)
	}
	if _, err := s.Import(ctx, byB, trustFor(pubB), ImportOptions{Repin: true}); err != nil {
		t.Fatalf("explicit re-pin must accept key B: %v", err)
	}
	pins, _ = s.KeyPins(ctx)
	if len(pins) != 1 || pins[0].KeyFingerprint != KeyFingerprint(pubB) {
		t.Fatalf("re-pin must record key B: %+v", pins)
	}
}

// Each import gets its own versioned directory; the previous one is removed
// only after the new one is active, and the superseded index rows go with it.
func TestStoreVersionedDirsAndPrune(t *testing.T) {
	s, ctx, done := openTestStore(t)
	defer done()
	pub, priv, _ := GenerateKey()
	v1 := buildSamplePackWith(t, "2026.11.01", priv)
	v2 := buildSamplePackWith(t, "2026.11.02", priv)
	trust := trustFor(pub)

	if _, err := s.Import(ctx, v1, trust, ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	var dir1 string
	s.db.QueryRowContext(ctx, `SELECT dir FROM kb_packs WHERE active`).Scan(&dir1)
	abs1, err := s.cfg.packFilesDir(dir1)
	if err != nil || !strings.HasPrefix(dir1, "artex-core/2026.11.01-") {
		t.Fatalf("versioned dir %q: %v", dir1, err)
	}
	if _, err := os.Stat(filepath.Join(abs1, "exploitdb", "files_exploits.csv")); err != nil {
		t.Fatalf("v1 files: %v", err)
	}
	// A leftover staging dir from a crashed import is cleaned up too.
	stale := filepath.Join(s.cfg.PacksDir(), "artex-core", stagingPrefix+"crashed")
	os.MkdirAll(stale, 0o750)

	if _, err := s.Import(ctx, v2, trust, ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	var dir2 string
	s.db.QueryRowContext(ctx, `SELECT dir FROM kb_packs WHERE active`).Scan(&dir2)
	abs2, _ := s.cfg.packFilesDir(dir2)
	if _, err := os.Stat(abs2); err != nil || dir2 == dir1 {
		t.Fatalf("v2 dir %q: %v", dir2, err)
	}
	for _, gone := range []string{abs1, stale} {
		if _, err := os.Stat(gone); !os.IsNotExist(err) {
			t.Errorf("superseded %s must be removed: %v", gone, err)
		}
	}
	var docs int
	s.db.QueryRowContext(ctx, `SELECT count(*) FROM kb_documents d JOIN kb_packs p ON p.id=d.pack_id WHERE NOT p.active`).Scan(&docs)
	if docs != 0 {
		t.Errorf("superseded index rows must be removed, %d left", docs)
	}
	// Re-importing the active version works (rebuilds its index into a new dir).
	if _, err := s.Import(ctx, v2, trust, ImportOptions{}); err != nil {
		t.Fatalf("re-import of the active version: %v", err)
	}
	if hits, _ := s.SearchExploits(ctx, "apache path traversal", "", "", 8); len(hits) == 0 {
		t.Error("search after a re-import must still work")
	}
}

func TestStoreImportBusy(t *testing.T) {
	s, ctx, done := openTestStore(t)
	defer done()
	packPath, _, pub := buildSamplePack(t)
	s.importMu.Lock()
	_, err := s.Import(ctx, packPath, trustFor(pub), ImportOptions{})
	s.importMu.Unlock()
	if !errors.Is(err, ErrImportBusy) {
		t.Fatalf("a concurrent import must be refused with ErrImportBusy: %v", err)
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
