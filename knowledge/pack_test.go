package knowledge

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testPack writes a small signed pack to a temp file and returns its path plus
// the key pair that signed it.
func testPack(t *testing.T, files map[string]string) (path string, pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "src")
	in := PackInput{PackID: "artex-test", Version: "2026.11.27", KeyID: "test-key",
		Sources: []Source{{Name: "exploitdb", Version: "2026-11", License: "GPL-2.0"}},
		Files:   map[string]string{}}
	for p, body := range files {
		abs := filepath.Join(srcDir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		in.Files[p] = abs
	}
	path = filepath.Join(dir, "pack.tar.gz")
	if err := BuildPackFile(path, in, priv); err != nil {
		t.Fatal(err)
	}
	return path, pub, priv
}

func trustFor(pub ed25519.PublicKey) func(string) ([]byte, error) {
	return func(keyID string) ([]byte, error) {
		if keyID != "test-key" {
			return nil, &notTrustedError{keyID}
		}
		return pub, nil
	}
}

type notTrustedError struct{ id string }

func (e *notTrustedError) Error() string { return "key " + e.id + " not trusted" }

func TestPackRoundTrip(t *testing.T) {
	files := map[string]string{
		"exploitdb/files_exploits.csv": "id,file,description\n1,exploits/a.py,Example\n",
		"exploitdb/exploits/a.py":      "print('poc')\n",
		"nvd/cve-2021.json":            `{"cve":"CVE-2021-0001"}`,
		"docs/technique.md":            "# SQL injection\nUNION SELECT ...\n",
	}
	path, pub, _ := testPack(t, files)

	m, err := VerifyPackFile(path, trustFor(pub))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if m.PackID != "artex-test" || m.Version != "2026.11.27" || m.KeyID != "test-key" {
		t.Fatalf("manifest fields: %+v", m)
	}
	if len(m.Files) != len(files) {
		t.Fatalf("manifest lists %d files, want %d", len(m.Files), len(files))
	}

	dest := filepath.Join(t.TempDir(), "out")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ExtractPackFile(path, m, dest, ExtractLimits{}); err != nil {
		t.Fatalf("extract: %v", err)
	}
	for p, want := range files {
		got, err := os.ReadFile(filepath.Join(dest, filepath.FromSlash(p)))
		if err != nil || string(got) != want {
			t.Errorf("%s: got %q err %v, want %q", p, got, err, want)
		}
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	path, _, _ := testPack(t, map[string]string{"docs/x.md": "hi"})
	otherPub, _, _ := GenerateKey()
	if _, err := VerifyPackFile(path, trustFor(otherPub)); err == nil {
		t.Fatal("a pack must not verify against a different key")
	}
	// An untrusted key_id is refused before any signature check.
	_, err := VerifyPackFile(path, func(string) ([]byte, error) { return nil, &notTrustedError{"x"} })
	if err == nil || !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("untrusted key_id must be refused: %v", err)
	}
}

func TestVerifyRejectsTamperedManifest(t *testing.T) {
	path, pub, _ := testPack(t, map[string]string{"docs/x.md": "original"})
	tampered := filepath.Join(t.TempDir(), "tampered.tar.gz")
	rewriteManifest(t, path, tampered, func(b []byte) []byte {
		return bytes.Replace(b, []byte("artex-test"), []byte("artex-evil"), 1)
	})
	if _, err := VerifyPackFile(tampered, trustFor(pub)); err == nil {
		t.Fatal("a manifest edited after signing must fail verification")
	}
}

func TestExtractRejectsTamperedFile(t *testing.T) {
	// The signature covers the manifest, which carries each file's hash, so a
	// changed data file fails during extraction even though the manifest verifies.
	path, pub, _ := testPack(t, map[string]string{"docs/x.md": "original body"})
	tampered := filepath.Join(t.TempDir(), "tampered.tar.gz")
	rewriteFileBody(t, path, tampered, "docs/x.md", "swapped body!!")
	m, err := VerifyPackFile(tampered, trustFor(pub))
	if err != nil {
		t.Fatalf("manifest itself is untouched, should verify: %v", err)
	}
	dest := filepath.Join(t.TempDir(), "out")
	os.MkdirAll(dest, 0o755)
	if err := ExtractPackFile(tampered, m, dest, ExtractLimits{}); err == nil {
		t.Fatal("a data file not matching its manifest hash must fail extraction")
	}
}

func TestExtractRejectsUnlistedAndMissing(t *testing.T) {
	// Unlisted entry: inject a file the manifest does not mention.
	path, pub, _ := testPack(t, map[string]string{"docs/x.md": "a"})
	withExtra := filepath.Join(t.TempDir(), "extra.tar.gz")
	addRawFile(t, path, withExtra, "docs/evil.md", "surprise")
	m, _ := VerifyPackFile(withExtra, trustFor(pub))
	dest := filepath.Join(t.TempDir(), "o1")
	os.MkdirAll(dest, 0o755)
	if err := ExtractPackFile(withExtra, m, dest, ExtractLimits{}); err == nil {
		t.Fatal("an entry absent from the manifest must be refused")
	}

	// Missing entry: drop a file the manifest lists.
	path2, pub2, _ := testPack(t, map[string]string{"docs/x.md": "a", "docs/y.md": "b"})
	dropped := filepath.Join(t.TempDir(), "dropped.tar.gz")
	dropFile(t, path2, dropped, "docs/y.md")
	m2, _ := VerifyPackFile(dropped, trustFor(pub2))
	dest2 := filepath.Join(t.TempDir(), "o2")
	os.MkdirAll(dest2, 0o755)
	if err := ExtractPackFile(dropped, m2, dest2, ExtractLimits{}); err == nil {
		t.Fatal("a manifest file missing from the archive must fail")
	}
}

func TestSafePath(t *testing.T) {
	for _, bad := range []string{"", "/etc/passwd", "../x", "a/../../b", "a/../b", "C:/x", `a\b`, "foo/", "./", "a//b"} {
		if _, err := SafePath(bad); err == nil {
			t.Errorf("SafePath(%q) should be rejected", bad)
		}
	}
	for _, ok := range []string{"a", "a/b", "exploitdb/exploits/linux/x.c", "nvd/CVE-2021-0001.json"} {
		if got, err := SafePath(ok); err != nil || got != ok {
			t.Errorf("SafePath(%q) = %q, %v", ok, got, err)
		}
	}
}

func TestManifestValidate(t *testing.T) {
	good := &Manifest{PackID: "p", Version: "1", KeyID: "k",
		Files: []FileEntry{{Path: "a/b.txt", Size: 3, SHA256: strings.Repeat("ab", 32)}}}
	if err := good.Validate(); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
	for name, m := range map[string]*Manifest{
		"no id":      {Version: "1", KeyID: "k"},
		"no version": {PackID: "p", KeyID: "k"},
		"no key":     {PackID: "p", Version: "1"},
		"bad hash":   {PackID: "p", Version: "1", KeyID: "k", Files: []FileEntry{{Path: "a", Size: 1, SHA256: "xyz"}}},
		"traversal":  {PackID: "p", Version: "1", KeyID: "k", Files: []FileEntry{{Path: "../a", Size: 1, SHA256: strings.Repeat("a", 64)}}},
		"reserved":   {PackID: "p", Version: "1", KeyID: "k", Files: []FileEntry{{Path: ManifestName, Size: 1, SHA256: strings.Repeat("a", 64)}}},
	} {
		if err := m.Validate(); err == nil {
			t.Errorf("%s: should be invalid", name)
		}
	}
}

// --- tar rewrite helpers for the tamper tests ---

func readPack(t *testing.T, path string) map[string][]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	var order []string
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		b, _ := readAtMost(tr, 1<<30)
		out[h.Name] = b
		order = append(order, h.Name)
	}
	out["__order__"] = []byte(strings.Join(order, "\n"))
	return out
}

func writePack(t *testing.T, path string, entries map[string][]byte, order []string) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, name := range order {
		body := entries[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write(body)
	}
	tw.Close()
	gz.Close()
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func packOrder(entries map[string][]byte) []string {
	return strings.Split(string(entries["__order__"]), "\n")
}

func rewriteManifest(t *testing.T, src, dst string, fn func([]byte) []byte) {
	e := readPack(t, src)
	order := packOrder(e)
	e[ManifestName] = fn(e[ManifestName])
	writePack(t, dst, e, order)
}

func rewriteFileBody(t *testing.T, src, dst, name, body string) {
	e := readPack(t, src)
	order := packOrder(e)
	e[name] = []byte(body)
	writePack(t, dst, e, order)
}

func addRawFile(t *testing.T, src, dst, name, body string) {
	e := readPack(t, src)
	order := append(packOrder(e), name)
	e[name] = []byte(body)
	writePack(t, dst, e, order)
}

func dropFile(t *testing.T, src, dst, name string) {
	e := readPack(t, src)
	var order []string
	for _, n := range packOrder(e) {
		if n != name {
			order = append(order, n)
		}
	}
	writePack(t, dst, e, order)
}
