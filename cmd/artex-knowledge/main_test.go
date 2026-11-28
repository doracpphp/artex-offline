package main

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/doracpphp/artex-offline/knowledge"
)

// The builder packs data, not a checkout: hidden entries (.git) are skipped,
// ExploitDB contributes only its index and exploit files, and docs only text.
func TestCollectSelectsDataFiles(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("edb/files_exploits.csv", "id,file\n")
	write("edb/exploits/linux/remote/1.c", "x")
	write("edb/exploits/windows/local/2.exe", "MZ\x00")
	write("edb/.git/objects/ab/cdef", "blob")
	write("edb/searchsploit", "#!/bin/sh")
	write("edb/shellcodes/linux/3.c", "x")
	write("docs/sqli.md", "# SQLi")
	write("docs/.github/workflow.yml", "x")
	write("docs/logo.png", "\x89PNG")
	write("docs/guide/notes.txt", "notes")

	files := map[string]string{}
	if _, err := collect(files, "exploitdb", filepath.Join(root, "edb"), exploitDBFile); err != nil {
		t.Fatal(err)
	}
	if _, err := collect(files, "docs", filepath.Join(root, "docs"), hasExt(".md", ".markdown", ".txt", ".rst", ".adoc")); err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(files))
	for p := range files {
		got = append(got, p)
	}
	sort.Strings(got)
	want := []string{
		"docs/guide/notes.txt",
		"docs/sqli.md",
		"exploitdb/exploits/linux/remote/1.c",
		"exploitdb/exploits/windows/local/2.exe",
		"exploitdb/files_exploits.csv",
	}
	if len(got) != len(want) {
		t.Fatalf("collected %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("collected %v, want %v", got, want)
		}
	}
}

// build -base -delta-out writes the full pack and a delta against the previous
// full pack: only the changed files, the deletions, and base_version set.
func TestBuildWritesDeltaAgainstBase(t *testing.T) {
	dir := t.TempDir()
	keyBase := filepath.Join(dir, "k")
	if err := keygen([]string{"-out", keyBase}); err != nil {
		t.Fatal(err)
	}
	docs := func(name string, files map[string]string) string {
		d := filepath.Join(dir, name)
		for p, body := range files {
			os.MkdirAll(filepath.Dir(filepath.Join(d, p)), 0o755)
			os.WriteFile(filepath.Join(d, p), []byte(body), 0o644)
		}
		return d
	}
	v1 := filepath.Join(dir, "v1.tar.gz")
	common := []string{"-key", keyBase + ".key", "-key-id", "k1", "-pack-id", "artex-core"}
	if err := build(append(common, "-version", "1", "-out", v1,
		"-docs", docs("d1", map[string]string{"keep.md": "keep", "change.md": "old", "drop.md": "drop"}))); err != nil {
		t.Fatal(err)
	}
	v2, d2 := filepath.Join(dir, "v2.tar.gz"), filepath.Join(dir, "v2-delta.tar.gz")
	if err := build(append(common, "-version", "2", "-out", v2, "-base", v1, "-delta-out", d2,
		"-docs", docs("d2", map[string]string{"keep.md": "keep", "change.md": "new", "add.md": "add"}))); err != nil {
		t.Fatal(err)
	}
	m, err := knowledge.PackManifest(d2)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, f := range m.Files {
		files = append(files, f.Path)
	}
	sort.Strings(files)
	if m.BaseVersion != "1" || len(files) != 2 || files[0] != "docs/add.md" || files[1] != "docs/change.md" ||
		len(m.Deletions) != 1 || m.Deletions[0] != "docs/drop.md" {
		t.Fatalf("delta: base %q files %v deletions %v", m.BaseVersion, files, m.Deletions)
	}
	if full, err := knowledge.PackManifest(v2); err != nil || full.BaseVersion != "" || len(full.Files) != 3 {
		t.Fatalf("full v2: %+v %v", full, err)
	}
	if err := build(append(common, "-version", "3", "-out", filepath.Join(dir, "v3.tar.gz"), "-delta-out", filepath.Join(dir, "x"),
		"-docs", docs("d3", map[string]string{"a.md": "a"}))); err == nil {
		t.Error("-delta-out without -base must be refused")
	}
	// A base signed by another key is refused.
	other := filepath.Join(dir, "other")
	keygen([]string{"-out", other})
	if err := build([]string{"-key", other + ".key", "-key-id", "k1", "-pack-id", "artex-core", "-version", "3",
		"-out", filepath.Join(dir, "v3b.tar.gz"), "-base", v2, "-delta-out", filepath.Join(dir, "d3b.tar.gz"),
		"-docs", docs("d4", map[string]string{"a.md": "a"})}); err == nil {
		t.Error("a base pack signed by another key must be refused")
	}
}

// build -attack packs the STIX bundles under attack/ and records the ATT&CK
// source version.
func TestBuildPacksAttack(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "k")
	if err := keygen([]string{"-out", key}); err != nil {
		t.Fatal(err)
	}
	ad := filepath.Join(dir, "attack")
	os.MkdirAll(ad, 0o755)
	os.WriteFile(filepath.Join(ad, "enterprise-attack.json"), []byte(`{"type":"bundle","objects":[]}`), 0o644)
	out := filepath.Join(dir, "p.tar.gz")
	if err := build([]string{"-key", key + ".key", "-key-id", "k1", "-pack-id", "artex-core",
		"-version", "1", "-out", out, "-attack", ad, "-attack-version", "v16.1"}); err != nil {
		t.Fatal(err)
	}
	m, err := knowledge.PackManifest(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Files) != 1 || m.Files[0].Path != "attack/enterprise-attack.json" {
		t.Fatalf("attack file: %+v", m.Files)
	}
	var ok bool
	for _, src := range m.Sources {
		if src.Name == "mitre-attack" && src.Version == "v16.1" {
			ok = true
		}
	}
	if !ok {
		t.Errorf("attack source version not recorded: %+v", m.Sources)
	}
}
