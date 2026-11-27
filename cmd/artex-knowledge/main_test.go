package main

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
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
