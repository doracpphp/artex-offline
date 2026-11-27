package server

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestResolveServerPackPath(t *testing.T) {
	dir := t.TempDir()
	inbox := filepath.Join(dir, "inbox")
	os.MkdirAll(inbox, 0o755)
	packFile := filepath.Join(inbox, "pack.tar.gz")
	os.WriteFile(packFile, []byte("x"), 0o644)

	// A relative path resolves under the knowledge dir.
	got, err := resolveServerPackPath(dir, "inbox/pack.tar.gz")
	if err != nil || got != filepath.Clean(packFile) {
		t.Fatalf("relative: got %q err %v", got, err)
	}
	// An absolute path inside the dir is accepted.
	if _, err := resolveServerPackPath(dir, packFile); err != nil {
		t.Errorf("absolute inside: %v", err)
	}
	// Escapes are refused.
	escapes := []string{"../outside.tar.gz", "inbox/../../etc/passwd"}
	if runtime.GOOS != "windows" {
		escapes = append(escapes, "/etc/passwd")
	} else {
		escapes = append(escapes, `C:\Windows\win.ini`)
	}
	for _, p := range escapes {
		if _, err := resolveServerPackPath(dir, p); err == nil {
			t.Errorf("%q should be refused as outside the knowledge dir", p)
		}
	}
	// A missing file is refused.
	if _, err := resolveServerPackPath(dir, "inbox/nope.tar.gz"); err == nil {
		t.Error("a missing file should be refused")
	}
}

func TestTruthy(t *testing.T) {
	for _, y := range []string{"1", "true", "on", "YES"} {
		if !truthy(y) {
			t.Errorf("%q should be truthy", y)
		}
	}
	for _, n := range []string{"", "0", "false", "no", "maybe"} {
		if truthy(n) {
			t.Errorf("%q should not be truthy", n)
		}
	}
}
