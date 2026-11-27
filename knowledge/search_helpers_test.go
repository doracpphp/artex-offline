package knowledge

import (
	"testing"
	"unicode/utf8"
)

// read_knowledge caps a chunk at MaxChunkBytes; the cut must never split a
// multi-byte character, whatever the limit.
func TestTruncateUTF8(t *testing.T) {
	s := "abc日本語テキスト"
	for max := 1; max <= len(s)+1; max++ {
		got := truncateUTF8(s, max)
		if len(got) > max || !utf8.ValidString(got) {
			t.Fatalf("truncateUTF8(%q, %d) = %q (len %d, valid %v)", s, max, got, len(got), utf8.ValidString(got))
		}
		if max >= len(s) && got != s {
			t.Fatalf("truncateUTF8 with room for the whole string must return it: %q", got)
		}
	}
	// "abc" + "日" is 6 bytes; a limit of 5 must stop before "日".
	if got := truncateUTF8(s, 5); got != "abc" {
		t.Errorf("truncateUTF8(%q, 5) = %q, want %q", s, got, "abc")
	}
	if got := truncateUTF8(s, 0); got != s {
		t.Errorf("a non-positive limit means no limit: %q", got)
	}
}
