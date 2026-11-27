package knowledge

import (
	"strings"
	"testing"
)

func TestChunkText(t *testing.T) {
	// Paragraph boundary preferred.
	text := "para one line\n\npara two line\n\npara three line"
	cs := ChunkText(text, 20)
	if len(cs) < 2 {
		t.Fatalf("expected multiple chunks, got %d: %+v", len(cs), cs)
	}
	for i, c := range cs {
		if c.Index != i+1 {
			t.Errorf("chunk %d has index %d", i, c.Index)
		}
		if len(c.Text) > 20 && !strings.Contains(c.Text, " ") {
			t.Errorf("chunk over budget: %q", c.Text)
		}
		if c.Text != strings.TrimSpace(c.Text) {
			t.Errorf("chunk not trimmed: %q", c.Text)
		}
	}
	// Reassembled content is preserved (modulo whitespace).
	joined := ""
	for _, c := range cs {
		joined += c.Text + " "
	}
	for _, w := range []string{"one", "two", "three"} {
		if !strings.Contains(joined, w) {
			t.Errorf("lost %q", w)
		}
	}
}

func TestChunkShortTextOneChunk(t *testing.T) {
	cs := ChunkText("short", 4096)
	if len(cs) != 1 || cs[0].Text != "short" || cs[0].Index != 1 {
		t.Fatalf("got %+v", cs)
	}
	if len(ChunkText("   \n  ", 100)) != 0 {
		t.Error("whitespace-only text should produce no chunks")
	}
}

func TestChunkNeverSplitsRune(t *testing.T) {
	// A long line of multibyte runes with no break opportunity.
	text := strings.Repeat("あ", 100) // 3 bytes each = 300 bytes
	cs := ChunkText(text, 64)
	if len(cs) < 2 {
		t.Fatalf("expected a split, got %d", len(cs))
	}
	for _, c := range cs {
		for _, r := range c.Text {
			if r == '�' {
				t.Fatalf("a rune was split: %q", c.Text)
			}
		}
	}
}
