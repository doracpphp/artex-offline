package knowledge

import (
	"strings"
	"unicode/utf8"
)

// Chunking for the full-text index. A document (a technique page, an exploit
// source file) is split into chunks so search returns a focused, size-bounded
// passage with its position, and read_knowledge can fetch one chunk's full text.
// The split prefers paragraph and line boundaries so a chunk stays readable, and
// never splits a UTF-8 rune.

// Chunk is one indexed passage of a document.
type Chunk struct {
	Index int    // 1-based position within the document
	Text  string // the passage, at most the configured byte budget
}

// ChunkText splits text into chunks of at most maxBytes bytes each. It breaks on
// the last blank line, else the last newline, within the budget; failing that
// (one very long line) it breaks on a rune boundary at the budget. Leading and
// trailing whitespace of each chunk is trimmed, and empty chunks are dropped.
func ChunkText(text string, maxBytes int) []Chunk {
	if maxBytes < 16 {
		maxBytes = 16 // a floor so a tiny budget cannot loop on a single rune
	}
	var chunks []Chunk
	rest := text
	for len(rest) > 0 {
		var piece string
		if len(rest) <= maxBytes {
			piece, rest = rest, ""
		} else {
			cut := breakPoint(rest, maxBytes)
			piece, rest = rest[:cut], rest[cut:]
		}
		if t := strings.TrimSpace(piece); t != "" {
			chunks = append(chunks, Chunk{Index: len(chunks) + 1, Text: t})
		}
	}
	return chunks
}

// breakPoint returns the byte offset to cut s at, no more than maxBytes: the
// last blank-line boundary, else the last newline, else a rune-safe offset at
// the budget. The returned offset is always > 0 and <= maxBytes.
func breakPoint(s string, maxBytes int) int {
	window := s[:maxBytes]
	if i := strings.LastIndex(window, "\n\n"); i > 0 {
		return i + 2
	}
	if i := strings.LastIndexByte(window, '\n'); i > 0 {
		return i + 1
	}
	// One long line: back up to a rune boundary at or before the budget.
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	if cut == 0 {
		cut = maxBytes // degenerate; emit the budget as-is
	}
	return cut
}
