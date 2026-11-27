package knowledge

import (
	"sort"
	"strings"
)

// source builds the citation string a tool returns: "pack-id:path" or
// "pack-id:path:chunk" (chunk omitted when 0), or just "pack-id" when path is
// empty. The model copies it into a finding's evidence.
func source(packID, path string, chunk int) string {
	s := packID
	if path != "" {
		s += ":" + path
	}
	if chunk > 0 {
		s += ":" + itoa(chunk)
	}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// snippet returns a short excerpt of body around the first query term, with the
// text collapsed to single spaces and capped at about max bytes. It never splits
// a UTF-8 rune at the cap.
func snippet(body, query string, max int) string {
	flat := strings.Join(strings.Fields(body), " ")
	if len(flat) <= max {
		return flat
	}
	lower := strings.ToLower(flat)
	pos := -1
	for _, term := range strings.Fields(strings.ToLower(query)) {
		if i := strings.Index(lower, term); i >= 0 {
			pos = i
			break
		}
	}
	start := 0
	if pos > max/3 {
		start = pos - max/3
	}
	for start > 0 && !utf8Start(flat[start]) {
		start--
	}
	end := start + max
	if end > len(flat) {
		end = len(flat)
	}
	for end < len(flat) && !utf8Start(flat[end]) {
		end++
	}
	out := flat[start:end]
	if start > 0 {
		out = "…" + out
	}
	if end < len(flat) {
		out += "…"
	}
	return out
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

// clampLimit bounds a requested result count to [1, max].
func clampLimit(req, max int) int {
	if max <= 0 {
		max = 8
	}
	if req <= 0 || req > max {
		return max
	}
	return req
}

// sortByCVSS orders software hits by CVSS base score descending, then CVE id, so
// the result is stable.
func sortByCVSS(hits []SoftwareHit) {
	sort.SliceStable(hits, func(i, j int) bool {
		si, sj := 0.0, 0.0
		if hits[i].CVSS != nil {
			si = hits[i].CVSS.BaseScore
		}
		if hits[j].CVSS != nil {
			sj = hits[j].CVSS.BaseScore
		}
		if si != sj {
			return si > sj
		}
		return hits[i].CVE > hits[j].CVE
	})
}

// parsePGTextArray parses a PostgreSQL text[] output literal ({"a","b"}) into a
// slice. It is the read-side counterpart of pgTextArray and handles the quoting
// and escaping PostgreSQL emits.
func parsePGTextArray(s string) []string {
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != '{' || s[len(s)-1] != '}' {
		return nil
	}
	inner := s[1 : len(s)-1]
	if inner == "" {
		return nil
	}
	var out []string
	var cur strings.Builder
	inQuote := false
	escaped := false
	flush := func() {
		out = append(out, cur.String())
		cur.Reset()
	}
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		switch {
		case escaped:
			cur.WriteByte(c)
			escaped = false
		case c == '\\':
			escaped = true
		case c == '"':
			inQuote = !inQuote
		case c == ',' && !inQuote:
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}
