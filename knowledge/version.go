package knowledge

import (
	"strconv"
	"strings"
)

// CPE version-range matching for lookup_software. A CVE's CPEMatch names a
// product and a version range; a fingerprint (product + version) matches when
// the product's CPE equals the criterion's vendor/product and the version falls
// in the range. The criterion's own version field can also pin an exact version
// ("2.4.49") or mean "any" ("*"/"-").

// MatchesVersion reports whether version satisfies m: its explicit version
// field (when not a wildcard) or, when the field is a wildcard, its
// start/end range bounds. An empty fingerprint version matches only a wildcard
// criterion with no range (i.e. "all versions"), since nothing is known to
// exclude.
func (m CPEMatch) MatchesVersion(version string) bool {
	crit, ok := ParseCPE(m.Criteria)
	if !ok {
		return false
	}
	pinned := crit.Version
	hasRange := m.VersionStartIncluding != "" || m.VersionStartExcluding != "" ||
		m.VersionEndIncluding != "" || m.VersionEndExcluding != ""

	// A pinned exact version in the criterion (not * or -) must equal the query,
	// and a range is not expected alongside it.
	if pinned != "" && pinned != "*" && pinned != "-" {
		return strings.EqualFold(pinned, version)
	}
	// Wildcard version. Without a range the criterion covers every version.
	if !hasRange {
		return true
	}
	if version == "" {
		return false // a range constrains versions; an unknown one cannot be placed
	}
	if m.VersionStartIncluding != "" && CompareVersions(version, m.VersionStartIncluding) < 0 {
		return false
	}
	if m.VersionStartExcluding != "" && CompareVersions(version, m.VersionStartExcluding) <= 0 {
		return false
	}
	if m.VersionEndIncluding != "" && CompareVersions(version, m.VersionEndIncluding) > 0 {
		return false
	}
	if m.VersionEndExcluding != "" && CompareVersions(version, m.VersionEndExcluding) >= 0 {
		return false
	}
	return true
}

// CompareVersions orders two dotted versions by comparing components
// left to right: numeric components numerically, and a mixed/alpha component by
// splitting it into numeric and non-numeric runs so "2.4.49" < "2.4.49a" <
// "2.4.50" and "1.0.0" < "1.0.0.1". It is a best-effort order for the common
// software versions in CPE data, not a full semver implementation; equal
// prefixes with a longer tail sort the longer one higher. Returns -1, 0 or 1.
func CompareVersions(a, b string) int {
	as, bs := splitVersion(a), splitVersion(b)
	for i := 0; i < len(as) || i < len(bs); i++ {
		if i >= len(as) {
			return -1
		}
		if i >= len(bs) {
			return 1
		}
		if c := compareComponent(as[i], bs[i]); c != 0 {
			return c
		}
	}
	return 0
}

// splitVersion breaks a version on '.', '-', '_' and '+' into components.
func splitVersion(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool {
		return r == '.' || r == '-' || r == '_' || r == '+'
	})
}

// compareComponent compares two version components. Pure-numeric components
// compare as integers; otherwise each is split into alternating digit and
// non-digit runs, digit runs compared numerically and others lexically, with a
// numeric run ranking below a non-numeric one at the same position (so "49" <
// "49a").
func compareComponent(a, b string) int {
	if an, aerr := strconv.Atoi(a); aerr == nil {
		if bn, berr := strconv.Atoi(b); berr == nil {
			switch {
			case an < bn:
				return -1
			case an > bn:
				return 1
			default:
				return 0
			}
		}
	}
	ar, br := splitRuns(a), splitRuns(b)
	for i := 0; i < len(ar) || i < len(br); i++ {
		if i >= len(ar) {
			return -1
		}
		if i >= len(br) {
			return 1
		}
		if c := compareRun(ar[i], br[i]); c != 0 {
			return c
		}
	}
	return 0
}

// splitRuns splits a component into maximal runs of digits or non-digits.
func splitRuns(s string) []string {
	var out []string
	var cur strings.Builder
	var curDigit bool
	for i, r := range s {
		d := r >= '0' && r <= '9'
		if i > 0 && d != curDigit {
			out = append(out, cur.String())
			cur.Reset()
		}
		cur.WriteRune(r)
		curDigit = d
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func compareRun(a, b string) int {
	an, aerr := strconv.Atoi(a)
	bn, berr := strconv.Atoi(b)
	switch {
	case aerr == nil && berr == nil:
		switch {
		case an < bn:
			return -1
		case an > bn:
			return 1
		default:
			return 0
		}
	case aerr == nil && berr != nil:
		return -1 // a numeric run ranks below a non-numeric one ("49" < "49a")
	case aerr != nil && berr == nil:
		return 1
	default:
		return strings.Compare(a, b)
	}
}
