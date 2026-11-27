package knowledge

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// NVD 2.0 ingestion. The builder snapshots the NVD 2.0 API (the CVE, and through
// each CVE's configurations the CPE match, data); the legacy 1.1 feeds were
// retired in 2023 (docs §5). lookup_cve returns a CVE's description, CVSS, CWE,
// references and affected products; lookup_software resolves a product+version
// fingerprint to CPEs and then, via the match criteria and their version ranges,
// to CVEs.

// CVE is one NVD record, reduced to the fields the tools use.
type CVE struct {
	ID          string
	Description string
	Published   string
	CVSS        *CVSS
	CWEs        []string // e.g. ["CWE-89"]
	References  []string // URLs
	CPEMatches  []CPEMatch
}

// CVSS is the best available score for a CVE: v3.1 is preferred, then v3.0, then
// v2.0 (Version records which).
type CVSS struct {
	Version   string  `json:"version"`
	BaseScore float64 `json:"base_score"`
	Severity  string  `json:"severity"`
	Vector    string  `json:"vector"`
}

// CPEMatch is one applicability entry: a CPE 2.3 criterion and the version range
// it covers. A fingerprint matches when its CPE equals the criterion's
// vendor/product and its version falls in the range (store.go evaluates this).
type CPEMatch struct {
	Criteria              string `json:"criteria"`
	Vulnerable            bool   `json:"vulnerable"`
	VersionStartIncluding string `json:"version_start_including,omitempty"`
	VersionStartExcluding string `json:"version_start_excluding,omitempty"`
	VersionEndIncluding   string `json:"version_end_including,omitempty"`
	VersionEndExcluding   string `json:"version_end_excluding,omitempty"`
}

// nvdVuln is one element of an NVD 2.0 file's "vulnerabilities" array.
type nvdVuln struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID           string         `json:"id"`
	Published    string         `json:"published"`
	Descriptions []nvdLangValue `json:"descriptions"`
	Metrics      nvdMetrics     `json:"metrics"`
	Weaknesses   []nvdWeakness  `json:"weaknesses"`
	References   []nvdReference `json:"references"`
	Configs      []nvdConfig    `json:"configurations"`
}

type nvdLangValue struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	V31 []nvdCVSSMetric `json:"cvssMetricV31"`
	V30 []nvdCVSSMetric `json:"cvssMetricV30"`
	V2  []nvdCVSSMetric `json:"cvssMetricV2"`
}

type nvdCVSSMetric struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"` // v2 puts severity here, not in cvssData
}

type nvdWeakness struct {
	Description []nvdLangValue `json:"description"`
}

type nvdReference struct {
	URL string `json:"url"`
}

type nvdConfig struct {
	Nodes []nvdNode `json:"nodes"`
}

type nvdNode struct {
	CPEMatch []nvdCPEMatch `json:"cpeMatch"`
}

type nvdCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

// ParseNVD streams the vulnerabilities array of an NVD 2.0 JSON file, calling fn
// for each CVE. Streaming keeps a large yearly file off the heap. fn's error
// stops the parse.
func ParseNVD(r io.Reader, fn func(CVE) error) error {
	dec := json.NewDecoder(r)
	// Advance to the "vulnerabilities" array, then decode its elements one by one.
	if err := seekToArray(dec, "vulnerabilities"); err != nil {
		return err
	}
	for dec.More() {
		var v nvdVuln
		if err := dec.Decode(&v); err != nil {
			return fmt.Errorf("decode nvd vulnerability: %w", err)
		}
		if c := v.CVE.toCVE(); c.ID != "" {
			if err := fn(c); err != nil {
				return err
			}
		}
	}
	return nil
}

// ParseNVDAll is ParseNVD collected into a slice (tests and small files).
func ParseNVDAll(r io.Reader) ([]CVE, error) {
	var out []CVE
	err := ParseNVD(r, func(c CVE) error { out = append(out, c); return nil })
	return out, err
}

// seekToArray reads tokens until it reaches the value of the named top-level
// object key and confirms that value opens an array (consuming the '['). The NVD
// files are a JSON object whose "vulnerabilities" key holds the array.
func seekToArray(dec *json.Decoder, key string) error {
	// opening object brace
	t, err := dec.Token()
	if err != nil {
		return fmt.Errorf("read nvd json: %w", err)
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("nvd json does not start with an object")
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		name, _ := keyTok.(string)
		if name == key {
			open, err := dec.Token()
			if err != nil {
				return err
			}
			if d, ok := open.(json.Delim); !ok || d != '[' {
				return fmt.Errorf("nvd %q is not an array", key)
			}
			return nil
		}
		// Not the key we want: skip its value, nested structures included.
		if err := skipValue(dec); err != nil {
			return err
		}
	}
	return fmt.Errorf("nvd json has no %q array", key)
}

// skipValue consumes one JSON value from dec, descending through objects and
// arrays. The decoder has already read the field name; this reads its value.
func skipValue(dec *json.Decoder) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := t.(json.Delim); ok && (d == '{' || d == '[') {
		for dec.More() {
			if d == '{' {
				if _, err := dec.Token(); err != nil { // key
					return err
				}
			}
			if err := skipValue(dec); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil { // closing delim
			return err
		}
	}
	return nil
}

func (c nvdCVE) toCVE() CVE {
	out := CVE{ID: strings.TrimSpace(c.ID), Published: c.Published}
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			out.Description = d.Value
			break
		}
	}
	if out.Description == "" && len(c.Descriptions) > 0 {
		out.Description = c.Descriptions[0].Value
	}
	out.CVSS = bestCVSS(c.Metrics)
	cweSeen := map[string]bool{}
	for _, w := range c.Weaknesses {
		for _, d := range w.Description {
			if d.Lang == "en" && strings.HasPrefix(d.Value, "CWE-") && !cweSeen[d.Value] {
				cweSeen[d.Value] = true
				out.CWEs = append(out.CWEs, d.Value)
			}
		}
	}
	sort.Strings(out.CWEs)
	refSeen := map[string]bool{}
	for _, r := range c.References {
		if r.URL != "" && !refSeen[r.URL] {
			refSeen[r.URL] = true
			out.References = append(out.References, r.URL)
		}
	}
	for _, cfg := range c.Configs {
		for _, n := range cfg.Nodes {
			for _, m := range n.CPEMatch {
				if m.Criteria == "" {
					continue
				}
				out.CPEMatches = append(out.CPEMatches, CPEMatch{
					Criteria:              m.Criteria,
					Vulnerable:            m.Vulnerable,
					VersionStartIncluding: m.VersionStartIncluding,
					VersionStartExcluding: m.VersionStartExcluding,
					VersionEndIncluding:   m.VersionEndIncluding,
					VersionEndExcluding:   m.VersionEndExcluding,
				})
			}
		}
	}
	return out
}

func bestCVSS(m nvdMetrics) *CVSS {
	pick := func(ms []nvdCVSSMetric, ver string) *CVSS {
		if len(ms) == 0 {
			return nil
		}
		d := ms[0]
		sev := d.CVSSData.BaseSeverity
		if sev == "" {
			sev = d.BaseSeverity // v2
		}
		return &CVSS{Version: ver, BaseScore: d.CVSSData.BaseScore, Severity: strings.ToUpper(sev), Vector: d.CVSSData.VectorString}
	}
	if c := pick(m.V31, "3.1"); c != nil {
		return c
	}
	if c := pick(m.V30, "3.0"); c != nil {
		return c
	}
	return pick(m.V2, "2.0")
}

// CPE 2.3 URI: cpe:2.3:part:vendor:product:version:update:edition:lang:sw_edition:target_sw:target_hw:other
// (13 colon-separated fields, "*" for any). A field may contain an escaped colon
// (`\:`), which these helpers preserve by not splitting on it.

// CPEParts holds the fields of a CPE 2.3 URI the tools use.
type CPEParts struct {
	Part    string // a | o | h
	Vendor  string
	Product string
	Version string
}

// ParseCPE parses a CPE 2.3 URI into the fields lookup_software keys on. It
// returns ok=false for anything that is not a 2.3 URI.
func ParseCPE(uri string) (CPEParts, bool) {
	if !strings.HasPrefix(uri, "cpe:2.3:") {
		return CPEParts{}, false
	}
	fields := splitCPE(uri)
	if len(fields) < 6 {
		return CPEParts{}, false
	}
	// fields[0]="cpe", [1]="2.3", [2]=part, [3]=vendor, [4]=product, [5]=version
	return CPEParts{
		Part:    fields[2],
		Vendor:  strings.ToLower(fields[3]),
		Product: strings.ToLower(fields[4]),
		Version: fields[5],
	}, true
}

// splitCPE splits a CPE 2.3 URI on unescaped colons.
func splitCPE(uri string) []string {
	var out []string
	var cur strings.Builder
	escaped := false
	for _, r := range uri {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\':
			cur.WriteRune(r)
			escaped = true
		case r == ':':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	out = append(out, cur.String())
	return out
}
