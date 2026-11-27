package knowledge

import (
	"strings"
	"testing"
)

func TestParseExploitDB(t *testing.T) {
	csv := "id,file,description,date_published,author,type,platform,port,verified,codes\n" +
		"42,exploits/linux/remote/42.c,Example RCE,2021-01-02,alice,remote,linux,445,1,CVE-2021-1234;OSVDB-9\n" +
		"43,exploits/php/webapps/43.txt,\"SQLi, blind\",2020-05-06,bob,webapps,php,,0,\n" +
		",exploits/skip.me,missing id,,,,,,,\n" +
		"44,,missing file,,,,,,,\n"
	ex, skipped, err := ParseExploitDB(strings.NewReader(csv))
	if err != nil {
		t.Fatal(err)
	}
	if len(ex) != 2 || skipped != 2 {
		t.Fatalf("got %d exploits, %d skipped; want 2,2", len(ex), skipped)
	}
	if ex[0].EDBID != "42" || ex[0].File != "exploits/linux/remote/42.c" || !ex[0].Verified {
		t.Errorf("row0: %+v", ex[0])
	}
	if len(ex[0].CVEs) != 1 || ex[0].CVEs[0] != "CVE-2021-1234" {
		t.Errorf("row0 CVEs: %v", ex[0].CVEs)
	}
	if ex[1].Description != "SQLi, blind" || ex[1].Type != "webapps" || ex[1].Port != "" {
		t.Errorf("row1 (quoted comma): %+v", ex[1])
	}
}

func TestExploitDBColumnOrderIndependent(t *testing.T) {
	// A different column order (an added upstream column) must not shift fields.
	csv := "codes,file,id,platform,description\n" +
		"CVE-2019-0001,exploits/x.rb,7,windows,Title here\n"
	ex, _, err := ParseExploitDB(strings.NewReader(csv))
	if err != nil || len(ex) != 1 {
		t.Fatalf("parse: %v %d", err, len(ex))
	}
	if ex[0].EDBID != "7" || ex[0].File != "exploits/x.rb" || ex[0].Platform != "windows" || ex[0].CVEs[0] != "CVE-2019-0001" {
		t.Errorf("fields mapped by position, not header: %+v", ex[0])
	}
}

func TestExtractCVEs(t *testing.T) {
	got := ExtractCVEs("see cve-2021-1 and CVE-2021-0001, also CVE-2021-0001 dup, CVE-2020-99999")
	// cve-2021-1 has too few digits in the sequence (needs 4+), so it is skipped.
	want := []string{"CVE-2020-99999", "CVE-2021-0001"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
	if ExtractCVEs("nothing here") != nil {
		t.Error("no CVEs should return nil")
	}
}

const nvdSample = `{
  "resultsPerPage": 1,
  "format": "NVD_CVE",
  "vulnerabilities": [
    {"cve": {
      "id": "CVE-2021-41773",
      "published": "2021-10-05T07:15:00.000",
      "descriptions": [
        {"lang": "es", "value": "ruta"},
        {"lang": "en", "value": "Path traversal in Apache HTTP Server 2.4.49"}
      ],
      "metrics": {"cvssMetricV31": [
        {"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N"}}
      ]},
      "weaknesses": [{"description": [{"lang": "en", "value": "CWE-22"}]}],
      "references": [{"url": "https://httpd.apache.org/x"}, {"url": "https://httpd.apache.org/x"}],
      "configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": true, "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}
      ]}]}]
    }},
    {"cve": {
      "id": "CVE-2020-0001",
      "descriptions": [{"lang": "en", "value": "range example"}],
      "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0, "vectorString": "AV:N"}, "baseSeverity": "MEDIUM"}]},
      "configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": true, "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "versionStartIncluding": "2.4.0", "versionEndExcluding": "2.4.50"}
      ]}]}]
    }}
  ]
}`

func TestParseNVD(t *testing.T) {
	cves, err := ParseNVDAll(strings.NewReader(nvdSample))
	if err != nil {
		t.Fatal(err)
	}
	if len(cves) != 2 {
		t.Fatalf("got %d CVEs", len(cves))
	}
	a := cves[0]
	if a.ID != "CVE-2021-41773" || !strings.Contains(a.Description, "Path traversal") {
		t.Errorf("A: %+v", a)
	}
	if a.CVSS == nil || a.CVSS.Version != "3.1" || a.CVSS.BaseScore != 7.5 || a.CVSS.Severity != "HIGH" {
		t.Errorf("A CVSS: %+v", a.CVSS)
	}
	if len(a.CWEs) != 1 || a.CWEs[0] != "CWE-22" {
		t.Errorf("A CWEs: %v", a.CWEs)
	}
	if len(a.References) != 1 { // duplicate URL deduped
		t.Errorf("A refs: %v", a.References)
	}
	if len(a.CPEMatches) != 1 || a.CPEMatches[0].Criteria != "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*" {
		t.Errorf("A cpe: %+v", a.CPEMatches)
	}
	b := cves[1]
	if b.CVSS.Version != "2.0" || b.CVSS.Severity != "MEDIUM" {
		t.Errorf("B CVSS (v2 fallback): %+v", b.CVSS)
	}
}

func TestParseCPE(t *testing.T) {
	p, ok := ParseCPE("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
	if !ok || p.Part != "a" || p.Vendor != "apache" || p.Product != "http_server" || p.Version != "2.4.49" {
		t.Fatalf("parsed %+v ok=%v", p, ok)
	}
	if _, ok := ParseCPE("cpe:/a:apache:http_server"); ok {
		t.Error("a 2.2 URI must not parse as 2.3")
	}
}

func TestCPEMatchVersion(t *testing.T) {
	exact := CPEMatch{Criteria: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}
	if !exact.MatchesVersion("2.4.49") || exact.MatchesVersion("2.4.50") {
		t.Error("pinned version must match only itself")
	}
	rng := CPEMatch{
		Criteria:              "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
		VersionStartIncluding: "2.4.0", VersionEndExcluding: "2.4.50",
	}
	for _, in := range []string{"2.4.0", "2.4.49", "2.4.1"} {
		if !rng.MatchesVersion(in) {
			t.Errorf("%s should be in range", in)
		}
	}
	for _, out := range []string{"2.3.9", "2.4.50", "2.5.0"} {
		if rng.MatchesVersion(out) {
			t.Errorf("%s should be out of range", out)
		}
	}
	any := CPEMatch{Criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"}
	if !any.MatchesVersion("9.9.9") || !any.MatchesVersion("") {
		t.Error("a wildcard with no range covers every version")
	}
}

func TestCompareVersions(t *testing.T) {
	less := [][2]string{
		{"2.4.49", "2.4.50"}, {"2.4.49", "2.4.49a"}, {"1.0.0", "1.0.0.1"},
		{"1.9", "1.10"}, {"2.4.9", "2.4.49"}, {"1.0", "1.0.1"},
	}
	for _, p := range less {
		if CompareVersions(p[0], p[1]) >= 0 {
			t.Errorf("%s should be < %s", p[0], p[1])
		}
		if CompareVersions(p[1], p[0]) <= 0 {
			t.Errorf("%s should be > %s", p[1], p[0])
		}
	}
	for _, eq := range [][2]string{{"2.4.49", "2.4.49"}, {"1.0.0", "1.0.0"}} {
		if CompareVersions(eq[0], eq[1]) != 0 {
			t.Errorf("%s == %s", eq[0], eq[1])
		}
	}
}
